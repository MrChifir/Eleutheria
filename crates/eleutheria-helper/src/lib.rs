//! Привилегированная служба: запускает sing-box в режиме TUN по запросу владельца установки.
//! Минимум функций: ping, start, stop, status. Конфиг строится здесь из проверенных данных,
//! готовый конфиг от клиента не принимается.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use eleutheria_core::client::config::{self, ClientOpts};
use eleutheria_core::ipc::{Request, Response, StartParams, StatusInfo};
use eleutheria_core::store::write_secret_file;
use serde::Deserialize;
use tokio::sync::Mutex;

#[derive(Deserialize, Clone, Debug)]
pub struct HelperConfig {
    /// Unix: uid владельца установки.
    #[serde(default)]
    pub allowed_uid: u32,
    /// Windows: SID владельца установки (доступ к named pipe).
    #[serde(default)]
    pub allowed_sid: String,
    pub singbox_path: String,
    pub runtime_dir: String,
    pub socket_path: String,
}

/// Приоритеты правил маршрутизации, оставленных sing-box (auto_route использует 9000–9010 и таблицу 2022).
/// Правила считаются висящими, только если среди них есть ссылка на таблицу 2022.
pub fn stale_rule_priorities(show: &str) -> Vec<u32> {
    if !show.lines().any(|l| l.contains("lookup 2022")) {
        return vec![];
    }
    let mut v: Vec<u32> = show
        .lines()
        .filter_map(|l| l.split(':').next()?.trim().parse::<u32>().ok())
        .filter(|p| (9000..=9010).contains(p))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Убрать правила маршрутизации, которые мог оставить аварийно завершённый sing-box (kill -9, паника, OOM).
/// После нормальной остановки sing-box чистит их сам, тогда ничего не найдётся. Только Linux.
pub async fn cleanup_stale_rules() {
    if !cfg!(target_os = "linux") {
        return;
    }
    for fam in ["-4", "-6"] {
        let Ok(out) = tokio::process::Command::new("ip").args([fam, "rule", "show"]).output().await else { continue };
        if !out.status.success() {
            continue;
        }
        for p in stale_rule_priorities(&String::from_utf8_lossy(&out.stdout)) {
            for _ in 0..20 {
                // на одном приоритете может быть несколько правил
                let ok = tokio::process::Command::new("ip")
                    .args([fam, "rule", "del", "priority", &p.to_string()])
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !ok {
                    break;
                }
            }
        }
        let _ = tokio::process::Command::new("ip").args([fam, "route", "flush", "table", "2022"]).status().await;
    }
}

struct Running {
    pid: u32,
    info: StatusInfo,
}

#[derive(Clone)]
pub struct Helper {
    cfg: HelperConfig,
    state: Arc<Mutex<Option<Running>>>,
    op: Arc<Mutex<()>>, // start/stop не должны идти одновременно
}

#[cfg(unix)]
fn signal(pid: u32, force: bool) {
    let mut c = std::process::Command::new("kill");
    if force {
        c.arg("-9");
    }
    let _ = c.arg(pid.to_string()).status();
}

/// У консольного процесса без окна нет мягкой остановки через taskkill, поэтому всегда /F (с дочерними, /T).
/// Адаптер Wintun и его маршруты исчезают вместе с процессом.
#[cfg(windows)]
fn signal(pid: u32, _force: bool) {
    let _ = std::process::Command::new("taskkill").args(["/PID", &pid.to_string(), "/T", "/F"]).output();
}

#[cfg(unix)]
fn random_bytes(b: &mut [u8; 16]) {
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, b))
        .expect("нет /dev/urandom");
}

#[cfg(windows)]
fn random_bytes(b: &mut [u8; 16]) {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    // NTSTATUS: успех, если значение неотрицательное
    let st = unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), b.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    assert!(st >= 0, "BCryptGenRandom вернул ошибку {st:#x}");
}

fn secret() -> String {
    // 128 бит из ядра ОС; секрет API живёт только в памяти helper'а и в конфиге с ограниченным доступом
    let mut b = [0u8; 16];
    random_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Закрыть каталог для всех, кроме SYSTEM и администраторов (аналог 0700 на Unix). Служба работает от SYSTEM.
#[cfg(windows)]
fn restrict_dir(dir: &std::path::Path) -> Result<()> {
    let args = eleutheria_core::winhelper::icacls_lockdown_args(dir);
    let out = std::process::Command::new("icacls").args(&args).output().context("не удалось запустить icacls")?;
    if !out.status.success() {
        bail!("icacls: {}", String::from_utf8_lossy(&out.stdout).trim());
    }
    Ok(())
}

impl Helper {
    pub fn new(cfg: HelperConfig) -> Self {
        Self { cfg, state: Arc::new(Mutex::new(None)), op: Arc::new(Mutex::new(())) }
    }

    pub async fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong { version: env!("CARGO_PKG_VERSION").to_string() },
            Request::Start(p) => match self.start(p).await {
                Ok(pid) => Response::Started { pid },
                Err(e) => Response::Error { message: format!("{e:#}") },
            },
            Request::Stop => Response::Stopped { was_running: self.stop().await },
            Request::Status => Response::Status(self.status().await),
        }
    }

    pub async fn status(&self) -> StatusInfo {
        match &*self.state.lock().await {
            Some(r) => r.info.clone(),
            None => StatusInfo::default(),
        }
    }

    pub async fn stop(&self) -> bool {
        let _g = self.op.lock().await;
        self.stop_locked().await
    }

    async fn stop_locked(&self) -> bool {
        let pid = self.state.lock().await.as_ref().map(|r| r.pid);
        let Some(pid) = pid else { return false };
        signal(pid, false);
        for round in 0..2 {
            for _ in 0..20 {
                if self.state.lock().await.is_none() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            if round == 0 {
                signal(pid, true);
            }
        }
        *self.state.lock().await = None;
        true
    }

    fn validate(p: &StartParams) -> Result<()> {
        if p.servers.is_empty() || p.servers.len() > 50 {
            bail!("нужно от 1 до 50 серверов");
        }
        for s in &p.servers {
            s.validate().with_context(|| format!("сервер `{}`", s.name.chars().take(32).collect::<String>()))?;
        }
        let u = &p.test_url;
        if !u.starts_with("https://") || u.len() > 512 || u.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\') {
            bail!("недопустимый test_url");
        }
        if let Some(sel) = &p.selected {
            if !p.servers.iter().any(|s| &s.name == sel) {
                bail!("сервера `{}` нет в списке", sel.chars().take(32).collect::<String>());
            }
        }
        Ok(())
    }

    async fn start(&self, p: StartParams) -> Result<u32> {
        Self::validate(&p)?;
        let _g = self.op.lock().await;
        self.stop_locked().await; // применение нового списка серверов = перезапуск туннеля

        let clash_port = std::net::TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let secret = secret();
        let copts = ClientOpts {
            listen_port: 0,
            clash_port,
            secret: secret.clone(),
            test_url: p.test_url.clone(),
            ru_direct: p.ru_direct,
            selected: p.selected.clone(),
            tun: true,
            ipv6: config::ipv6_available(),
            strict_route: config::ipv6_supported(),
        };
        let cfg = config::build(&p.servers, &copts)?;

        let dir = PathBuf::from(&self.cfg.runtime_dir);
        tokio::fs::create_dir_all(&dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        restrict_dir(&dir)?;
        let cfg_path = dir.join("config.json");
        write_secret_file(&cfg_path, &serde_json::to_vec_pretty(&cfg)?)?;

        let chk = tokio::process::Command::new(&self.cfg.singbox_path)
            .args(["check", "-c"])
            .arg(&cfg_path)
            .output()
            .await
            .with_context(|| format!("не удалось запустить {}", self.cfg.singbox_path))?;
        if !chk.status.success() {
            bail!("sing-box отклонил конфиг: {}", String::from_utf8_lossy(&chk.stderr).trim());
        }

        let log_path = dir.join("sing-box.log");
        let log = std::fs::File::create(&log_path)?;
        let mut child = tokio::process::Command::new(&self.cfg.singbox_path)
            .args(["run", "-c"])
            .arg(&cfg_path)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("не удалось запустить sing-box")?;
        let pid = child.id().context("нет pid у sing-box")?;

        let info = StatusInfo {
            running: true,
            pid: Some(pid),
            clash_port: Some(clash_port),
            secret: Some(secret),
            test_url: Some(p.test_url.clone()),
            servers: (0..p.servers.len()).map(|i| config::server_tag(i)).zip(p.servers.iter().map(|s| s.name.clone())).collect(),
        };
        *self.state.lock().await = Some(Running { pid, info });

        let state = self.state.clone();
        tokio::spawn(async move {
            let _ = child.wait().await;
            cleanup_stale_rules().await; // до освобождения состояния, чтобы не помешать следующему запуску
            let mut st = state.lock().await;
            if st.as_ref().map(|r| r.pid) == Some(pid) {
                *st = None;
            }
        });

        // готовность: процесс жив и API управления отвечает
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if self.state.lock().await.as_ref().map(|r| r.pid) != Some(pid) {
                break;
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", clash_port)).await.is_ok() {
                return Ok(pid);
            }
        }
        let alive = self.state.lock().await.as_ref().map(|r| r.pid) == Some(pid);
        if alive {
            signal(pid, false);
        }
        let tail: Vec<String> = std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(8)
            .map(str::to_string)
            .collect();
        let tail: Vec<String> = tail.into_iter().rev().collect();
        bail!("sing-box не запустился. Лог:\n{}", tail.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eleutheria_core::client::config::RuDirect;
    use eleutheria_core::client::profile::parse_vless;

    fn helper() -> Helper {
        Helper::new(HelperConfig {
            allowed_uid: 0,
            allowed_sid: String::new(),
            singbox_path: "/nonexistent/sing-box".into(),
            runtime_dir: std::env::temp_dir().join("el-helper-test").to_string_lossy().into(),
            socket_path: "/tmp/unused.sock".into(),
        })
    }

    fn params(link: &str, url: &str) -> StartParams {
        StartParams {
            servers: vec![parse_vless(link).unwrap()],
            ru_direct: RuDirect::Minimal,
            selected: None,
            test_url: url.into(),
        }
    }

    const LINK: &str = "vless://a158cda3-0b3d-424b-a8f8-26a6462c8349@203.0.113.5:443?security=reality&pbk=PUB&sid=abcd&sni=www.microsoft.com&flow=xtls-rprx-vision#s";

    #[tokio::test]
    async fn idle_status_and_stop() {
        let h = helper();
        assert!(!h.status().await.running);
        assert!(matches!(h.handle(Request::Stop).await, Response::Stopped { was_running: false }));
        assert!(matches!(h.handle(Request::Ping).await, Response::Pong { .. }));
    }

    #[tokio::test]
    async fn start_rejects_bad_input_before_touching_system() {
        let h = helper();
        let err = |r: Response| match r { Response::Error { message } => message, o => panic!("{o:?}") };
        let ok_url = "https://www.gstatic.com/generate_204";

        let mut p = params(LINK, ok_url);
        p.servers.clear();
        assert!(err(h.handle(Request::Start(p)).await).contains("от 1 до 50"));

        let mut p = params(LINK, ok_url);
        p.servers[0].host = "evil\"host".into();
        assert!(err(h.handle(Request::Start(p)).await).contains("недопустимый хост"));

        assert!(err(h.handle(Request::Start(params(LINK, "http://x/"))).await).contains("test_url"));
        assert!(err(h.handle(Request::Start(params(LINK, "https://x/ y"))).await).contains("test_url"));

        let mut p = params(LINK, ok_url);
        p.selected = Some("nope".into());
        assert!(err(h.handle(Request::Start(p)).await).contains("нет в списке"));

        // валидные данные доходят до запуска sing-box, которого здесь нет: ошибка запуска, а не паника
        let m = err(h.handle(Request::Start(params(LINK, ok_url))).await);
        assert!(m.contains("не удалось запустить"), "{m}");
        assert!(!h.status().await.running);
    }

    #[test]
    fn detects_stale_singbox_rules_only_when_table_2022_is_referenced() {
        let after_crash = "0:\tfrom all lookup local\n9000:\tfrom all to 172.19.0.0/30 lookup 2022\n9001:\tfrom all lookup 2022 suppress_prefixlength 0\n9002:\tnot from all dport 53 lookup main suppress_prefixlength 0\n9002:\tfrom all iif tun0 [detached] goto 9010\n9003:\tnot from all iif lo lookup 2022\n9010:\tfrom all nop\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
        assert_eq!(stale_rule_priorities(after_crash), vec![9000, 9001, 9002, 9003, 9010]);
        // чужие правила в том же диапазоне без таблицы 2022 не трогаем
        let foreign = "0:\tfrom all lookup local\n9001:\tfrom 10.0.0.0/8 lookup 100\n32766:\tfrom all lookup main\n";
        assert!(stale_rule_priorities(foreign).is_empty());
        // чистое состояние
        assert!(stale_rule_priorities("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n").is_empty());
    }
}
