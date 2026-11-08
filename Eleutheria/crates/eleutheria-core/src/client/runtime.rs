//! Запуск sing-box как клиента: connect / disconnect / status. Режим без TUN (локальный прокси);
//! системный TUN приедет вместе с helper-службой (M2.2).

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::categories;
use super::config::{self, ClientOpts, RuDirect};
use super::prober::ProbePlan;
use super::profile::Server;
use super::watch::{self, Link};
use crate::singbox;
use crate::store::{config_dir, write_secret_file};

pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

pub struct ConnectOpts {
    pub listen_port: u16,
    pub clash_port: u16,
    pub test_url: String,
    pub ru_direct: RuDirect,
    pub selected: Option<String>,
    /// пробные входы для пробера (`eleutheria watch`, автопереключение)
    pub probes: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Meta {
    pid: u32,
    listen_port: u16,
    clash_port: u16,
    secret: String,
    test_url: String,
    servers: Vec<(String, String)>, // (tag, имя)
    #[serde(default)]
    probe: Option<ProbePlan>,
}

pub struct ConnectInfo {
    pub listen_port: u16,
    pub pid: u32,
    /// задержка до цели через выбранный сервер; None = тест не прошёл (причина в `warning`)
    pub delay_ms: Option<u64>,
    pub warning: Option<String>,
}

pub struct ServerStatus {
    pub name: String,
    pub delay_ms: Option<u64>,
    pub error: Option<String>,
    pub active: bool,
}

pub struct Status {
    pub pid: u32,
    pub listen_port: u16,
    pub mode: String, // "авто" или имя выбранного сервера
    pub servers: Vec<ServerStatus>,
}

fn dir() -> PathBuf {
    config_dir().join("runtime")
}
fn meta_path() -> PathBuf {
    dir().join("meta.json")
}

fn read_meta() -> Option<Meta> {
    serde_json::from_str(&fs::read_to_string(meta_path()).ok()?).ok()
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("sing-box"))
        .unwrap_or(false)
}
#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .map(|o| crate::winhelper::tasklist_has_image(&String::from_utf8_lossy(&o.stdout), "sing-box"))
        .unwrap_or(false)
}

#[cfg(unix)]
fn signal(pid: u32, force: bool) {
    let mut c = Command::new("kill");
    if force {
        c.arg("-9");
    }
    let _ = c.arg(pid.to_string()).status();
}
/// У консольного процесса без окна нет мягкой остановки через taskkill, поэтому всегда /F (вместе с дочерними, /T).
#[cfg(windows)]
fn signal(pid: u32, _force: bool) {
    let _ = Command::new("taskkill").args(["/PID", &pid.to_string(), "/T", "/F"]).output();
}

#[cfg(unix)]
fn spawn_detached(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0).spawn() // переживает закрытие терминала и Ctrl-C
}
#[cfg(windows)]
fn spawn_detached(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW: переживает закрытие консоли и Ctrl-C
    cmd.creation_flags(0x0000_0008 | 0x0000_0200 | 0x0800_0000).spawn()
}

async fn clash_get(m: &Meta, path: &str, timeout: Duration) -> Result<Value> {
    let c = reqwest::Client::builder().no_proxy().timeout(timeout).build()?;
    let r = c
        .get(format!("http://127.0.0.1:{}{path}", m.clash_port))
        .bearer_auth(&m.secret)
        .send()
        .await?;
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("{}", v.get("message").and_then(|x| x.as_str()).unwrap_or(status.as_str()));
    }
    Ok(v)
}

async fn delay(m: &Meta, tag: &str) -> Result<u64> {
    let path = format!("/proxies/{tag}/delay?url={}&timeout=5000", urlencoding::encode(&m.test_url));
    let v = clash_get(m, &path, Duration::from_secs(8)).await?;
    v.get("delay").and_then(|d| d.as_u64()).context("в ответе нет задержки")
}

fn secret() -> String {
    format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>())
}

pub fn is_running() -> bool {
    read_meta().map(|m| pid_alive(m.pid)).unwrap_or(false)
}

/// Подключение пробера к запущенному локальному прокси (None: не запущен или запущен без проб).
pub fn link() -> Option<Link> {
    let m = read_meta()?;
    if !pid_alive(m.pid) {
        return None;
    }
    Some(Link { clash_port: m.clash_port, secret: m.secret, plan: m.probe? })
}

/// То же для туннеля helper'а (TUN).
pub fn link_from_helper(info: &crate::ipc::StatusInfo) -> Option<Link> {
    if !info.running {
        return None;
    }
    Some(Link { clash_port: info.clash_port?, secret: info.secret.clone()?, plan: info.probe.clone()? })
}

/// Лёгкая проверка локального прокси без обращения к Clash API и замеров задержки (для частого опроса из GUI).
pub fn running_info() -> Option<(u32, u16)> {
    let m = read_meta()?;
    pid_alive(m.pid).then_some((m.pid, m.listen_port))
}

pub async fn connect(servers: &[Server], o: &ConnectOpts) -> Result<ConnectInfo> {
    if !o.test_url.starts_with("https://") {
        // Clash API sing-box подменяет http://-URL на https://www.gstatic.com, результат был бы обманчивым
        bail!("--test-url должен начинаться с https:// (sing-box игнорирует http:// при замере задержки)");
    }
    if is_running() {
        bail!("уже подключено. Сначала `eleutheria disconnect`");
    }
    for (port, what) in [(o.listen_port, "прокси"), (o.clash_port, "API управления")] {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            bail!("порт {port} ({what}) занят. Выбери другой (--port / --clash-port)");
        }
    }
    let bin = singbox::ensure_local_binary().await?;

    let cats = categories::load();
    let probe = if o.probes { Some(watch::make_plan(servers, o.selected.as_deref(), &cats, &o.test_url)?) } else { None };
    let copts = ClientOpts {
        listen_port: o.listen_port,
        clash_port: o.clash_port,
        secret: secret(),
        test_url: o.test_url.clone(),
        ru_direct: o.ru_direct,
        selected: o.selected.clone(),
        tun: false,
        ipv6: false,
        strict_route: false,
        categories: cats,
        probe_ports: probe.as_ref().map(|p| p.ports.clone()).unwrap_or_default(),
    };
    let set = crate::userprofiles::profile_set(&crate::userprofiles::files_for_servers(&crate::userprofiles::root(), servers)?)?;
    let cfg = config::build_with_profiles(servers, &copts, &set)?;
    let d = dir();
    fs::create_dir_all(&d)?;
    let cfg_path = d.join("config.json");
    write_secret_file(&cfg_path, &serde_json::to_vec_pretty(&cfg)?)?; // в конфиге secret API

    let chk = Command::new(&bin).args(["check", "-c"]).arg(&cfg_path).output()?;
    if !chk.status.success() {
        bail!("sing-box отклонил клиентский конфиг: {}", String::from_utf8_lossy(&chk.stderr).trim());
    }

    let log_path = d.join("sing-box.log");
    let log = fs::File::create(&log_path)?;
    let child = spawn_detached(
        Command::new(&bin)
            .args(["run", "-c"])
            .arg(&cfg_path)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log),
    )
    .context("не удалось запустить sing-box")?;
    let pid = child.id();

    let meta = Meta {
        pid,
        listen_port: o.listen_port,
        clash_port: o.clash_port,
        secret: copts.secret.clone(),
        test_url: o.test_url.clone(),
        servers: servers.iter().enumerate().map(|(i, s)| (config::server_tag(i), s.name.clone())).collect(),
        probe,
    };
    write_secret_file(&meta_path(), &serde_json::to_vec_pretty(&meta)?)?;

    // ждём, пока поднимутся прокси и API
    let mut up = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if TcpStream::connect(("127.0.0.1", o.listen_port)).is_ok()
            && TcpStream::connect(("127.0.0.1", o.clash_port)).is_ok()
        {
            up = true;
            break;
        }
        if !pid_alive(pid) {
            break;
        }
    }
    if !up {
        signal(pid, false);
        let tail: String = fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        let _ = fs::remove_file(meta_path());
        bail!("sing-box не запустился. Лог:\n{tail}");
    }

    // проверка пути до цели через выбранный сервер; для urltest даём время на первый замер
    let (mut delay_ms, mut warning) = (None, None);
    for attempt in 0..3 {
        match delay(&meta, "proxy").await {
            Ok(ms) => {
                delay_ms = Some(ms);
                warning = None;
                break;
            }
            Err(e) => {
                warning = Some(format!("{e:#}"));
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    Ok(ConnectInfo { listen_port: o.listen_port, pid, delay_ms, warning })
}

pub async fn disconnect() -> Result<bool> {
    let Some(m) = read_meta() else { return Ok(false) };
    let was = pid_alive(m.pid);
    if was {
        signal(m.pid, false);
        for _ in 0..20 {
            if !pid_alive(m.pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if pid_alive(m.pid) {
            signal(m.pid, true);
        }
    }
    let _ = fs::remove_file(meta_path());
    Ok(was)
}

pub async fn status() -> Result<Option<Status>> {
    let Some(m) = read_meta() else { return Ok(None) };
    if !pid_alive(m.pid) {
        return Ok(None);
    }
    Ok(Some(status_for(&m).await?))
}

/// Статус туннеля, запущенного helper'ом (TUN).
pub async fn status_from_helper(info: &crate::ipc::StatusInfo) -> Result<Option<Status>> {
    if !info.running {
        return Ok(None);
    }
    let (Some(clash_port), Some(secret)) = (info.clash_port, info.secret.clone()) else { return Ok(None) };
    let m = Meta {
        pid: info.pid.unwrap_or(0),
        listen_port: 0,
        clash_port,
        secret,
        test_url: info.test_url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
        servers: info.servers.clone(),
        probe: info.probe.clone(),
    };
    Ok(Some(status_for(&m).await?))
}

async fn status_for(m: &Meta) -> Result<Status> {
    let name_of = |tag: &str| m.servers.iter().find(|(t, _)| t == tag).map(|(_, n)| n.clone());

    let now = clash_get(m, "/proxies/proxy", Duration::from_secs(5)).await?;
    let now = now.get("now").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (mode, active_tag) = if now == "auto" {
        let a = clash_get(m, "/proxies/auto", Duration::from_secs(5)).await?;
        ("авто".to_string(), a.get("now").and_then(|v| v.as_str()).unwrap_or("").to_string())
    } else {
        (name_of(&now).unwrap_or_else(|| now.clone()), now.clone())
    };

    let handles: Vec<_> = m
        .servers
        .iter()
        .map(|(tag, name)| {
            let (m2, tag, name, active) = (m.clone(), tag.clone(), name.clone(), active_tag.clone());
            tokio::spawn(async move {
                let r = delay(&m2, &tag).await;
                ServerStatus {
                    active: tag == active,
                    name,
                    delay_ms: r.as_ref().ok().copied(),
                    error: r.err().map(|e| format!("{e:#}")),
                }
            })
        })
        .collect();
    let mut servers = Vec::new();
    for h in handles {
        servers.push(h.await?);
    }
    Ok(Status { pid: m.pid, listen_port: m.listen_port, mode, servers })
}
