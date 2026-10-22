//! Установка и удаление helper-службы на Windows (нужны права администратора, один запрос UAC).
//! Служба запускается от LocalSystem, слушает named pipe с DACL для установившего пользователя.
//! Код не проверялся на живой Windows: логика имён, SDDL, аргументов sc/icacls покрыта тестами в `winhelper`.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::winhelper::{self, SvcState, SERVICE_NAME};
use crate::{ipc, singbox};

fn env_dir(var: &str, default: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn paths() -> winhelper::WinPaths {
    winhelper::win_paths(&env_dir("ProgramFiles", r"C:\Program Files"), &env_dir("ProgramData", r"C:\ProgramData"))
}

/// Вызвать системную утилиту, вернуть (успех, stdout).
fn run_capture(cmd: &str, args: &[String]) -> Result<(bool, String)> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("не удалось запустить {cmd}"))?;
    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&o.stderr));
    Ok((o.status.success(), text))
}

fn run_ok(cmd: &str, args: &[String]) -> Result<()> {
    let (ok, out) = run_capture(cmd, args)?;
    if !ok {
        bail!("`{cmd} {}` завершилась с ошибкой: {}", args.first().map(String::as_str).unwrap_or(""), out.trim());
    }
    Ok(())
}

fn sc(args: &[&str]) -> Result<(bool, String)> {
    run_capture("sc", &args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

fn service_state() -> SvcState {
    match sc(&["query", SERVICE_NAME]) {
        Ok((ok, out)) => winhelper::parse_sc_query(&out, ok),
        Err(_) => SvcState::Missing,
    }
}

/// Права администратора: `net session` работает только из повышенного процесса, от локали не зависит.
pub fn is_elevated() -> bool {
    Command::new("net").arg("session").output().map(|o| o.status.success()).unwrap_or(false)
}

/// SID текущего пользователя (того, кто запустил установку).
pub fn current_user_sid() -> Option<String> {
    let (ok, out) = run_capture("whoami", &["/user".into(), "/fo".into(), "csv".into(), "/nh".into()]).ok()?;
    if !ok {
        return None;
    }
    winhelper::parse_whoami_sid(&out).ok()
}

async fn wait_state(want: SvcState, secs: u64) -> bool {
    for _ in 0..secs * 4 {
        if service_state() == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    service_state() == want
}

/// Копирование с повторами: сразу после остановки службы файл может быть ещё занят.
async fn copy_exe(src: &Path, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("part");
    fs::copy(src, &tmp).with_context(|| format!("не удалось скопировать {} в {}", src.display(), tmp.display()))?;
    let mut last = None;
    for _ in 0..20 {
        match fs::rename(&tmp, dst) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(anyhow::Error::from(last.unwrap())).with_context(|| format!("не удалось заменить {} (файл занят?)", dst.display()))
}

pub async fn install(allowed_sid: &str, helper_src: &Path, report: &(dyn Fn(&str) + Sync)) -> Result<()> {
    if !is_elevated() {
        bail!("нужны права администратора: запусти терминал «От имени администратора» и повтори `eleutheria helper install`");
    }
    if !helper_src.exists() {
        bail!("не найден helper {} (он должен лежать рядом с eleutheria.exe)", helper_src.display());
    }
    winhelper::pipe_sddl(allowed_sid)?; // проверяет SID до любых изменений в системе
    report("Готовлю sing-box (проверка SHA256)…");
    let sb_exe = singbox::ensure_local_binary().await?;

    let p = paths();
    if matches!(service_state(), SvcState::Running | SvcState::Other) {
        report("Останавливаю старую версию службы…");
        let _ = sc(&["stop", SERVICE_NAME]);
        if !wait_state(SvcState::Stopped, 20).await {
            bail!("служба {SERVICE_NAME} не остановилась за 20 секунд");
        }
    }

    report(&format!("Копирую файлы в {}", p.bin_dir.display()));
    fs::create_dir_all(&p.bin_dir)?;
    copy_exe(&sb_exe, &p.singbox_exe).await?;
    copy_exe(helper_src, &p.helper_exe).await?;
    if let Some(src_dir) = sb_exe.parent() {
        for e in fs::read_dir(src_dir)?.flatten() {
            let path = e.path();
            if path.extension().is_some_and(|x| x.eq_ignore_ascii_case("dll")) {
                if let Some(name) = path.file_name() {
                    copy_exe(&path, &p.bin_dir.join(name)).await?;
                }
            }
        }
    }

    // каталог с конфигом и рабочими файлами sing-box (в них учётные данные серверов): только SYSTEM и администраторы
    fs::create_dir_all(&p.runtime_dir)?;
    run_ok("icacls", &winhelper::icacls_lockdown_args(&p.config_dir)).context("не удалось закрыть доступ к каталогу данных")?;

    let cfg = serde_json::json!({
        "allowed_sid": allowed_sid,
        "singbox_path": p.singbox_exe,
        "runtime_dir": p.runtime_dir,
        "socket_path": ipc::default_socket_path(),
    });
    fs::write(&p.config_path, serde_json::to_vec_pretty(&cfg)?)?;

    let args = winhelper::sc_create_args(&p.helper_exe);
    if service_state() == SvcState::Missing {
        run_ok("sc", &args).context("не удалось создать службу")?;
        let _ = run_capture("sc", &["description".into(), SERVICE_NAME.into(), "Eleutheria: запускает sing-box в режиме TUN по запросу владельца установки".into()]);
    } else {
        let mut a = args;
        a[0] = "config".into();
        run_ok("sc", &a).context("не удалось обновить службу")?;
    }
    let _ = run_capture("sc", &winhelper::sc_failure_args());

    run_ok("sc", &["start".into(), SERVICE_NAME.into()]).context("не удалось запустить службу")?;
    if !wait_state(SvcState::Running, 20).await {
        bail!("служба {SERVICE_NAME} не перешла в состояние «работает». Подробности: Просмотр событий → Журналы Windows → Система");
    }
    report(&format!("Служба установлена; доступ только для SID {allowed_sid}, SYSTEM и администраторов"));
    Ok(())
}

pub fn uninstall(report: &(dyn Fn(&str) + Sync)) -> Result<()> {
    if !is_elevated() {
        bail!("нужны права администратора: запусти терминал «От имени администратора» и повтори `eleutheria helper uninstall`");
    }
    if service_state() != SvcState::Missing {
        let _ = sc(&["stop", SERVICE_NAME]);
        for _ in 0..80 {
            if service_state() == SvcState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = sc(&["delete", SERVICE_NAME]);
    }
    let p = paths();
    for f in [&p.helper_exe, &p.singbox_exe] {
        let _ = fs::remove_file(f);
    }
    if let Ok(rd) = fs::read_dir(&p.bin_dir) {
        for e in rd.flatten() {
            if e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("dll")) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    let _ = fs::remove_dir(&p.bin_dir);
    let _ = fs::remove_dir_all(&p.config_dir);
    report("Служба и файлы удалены");
    Ok(())
}
