use std::path::PathBuf;

use anyhow::{Context, Result};
use eleutheria_helper::HelperConfig;

fn load_config() -> Result<HelperConfig> {
    let default = if cfg!(windows) {
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        eleutheria_core::winhelper::win_paths(r"C:\Program Files", &pd).config_path
    } else {
        PathBuf::from("/etc/eleutheria/helper.json")
    };
    let cfg_path = std::env::var_os("ELEUTHERIA_HELPER_CONFIG").map(PathBuf::from).unwrap_or(default);
    serde_json::from_slice(&std::fs::read(&cfg_path).with_context(|| format!("нет конфига helper'а {}", cfg_path.display()))?)
        .context("конфиг helper'а повреждён")
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => platform::run_console(),
        #[cfg(windows)]
        Some("service") => platform::run_service(),
        Some("--version") => {
            println!("eleutheria-helper {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(other) => anyhow::bail!("неизвестная команда `{other}` (поддерживается `run`{})", if cfg!(windows) { " и `service`" } else { "" }),
    }
}

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use eleutheria_core::ipc;
    use eleutheria_helper::{cleanup_stale_rules, Helper};
    use tokio::net::UnixListener;
    use tokio::signal::unix::{signal, SignalKind};

    pub fn run_console() -> Result<()> {
        tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
    }

    async fn run() -> Result<()> {
        let cfg = super::load_config()?;
        let sock = PathBuf::from(&cfg.socket_path);
        if let Some(dir) = sock.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).with_context(|| format!("не удалось создать сокет {}", sock.display()))?;
        // владелец установки и 0600: посторонний пользователь не сможет даже подключиться
        std::os::unix::fs::chown(&sock, Some(cfg.allowed_uid), None)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;

        cleanup_stale_rules().await; // следы предыдущего аварийного завершения
        let helper = Helper::new(cfg.clone());
        eprintln!("eleutheria-helper {} слушает {} (uid {})", env!("CARGO_PKG_VERSION"), sock.display(), cfg.allowed_uid);

        let h = helper.clone();
        let server = tokio::spawn(ipc::serve(listener, cfg.allowed_uid, move |req| {
            let h = h.clone();
            async move { h.handle(req).await }
        }));

        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
            r = server => { eprintln!("сервер IPC завершился: {r:?}"); }
        }
        helper.stop().await;
        cleanup_stale_rules().await;
        let _ = std::fs::remove_file(&sock);
        Ok(())
    }
}

/// Windows: `run` запускает helper в консоли (для отладки), `service` вызывается диспетчером служб.
/// Не проверялось на живой Windows.
#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::future::Future;
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::Duration;

    use anyhow::Result;
    use eleutheria_core::ipc;
    use eleutheria_core::winhelper::{self, SERVICE_NAME};
    use eleutheria_helper::Helper;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    /// У службы нет консоли: ошибки пишем в файл в закрытом для обычных пользователей каталоге данных.
    fn log(msg: &str) {
        eprintln!("{msg}");
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        let dir = winhelper::win_paths(r"C:\Program Files", &pd).config_dir;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("helper.log")) {
            let _ = writeln!(f, "{msg}");
        }
    }

    async fn serve_until(stop: impl Future<Output = ()>) -> Result<()> {
        let cfg = super::load_config()?;
        let sddl = winhelper::pipe_sddl(&cfg.allowed_sid)?;
        let helper = Helper::new(cfg.clone());
        log(&format!("eleutheria-helper {} слушает {} (SID {})", env!("CARGO_PKG_VERSION"), cfg.socket_path, cfg.allowed_sid));

        let h = helper.clone();
        let name = cfg.socket_path.clone();
        let server = tokio::spawn(async move {
            ipc::serve_pipe(&name, &sddl, move |req| {
                let h = h.clone();
                async move { h.handle(req).await }
            })
            .await
        });
        tokio::select! {
            _ = stop => {}
            r = server => { log(&format!("сервер IPC завершился: {r:?}")); }
        }
        helper.stop().await;
        Ok(())
    }

    fn runtime() -> Result<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
    }

    pub fn run_console() -> Result<()> {
        runtime()?.block_on(serve_until(async {
            let _ = tokio::signal::ctrl_c().await;
        }))
    }

    pub fn run_service() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = service_body() {
            log(&format!("служба завершилась с ошибкой: {e:#}"));
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        }
    }

    fn service_body() -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = Mutex::new(Some(tx));
        let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(t) = tx.lock().unwrap().take() {
                    let _ = t.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

        handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0))?;
        let res = runtime().and_then(|rt| {
            rt.block_on(serve_until(async {
                let _ = rx.await;
            }))
        });
        let code = if res.is_ok() { 0 } else { 1 };
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code))?;
        res
    }
}
