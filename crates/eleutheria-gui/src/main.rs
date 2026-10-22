//! Тонкая оболочка Tauri: каждая команда вызывает функцию из `eleutheria-app`.
//! Логика и тесты живут там; здесь только преобразование ошибок в строки для интерфейса.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use std::time::Duration;

use eleutheria_app as app;
use eleutheria_app::partners::{self, Partner};
use eleutheria_app::server::{self, HostKeyProbe, ProvisionRequest, ProvisionResult, ServerUpdateDto, SshConn, UsersView};
use eleutheria_app::update::{self, CheckOutcome, UpdateInfo};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::{Update, UpdaterExt};

fn msg(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[tauri::command]
async fn overview() -> app::Overview {
    app::overview().await
}

#[tauri::command]
async fn latency() -> Result<Option<app::Latency>, String> {
    app::latency().await.map_err(msg)
}

#[tauri::command]
async fn connect(req: app::ConnectRequest) -> Result<app::ConnectResult, String> {
    app::connect(req).await.map_err(msg)
}

#[tauri::command]
async fn disconnect() -> Result<bool, String> {
    app::disconnect().await.map_err(msg)
}

#[tauri::command]
async fn import_servers(source: String, name: Option<String>) -> Result<app::ImportResult, String> {
    app::import(&source, name).await.map_err(msg)
}

#[tauri::command]
fn remove_server(name: String) -> Result<(), String> {
    app::remove_server(&name).map_err(msg)
}

/// Ход длинных операций уходит в интерфейс событием `progress`.
fn emit(app: &AppHandle) -> impl Fn(&str) + Sync + '_ {
    move |m: &str| {
        let _ = app.emit("progress", m.to_string());
    }
}

#[tauri::command]
async fn probe_host_key(host: String, port: u16) -> Result<HostKeyProbe, String> {
    server::probe_host_key(&host, port).await.map_err(msg)
}

#[tauri::command]
async fn provision(app: AppHandle, conn: SshConn, req: ProvisionRequest) -> Result<ProvisionResult, String> {
    server::provision(&conn, &req, &emit(&app)).await.map_err(msg)
}

#[tauri::command]
async fn list_users(conn: SshConn) -> Result<UsersView, String> {
    server::list_users(&conn).await.map_err(msg)
}

#[tauri::command]
async fn add_user(app: AppHandle, conn: SshConn, name: String) -> Result<UsersView, String> {
    server::add_user(&conn, &name, &emit(&app)).await.map_err(msg)
}

#[tauri::command]
async fn remove_user(app: AppHandle, conn: SshConn, name: String) -> Result<UsersView, String> {
    server::remove_user(&conn, &name, &emit(&app)).await.map_err(msg)
}

#[tauri::command]
async fn install_helper() -> Result<(), String> {
    app::elevate::install_helper().await.map_err(msg)
}

/// Найденное обновление и скачанный (уже проверенный по подписи) пакет. Установка идёт отдельным шагом,
/// чтобы ничего не останавливать, пока пакет не скачан и не проверен.
#[derive(Default)]
struct Pending {
    update: Mutex<Option<Update>>,
    bytes: Mutex<Option<Vec<u8>>>,
}

fn updater_pubkey(app: &AppHandle) -> String {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|v| v.get("pubkey"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn upd_err(e: impl std::fmt::Display) -> String {
    format!("{e}")
}

/// Пора ли делать автоматическую проверку (раз в сутки).
#[tauri::command]
fn update_due() -> bool {
    update::should_check(update::now_unix(), update::load_prefs().last_check, update::CHECK_INTERVAL_SECS)
}

#[tauri::command]
async fn check_update(app: AppHandle, pending: State<'_, Pending>) -> Result<CheckOutcome, String> {
    if !update::pubkey_configured(&updater_pubkey(&app)) {
        return Ok(CheckOutcome::Disabled);
    }
    if let Err(reason) = update::install_supported(std::env::consts::OS, std::env::var_os("APPIMAGE").is_some()) {
        return Ok(CheckOutcome::Unsupported { reason });
    }
    // попытка фиксируется сразу: недоступные зеркала не должны вызывать проверку при каждом запуске
    update::mark_checked(update::now_unix());
    let mut b = app.updater_builder().timeout(Duration::from_secs(20));
    if let Some(p) = update::proxy_url(&app::overview().await) {
        b = b.proxy(p.parse().map_err(|_| "некорректный адрес прокси".to_string())?);
    }
    let found = b.build().map_err(upd_err)?.check().await.map_err(upd_err)?;
    *pending.bytes.lock().unwrap() = None;
    match found {
        None => {
            *pending.update.lock().unwrap() = None;
            Ok(CheckOutcome::UpToDate)
        }
        Some(u) => {
            let info = UpdateInfo { version: u.version.clone(), current: u.current_version.clone(), notes: u.body.clone(), date: u.date.map(|d| d.date().to_string()) };
            *pending.update.lock().unwrap() = Some(u);
            Ok(CheckOutcome::Available { info })
        }
    }
}

/// Шаг 1: скачать и проверить подпись. Ход уходит событием `update-progress`. Ничего не останавливается.
#[tauri::command]
async fn download_update(app: AppHandle, pending: State<'_, Pending>) -> Result<(), String> {
    let u = pending.update.lock().unwrap().clone().ok_or("обновление не найдено: сначала выполни проверку")?;
    let mut done: u64 = 0;
    let a = app.clone();
    let bytes = u
        .download(
            move |chunk, total| {
                done += chunk as u64;
                let _ = a.emit("update-progress", serde_json::json!({ "done": done, "total": total }));
            },
            || {},
        )
        .await
        .map_err(upd_err)?;
    *pending.bytes.lock().unwrap() = Some(bytes);
    Ok(())
}

/// Шаг 2: установить скачанный пакет и перезапустить приложение (на Windows установщик сам завершает приложение).
#[tauri::command]
fn install_update(app: AppHandle, pending: State<'_, Pending>) -> Result<(), String> {
    let u = pending.update.lock().unwrap().clone().ok_or("обновление не найдено")?;
    let bytes = pending.bytes.lock().unwrap().take().ok_or("пакет ещё не скачан")?;
    // откат: копия текущей установки и сторож. Нет возможности откатываться (.deb, нет CLI рядом) не мешает
    // обновлению, но пользователь об этом узнаёт.
    if let Err(e) = update::arm_rollback(&u.current_version, &u.version) {
        let _ = app.emit("update-warning", format!("Автоматический откат при неудачном обновлении недоступен: {e:#}"));
    }
    if let Err(e) = u.install(&bytes) {
        update::disarm_rollback();
        return Err(upd_err(e));
    }
    app.restart()
}

/// Интерфейс отрисован: подтверждаем обновление (сторож отката завершится) и сообщаем, если прошлое откатилось.
#[tauri::command]
fn confirm_started(app: AppHandle) -> update::StartReport {
    update::confirm_started_now(&app.package_info().version.to_string())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ManualResult {
    version: String,
    restarting: bool,
}

/// Ручной импорт: пакет и `.sig` лежат на диске. Подпись, версия и запрет понижения проверяются до любых
/// изменений; затем та же защита откатом, что и у обычного обновления.
#[tauri::command]
async fn import_update(app: AppHandle, file: String, sig: String) -> Result<ManualResult, String> {
    let clean = |s: &str| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
    let (file, sig) = (std::path::PathBuf::from(clean(&file)), std::path::PathBuf::from(clean(&sig)));
    let pubkey = updater_pubkey(&app);
    if !update::pubkey_configured(&pubkey) {
        return Err("обновления выключены: в сборке нет публичного ключа подписи".into());
    }
    const MAX_PACKAGE: u64 = 600 * 1024 * 1024;
    let size = std::fs::metadata(&file).map_err(|e| format!("не открыть {}: {e}", file.display()))?.len();
    if size > MAX_PACKAGE {
        return Err("файл слишком большой для пакета обновления".into());
    }
    let data = std::fs::read(&file).map_err(|e| format!("не прочитать {}: {e}", file.display()))?;
    let sig_text = std::fs::read_to_string(&sig).map_err(|e| format!("не прочитать {}: {e}", sig.display()))?;
    let current = app.package_info().version.to_string();
    let version = update::verify_package(&pubkey, &data, &sig_text, &current).map_err(msg)?;
    drop(data);
    let appimage = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from);
    let plan = update::manual_install_plan(std::env::consts::OS, appimage.is_some(), &file)?;
    if let Err(e) = update::arm_rollback(&current, &version) {
        let _ = app.emit("update-warning", format!("Автоматический откат при неудачном обновлении недоступен: {e:#}"));
    }
    match plan {
        update::ManualInstall::ReplaceAppImage => {
            let target = appimage.ok_or("не определён путь AppImage")?;
            if let Err(e) = update::replace_file_atomically(&file, &target) {
                update::disarm_rollback();
                return Err(msg(e));
            }
            app.restart()
        }
        update::ManualInstall::RunInstaller { program, args } => {
            if let Err(e) = std::process::Command::new(&program).args(&args).spawn() {
                update::disarm_rollback();
                return Err(format!("не удалось запустить установщик: {e}"));
            }
            app.exit(0);
            Ok(ManualResult { version, restarting: true })
        }
    }
}

#[tauri::command]
async fn server_update_status(conn: SshConn) -> Result<ServerUpdateDto, String> {
    server::server_update_status(&conn).await.map_err(msg)
}

#[tauri::command]
async fn update_server(app: AppHandle, conn: SshConn) -> Result<ServerUpdateDto, String> {
    server::update_server(&conn, &emit(&app)).await.map_err(msg)
}

/// Список партнёрских хостингов для блока «Нет сервера?».
#[tauri::command]
fn partners_list() -> Vec<Partner> {
    partners::PARTNERS.to_vec()
}

/// Открывает партнёрскую ссылку в браузере по id из белого списка. Произвольный адрес не принимается.
#[tauri::command]
fn open_partner(app: AppHandle, id: String) -> Result<(), String> {
    let url = partners::url_for(&id).ok_or_else(|| "неизвестный хостинг".to_string())?;
    app.opener().open_url(url, None::<&str>).map_err(upd_err)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .manage(Pending::default())
        .invoke_handler(tauri::generate_handler![
            overview,
            latency,
            connect,
            disconnect,
            import_servers,
            remove_server,
            probe_host_key,
            provision,
            list_users,
            add_user,
            remove_user,
            install_helper,
            update_due,
            check_update,
            download_update,
            install_update,
            confirm_started,
            import_update,
            server_update_status,
            update_server,
            partners_list,
            open_partner
        ])
        .run(tauri::generate_context!())
        .expect("не удалось запустить приложение");
}
