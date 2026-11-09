//! Обновление приложения: вся логика, не зависящая от Tauri (расписание проверок, прокси через туннель,
//! устаревший helper, проверка ключа подписи). Скачивание и установка делает плагин updater в `eleutheria-gui`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use eleutheria_core::store;
use eleutheria_core::version;
use serde::{Deserialize, Serialize};

use crate::{HelperDto, Mode, Overview};

/// Автоматическая проверка раз в сутки (плюс по кнопке).
pub const CHECK_INTERVAL_SECS: u64 = 24 * 3600;

/// Значение `plugins.updater.pubkey` в репозитории, пока не вставлен настоящий публичный ключ.
pub const PUBKEY_PLACEHOLDER: &str = "REPLACE_WITH_UPDATER_PUBLIC_KEY";

/// Публичный ключ настроен (не пустой и не заглушка). Без него обновления выключены, а не «тихо не работают».
pub fn pubkey_configured(pubkey: &str) -> bool {
    let k = pubkey.trim();
    !k.is_empty() && k != PUBKEY_PLACEHOLDER
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePrefs {
    /// unix-время последней попытки проверки (успешной или нет, чтобы не долбить недоступные зеркала)
    pub last_check: Option<u64>,
}

fn prefs_path() -> PathBuf {
    store::config_dir().join("update.json")
}

pub fn load_prefs_from(path: &Path) -> UpdatePrefs {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn save_prefs_to(path: &Path, p: &UpdatePrefs) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("не удалось создать {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.part");
    std::fs::write(&tmp, serde_json::to_vec_pretty(p)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn load_prefs() -> UpdatePrefs {
    load_prefs_from(&prefs_path())
}

/// Запомнить попытку проверки. Ошибка записи не должна ломать проверку, поэтому наружу не пробрасывается.
pub fn mark_checked(now: u64) {
    let _ = save_prefs_to(&prefs_path(), &UpdatePrefs { last_check: Some(now) });
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Пора ли делать автоматическую проверку. Часы, ушедшие назад (`last` в будущем), считаются «пора».
pub fn should_check(now: u64, last: Option<u64>, interval: u64) -> bool {
    match last {
        None => true,
        Some(l) if l > now => true,
        Some(l) => now - l >= interval,
    }
}

/// Прокси для проверки обновлений. Если поднят локальный прокси, идём через него (GitHub у части
/// пользователей недоступен без туннеля). В режиме TUN весь трафик приложения и так идёт через туннель.
pub fn proxy_url(ov: &Overview) -> Option<String> {
    let c = ov.connection.as_ref()?;
    match (c.mode, c.listen_port) {
        (Mode::Proxy, Some(p)) => Some(format!("http://127.0.0.1:{p}")),
        _ => None,
    }
}

/// Helper старее приложения (после обновления приложения службу нужно переустановить: одно подтверждение прав).
/// Неразобранные версии и helper новее приложения не считаются устаревшими.
pub fn helper_outdated(app_version: &str, h: &HelperDto) -> bool {
    h.running && h.version.as_deref().and_then(|v| version::compare(v, app_version)) == Some(std::cmp::Ordering::Less)
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub current: String,
    /// changelog из latest.json
    pub notes: Option<String>,
    pub date: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CheckOutcome {
    /// публичный ключ подписи не настроен, обновления выключены
    Disabled,
    /// этот способ установки не умеет обновляться изнутри (например, .deb: нужен AppImage)
    #[serde(rename_all = "camelCase")]
    Unsupported { reason: String },
    UpToDate,
    Available { info: UpdateInfo },
}

/// Умеет ли эта установка заменять себя. Tauri updater на Linux работает только с AppImage
/// (его выдаёт переменная окружения `APPIMAGE`), на Windows и macOS с любой обычной установкой.
pub fn install_supported(os: &str, appimage: bool) -> Result<(), String> {
    match os {
        "linux" if !appimage => Err("Обновление изнутри приложения работает только в сборке AppImage. Для пакета .deb скачай новую версию и установи её поверх.".into()),
        "linux" | "windows" | "macos" => Ok(()),
        other => Err(format!("Обновление изнутри приложения не поддерживается на этой ОС ({other}).")),
    }
}

/// Подготовить откат перед установкой обновления: копия текущей установки, маркер и сторож.
/// Ошибка не фатальна для обновления: вызывающий показывает предупреждение и продолжает.
pub fn arm_rollback(from: &str, to: &str) -> Result<()> {
    let exe = std::env::current_exe().context("не удалось определить путь приложения")?;
    let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
    let cli = exe.with_file_name(format!("eleutheria{}", std::env::consts::EXE_SUFFIX));
    arm_rollback_in(&store::config_dir(), std::env::consts::OS, appimage.as_deref(), &exe, &cli, from, to, eleutheria_core::rollback::START_TIMEOUT_SECS)
}

pub fn arm_rollback_in(dir: &Path, os: &str, appimage: Option<&Path>, exe: &Path, cli: &Path, from: &str, to: &str, timeout: u64) -> Result<()> {
    use eleutheria_core::rollback;
    let (target, kind, relaunch) = rollback::target_for(os, appimage, exe).map_err(anyhow::Error::msg)?;
    if !cli.exists() {
        anyhow::bail!("рядом с приложением нет eleutheria (сторожу отката нечем запускаться)");
    }
    rollback::prepare(dir, from, to, &target, kind, &relaunch, rollback::now_unix(), timeout)?;
    if let Err(e) = rollback::spawn_watchdog(dir, cli) {
        // без сторожа копия бесполезна: убираем маркер, чтобы не оставлять ложного ощущения защиты
        let _ = std::fs::remove_file(dir.join(rollback::MARKER_FILE));
        return Err(e);
    }
    Ok(())
}

/// Установка не удалась до замены файлов: откат не нужен.
pub fn disarm_rollback() {
    eleutheria_core::rollback::disarm(&store::config_dir());
}

pub fn confirm_started_now(running_version: &str) -> StartReport {
    confirm_started(&store::config_dir(), running_version)
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct StartReport {
    /// запущена новая версия после обновления (обновление подтверждено)
    pub updated_to: Option<String>,
    /// прошлое обновление не стартовало и было откатано: версия, которая не запустилась
    pub rolled_back_from: Option<String>,
}

/// Вызывается интерфейсом после успешной отрисовки: подтверждает обновление и сообщает об откате.
pub fn confirm_started(dir: &Path, running_version: &str) -> StartReport {
    use eleutheria_core::rollback::{self, Confirm};
    let mut r = StartReport::default();
    if let Confirm::Updated { version } = rollback::confirm(dir, running_version) {
        r.updated_to = Some(version);
    }
    if let Some(n) = rollback::take_notice(dir) {
        r.rolled_back_from = Some(n.failed_version);
    }
    r
}

/// Ручной импорт файла обновления (когда нет доступа ни к GitHub, ни к зеркалу): пакет и его `.sig`,
/// полученные другим путём. Плагин updater ставит только по манифесту, поэтому подпись проверяем сами теми же
/// правилами, что и плагин при `requireSignedVersion`: подпись нашим ключом + версия внутри подписанного
/// комментария. Дополнительно запрещаем понижение: старый валидно подписанный пакет иначе можно подсунуть.
pub fn verify_package(pubkey_b64: &str, data: &[u8], sig: &str, current: &str) -> Result<String> {
    use base64::Engine;
    use minisign_verify::{PublicKey, Signature};
    if !pubkey_configured(pubkey_b64) {
        anyhow::bail!("публичный ключ обновлений не настроен: проверять подпись нечем");
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let decode = |s: &str| -> Result<String> {
        let raw = b64.decode(s.trim()).context("не base64")?;
        Ok(String::from_utf8(raw).context("не текст")?)
    };
    let pk = PublicKey::decode(&decode(pubkey_b64).context("публичный ключ в конфигурации повреждён")?)
        .map_err(|e| anyhow::anyhow!("публичный ключ в конфигурации повреждён: {e}"))?;
    // файл .sig, созданный Tauri, это base64 от minisign-подписи; обычная minisign-подпись тоже принимается
    let sig_text = if sig.trim_start().starts_with("untrusted comment:") { sig.to_string() } else { decode(sig).context("файл подписи не похож на .sig")? };
    let signature = Signature::decode(&sig_text).map_err(|e| anyhow::anyhow!("файл подписи повреждён: {e}"))?;
    pk.verify(data, &signature, true).map_err(|_| anyhow::anyhow!("подпись не совпадает: файл изменён или подписан не нашим ключом"))?;
    // trusted comment защищён подписью, поэтому версию берём только отсюда и только после проверки
    let version = signature
        .trusted_comment()
        .split('\t')
        .find_map(|f| f.strip_prefix("version:"))
        .ok_or_else(|| anyhow::anyhow!("в подписи нет версии пакета (такие релизы без защиты от подмены версии не принимаем)"))?
        .trim_start_matches('v')
        .to_string();
    match version::compare(&version, current) {
        Some(std::cmp::Ordering::Greater) => Ok(version),
        Some(_) => anyhow::bail!("версия пакета ({version}) не новее установленной ({current}): понижение версии запрещено"),
        None => anyhow::bail!("не удалось сравнить версии: пакет {version}, установлена {current}"),
    }
}

/// Что делать с проверенным пакетом на этой ОС.
#[derive(Debug, PartialEq, Eq)]
pub enum ManualInstall {
    /// заменить файл AppImage (Linux): прежний сохраняется откатом
    ReplaceAppImage,
    /// запустить установщик (Windows): имя программы и аргументы
    RunInstaller { program: String, args: Vec<String> },
}

pub fn manual_install_plan(os: &str, appimage: bool, package: &Path) -> Result<ManualInstall, String> {
    let name = package.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    match os {
        "linux" => {
            if !appimage {
                return Err("Ручное обновление работает только в сборке AppImage.".into());
            }
            if !name.ends_with(".appimage") {
                return Err("Для Linux нужен файл .AppImage.".into());
            }
            Ok(ManualInstall::ReplaceAppImage)
        }
        "windows" if name.ends_with(".msi") => Ok(ManualInstall::RunInstaller {
            program: "msiexec".into(),
            args: vec!["/i".into(), package.to_string_lossy().into_owned(), "/passive".into()],
        }),
        "windows" if name.ends_with(".exe") => Ok(ManualInstall::RunInstaller { program: package.to_string_lossy().into_owned(), args: vec!["/P".into(), "/R".into()] }),
        "windows" => Err("Для Windows нужен установщик .exe или .msi.".into()),
        "macos" => Err("Ручное обновление на macOS пока не поддерживается: скачай новую версию и замени приложение.".into()),
        other => Err(format!("Ручное обновление не поддерживается на этой ОС ({other}).")),
    }
}

/// Заменить файл AppImage проверенным пакетом: запись рядом и атомарное переименование.
pub fn replace_file_atomically(package: &Path, target: &Path) -> Result<()> {
    let tmp = target.with_extension("AppImage.new");
    std::fs::copy(package, &tmp).with_context(|| format!("не удалось скопировать {}", package.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, target).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionDto;

    fn ov(conn: Option<ConnectionDto>) -> Overview {
        Overview { servers: vec![], connection: conn, helper: HelperDto { running: false, version: None }, app_version: "0.2.0".into() }
    }

    #[test]
    fn schedule_is_daily_and_survives_clock_skew() {
        let d = CHECK_INTERVAL_SECS;
        assert!(should_check(1000, None, d));
        assert!(!should_check(1000 + d - 1, Some(1000), d));
        assert!(should_check(1000 + d, Some(1000), d));
        assert!(should_check(500, Some(1000), d), "часы ушли назад: проверяем");
    }

    #[test]
    fn pubkey_placeholder_disables_updates() {
        assert!(!pubkey_configured(""));
        assert!(!pubkey_configured("  "));
        assert!(!pubkey_configured(PUBKEY_PLACEHOLDER));
        assert!(pubkey_configured("dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEFBQUE="));
    }

    #[test]
    fn proxy_only_for_local_proxy_mode() {
        assert_eq!(proxy_url(&ov(None)), None);
        let proxy = ConnectionDto { mode: Mode::Proxy, pid: 1, listen_port: Some(7890) };
        assert_eq!(proxy_url(&ov(Some(proxy))), Some("http://127.0.0.1:7890".into()));
        let tun = ConnectionDto { mode: Mode::Tun, pid: 1, listen_port: None };
        assert_eq!(proxy_url(&ov(Some(tun))), None, "в TUN прокси не нужен: трафик идёт через туннель");
    }

    #[test]
    fn helper_outdated_only_when_running_and_older() {
        let h = |running, v: Option<&str>| HelperDto { running, version: v.map(String::from) };
        assert!(helper_outdated("0.2.0", &h(true, Some("0.1.0"))));
        assert!(!helper_outdated("0.2.0", &h(true, Some("0.2.0"))));
        assert!(!helper_outdated("0.2.0", &h(true, Some("0.3.0"))));
        assert!(!helper_outdated("0.2.0", &h(false, None)), "helper не запущен: обновлять нечего");
        assert!(!helper_outdated("0.2.0", &h(true, Some("мусор"))));
        assert!(!helper_outdated("0.2.0", &h(true, None)));
    }

    #[test]
    fn prefs_roundtrip_and_corrupt_file_is_ignored() {
        let dir = std::env::temp_dir().join(format!("el-upd-{}", std::process::id()));
        let path = dir.join("nested").join("update.json");
        assert_eq!(load_prefs_from(&path), UpdatePrefs::default());
        save_prefs_to(&path, &UpdatePrefs { last_check: Some(42) }).unwrap();
        assert_eq!(load_prefs_from(&path), UpdatePrefs { last_check: Some(42) });
        std::fs::write(&path, "{ не json").unwrap();
        assert_eq!(load_prefs_from(&path), UpdatePrefs::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn self_update_support_by_install_kind() {
        assert!(install_supported("linux", true).is_ok());
        assert!(install_supported("linux", false).unwrap_err().contains("AppImage"));
        assert!(install_supported("windows", false).is_ok());
        assert!(install_supported("macos", false).is_ok());
        assert!(install_supported("freebsd", false).is_err());
    }

    #[test]
    fn outcome_serializes_for_the_frontend() {
        let j = serde_json::to_value(CheckOutcome::Available {
            info: UpdateInfo { version: "0.2.0".into(), current: "0.1.0".into(), notes: Some("n".into()), date: None },
        })
        .unwrap();
        assert_eq!(j["kind"], "available");
        assert_eq!(j["info"]["version"], "0.2.0");
        assert_eq!(serde_json::to_value(CheckOutcome::Disabled).unwrap()["kind"], "disabled");
        assert_eq!(serde_json::to_value(CheckOutcome::UpToDate).unwrap()["kind"], "upToDate");
        let u = serde_json::to_value(CheckOutcome::Unsupported { reason: "r".into() }).unwrap();
        assert_eq!((u["kind"].as_str(), u["reason"].as_str()), (Some("unsupported"), Some("r")));
    }

    #[test]
    fn arm_rollback_refuses_unsupported_and_incomplete_installs() {
        let dir = std::env::temp_dir().join(format!("el-arm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("gui");
        std::fs::write(&exe, "x").unwrap();
        let no_cli = dir.join("eleutheria");
        let e = arm_rollback_in(&dir, "linux", None, &exe, &no_cli, "0.1.0", "0.2.0", 5).unwrap_err();
        assert!(format!("{e}").contains("AppImage"));
        let ai = dir.join("A.AppImage");
        std::fs::write(&ai, "x").unwrap();
        let e = arm_rollback_in(&dir, "linux", Some(&ai), &exe, &no_cli, "0.1.0", "0.2.0", 5).unwrap_err();
        assert!(format!("{e}").contains("eleutheria"));
        assert!(!dir.join("pending-update.json").exists(), "без сторожа маркера нет");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_report_confirms_update_and_reports_rollback_once() {
        use eleutheria_core::rollback::{self, Kind};
        let dir = std::env::temp_dir().join(format!("el-rep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = dir.join("app");
        std::fs::write(&t, "old").unwrap();
        rollback::prepare(&dir, "0.1.0", "0.2.0", &t, Kind::File, &t, 0, 100).unwrap();
        assert_eq!(confirm_started(&dir, "0.2.0"), StartReport { updated_to: Some("0.2.0".into()), rolled_back_from: None });
        assert_eq!(confirm_started(&dir, "0.2.0"), StartReport::default());
        std::fs::write(dir.join("rolled-back.json"), r#"{"failedVersion":"0.3.0","restoredVersion":"0.2.0"}"#).unwrap();
        assert_eq!(confirm_started(&dir, "0.2.0").rolled_back_from.as_deref(), Some("0.3.0"));
        assert_eq!(confirm_started(&dir, "0.2.0").rolled_back_from, None, "сообщение один раз");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ручной импорт ---
    fn signed(version_comment: &str, data: &[u8]) -> (String, String) {
        // возвращает (pubkey_b64 как в tauri.conf.json, sig как в файле .sig)
        use base64::Engine;
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = minisign::sign(None, &kp.sk, std::io::Cursor::new(data), Some(version_comment), None).unwrap().to_string();
        let pk_text = kp.pk.to_box().unwrap().to_string();
        let b64 = base64::engine::general_purpose::STANDARD;
        (b64.encode(pk_text), b64.encode(sig))
    }

    #[test]
    fn manual_package_accepts_valid_newer_signed_version() {
        let data = b"appimage bytes";
        let (pk, sig) = signed("timestamp:1\tfile:app.AppImage\tversion:0.2.0", data);
        assert_eq!(verify_package(&pk, data, &sig, "0.1.0").unwrap(), "0.2.0");
        // обычная minisign-подпись без обёртки base64 тоже подходит
        use base64::Engine;
        let raw = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&sig).unwrap()).unwrap();
        assert_eq!(verify_package(&pk, data, &raw, "0.1.0").unwrap(), "0.2.0");
    }

    #[test]
    fn manual_package_rejects_tampering_wrong_key_downgrade_and_missing_version() {
        let data = b"appimage bytes";
        let (pk, sig) = signed("timestamp:1\tversion:0.2.0", data);
        let e = |r: Result<String>| format!("{:#}", r.unwrap_err());
        assert!(e(verify_package(&pk, b"appimage bytez", &sig, "0.1.0")).contains("подпись не совпадает"));
        let (other_pk, _) = signed("version:0.2.0", data);
        assert!(e(verify_package(&other_pk, data, &sig, "0.1.0")).contains("подпись не совпадает"), "чужой ключ");
        assert!(e(verify_package(&pk, data, &sig, "0.2.0")).contains("не новее"), "та же версия");
        assert!(e(verify_package(&pk, data, &sig, "0.3.0")).contains("понижение"), "старый подписанный пакет");
        let (pk2, sig2) = signed("timestamp:1\tfile:x", data);
        assert!(e(verify_package(&pk2, data, &sig2, "0.1.0")).contains("нет версии"));
        assert!(e(verify_package(PUBKEY_PLACEHOLDER, data, &sig, "0.1.0")).contains("не настроен"));
        assert!(e(verify_package(&pk, data, "мусор", "0.1.0")).contains("подпис"));
        assert!(e(verify_package("!!!", data, &sig, "0.1.0")).contains("повреждён"));
    }

    #[test]
    fn manual_install_plan_by_os() {
        let p = |s: &str| std::path::PathBuf::from(s);
        assert_eq!(manual_install_plan("linux", true, &p("/d/Eleutheria_0.2.0_amd64.AppImage")), Ok(ManualInstall::ReplaceAppImage));
        assert!(manual_install_plan("linux", false, &p("/d/x.AppImage")).is_err());
        assert!(manual_install_plan("linux", true, &p("/d/x.deb")).is_err());
        assert_eq!(
            manual_install_plan("windows", false, &p("C:/d/Eleutheria_0.2.0_x64-setup.exe")),
            Ok(ManualInstall::RunInstaller { program: "C:/d/Eleutheria_0.2.0_x64-setup.exe".into(), args: vec!["/P".into(), "/R".into()] })
        );
        assert!(matches!(manual_install_plan("windows", false, &p("C:/d/a.MSI")), Ok(ManualInstall::RunInstaller { program, .. }) if program == "msiexec"));
        assert!(manual_install_plan("windows", false, &p("C:/d/a.zip")).is_err());
        assert!(manual_install_plan("macos", false, &p("/d/a.app.tar.gz")).is_err());
    }

    #[test]
    fn replace_file_is_atomic_and_executable() {
        let d = std::env::temp_dir().join(format!("el-repl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (pkg, tgt) = (d.join("new.AppImage"), d.join("cur.AppImage"));
        std::fs::write(&pkg, "NEW").unwrap();
        std::fs::write(&tgt, "OLD").unwrap();
        replace_file_atomically(&pkg, &tgt).unwrap();
        assert_eq!(std::fs::read_to_string(&tgt).unwrap(), "NEW");
        assert!(!d.join("cur.AppImage.new").exists(), "временного файла не остаётся");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&tgt).unwrap().permissions().mode() & 0o111, 0o111);
        }
        assert!(replace_file_atomically(&d.join("missing"), &tgt).is_err());
        assert_eq!(std::fs::read_to_string(&tgt).unwrap(), "NEW", "при сбое цель не тронута");
        let _ = std::fs::remove_dir_all(&d);
    }
}
