//! Чистая логика Windows-части helper'а: имена, SDDL, разбор `whoami`, аргументы `sc`/`icacls`, пути.
//! Модуль собирается на всех ОС, чтобы эту логику можно было проверять тестами на Linux/macOS.
//! Всё, что реально вызывает WinAPI, лежит в `ipc` / `helper_install` / helper и собирается только под Windows.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Имя службы в SCM (`sc query EleutheriaHelper`).
pub const SERVICE_NAME: &str = "EleutheriaHelper";
pub const SERVICE_DISPLAY: &str = "Eleutheria helper (TUN)";
/// Имя named pipe для IPC.
pub const PIPE_NAME: &str = r"\\.\pipe\eleutheria-helper";

/// Известные SID: SYSTEM и локальные администраторы. С префиксом `*` их понимают `icacls` и SDDL
/// на любой локализации Windows (имена групп переводятся, SID нет).
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINS: &str = "S-1-5-32-544";

/// Строка вида `S-1-5-21-…`: ревизия 1, затем 2–15 числовых подавторитетов. Используется до подстановки
/// в SDDL и в командную строку, поэтому проверка строгая.
pub fn is_valid_sid(s: &str) -> bool {
    if s.len() > 184 {
        return false;
    }
    let Some(rest) = s.strip_prefix("S-1-") else { return false };
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() < 2 || parts.len() > 15 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// SDDL для named pipe: запрещено сетевым входам; полный доступ SYSTEM и администраторам;
/// чтение/запись установившему пользователю. Остальные локальные пользователи не смогут открыть pipe.
pub fn pipe_sddl(user_sid: &str) -> Result<String> {
    if !is_valid_sid(user_sid) {
        bail!("некорректный SID `{}`", user_sid.chars().take(64).collect::<String>());
    }
    Ok(format!("D:P(D;;GA;;;NU)(A;;GA;;;{SID_SYSTEM})(A;;GA;;;{SID_ADMINS})(A;;GRGW;;;{user_sid})"))
}

/// Разбор вывода `whoami /user /fo csv /nh`: `"DOMAIN\user","S-1-5-21-…"`. Возвращает SID.
pub fn parse_whoami_sid(out: &str) -> Result<String> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    let last = line.rsplit(',').next().unwrap_or("").trim().trim_matches('"');
    if !is_valid_sid(last) {
        bail!("не удалось определить SID пользователя из вывода whoami: `{}`", line.chars().take(120).collect::<String>());
    }
    Ok(last.to_string())
}

/// Пути установки на Windows. Принимает значения `%ProgramFiles%` и `%ProgramData%`, чтобы тестироваться без Windows.
#[derive(Debug, PartialEq, Eq)]
pub struct WinPaths {
    /// Бинарники (helper, sing-box): запись только администраторам, это наследуется от Program Files.
    pub bin_dir: PathBuf,
    pub helper_exe: PathBuf,
    pub singbox_exe: PathBuf,
    /// helper.json
    pub config_dir: PathBuf,
    pub config_path: PathBuf,
    /// config.json sing-box и его лог: каталог закрывается ACL (только SYSTEM и администраторы).
    pub runtime_dir: PathBuf,
}

pub fn win_paths(program_files: &str, program_data: &str) -> WinPaths {
    let bin_dir = Path::new(program_files).join("Eleutheria");
    let config_dir = Path::new(program_data).join("Eleutheria");
    WinPaths {
        helper_exe: bin_dir.join("eleutheria-helper.exe"),
        singbox_exe: bin_dir.join("sing-box.exe"),
        config_path: config_dir.join("helper.json"),
        runtime_dir: config_dir.join("run"),
        bin_dir,
        config_dir,
    }
}

/// Аргументы `icacls`: убрать унаследованные права, оставить только SYSTEM и администраторов (рекурсивно).
pub fn icacls_lockdown_args(dir: &Path) -> Vec<String> {
    vec![
        dir.display().to_string(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("*{SID_SYSTEM}:(OI)(CI)F"),
        format!("*{SID_ADMINS}:(OI)(CI)F"),
    ]
}

/// Аргументы `sc create`. У `sc` значение идёт отдельным аргументом после `имя=`.
/// В `binPath` обязательны кавычки вокруг пути: `Program Files` содержит пробел.
pub fn sc_create_args(helper_exe: &Path) -> Vec<String> {
    vec![
        "create".into(),
        SERVICE_NAME.into(),
        "binPath=".into(),
        format!("\"{}\" service", helper_exe.display()),
        "start=".into(),
        "auto".into(),
        "obj=".into(),
        "LocalSystem".into(),
        "DisplayName=".into(),
        SERVICE_DISPLAY.into(),
    ]
}

/// Перезапуск службы при сбое: через 3 с, 3 с, 10 с; счётчик сбрасывается через сутки.
pub fn sc_failure_args() -> Vec<String> {
    ["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/3000/restart/3000/restart/10000"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Состояние службы по выводу `sc query`: нет такой службы / остановлена / работает.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SvcState {
    Missing,
    Stopped,
    Running,
    Other,
}

pub fn parse_sc_query(stdout: &str, success: bool) -> SvcState {
    if !success && (stdout.contains("1060") || stdout.to_lowercase().contains("does not exist")) {
        return SvcState::Missing;
    }
    // строка вида `STATE : 4  RUNNING`; слово зависит от локали, поэтому смотрим на код состояния
    for l in stdout.lines() {
        let l = l.trim();
        if l.starts_with("STATE") {
            let code = l.split(':').nth(1).and_then(|r| r.split_whitespace().next());
            return match code {
                Some("1") => SvcState::Stopped,
                Some("4") => SvcState::Running,
                _ => SvcState::Other,
            };
        }
    }
    if success { SvcState::Other } else { SvcState::Missing }
}

/// Вывод `tasklist /FI "PID eq N" /FO CSV /NH` содержит имя образа, если процесс жив.
pub fn tasklist_has_image(stdout: &str, image: &str) -> bool {
    let want = image.to_lowercase();
    stdout.lines().any(|l| l.trim_start_matches('"').to_lowercase().starts_with(&want))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    #[test]
    fn sid_validation_is_strict() {
        assert!(is_valid_sid(SID));
        assert!(is_valid_sid("S-1-5-18"));
        assert!(is_valid_sid("S-1-5-32-544"));
        for bad in ["", "S-1-", "S-1-5", "S-2-5-18", "S-1-5-18)(A;;GA;;;WD", "S-1-5-x", "s-1-5-18", "S-1-5--18", "S-1-5-18 ", "S-1-5-99999999999"] {
            assert!(!is_valid_sid(bad), "{bad}");
        }
        assert!(!is_valid_sid(&format!("S-1-5-{}", "1-".repeat(100))));
    }

    #[test]
    fn sddl_denies_network_and_names_only_expected_sids() {
        let s = pipe_sddl(SID).unwrap();
        assert_eq!(s, format!("D:P(D;;GA;;;NU)(A;;GA;;;S-1-5-18)(A;;GA;;;S-1-5-32-544)(A;;GRGW;;;{SID})"));
        // протектед DACL, всего три разрешения и один запрет: «Everyone» (WD) и «Users» (BU) не упомянуты
        assert!(s.starts_with("D:P("));
        assert!(!s.contains(";WD)") && !s.contains(";BU)") && !s.contains(";AU)"));
        // инъекция через SID невозможна
        assert!(pipe_sddl("S-1-5-18)(A;;GA;;;WD").is_err());
        assert!(pipe_sddl("").is_err());
    }

    #[test]
    fn whoami_csv_parsing() {
        assert_eq!(parse_whoami_sid(&format!("\"DESKTOP-AB12\\mucha\",\"{SID}\"\r\n")).unwrap(), SID);
        // имя с запятой не ломает разбор: берётся последнее поле
        assert_eq!(parse_whoami_sid(&format!("\"CORP\\last, first\",\"{SID}\"\n")).unwrap(), SID);
        assert!(parse_whoami_sid("").is_err());
        assert!(parse_whoami_sid("ERROR: Access is denied").is_err());
        assert!(parse_whoami_sid("\"a\\b\",\"not-a-sid\"").is_err());
    }

    #[test]
    fn paths_are_under_program_files_and_program_data() {
        let p = win_paths(r"C:\Program Files", r"C:\ProgramData");
        assert_eq!(p.helper_exe, Path::new(r"C:\Program Files").join("Eleutheria").join("eleutheria-helper.exe"));
        assert_eq!(p.runtime_dir, Path::new(r"C:\ProgramData").join("Eleutheria").join("run"));
        assert_eq!(p.config_path.file_name().unwrap(), "helper.json");
        assert!(p.singbox_exe.starts_with(&p.bin_dir));
        assert!(p.config_path.starts_with(&p.config_dir) && p.runtime_dir.starts_with(&p.config_dir));
    }

    #[test]
    fn icacls_uses_locale_independent_sids_and_drops_inheritance() {
        let a = icacls_lockdown_args(Path::new(r"C:\ProgramData\Eleutheria\run"));
        assert_eq!(a[1], "/inheritance:r");
        assert!(a.contains(&"*S-1-5-18:(OI)(CI)F".to_string()) && a.contains(&"*S-1-5-32-544:(OI)(CI)F".to_string()));
        assert_eq!(a.iter().filter(|x| x.starts_with('*')).count(), 2, "никаких других субъектов");
    }

    #[test]
    fn sc_create_quotes_path_and_separates_values() {
        let a = sc_create_args(Path::new(r"C:\Program Files\Eleutheria\eleutheria-helper.exe"));
        let i = a.iter().position(|x| x == "binPath=").unwrap();
        assert_eq!(a[i + 1], r#""C:\Program Files\Eleutheria\eleutheria-helper.exe" service"#);
        for key in ["binPath=", "start=", "obj=", "DisplayName="] {
            let i = a.iter().position(|x| x == key).unwrap();
            assert!(i + 1 < a.len() && !a[i + 1].ends_with('='), "{key}");
        }
        assert_eq!(a[a.iter().position(|x| x == "obj=").unwrap() + 1], "LocalSystem");
        let f = sc_failure_args();
        assert_eq!(f[1], SERVICE_NAME);
        assert!(f.last().unwrap().starts_with("restart/"));
    }

    #[test]
    fn sc_query_states() {
        let running = "SERVICE_NAME: EleutheriaHelper\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n";
        let stopped = "        STATE              : 1  STOPPED\n";
        let localized = "        STATE              : 4  ВЫПОЛНЯЕТСЯ\n";
        let missing = "[SC] EnumQueryServicesStatus:OpenService: ошибка: 1060:\n";
        assert_eq!(parse_sc_query(running, true), SvcState::Running);
        assert_eq!(parse_sc_query(stopped, true), SvcState::Stopped);
        assert_eq!(parse_sc_query(localized, true), SvcState::Running);
        assert_eq!(parse_sc_query(missing, false), SvcState::Missing);
        assert_eq!(parse_sc_query("", false), SvcState::Missing);
        assert_eq!(parse_sc_query("        STATE              : 2  START_PENDING\n", true), SvcState::Other);
    }

    #[test]
    fn tasklist_matching() {
        assert!(tasklist_has_image("\"sing-box.exe\",\"4242\",\"Services\",\"0\",\"60,000 K\"\r\n", "sing-box.exe"));
        assert!(!tasklist_has_image("INFO: No tasks are running which match the specified criteria.\r\n", "sing-box.exe"));
        assert!(!tasklist_has_image("\"notepad.exe\",\"4242\"\r\n", "sing-box.exe"));
    }
}
