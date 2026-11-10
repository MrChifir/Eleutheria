//! Установка helper из GUI: запуск `eleutheria helper install` с повышением прав средствами ОС
//! (pkexec на Linux, диалог администратора на macOS, UAC на Windows). GUI сам привилегий не получает.
//!
//! Построение команд вынесено в чистые функции и покрыто тестами; сам запуск на живых ОС не проверялся.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use eleutheria_core::tr;
use eleutheria_core::winhelper::is_valid_sid;

/// Кавычки для POSIX sh: всё в одинарных, внутренняя `'` превращается в `'\''`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Экранирование строки внутри двойных кавычек AppleScript.
pub fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Кавычки для PowerShell: одинарные, внутренняя `'` удваивается.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Команда повышения прав для `os` (значение `std::env::consts::OS`). `who`: uid (unix) или SID (Windows).
pub fn helper_install_command(os: &str, cli: &Path, who: &str) -> Result<(String, Vec<String>)> {
    let cli_s = cli.to_str().ok_or_else(|| anyhow!("{}", tr!("путь к eleutheria содержит недопустимые символы", "path to eleutheria contains invalid characters")))?;
    match os {
        "linux" => {
            if who.is_empty() || !who.bytes().all(|b| b.is_ascii_digit()) {
                bail!("{}", tr!("некорректный uid", "invalid uid"));
            }
            Ok(("pkexec".into(), vec![cli_s.into(), "helper".into(), "install".into(), "--allowed-uid".into(), who.into()]))
        }
        "macos" => {
            if who.is_empty() || !who.bytes().all(|b| b.is_ascii_digit()) {
                bail!("{}", tr!("некорректный uid", "invalid uid"));
            }
            let sh = format!("{} helper install --allowed-uid {who}", sh_quote(cli_s));
            let script = format!("do shell script \"{}\" with administrator privileges", applescript_escape(&sh));
            Ok(("osascript".into(), vec!["-e".into(), script]))
        }
        "windows" => {
            if !is_valid_sid(who) {
                bail!("{}", tr!("некорректный SID", "invalid SID"));
            }
            let ps = format!(
                "$p = Start-Process -FilePath {} -ArgumentList 'helper','install','--allowed-sid',{} -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
                ps_quote(cli_s),
                ps_quote(who)
            );
            Ok(("powershell".into(), vec!["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), ps]))
        }
        other => bail!("{}", tr!(format!("установка helper из GUI не поддерживается на этой ОС ({other})"), format!("installing the helper from the GUI is not supported on this OS ({other})"))),
    }
}

/// Установить helper. `eleutheria` (CLI) и `eleutheria-helper` должны лежать рядом с GUI.
pub async fn install_helper() -> Result<()> {
    let exe = std::env::current_exe().context(tr!("не удалось определить путь приложения", "failed to determine the application path"))?;
    let suffix = std::env::consts::EXE_SUFFIX;
    let cli = exe.with_file_name(format!("eleutheria{suffix}"));
    let helper = exe.with_file_name(format!("eleutheria-helper{suffix}"));
    if !cli.exists() || !helper.exists() {
        bail!("{}", tr!("рядом с приложением нет eleutheria и eleutheria-helper (установка собрана не полностью)", "eleutheria and eleutheria-helper are missing next to the application (incomplete installation)"));
    }
    #[cfg(unix)]
    let who = eleutheria_core::helper_install::current_uid().ok_or_else(|| anyhow!("{}", tr!("не удалось определить uid", "failed to determine uid")))?.to_string();
    #[cfg(windows)]
    let who = eleutheria_core::helper_install::current_user_sid().ok_or_else(|| anyhow!("{}", tr!("не удалось определить SID пользователя", "failed to determine the user SID")))?;

    let (prog, args) = helper_install_command(std::env::consts::OS, &cli, &who)?;
    let out = tokio::process::Command::new(&prog)
        .args(&args)
        .output()
        .await
        .with_context(|| tr!(format!("не удалось запустить {prog}"), format!("failed to launch {prog}")))?;
    if out.status.success() {
        return Ok(());
    }
    let code = out.status.code();
    // pkexec: 126 = окно закрыто без ввода пароля, 127 = не авторизован
    if matches!(code, Some(126) | Some(127)) && prog == "pkexec" {
        bail!("{}", tr!("установка отменена", "installation cancelled"));
    }
    let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let code_s = code.map(|c| c.to_string()).unwrap_or_else(|| "?".into());
    let detail = if text.is_empty() { String::new() } else { format!(": {text}") };
    let manual = if cfg!(windows) {
        tr!("eleutheria helper install (терминал от имени администратора)", "eleutheria helper install (terminal as administrator)")
    } else {
        "sudo eleutheria helper install"
    };
    bail!(
        "{}",
        tr!(
            format!("установка helper не удалась (код {code_s}){detail}. Можно выполнить вручную: {manual}"),
            format!("helper installation failed (code {code_s}){detail}. You can run it manually: {manual}")
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn quoting_neutralises_metacharacters() {
        assert_eq!(sh_quote("/opt/El eutheria/cli"), "'/opt/El eutheria/cli'");
        assert_eq!(sh_quote("a'b"), r"'a'\''b'");
        assert_eq!(sh_quote("$(rm -rf ~)"), "'$(rm -rf ~)'");
        assert_eq!(ps_quote("C:\\a'b"), "'C:\\a''b'");
        assert_eq!(applescript_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn linux_uses_pkexec_with_explicit_uid() {
        let (p, a) = helper_install_command("linux", &PathBuf::from("/usr/bin/eleutheria"), "1000").unwrap();
        assert_eq!(p, "pkexec");
        // без явного uid CLI под pkexec решил бы, что владелец root
        assert_eq!(a, ["/usr/bin/eleutheria", "helper", "install", "--allowed-uid", "1000"]);
        assert!(helper_install_command("linux", &PathBuf::from("/x"), "1000; id").is_err());
        assert!(helper_install_command("linux", &PathBuf::from("/x"), "").is_err());
    }

    #[test]
    fn macos_command_is_quoted_twice() {
        let (p, a) = helper_install_command("macos", &PathBuf::from("/Applications/My App/eleutheria"), "501").unwrap();
        assert_eq!((p.as_str(), a[0].as_str()), ("osascript", "-e"));
        assert_eq!(a[1], r#"do shell script "'/Applications/My App/eleutheria' helper install --allowed-uid 501" with administrator privileges"#);
        // кавычка в пути не разрывает ни shell-, ни AppleScript-строку
        let (_, a) = helper_install_command("macos", &PathBuf::from("/a\"b'c/eleutheria"), "501").unwrap();
        assert!(a[1].contains(r#"'/a\"b'\\''c/eleutheria'"#), "{}", a[1]);
    }

    #[test]
    fn windows_asks_uac_and_validates_sid() {
        let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
        let (p, a) = helper_install_command("windows", &PathBuf::from(r"C:\Program Files\Eleutheria\eleutheria.exe"), sid).unwrap();
        assert_eq!(p, "powershell");
        let ps = a.last().unwrap();
        assert!(ps.contains("-Verb RunAs") && ps.contains("-Wait") && ps.contains("exit $p.ExitCode"));
        assert!(ps.contains(r"'C:\Program Files\Eleutheria\eleutheria.exe'") && ps.contains(&format!("'{sid}'")));
        assert!(helper_install_command("windows", &PathBuf::from("x.exe"), "S-1-5-18'; calc; '").is_err());
        assert!(helper_install_command("freebsd", &PathBuf::from("x"), "1").is_err());
    }
}
