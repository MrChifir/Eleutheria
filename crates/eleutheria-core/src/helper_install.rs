//! Установка и удаление helper-службы (нужен root). Linux: systemd. macOS: launchd (не проверено).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{ipc, singbox};

const CONFIG_DIR: &str = "/etc/eleutheria";
pub const CONFIG_PATH: &str = "/etc/eleutheria/helper.json";
const UNIT_PATH: &str = "/etc/systemd/system/eleutheria-helper.service";
const PLIST_PATH: &str = "/Library/LaunchDaemons/org.eleutheria.helper.plist";

fn lib_dir() -> PathBuf {
    PathBuf::from(if cfg!(target_os = "macos") { "/usr/local/lib/eleutheria" } else { "/usr/lib/eleutheria" })
}

fn runtime_dir() -> &'static str {
    if cfg!(target_os = "macos") { "/var/run/eleutheria" } else { "/run/eleutheria" }
}

pub fn current_uid() -> Option<u32> {
    let o = Command::new("id").arg("-u").output().ok()?;
    String::from_utf8_lossy(&o.stdout).trim().parse().ok()
}

fn unit() -> String {
    let bin = lib_dir().join("eleutheria-helper");
    format!(
        "[Unit]
Description=Eleutheria helper (TUN)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={bin} run
Restart=on-failure
RestartSec=3
RuntimeDirectory=eleutheria
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
",
        bin = bin.display()
    )
}

fn plist() -> String {
    let bin = lib_dir().join("eleutheria-helper");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>org.eleutheria.helper</string>
<key>ProgramArguments</key><array><string>{bin}</string><string>run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
"#,
        bin = bin.display()
    )
}

fn copy_exe(src: &Path, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("part");
    fs::copy(src, &tmp).with_context(|| format!("не удалось скопировать {} в {}", src.display(), tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, dst)?;
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(cmd).args(args).status().with_context(|| format!("не удалось запустить {cmd}"))?;
    if !st.success() {
        bail!("`{cmd} {}` завершилась с ошибкой", args.join(" "));
    }
    Ok(())
}

pub async fn install(allowed_uid: u32, helper_src: &Path, report: &(dyn Fn(&str) + Sync)) -> Result<()> {
    if current_uid() != Some(0) {
        bail!("нужны права root: запусти `sudo eleutheria helper install`");
    }
    if !helper_src.exists() {
        bail!("не найден бинарник helper'а {} (он должен лежать рядом с eleutheria)", helper_src.display());
    }
    report("Готовлю sing-box (проверка SHA256)…");
    let sb = singbox::ensure_local_binary().await?;

    let lib = lib_dir();
    fs::create_dir_all(&lib)?;
    fs::set_permissions(&lib, fs::Permissions::from_mode(0o755))?;
    report(&format!("Копирую файлы в {}", lib.display()));
    copy_exe(&sb, &lib.join("sing-box"))?;
    copy_exe(helper_src, &lib.join("eleutheria-helper"))?;

    fs::create_dir_all(CONFIG_DIR)?;
    let cfg = serde_json::json!({
        "allowed_uid": allowed_uid,
        "singbox_path": lib.join("sing-box"),
        "runtime_dir": runtime_dir(),
        "socket_path": ipc::default_socket_path(),
    });
    fs::write(CONFIG_PATH, serde_json::to_vec_pretty(&cfg)?)?;
    fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o644))?;

    if cfg!(target_os = "macos") {
        fs::write(PLIST_PATH, plist())?;
        let _ = run("launchctl", &["bootout", "system", PLIST_PATH]);
        run("launchctl", &["bootstrap", "system", PLIST_PATH])?;
    } else {
        fs::write(UNIT_PATH, unit())?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "eleutheria-helper"])?;
        run("systemctl", &["restart", "eleutheria-helper"])?;
    }
    report(&format!("Служба установлена; доступ только для uid {allowed_uid} и root"));
    Ok(())
}

pub fn uninstall(report: &(dyn Fn(&str) + Sync)) -> Result<()> {
    if current_uid() != Some(0) {
        bail!("нужны права root: запусти `sudo eleutheria helper uninstall`");
    }
    if cfg!(target_os = "macos") {
        let _ = run("launchctl", &["bootout", "system", PLIST_PATH]);
        let _ = fs::remove_file(PLIST_PATH);
    } else {
        let _ = run("systemctl", &["disable", "--now", "eleutheria-helper"]);
        let _ = fs::remove_file(UNIT_PATH);
        let _ = run("systemctl", &["daemon-reload"]);
    }
    for f in [lib_dir().join("sing-box"), lib_dir().join("eleutheria-helper")] {
        let _ = fs::remove_file(f);
    }
    let _ = fs::remove_dir(lib_dir());
    let _ = fs::remove_file(CONFIG_PATH);
    let _ = fs::remove_file(ipc::default_socket_path());
    report("Служба и файлы удалены");
    Ok(())
}
