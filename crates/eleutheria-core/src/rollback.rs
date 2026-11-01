//! Откат приложения после неудачного обновления: «не стартовало за N секунд, вернуть прежнее».
//!
//! Схема:
//! 1. Перед установкой обновления (`prepare`) текущая установка копируется в `<config>/rollback/backup`,
//!    рядом пишется маркер `pending-update.json` с дедлайном.
//! 2. Отдельный процесс-сторож (копия CLI `eleutheria`, лежащая вне каталога установки, поэтому установщик
//!    его не заменяет и не блокирует) ждёт: если до дедлайна маркер не исчез, восстанавливает копию и
//!    запускает прежнюю версию.
//! 3. Новая версия после успешного старта окна вызывает `confirm`: маркер удаляется, сторож завершается.
//!
//! Что откатывается: AppImage (один файл), `.app` на macOS и каталог установки на Windows (пользовательская
//! установка). Для `.deb` и установки в защищённый каталог откат не поддерживается: обновление изнутри там
//! и так не работает или требует прав администратора, а сторож работает с правами пользователя.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Сколько даём новой версии на запуск окна (установка + старт).
pub const START_TIMEOUT_SECS: u64 = 120;
pub const MARKER_FILE: &str = "pending-update.json";
pub const NOTICE_FILE: &str = "rolled-back.json";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub from_version: String,
    pub to_version: String,
    /// что заменяется обновлением: файл AppImage, каталог `.app` или каталог установки
    pub target: PathBuf,
    pub kind: Kind,
    /// копия прежней версии
    pub backup: PathBuf,
    /// что запустить после отката
    pub relaunch: PathBuf,
    /// unix-время, после которого без подтверждения делаем откат
    pub deadline: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    /// версия, которая не запустилась
    pub failed_version: String,
    /// версия, к которой вернулись
    pub restored_version: String,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn marker_path(dir: &Path) -> PathBuf {
    dir.join(MARKER_FILE)
}

fn rollback_dir(dir: &Path) -> PathBuf {
    dir.join("rollback")
}

/// Что именно заменяет обновление и что запускать после отката. `appimage` — значение `$APPIMAGE`.
pub fn target_for(os: &str, appimage: Option<&Path>, exe: &Path) -> Result<(PathBuf, Kind, PathBuf), String> {
    match os {
        "linux" => match appimage {
            Some(p) => Ok((p.to_path_buf(), Kind::File, p.to_path_buf())),
            None => Err("откат поддерживается только для AppImage".into()),
        },
        "macos" => {
            let app = exe
                .ancestors()
                .find(|a| a.extension().is_some_and(|e| e == "app"))
                .ok_or("не нашёл каталог .app рядом с исполняемым файлом")?;
            Ok((app.to_path_buf(), Kind::Dir, exe.to_path_buf()))
        }
        "windows" => {
            let dir = exe.parent().ok_or("не определён каталог установки")?;
            Ok((dir.to_path_buf(), Kind::Dir, exe.to_path_buf()))
        }
        other => Err(format!("откат не поддерживается на этой ОС ({other})")),
    }
}

/// Рекурсивная копия с сохранением ссылок (важно для `.app` на macOS) и прав.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("нет {}", src.display()))?;
    if meta.file_type().is_symlink() {
        #[cfg(unix)]
        {
            let link = fs::read_link(src)?;
            std::os::unix::fs::symlink(link, dst)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            fs::copy(src, dst)?;
            return Ok(());
        }
    }
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for e in fs::read_dir(src)? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
        return Ok(());
    }
    fs::copy(src, dst).with_context(|| format!("копирование {}", src.display()))?;
    Ok(())
}

fn remove_any(p: &Path) {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = fs::remove_file(p);
        }
        Err(_) => {}
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("json.part");
    fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Сделать копию текущей установки и записать маркер. Вызывается ДО установки обновления.
pub fn prepare(dir: &Path, from: &str, to: &str, target: &Path, kind: Kind, relaunch: &Path, now: u64, timeout: u64) -> Result<Pending> {
    if !target.exists() {
        bail!("нечего сохранять: {} не существует", target.display());
    }
    let root = rollback_dir(dir);
    let backup = root.join("backup");
    remove_any(&backup);
    fs::create_dir_all(&root)?;
    // копия сначала во временное имя: недокопированный бэкап не должен выглядеть пригодным
    let part = root.join("backup.part");
    remove_any(&part);
    copy_tree(target, &part).context("не удалось сохранить прежнюю версию")?;
    fs::rename(&part, &backup)?;
    let p = Pending {
        from_version: from.into(),
        to_version: to.into(),
        target: target.to_path_buf(),
        kind,
        backup,
        relaunch: relaunch.to_path_buf(),
        deadline: now + timeout,
    };
    write_json_atomic(&marker_path(dir), &p)?;
    Ok(p)
}

pub fn read_pending(dir: &Path) -> Option<Pending> {
    fs::read_to_string(marker_path(dir)).ok().and_then(|s| serde_json::from_str(&s).ok())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Confirm {
    /// обновления не было
    NoPending,
    /// запущена новая версия: всё хорошо, маркер и копия удалены
    Updated { version: String },
    /// запущена прежняя версия (обновление не применилось или откат уже сделан), маркер удалён
    Unchanged,
}

/// Вызывается новой версией после успешного старта окна.
pub fn confirm(dir: &Path, running_version: &str) -> Confirm {
    let Some(p) = read_pending(dir) else { return Confirm::NoPending };
    let _ = fs::remove_file(marker_path(dir));
    if running_version == p.to_version {
        remove_any(&rollback_dir(dir).join("backup"));
        Confirm::Updated { version: p.to_version }
    } else {
        Confirm::Unchanged
    }
}

/// Проверка, что маркер не заставит сторожа тронуть чужие пути: копия обязана лежать в нашем каталоге.
fn validate(dir: &Path, p: &Pending) -> Result<()> {
    if p.backup != rollback_dir(dir).join("backup") {
        bail!("копия лежит не в каталоге отката: {}", p.backup.display());
    }
    if p.target.parent().is_none() {
        bail!("цель отката не может быть корнем");
    }
    let ok = match p.kind {
        Kind::File => p.backup.is_file(),
        Kind::Dir => p.backup.is_dir(),
    };
    if !ok {
        bail!("копии прежней версии нет или она не того типа");
    }
    Ok(())
}

/// Вернуть прежнюю версию на место. Новая версия не удаляется, а откладывается рядом (`*.failed`),
/// чтобы её можно было разобрать.
pub fn restore(p: &Pending) -> Result<()> {
    let name = p.target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "app".into());
    let failed = p.target.with_file_name(format!("{name}.failed"));
    remove_any(&failed);
    if p.target.exists() {
        fs::rename(&p.target, &failed).with_context(|| format!("не удалось убрать новую версию {}", p.target.display()))?;
    }
    if let Err(e) = copy_tree(&p.backup, &p.target) {
        // вернуть всё как было, чтобы не остаться совсем без приложения
        remove_any(&p.target);
        let _ = fs::rename(&failed, &p.target);
        return Err(e.context("не удалось восстановить прежнюю версию"));
    }
    remove_any(&failed);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Watch {
    /// маркер исчез: новая версия подтвердила запуск
    Confirmed,
    /// дедлайн прошёл, прежняя версия возвращена (её надо запустить)
    RolledBack(Pending),
    /// дедлайн прошёл, но вернуть не удалось
    Failed(String),
}

/// Тело сторожа. `now` и `sleep` вынесены для тестов.
pub fn watch(dir: &Path, now: impl Fn() -> u64, sleep: impl Fn(Duration)) -> Watch {
    loop {
        let Some(p) = read_pending(dir) else { return Watch::Confirmed };
        if now() < p.deadline {
            sleep(Duration::from_secs(1));
            continue;
        }
        // последняя проверка: подтверждение могло прийти между чтением и решением
        if read_pending(dir).is_none() {
            return Watch::Confirmed;
        }
        if let Err(e) = validate(dir, &p) {
            let _ = fs::remove_file(marker_path(dir));
            return Watch::Failed(format!("{e:#}"));
        }
        return match restore(&p) {
            Ok(()) => {
                let _ = fs::remove_file(marker_path(dir));
                let _ = write_json_atomic(
                    &dir.join(NOTICE_FILE),
                    &Notice { failed_version: p.to_version.clone(), restored_version: p.from_version.clone() },
                );
                Watch::RolledBack(p)
            }
            Err(e) => {
                let _ = fs::remove_file(marker_path(dir));
                Watch::Failed(format!("{e:#}"))
            }
        };
    }
}

/// Снять защиту, если установка обновления не началась (ошибка до замены файлов): сторож завершится сам.
pub fn disarm(dir: &Path) {
    let _ = fs::remove_file(marker_path(dir));
    remove_any(&rollback_dir(dir).join("backup"));
}

/// Сообщение об откате для интерфейса: показывается один раз.
pub fn take_notice(dir: &Path) -> Option<Notice> {
    let path = dir.join(NOTICE_FILE);
    let n = fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok());
    let _ = fs::remove_file(&path);
    n
}

/// Запустить сторожа: копия CLI во внешнем каталоге + отсоединённый процесс `update-watchdog`.
pub fn spawn_watchdog(dir: &Path, cli: &Path) -> Result<()> {
    let root = rollback_dir(dir);
    fs::create_dir_all(&root)?;
    let copy = root.join(format!("watchdog{}", std::env::consts::EXE_SUFFIX));
    remove_any(&copy);
    fs::copy(cli, &copy).with_context(|| format!("не удалось скопировать {}", cli.display()))?;
    let mut cmd = std::process::Command::new(&copy);
    cmd.arg("update-watchdog")
        .env("ELEUTHERIA_CONFIG_DIR", dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // свой process group: не умирает вместе с приложением
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0000_0008 | 0x0000_0200); // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    }
    cmd.spawn().context("не удалось запустить сторожа отката")?;
    Ok(())
}

/// Запустить прежнюю версию после отката.
pub fn relaunch(p: &Pending) -> Result<()> {
    let mut cmd = std::process::Command::new(&p.relaunch);
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().with_context(|| format!("не удалось запустить {}", p.relaunch.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("el-rb-{tag}-{}-{}", std::process::id(), now_unix()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn target_by_platform() {
        let ai = Path::new("/home/u/Eleutheria.AppImage");
        assert_eq!(target_for("linux", Some(ai), Path::new("/tmp/.mount_x/usr/bin/eleutheria-gui")).unwrap(), (ai.into(), Kind::File, ai.into()));
        assert!(target_for("linux", None, Path::new("/usr/bin/eleutheria-gui")).is_err());
        let exe = Path::new("/Applications/Eleutheria.app/Contents/MacOS/eleutheria-gui");
        let (t, k, r) = target_for("macos", None, exe).unwrap();
        assert_eq!((t.as_path(), k, r.as_path()), (Path::new("/Applications/Eleutheria.app"), Kind::Dir, exe));
        assert!(target_for("macos", None, Path::new("/usr/local/bin/x")).is_err());
        let w = Path::new("C:/Users/u/AppData/Local/Eleutheria/eleutheria-gui.exe");
        assert_eq!(target_for("windows", None, w).unwrap().1, Kind::Dir);
        assert!(target_for("freebsd", None, w).is_err());
    }

    #[test]
    fn copy_tree_keeps_structure_and_symlinks() {
        let d = tmp("copy");
        let src = d.join("A.app");
        fs::create_dir_all(src.join("Contents/MacOS")).unwrap();
        fs::write(src.join("Contents/MacOS/bin"), "v1").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("MacOS/bin", src.join("Contents/link")).unwrap();
        copy_tree(&src, &d.join("B.app")).unwrap();
        assert_eq!(fs::read_to_string(d.join("B.app/Contents/MacOS/bin")).unwrap(), "v1");
        #[cfg(unix)]
        assert_eq!(fs::read_link(d.join("B.app/Contents/link")).unwrap(), PathBuf::from("MacOS/bin"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unconfirmed_update_is_rolled_back_file() {
        let d = tmp("file");
        let target = d.join("app.AppImage");
        fs::write(&target, "old").unwrap();
        let p = prepare(&d, "0.1.0", "0.2.0", &target, Kind::File, &target, 1000, 120).unwrap();
        assert_eq!(p.deadline, 1120);
        fs::write(&target, "new-broken").unwrap(); // установщик заменил файл
        let t = Cell::new(1000u64);
        let r = watch(&d, || t.get(), |_| t.set(t.get() + 30));
        assert_eq!(r, Watch::RolledBack(p));
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        assert!(!d.join("app.AppImage.failed").exists());
        assert!(read_pending(&d).is_none(), "маркер удалён");
        assert_eq!(take_notice(&d), Some(Notice { failed_version: "0.2.0".into(), restored_version: "0.1.0".into() }));
        assert_eq!(take_notice(&d), None, "сообщение показывается один раз");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unconfirmed_update_is_rolled_back_dir() {
        let d = tmp("dir");
        let target = d.join("Eleutheria");
        fs::create_dir_all(target.join("sub")).unwrap();
        fs::write(target.join("app.exe"), "old").unwrap();
        fs::write(target.join("sub/lib.dll"), "oldlib").unwrap();
        prepare(&d, "0.1.0", "0.2.0", &target, Kind::Dir, &target.join("app.exe"), 0, 10).unwrap();
        fs::write(target.join("app.exe"), "new").unwrap();
        fs::write(target.join("extra.dll"), "only-in-new").unwrap();
        let t = Cell::new(0u64);
        assert!(matches!(watch(&d, || t.get(), |_| t.set(t.get() + 5)), Watch::RolledBack(_)));
        assert_eq!(fs::read_to_string(target.join("app.exe")).unwrap(), "old");
        assert_eq!(fs::read_to_string(target.join("sub/lib.dll")).unwrap(), "oldlib");
        assert!(!target.join("extra.dll").exists(), "файлы новой версии не остаются");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn confirmed_update_is_left_alone() {
        let d = tmp("ok");
        let target = d.join("app");
        fs::write(&target, "old").unwrap();
        prepare(&d, "0.1.0", "0.2.0", &target, Kind::File, &target, 0, 100).unwrap();
        fs::write(&target, "new-good").unwrap();
        // сторож делает несколько кругов, на третьем новая версия подтверждает запуск
        let n = Cell::new(0);
        let r = watch(&d, || 0, |_| {
            n.set(n.get() + 1);
            if n.get() == 3 {
                assert_eq!(confirm(&d, "0.2.0"), Confirm::Updated { version: "0.2.0".into() });
            }
        });
        assert_eq!(r, Watch::Confirmed);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new-good");
        assert!(!rollback_dir(&d).join("backup").exists(), "копия удалена после подтверждения");
        assert_eq!(take_notice(&d), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn confirm_variants() {
        let d = tmp("cf");
        assert_eq!(confirm(&d, "0.1.0"), Confirm::NoPending);
        let target = d.join("app");
        fs::write(&target, "old").unwrap();
        prepare(&d, "0.1.0", "0.2.0", &target, Kind::File, &target, 0, 100).unwrap();
        assert_eq!(confirm(&d, "0.1.0"), Confirm::Unchanged, "обновление не применилось");
        assert!(read_pending(&d).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_marker_cannot_point_outside_rollback_dir() {
        let d = tmp("evil");
        let target = d.join("app");
        fs::write(&target, "new").unwrap();
        let victim = d.join("victim");
        fs::write(&victim, "secret").unwrap();
        let p = Pending { from_version: "0.1.0".into(), to_version: "0.2.0".into(), target: target.clone(), kind: Kind::File, backup: victim.clone(), relaunch: target.clone(), deadline: 0 };
        write_json_atomic(&marker_path(&d), &p).unwrap();
        assert!(matches!(watch(&d, || 10, |_| {}), Watch::Failed(_)));
        assert_eq!(fs::read_to_string(&target).unwrap(), "new", "цель не тронута");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_restore_keeps_the_new_version() {
        let d = tmp("fail");
        let target = d.join("Eleutheria");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("a"), "old").unwrap();
        let p = prepare(&d, "0.1.0", "0.2.0", &target, Kind::Dir, &target.join("a"), 0, 1).unwrap();
        fs::write(target.join("a"), "new").unwrap();
        // портим копию: каталог превращается в файл, copy_tree упадёт
        fs::remove_dir_all(&p.backup).unwrap();
        fs::write(&p.backup, "oops").unwrap();
        assert!(matches!(watch(&d, || 5, |_| {}), Watch::Failed(_)));
        assert_eq!(fs::read_to_string(target.join("a")).unwrap(), "new");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn prepare_refuses_missing_target() {
        let d = tmp("miss");
        assert!(prepare(&d, "1", "2", &d.join("nope"), Kind::File, &d.join("nope"), 0, 1).is_err());
        assert!(read_pending(&d).is_none());
        let _ = fs::remove_dir_all(&d);
    }
}
