//! Клиентское хранилище: каталог конфигурации, pinning host key, SSH-ключи.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{decode_secret_key, Algorithm, PrivateKey};

use crate::secrets::{default_store, SecretStore};

pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("ELEUTHERIA_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    base.join("eleutheria")
}

fn known_hosts_path(dir: &Path) -> PathBuf {
    dir.join("known_hosts.json")
}

fn load_known(dir: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(known_hosts_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[derive(Debug, PartialEq, Eq)]
pub enum HostCheck {
    Unknown,
    Match,
    Mismatch(String),
}

pub fn host_id(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

pub fn check_host(id: &str, fp: &str) -> HostCheck {
    check_host_in(&config_dir(), id, fp)
}

fn check_host_in(dir: &Path, id: &str, fp: &str) -> HostCheck {
    match load_known(dir).get(id) {
        None => HostCheck::Unknown,
        Some(old) if old == fp => HostCheck::Match,
        Some(old) => HostCheck::Mismatch(old.clone()),
    }
}

pub fn remember_host(id: &str, fp: &str) -> Result<()> {
    remember_host_in(&config_dir(), id, fp)
}

fn remember_host_in(dir: &Path, id: &str, fp: &str) -> Result<()> {
    let mut m = load_known(dir);
    m.insert(id.to_string(), fp.to_string());
    fs::create_dir_all(dir)?;
    fs::write(known_hosts_path(dir), serde_json::to_vec_pretty(&m)?)?;
    Ok(())
}

/// Забыть сохранённый ключ хоста (после переустановки сервера). Возвращает, сколько записей удалено.
pub fn forget_host(host: &str) -> Result<usize> {
    forget_host_in(&config_dir(), host)
}

fn forget_host_in(dir: &Path, host: &str) -> Result<usize> {
    let mut m = load_known(dir);
    let prefix = format!("{host}:");
    let before = m.len();
    m.retain(|k, _| !k.starts_with(&prefix));
    let removed = before - m.len();
    if removed > 0 {
        fs::write(known_hosts_path(dir), serde_json::to_vec_pretty(&m)?)?;
    }
    Ok(removed)
}

fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Путь старого файлового хранилища ключей (до M2.4). Нужен только для миграции.
fn legacy_key_path_in(dir: &Path, host: &str) -> PathBuf {
    dir.join("keys").join(format!("{}_ed25519", sanitize(host)))
}

/// Записать секретный файл (права 600), перезаписывая существующий.
pub fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("не удалось записать {}", path.display()))?
        .write_all(data)?;
    Ok(())
}

/// SSH-ключ сервера: приватный ключ в формате OpenSSH и строка публичного ключа для authorized_keys.
pub struct SshKey {
    pub pem: String,
    pub public: String,
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey").field("pem", &"<скрыто>").field("public", &self.public).finish()
    }
}

fn key_secret_name(host: &str) -> String {
    format!("ssh-key/{host}")
}

fn parse_key(pem: &str) -> Result<SshKey> {
    let key = decode_secret_key(pem, None).context("сохранённый SSH-ключ повреждён")?;
    Ok(SshKey { pem: pem.to_string(), public: key.public_key().to_openssh()? })
}

/// Сохранённый ключ для сервера или `None`. Ключ из старого файла `keys/` переносится в хранилище
/// секретов; файл удаляется только после того, как запись прочитана обратно и совпала.
pub fn saved_key(host: &str) -> Result<Option<SshKey>> {
    saved_key_in(&config_dir(), default_store()?, host)
}

pub fn has_key(host: &str) -> Result<bool> {
    Ok(saved_key(host)?.is_some())
}

fn saved_key_in(dir: &Path, store: &dyn SecretStore, host: &str) -> Result<Option<SshKey>> {
    let name = key_secret_name(host);
    if let Some(raw) = store.get(&name)? {
        return parse_key(&String::from_utf8(raw).context("сохранённый SSH-ключ повреждён")?).map(Some);
    }
    let legacy = legacy_key_path_in(dir, host);
    if !legacy.exists() {
        return Ok(None);
    }
    let pem = fs::read_to_string(&legacy).with_context(|| format!("не удалось прочитать {}", legacy.display()))?;
    let key = parse_key(&pem)?;
    store.set(&name, pem.as_bytes())?;
    if store.get(&name)?.as_deref() != Some(pem.as_bytes()) {
        bail!("перенос SSH-ключа в {}: проверка записи не прошла, старый файл не тронут", store.kind());
    }
    if let Err(e) = fs::remove_file(&legacy) {
        eprintln!("Предупреждение: ключ перенесён, но удалить {} не удалось: {e}. Удали файл вручную.", legacy.display());
    }
    Ok(Some(key))
}

/// Ключ для сервера: берёт сохранённый или генерирует новый ed25519.
pub fn ensure_key(host: &str) -> Result<SshKey> {
    ensure_key_in(&config_dir(), default_store()?, host)
}

fn ensure_key_in(dir: &Path, store: &dyn SecretStore, host: &str) -> Result<SshKey> {
    if let Some(k) = saved_key_in(dir, store, host)? {
        return Ok(k);
    }
    let mut key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    key.set_comment(format!("eleutheria@{host}"));
    let pem = key.to_openssh(LineEnding::LF)?.to_string();
    store.set(&key_secret_name(host), pem.as_bytes())?;
    Ok(SshKey { pem, public: key.public_key().to_openssh()? })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eleutheria-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn host_pinning_roundtrip() {
        let dir = tmp("hosts");
        let id = host_id("203.0.113.9", 22);
        assert_eq!(check_host_in(&dir, &id, "SHA256:aaa"), HostCheck::Unknown);
        remember_host_in(&dir, &id, "SHA256:aaa").unwrap();
        assert_eq!(check_host_in(&dir, &id, "SHA256:aaa"), HostCheck::Match);
        assert_eq!(check_host_in(&dir, &id, "SHA256:bbb"), HostCheck::Mismatch("SHA256:aaa".into()));
        assert_eq!(forget_host_in(&dir, "203.0.113.9").unwrap(), 1);
        assert_eq!(check_host_in(&dir, &id, "SHA256:bbb"), HostCheck::Unknown);
    }

    use crate::secrets::MemStore;

    const TEST_PEM_HOST: &str = "test.host";

    #[test]
    fn key_is_generated_once_and_reused() {
        let (dir, store) = (tmp("keys"), MemStore::new());
        let k1 = ensure_key_in(&dir, &store, TEST_PEM_HOST).unwrap();
        let k2 = ensure_key_in(&dir, &store, TEST_PEM_HOST).unwrap();
        assert_eq!(k1.pem, k2.pem);
        assert_eq!(k1.public, k2.public);
        assert!(k1.public.starts_with("ssh-ed25519 "));
        assert!(k1.pem.contains("OPENSSH PRIVATE KEY"));
        assert_eq!(store.len(), 1);
        assert!(!dir.join("keys").exists(), "новые ключи не пишутся в файлы");
        // другой сервер: другой ключ
        assert_ne!(ensure_key_in(&dir, &store, "other.host").unwrap().pem, k1.pem);
    }

    #[test]
    fn saved_key_is_none_when_absent() {
        let (dir, store) = (tmp("nokey"), MemStore::new());
        assert!(saved_key_in(&dir, &store, TEST_PEM_HOST).unwrap().is_none());
        assert!(store.is_empty());
    }

    /// Старый ключ из keys/ переносится в хранилище, файл удаляется, ключ тот же.
    #[test]
    fn legacy_key_file_is_migrated_and_removed() {
        let (dir, store) = (tmp("legacy"), MemStore::new());
        let path = legacy_key_path_in(&dir, TEST_PEM_HOST);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        key.set_comment("eleutheria@test.host");
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        fs::write(&path, &pem).unwrap();

        let got = saved_key_in(&dir, &store, TEST_PEM_HOST).unwrap().unwrap();
        assert_eq!(got.pem, pem);
        assert_eq!(got.public, key.public_key().to_openssh().unwrap());
        assert!(!path.exists());
        // повторный вызов отдаёт тот же ключ уже из хранилища
        assert_eq!(saved_key_in(&dir, &store, TEST_PEM_HOST).unwrap().unwrap().pem, pem);
        assert_eq!(ensure_key_in(&dir, &store, TEST_PEM_HOST).unwrap().pem, pem);
    }

    struct FailingStore;
    impl SecretStore for FailingStore {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>> { Ok(None) }
        fn set(&self, _: &str, _: &[u8]) -> Result<()> { bail!("хранилище заблокировано") }
        fn delete(&self, _: &str) -> Result<bool> { Ok(false) }
        fn kind(&self) -> &'static str { "сломанное" }
    }

    /// Если запись в хранилище не удалась, старый файл с ключом остаётся: ключ нельзя потерять.
    #[test]
    fn failed_migration_keeps_legacy_file() {
        let dir = tmp("legacy-fail");
        let path = legacy_key_path_in(&dir, TEST_PEM_HOST);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        assert!(saved_key_in(&dir, &FailingStore, TEST_PEM_HOST).is_err());
        assert!(path.exists());
        assert!(ensure_key_in(&dir, &FailingStore, TEST_PEM_HOST).is_err(), "новый ключ не генерируется поверх существующего");
    }

    #[test]
    fn corrupt_key_is_an_error_not_a_silent_regeneration() {
        let (dir, store) = (tmp("corrupt"), MemStore::new());
        store.set(&key_secret_name(TEST_PEM_HOST), b"garbage").unwrap();
        assert!(ensure_key_in(&dir, &store, TEST_PEM_HOST).is_err());
        assert_eq!(store.get(&key_secret_name(TEST_PEM_HOST)).unwrap().unwrap(), b"garbage");
    }
}
