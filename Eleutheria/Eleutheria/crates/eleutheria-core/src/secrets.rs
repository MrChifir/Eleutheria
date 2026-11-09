//! Хранилище секретов (M2.4): SSH-ключи и профили серверов лежат в OS keyring
//! (Secret Service / Keychain / Credential Manager), а не в файлах.
//!
//! Если keyring недоступен (headless Linux без D-Bus, CI, контейнер), используется файловое
//! хранилище с правами 600. Выбор делается один раз за процесс. `ELEUTHERIA_SECRETS=keyring|file`
//! принудительно выбирает бэкенд: при `keyring` ошибка не маскируется fallback'ом.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};

use crate::store::{config_dir, write_secret_file};

const SERVICE: &str = "eleutheria";

pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    /// `true`, если запись существовала.
    fn delete(&self, key: &str) -> Result<bool>;
    /// Человекочитаемое имя бэкенда (для сообщений пользователю).
    fn kind(&self) -> &'static str;
}

// ---------- OS keyring ----------

pub struct KeyringStore;

fn entry(key: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, key).map_err(|e| anyhow!("keyring недоступен: {e}"))
}

impl SecretStore for KeyringStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match entry(key)?.get_secret() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("keyring: не удалось прочитать `{key}`: {e}")),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        entry(key)?.set_secret(value).map_err(|e| anyhow!("keyring: не удалось записать `{key}`: {e}"))
    }

    fn delete(&self, key: &str) -> Result<bool> {
        match entry(key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(anyhow!("keyring: не удалось удалить `{key}`: {e}")),
        }
    }

    fn kind(&self) -> &'static str {
        "системное хранилище (keyring)"
    }
}

// ---------- файловый fallback ----------

pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, key: &str) -> PathBuf {
        // hex: произвольные имена серверов не должны выходить из каталога
        self.dir.join(hex::encode(key.as_bytes()))
    }
}

impl SecretStore for FileStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.path(key)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("не удалось прочитать секрет `{key}`")),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.dir)?;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&self.dir)?;
        write_secret_file(&self.path(key), value)
    }

    fn delete(&self, key: &str) -> Result<bool> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("не удалось удалить секрет `{key}`")),
        }
    }

    fn kind(&self) -> &'static str {
        "файл с правами 600 (системный keyring недоступен)"
    }
}

// ---------- память (тесты) ----------

#[derive(Default)]
pub struct MemStore(Mutex<BTreeMap<String, Vec<u8>>>);

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SecretStore for MemStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool> {
        Ok(self.0.lock().unwrap().remove(key).is_some())
    }

    fn kind(&self) -> &'static str {
        "память (тест)"
    }
}

// ---------- выбор бэкенда ----------

/// Проверка, что keyring реально работает: запись, чтение, удаление пробной записи.
fn keyring_probe() -> Result<()> {
    let k = KeyringStore;
    let key = format!("probe-{}", std::process::id());
    k.set(&key, b"ok")?;
    let back = k.get(&key)?;
    let _ = k.delete(&key);
    if back.as_deref() != Some(b"ok".as_slice()) {
        bail!("keyring принял запись, но вернул другое значение");
    }
    Ok(())
}

fn choose(mode: Option<&str>, probe: impl FnOnce() -> Result<()>, file_dir: PathBuf) -> Result<Box<dyn SecretStore>> {
    match mode {
        Some("file") => Ok(Box::new(FileStore::new(file_dir))),
        Some("keyring") => {
            probe().context("ELEUTHERIA_SECRETS=keyring, но keyring не работает")?;
            Ok(Box::new(KeyringStore))
        }
        None | Some("") | Some("auto") => match probe() {
            Ok(()) => Ok(Box::new(KeyringStore)),
            Err(e) => {
                eprintln!("Предупреждение: системный keyring недоступен ({e:#}). Секреты будут храниться в файлах с правами 600.");
                Ok(Box::new(FileStore::new(file_dir)))
            }
        },
        Some(other) => bail!("ELEUTHERIA_SECRETS={other}: допустимо keyring, file или auto"),
    }
}

static DEFAULT: OnceLock<Box<dyn SecretStore>> = OnceLock::new();

/// Бэкенд по умолчанию для процесса. Первая ошибка выбора (неверное значение переменной,
/// принудительный keyring не работает) возвращается вызывающему.
pub fn default_store() -> Result<&'static dyn SecretStore> {
    if let Some(s) = DEFAULT.get() {
        return Ok(s.as_ref());
    }
    let mode = std::env::var("ELEUTHERIA_SECRETS").ok();
    let s = choose(mode.as_deref(), keyring_probe, config_dir().join("secrets"))?;
    Ok(DEFAULT.get_or_init(|| s).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eleutheria-test-sec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn roundtrip(s: &dyn SecretStore) {
        assert_eq!(s.get("a/b").unwrap(), None);
        s.set("a/b", b"one").unwrap();
        s.set("a/b", b"two").unwrap(); // перезапись
        assert_eq!(s.get("a/b").unwrap().as_deref(), Some(b"two".as_slice()));
        assert!(s.delete("a/b").unwrap());
        assert!(!s.delete("a/b").unwrap());
        assert_eq!(s.get("a/b").unwrap(), None);
    }

    #[test]
    fn mem_and_file_stores_roundtrip() {
        roundtrip(&MemStore::new());
        roundtrip(&FileStore::new(tmp("file")));
    }

    #[test]
    fn file_store_hides_names_and_uses_private_modes() {
        let dir = tmp("modes");
        let s = FileStore::new(dir.clone());
        s.set("../../etc/passwd", b"x").unwrap();
        let names: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].chars().all(|c| c.is_ascii_hexdigit()), "имя файла не содержит исходный ключ: {names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(dir.join(&names[0])).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn choose_respects_mode_and_falls_back() {
        let d = tmp("choose");
        let fail = || -> Result<()> { bail!("нет D-Bus") };
        // auto + сбой keyring: fallback на файл
        assert!(choose(None, fail, d.clone()).unwrap().kind().contains("600"));
        // принудительный file: keyring даже не пробуется
        assert!(choose(Some("file"), || panic!("probe не должен вызываться"), d.clone()).unwrap().kind().contains("600"));
        // принудительный keyring + сбой: ошибка, без тихого fallback
        assert!(choose(Some("keyring"), fail, d.clone()).is_err());
        // auto + рабочий keyring
        assert!(choose(Some("auto"), || Ok(()), d.clone()).unwrap().kind().contains("keyring"));
        // мусор в переменной
        assert!(choose(Some("vault"), || Ok(()), d).is_err());
    }
}
