//! Серверы клиента: разбор vless://, подписки и локальное хранилище профилей.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::{State, User};
use crate::secrets::{default_store, SecretStore};
use crate::store::config_dir;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    /// "reality" или "tls"
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
}

impl Server {
    pub fn from_state(host: &str, s: &State, u: &User) -> Server {
        Server {
            name: host.to_string(),
            host: host.to_string(),
            port: s.port,
            uuid: u.uuid.clone(),
            flow: Some("xtls-rprx-vision".into()),
            security: "reality".into(),
            sni: s.sni.clone(),
            fingerprint: "chrome".into(),
            public_key: Some(s.public_key.clone()),
            short_id: Some(s.short_id.clone()),
        }
    }

    /// Проверка данных сервера. Обязательна для привилегированного helper'а: эти поля попадают в конфиг,
    /// который исполняется от root, поэтому допускаем только узкий набор символов.
    pub fn validate(&self) -> Result<()> {
        let charset = |s: &str, extra: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c));
        if self.name.is_empty() || self.name.chars().count() > 64 || self.name.chars().any(|c| c.is_control()) {
            bail!("недопустимое имя сервера");
        }
        if self.host.is_empty() || self.host.len() > 253 || !charset(&self.host, ".:-") {
            bail!("недопустимый хост `{}`", self.host);
        }
        if self.port == 0 {
            bail!("порт 0");
        }
        let u = &self.uuid;
        if u.len() != 36 || !charset(u, "-") {
            bail!("недопустимый uuid");
        }
        if self.sni.is_empty() || self.sni.len() > 253 || !charset(&self.sni, ".-") {
            bail!("недопустимый sni");
        }
        if !matches!(self.fingerprint.as_str(), "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized") {
            bail!("недопустимый fingerprint `{}`", self.fingerprint);
        }
        if let Some(f) = &self.flow {
            if f != "xtls-rprx-vision" {
                bail!("недопустимый flow");
            }
        }
        match self.security.as_str() {
            "reality" => {
                let pbk = self.public_key.as_deref().unwrap_or("");
                let sid = self.short_id.as_deref().unwrap_or("");
                if pbk.is_empty() || pbk.len() > 64 || !charset(pbk, "-_") {
                    bail!("недопустимый public_key");
                }
                if sid.len() > 16 || sid.len() % 2 != 0 || !sid.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!("недопустимый short_id");
                }
            }
            "tls" => {}
            other => bail!("недопустимый security `{other}`"),
        }
        Ok(())
    }

    fn same_endpoint(&self, o: &Server) -> bool {
        self.host == o.host && self.port == o.port && self.uuid == o.uuid
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').context("в IPv6-адресе нет закрывающей ]")?;
        (h.to_string(), tail.strip_prefix(':').context("нет порта после IPv6-адреса")?)
    } else {
        let (h, p) = s.rsplit_once(':').context("нет порта в host:port")?;
        (h.to_string(), p)
    };
    let port: u16 = port.parse().context("порт не число")?;
    if host.is_empty() || port == 0 {
        bail!("пустой хост или порт 0");
    }
    Ok((host, port))
}

pub fn parse_vless(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("vless://").context("это не vless:// ссылка")?;
    let (main, label) = match rest.split_once('#') {
        Some((m, l)) => (m, Some(urlencoding::decode(l)?.into_owned())),
        None => (rest, None),
    };
    let (auth_host, query) = main.split_once('?').unwrap_or((main, ""));
    let (uuid, hostport) = auth_host.split_once('@').context("нет uuid@host в ссылке")?;
    if uuid.len() != 36 {
        bail!("uuid выглядит неверно: `{uuid}`");
    }
    let (host, port) = split_host_port(hostport)?;

    let mut q: HashMap<String, String> = HashMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        q.insert(k.to_string(), urlencoding::decode(v)?.into_owned());
    }
    let get = |k: &str| q.get(k).map(String::as_str).filter(|v| !v.is_empty());

    if let Some(e) = get("encryption") {
        if e != "none" {
            bail!("encryption=`{e}` не поддерживается");
        }
    }
    if let Some(t) = get("type") {
        if t != "tcp" {
            bail!("транспорт `{t}` пока не поддерживается (только tcp)");
        }
    }
    let flow = match get("flow") {
        None => None,
        Some("xtls-rprx-vision") => Some("xtls-rprx-vision".to_string()),
        Some(f) => bail!("flow `{f}` не поддерживается"),
    };
    let security = get("security").unwrap_or("none");
    let (security, public_key, short_id) = match security {
        "reality" => {
            let pbk = get("pbk").context("для reality нужен pbk")?.to_string();
            ("reality".to_string(), Some(pbk), Some(get("sid").unwrap_or("").to_string()))
        }
        "tls" => ("tls".to_string(), None, None),
        other => bail!("security=`{other}` не поддерживается (нужны reality или tls)"),
    };

    Ok(Server {
        name: label.filter(|l| !l.is_empty()).unwrap_or_else(|| host.clone()),
        sni: get("sni").unwrap_or(&host).to_string(),
        fingerprint: get("fp").unwrap_or("chrome").to_string(),
        host,
        port,
        uuid: uuid.to_string(),
        flow,
        security,
        public_key,
        short_id,
    })
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Подписка бывает base64-списком ссылок или просто списком строк.
pub fn parse_subscription(body: &str) -> (Vec<Server>, Vec<String>) {
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let text = b64_decode(&compact)
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|t| t.contains("://"))
        .unwrap_or_else(|| body.to_string());

    let (mut servers, mut skipped) = (Vec::new(), Vec::new());
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("vless://") {
            match parse_vless(line) {
                Ok(s) => servers.push(s),
                Err(e) => skipped.push(format!("{}: {e:#}", line.chars().take(40).collect::<String>())),
            }
        } else {
            let scheme = line.split("://").next().unwrap_or("?");
            skipped.push(format!("схема `{scheme}` пока не поддерживается"));
        }
    }
    (servers, skipped)
}

pub async fn fetch_subscription(url: &str) -> Result<String> {
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("Eleutheria")
        .build()?;
    Ok(c.get(url)
        .send()
        .await
        .with_context(|| format!("не удалось скачать подписку {url}"))?
        .error_for_status()?
        .text()
        .await?)
}

// ---------- хранилище ----------
//
// Профили содержат учётные данные (uuid), поэтому лежат в хранилище секретов (M2.4): по записи на
// сервер (`server/<имя>`) и запись-индекс `servers/index` со списком имён. Раздельные записи нужны из-за
// лимита Windows Credential Manager (~2,5 КБ на запись). Старый `profiles.json` переносится при первом
// обращении и удаляется после проверки записи.

const INDEX: &str = "servers/index";

fn entry_name(name: &str) -> String {
    format!("server/{name}")
}

#[derive(Deserialize)]
struct LegacyFile {
    #[serde(default)]
    servers: Vec<Server>,
}

fn legacy_path_in(dir: &Path) -> PathBuf {
    dir.join("profiles.json")
}

fn read_index(store: &dyn SecretStore) -> Result<Option<Vec<String>>> {
    match store.get(INDEX)? {
        None => Ok(None),
        Some(raw) => Ok(Some(serde_json::from_slice(&raw).context("повреждён индекс серверов в хранилище секретов")?)),
    }
}

fn write_index(store: &dyn SecretStore, names: &[String]) -> Result<()> {
    store.set(INDEX, &serde_json::to_vec(names)?)
}

/// Записать список целиком: сначала записи серверов, потом индекс, потом чистка лишних.
fn save_all(store: &dyn SecretStore, servers: &[Server]) -> Result<()> {
    let old = read_index(store)?.unwrap_or_default();
    for s in servers {
        store.set(&entry_name(&s.name), &serde_json::to_vec(s)?)?;
    }
    let names: Vec<String> = servers.iter().map(|s| s.name.clone()).collect();
    write_index(store, &names)?;
    for n in old.iter().filter(|n| !names.contains(n)) {
        store.delete(&entry_name(n))?;
    }
    Ok(())
}

/// Перенос `profiles.json` в хранилище. Файл удаляется только после обратного чтения.
fn migrate_legacy(dir: &Path, store: &dyn SecretStore) -> Result<()> {
    let path = legacy_path_in(dir);
    if !path.exists() || read_index(store)?.is_some() {
        return Ok(());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("не удалось прочитать {}", path.display()))?;
    let legacy: LegacyFile = serde_json::from_str(&raw).with_context(|| format!("{} повреждён, перенос отменён", path.display()))?;
    save_all(store, &legacy.servers)?;
    if load_from(store)? != legacy.servers {
        bail!("перенос серверов в {}: проверка записи не прошла, {} не тронут", store.kind(), path.display());
    }
    if let Err(e) = fs::remove_file(&path) {
        eprintln!("Предупреждение: серверы перенесены, но удалить {} не удалось: {e}. Удали файл вручную.", path.display());
    }
    Ok(())
}

fn load_from(store: &dyn SecretStore) -> Result<Vec<Server>> {
    let mut out = Vec::new();
    for n in read_index(store)?.unwrap_or_default() {
        match store.get(&entry_name(&n))? {
            Some(raw) => out.push(serde_json::from_slice(&raw).with_context(|| format!("повреждена запись сервера `{n}`"))?),
            None => eprintln!("Предупреждение: сервер `{n}` есть в индексе, но его записи нет в хранилище; пропускаю."),
        }
    }
    Ok(out)
}

fn try_load_in(dir: &Path, store: &dyn SecretStore) -> Result<Vec<Server>> {
    migrate_legacy(dir, store)?;
    load_from(store)
}

/// Добавить сервер. Тот же сервер (host, port, uuid) обновляется, чужое занятое имя получает суффикс.
fn upsert_in(dir: &Path, store: &dyn SecretStore, mut s: Server) -> Result<String> {
    let mut all = try_load_in(dir, store)?;
    if let Some(i) = all.iter().position(|x| x.same_endpoint(&s)) {
        s.name = all[i].name.clone();
        all[i] = s.clone();
    } else {
        let base = s.name.clone();
        let mut n = 2;
        while all.iter().any(|x| x.name == s.name) {
            s.name = format!("{base}-{n}");
            n += 1;
        }
        all.push(s.clone());
    }
    save_all(store, &all)?;
    Ok(s.name)
}

fn remove_in(dir: &Path, store: &dyn SecretStore, name: &str) -> Result<bool> {
    let mut all = try_load_in(dir, store)?;
    let before = all.len();
    all.retain(|s| s.name != name);
    let removed = all.len() != before;
    if removed {
        save_all(store, &all)?;
    }
    Ok(removed)
}

/// Список серверов; ошибку хранилища (например, заблокированный keyring) возвращает как есть.
pub fn try_load() -> Result<Vec<Server>> {
    try_load_in(&config_dir(), default_store()?)
}

/// Список серверов. При ошибке хранилища печатает её в stderr и возвращает пустой список.
pub fn load() -> Vec<Server> {
    try_load().unwrap_or_else(|e| {
        eprintln!("Не удалось прочитать список серверов: {e:#}");
        Vec::new()
    })
}
pub fn upsert(s: Server) -> Result<String> {
    upsert_in(&config_dir(), default_store()?, s)
}
pub fn remove(name: &str) -> Result<bool> {
    remove_in(&config_dir(), default_store()?, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::vless_link;
    use crate::secrets::MemStore;

    const U: &str = "a158cda3-0b3d-424b-a8f8-26a6462c8349";

    fn reality_link() -> String {
        format!("vless://{U}@203.0.113.5:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUB&sid=abcd&type=tcp#My%20Server")
    }

    #[test]
    fn parses_reality_link() {
        let s = parse_vless(&reality_link()).unwrap();
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port), ("My Server", "203.0.113.5", 443));
        assert_eq!(s.security, "reality");
        assert_eq!(s.public_key.as_deref(), Some("PUB"));
        assert_eq!(s.short_id.as_deref(), Some("abcd"));
        assert_eq!(s.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(s.sni, "www.microsoft.com");
    }

    #[test]
    fn parses_ipv6_and_defaults() {
        let s = parse_vless(&format!("vless://{U}@[2001:db8::1]:8443?security=tls")).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.security.as_str()), ("2001:db8::1", 8443, "tls"));
        assert_eq!(s.name, "2001:db8::1");
        assert_eq!(s.sni, "2001:db8::1");
        assert_eq!(s.fingerprint, "chrome");
    }

    #[test]
    fn rejects_unsupported() {
        let bad = |q: &str| parse_vless(&format!("vless://{U}@h.example:443?{q}")).unwrap_err().to_string();
        assert!(bad("security=reality").contains("pbk"));
        assert!(bad("security=reality&pbk=x&type=ws").contains("ws"));
        assert!(bad("security=none").contains("security"));
        assert!(bad("security=tls&flow=xtls-rprx-direct").contains("flow"));
        assert!(parse_vless("vmess://abc").is_err());
        assert!(parse_vless("vless://short@h:1?security=tls").is_err());
    }

    #[test]
    fn roundtrip_with_server_side_link() {
        let st = State {
            version: 2, singbox: "1.14.3".into(), profile: "Eleutheria".into(),
            private_key: "p".into(), public_key: "PUBKEY".into(), short_id: "5bb5899f0cb12edf".into(),
            sni: "www.microsoft.com".into(), port: 443,
            users: vec![User { name: "default".into(), uuid: U.into() }],
        };
        let link = vless_link("203.0.113.5", &st, &st.users[0]);
        let parsed = parse_vless(&link).unwrap();
        let mut expected = Server::from_state("203.0.113.5", &st, &st.users[0]);
        expected.name = "Eleutheria".into();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn base64_both_alphabets_and_padding() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(b64_decode("-_-_").unwrap(), b64_decode("+/+/").unwrap());
        assert!(b64_decode("a:b").is_none());
    }

    #[test]
    fn subscription_plain_and_base64_with_skips() {
        let body = format!("{}\nvmess://zzz\nvless://bad\n", reality_link());
        let (s, skipped) = parse_subscription(&body);
        assert_eq!(s.len(), 1);
        assert_eq!(skipped.len(), 2);
        // то же самое в base64 (кодируем вручную, без зависимости)
        let enc = {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut o = String::new();
            for ch in body.as_bytes().chunks(3) {
                let n = ch.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
                for i in 0..4 {
                    if i <= ch.len() { o.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char) } else { o.push('=') }
                }
            }
            o
        };
        let (s2, skipped2) = parse_subscription(&enc);
        assert_eq!(s2, s);
        assert_eq!(skipped2.len(), 2);
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eleutheria-test-prof-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn store_upsert_dedups_and_renames() {
        let (dir, st) = (tmpdir("upsert"), MemStore::new());
        let a = parse_vless(&reality_link()).unwrap();
        assert_eq!(upsert_in(&dir, &st, a.clone()).unwrap(), "My Server");
        assert_eq!(upsert_in(&dir, &st, a.clone()).unwrap(), "My Server"); // тот же сервер: обновление
        assert_eq!(try_load_in(&dir, &st).unwrap().len(), 1);
        let mut b = a.clone();
        b.host = "198.51.100.7".into(); // другой сервер с тем же именем
        assert_eq!(upsert_in(&dir, &st, b).unwrap(), "My Server-2");
        assert_eq!(try_load_in(&dir, &st).unwrap().len(), 2);
        assert!(remove_in(&dir, &st, "My Server-2").unwrap());
        assert!(!remove_in(&dir, &st, "nope").unwrap());
        assert_eq!(try_load_in(&dir, &st).unwrap(), vec![a]);
        // удалённый сервер не оставляет записи в хранилище: индекс + одна запись
        assert_eq!(st.len(), 2);
    }

    #[test]
    fn profiles_never_touch_the_disk() {
        let (dir, st) = (tmpdir("nodisk"), MemStore::new());
        upsert_in(&dir, &st, parse_vless(&reality_link()).unwrap()).unwrap();
        assert!(!dir.exists(), "профили пишутся только в хранилище секретов");
    }

    fn legacy_servers() -> Vec<Server> {
        let a = parse_vless(&reality_link()).unwrap();
        let mut b = a.clone();
        b.name = "Second".into();
        b.host = "198.51.100.7".into();
        vec![a, b]
    }

    #[test]
    fn legacy_profiles_json_is_migrated_and_removed() {
        let (dir, st) = (tmpdir("legacy"), MemStore::new());
        fs::create_dir_all(&dir).unwrap();
        let servers = legacy_servers();
        fs::write(legacy_path_in(&dir), serde_json::to_vec_pretty(&serde_json::json!({ "servers": servers })).unwrap()).unwrap();
        assert_eq!(try_load_in(&dir, &st).unwrap(), servers);
        assert!(!legacy_path_in(&dir).exists());
        assert_eq!(try_load_in(&dir, &st).unwrap(), servers); // уже из хранилища
    }

    #[test]
    fn migration_does_not_overwrite_existing_store_and_keeps_file_on_failure() {
        // хранилище уже заполнено: старый файл игнорируется и не затирает новые данные
        let (dir, st) = (tmpdir("legacy-skip"), MemStore::new());
        fs::create_dir_all(&dir).unwrap();
        let one = vec![legacy_servers().remove(0)];
        save_all(&st, &one).unwrap();
        fs::write(legacy_path_in(&dir), serde_json::to_vec(&serde_json::json!({ "servers": legacy_servers() })).unwrap()).unwrap();
        assert_eq!(try_load_in(&dir, &st).unwrap(), one);

        // повреждённый файл: ошибка, файл на месте, хранилище пустое
        let (dir, st) = (tmpdir("legacy-bad"), MemStore::new());
        fs::create_dir_all(&dir).unwrap();
        fs::write(legacy_path_in(&dir), b"{not json").unwrap();
        assert!(try_load_in(&dir, &st).is_err());
        assert!(legacy_path_in(&dir).exists() && st.is_empty());
    }

    #[test]
    fn missing_entry_is_skipped_and_corrupt_entry_is_an_error() {
        let (dir, st) = (tmpdir("broken"), MemStore::new());
        let name = upsert_in(&dir, &st, parse_vless(&reality_link()).unwrap()).unwrap();
        st.set("servers/index", &serde_json::to_vec(&[name.clone(), "ghost".to_string()]).unwrap()).unwrap();
        assert_eq!(try_load_in(&dir, &st).unwrap().len(), 1);
        st.set(&entry_name(&name), b"garbage").unwrap();
        assert!(try_load_in(&dir, &st).is_err());
    }

    #[test]
    fn validate_accepts_good_and_rejects_injection() {
        let good = parse_vless(&reality_link()).unwrap();
        assert!(good.validate().is_ok());
        let bad = |f: &dyn Fn(&mut Server)| { let mut s = good.clone(); f(&mut s); s.validate().is_err() };
        assert!(bad(&|s| s.host = "a b".into()));
        assert!(bad(&|s| s.host = "x\"y".into()));
        assert!(bad(&|s| s.host = "/etc/passwd".into()));
        assert!(bad(&|s| s.sni = "../x".into()));
        assert!(bad(&|s| s.uuid = "short".into()));
        assert!(bad(&|s| s.fingerprint = "evil".into()));
        assert!(bad(&|s| s.public_key = Some("a/b".into())));
        assert!(bad(&|s| s.short_id = Some("zz".into())));
        assert!(bad(&|s| s.security = "none".into()));
        assert!(bad(&|s| s.port = 0));
        assert!(bad(&|s| s.name = "x".repeat(65)));
        assert!(bad(&|s| s.flow = Some("xtls-rprx-direct".into())));
    }
}
