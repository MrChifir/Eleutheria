//! Сторонние профили протоколов (M6.1): установка из папки с проверкой, diff и подтверждением.
//!
//! Серверный шаблон превращается в inbound sing-box, который работает на VPS от root, поэтому профиль из чужих
//! рук не доверенный. Проверяется не текст шаблона, а то, что из него получается после подстановки, плюс набор
//! допустимых переменных. Что запрещено:
//! - типы inbound/outbound вне списка (никаких tun, direct, socks и http без пароля, redirect и т.п.);
//! - ключи, которые направляют трафик или читают файлы: `detour`, `fallback`, `acme`, `*_path` (кроме
//!   `certificate_path`/`key_path` сервера со значениями, которые подставляет сам Eleutheria);
//! - любые файлы кроме `meta.yaml`, `server.json.tpl`, `client.json.tpl`. Скрипт `install.sh` из плана здесь
//!   не поддерживается намеренно: он выполнялся бы на сервере от root.
//!
//! Установка двухшаговая: `plan_install` читает и проверяет папку и считает diff с уже установленной версией,
//! `commit` пишет только после явного подтверждения вызывающего.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::profiles::{self, Profile, SCHEMA};
use crate::state::Proto;

pub const FILES: [&str; 3] = ["meta.yaml", "server.json.tpl", "client.json.tpl"];
const MAX_FILE: u64 = 16 * 1024;
const TYPES: [&str; 8] = ["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "shadowtls", "anytls"];
const FORBIDDEN_KEYS: [&str; 12] = [
    "detour", "domain_resolver", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark",
    "netns", "fallback", "fallback_for_alpn", "acme", "data_directory", "external_account",
];
const RESERVED_IDS: [&str; 6] = ["reality", "vless-reality", "direct", "proxy", "block", "dns"];

// образцовые значения: по ним проверяется результат подстановки
const S_PORT: u64 = 40443;
const S_CERT: &str = "/etc/eleutheria/cert.pem";
const S_KEY: &str = "/etc/eleutheria/key.pem";
const S_TAG: &str = "sample-tag";
const S_HOST: &str = "203.0.113.7";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Files {
    pub meta: String,
    pub server: String,
    pub client: String,
}

impl Files {
    fn get(&self, name: &str) -> &str {
        match name {
            "meta.yaml" => &self.meta,
            "server.json.tpl" => &self.server,
            _ => &self.client,
        }
    }

    /// Отпечаток содержимого: показывается при подтверждении, чтобы сверить с автором профиля.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for n in FILES {
            h.update(n.as_bytes());
            h.update([0]);
            h.update(self.get(n).as_bytes());
            h.update([0]);
        }
        hex::encode(h.finalize())
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub profile: Profile,
    pub files: Files,
}

impl Candidate {
    /// Все три файла целиком (при установке нового профиля пользователь должен увидеть, что ставит).
    pub fn files_listing(&self) -> String {
        FILES.iter().map(|n| format!("=== {n}\n{}\n", self.files.get(n).trim_end())).collect()
    }
}

pub fn root() -> PathBuf {
    crate::store::config_dir().join("profiles")
}

fn read_regular(path: &Path) -> Result<String> {
    let md = fs::symlink_metadata(path).with_context(|| format!("{}: нет файла", path.display()))?;
    if !md.file_type().is_file() {
        bail!("{}: не обычный файл (ссылки и устройства запрещены)", path.display());
    }
    if md.len() > MAX_FILE {
        bail!("{}: больше {} КиБ", path.display(), MAX_FILE / 1024);
    }
    String::from_utf8(fs::read(path)?).map_err(|_| anyhow!("{}: не UTF-8", path.display()))
}

/// Читает папку профиля и проверяет её целиком. Ничего не пишет.
pub fn load_dir(dir: &Path) -> Result<Candidate> {
    let md = fs::symlink_metadata(dir).with_context(|| format!("{}: нет папки", dir.display()))?;
    if !md.file_type().is_dir() {
        bail!("{}: не папка", dir.display());
    }
    for e in fs::read_dir(dir)? {
        let name = e?.file_name().to_string_lossy().to_string();
        if name == "install.sh" {
            bail!("install.sh не поддерживается: скрипт выполнялся бы на сервере от root, а сторонним профилям это запрещено");
        }
        if !FILES.contains(&name.as_str()) {
            bail!("лишний файл `{name}`: в профиле допустимы только {}", FILES.join(", "));
        }
    }
    let files = Files {
        meta: read_regular(&dir.join("meta.yaml"))?,
        server: read_regular(&dir.join("server.json.tpl"))?,
        client: read_regular(&dir.join("client.json.tpl"))?,
    };
    let profile = validate(&files)?;
    Ok(Candidate { profile, files })
}

/// Полная проверка недоверенного профиля.
pub fn validate(f: &Files) -> Result<Profile> {
    let p = Profile::parse(&f.meta, &f.server, &f.client)?;
    let m = &p.manifest;
    if Proto::from_id(&m.id).is_some() || RESERVED_IDS.contains(&m.id.as_str()) {
        bail!("id `{}` занят встроенным профилем или зарезервирован", m.id);
    }
    if m.description.chars().count() > 600 || m.description.chars().any(|c| c.is_control() && c != '\n') {
        bail!("meta.yaml: description длиннее 600 символов или с управляющими символами");
    }
    if m.params.len() > 16 || m.params.iter().any(|(_, v)| v.chars().count() > 256 || v.chars().any(char::is_control)) {
        bail!("meta.yaml: params: не больше 16 значений до 256 символов без управляющих");
    }
    let (st, ct) = p.templates();
    // ws_path (секретный путь WebSocket) и домен CDN есть только у встроенного vless-ws: сторонним профилям их не выдаём
    check_vars(st, &["port", "sni", "cert_path", "key_path", "server_key", "u", "param"], true)?;
    check_vars(ct, &["tag", "host", "port", "uuid", "sni", "password", "method", "pin_list", "param"], false)?;
    if m.server_key.is_some() && !st_uses(st, "server_key") {
        bail!("meta.yaml: server_key задан, а серверный шаблон не использует {{{{server_key}}}}");
    }
    if m.server_key.is_none() && st_uses(st, "server_key") {
        bail!("серверный шаблон использует {{{{server_key}}}}, а в meta.yaml нет server_key");
    }

    let server = p.render_server(&sample_server_vars()).context("пробная подстановка серверного шаблона")?;
    check_inbound(&server, &m.id)?;
    let client = p.render_client(&sample_client_vars()).context("пробная подстановка клиентского шаблона")?;
    check_outbound(&client)?;
    Ok(p)
}

fn st_uses(tpl: &Value, var: &str) -> bool {
    let mut names = Vec::new();
    let _ = profiles::scan(tpl, &mut names);
    names.iter().any(|n| n == var)
}

fn sample_server_vars() -> Value {
    json!({
        "port": S_PORT, "sni": "www.example.com", "ws_path": "/0123456789abcdef", "cert_path": S_CERT, "key_path": S_KEY,
        "server_key": "c2FtcGxlLXNlcnZlci1rZXk=",
        "users": [{ "name": "alice", "uuid": "a158cda3-0b3d-424b-a8f8-26a6462c8349", "password": "00112233445566778899aabbccddeeff" }],
    })
}

fn sample_client_vars() -> Value {
    json!({
        "tag": S_TAG, "host": S_HOST, "port": S_PORT, "uuid": "a158cda3-0b3d-424b-a8f8-26a6462c8349",
        "sni": "www.example.com", "password": "00112233445566778899aabbccddeeff", "method": "2022-blake3-aes-128-gcm",
        "ws_path": "/0123456789abcdef", "pin_list": ["c2FtcGxl"],
    })
}

/// Переменные шаблона только из известного набора; `$each` только по `users` с псевдонимом `u` и только на сервере.
fn check_vars(tpl: &Value, roots: &[&str], server: bool) -> Result<()> {
    let mut names = Vec::new();
    profiles::scan(tpl, &mut names)?;
    for n in names {
        let root = n.split('.').next().unwrap_or("");
        if !roots.contains(&root) {
            bail!("неизвестная переменная `{n}` (допустимы: {})", roots.join(", "));
        }
    }
    fn walk(v: &Value, server: bool) -> Result<()> {
        match v {
            Value::Object(m) => {
                if m.contains_key("$each") {
                    if !server {
                        bail!("`$each` в клиентском шаблоне запрещён");
                    }
                    if m["$each"] != json!("users") || m.get("as") != Some(&json!("u")) {
                        bail!("`$each` допустим только как {{\"$each\":\"users\",\"as\":\"u\",...}}");
                    }
                }
                m.values().try_for_each(|x| walk(x, server))
            }
            Value::Array(a) => a.iter().try_for_each(|x| walk(x, server)),
            _ => Ok(()),
        }
    }
    walk(tpl, server)
}

/// Запрещённые ключи на любой глубине; `*_path` обрабатывает вызывающий через `allow_path`.
fn walk_keys(v: &Value, allow_path: &dyn Fn(&str, &Value) -> bool) -> Result<()> {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if FORBIDDEN_KEYS.contains(&k.as_str()) {
                    bail!("ключ `{k}` запрещён в сторонних профилях");
                }
                if k.ends_with("_path") && !allow_path(k, x) {
                    bail!("ключ `{k}` читает файл и запрещён в сторонних профилях");
                }
                walk_keys(x, allow_path)?;
            }
            Ok(())
        }
        Value::Array(a) => a.iter().try_for_each(|x| walk_keys(x, allow_path)),
        _ => Ok(()),
    }
}

fn check_type(v: &Value, what: &str) -> Result<()> {
    let t = v.get("type").and_then(Value::as_str).ok_or_else(|| anyhow!("{what}: нет type"))?;
    if !TYPES.contains(&t) {
        bail!("{what}: тип `{t}` не разрешён (допустимы: {})", TYPES.join(", "));
    }
    Ok(())
}

fn check_inbound(v: &Value, id: &str) -> Result<()> {
    check_type(v, "inbound")?;
    if v.get("tag") != Some(&json!(id)) {
        bail!("inbound: tag должен совпадать с id профиля (`{id}`)");
    }
    if let Some(l) = v.get("listen") {
        if l != &json!("::") {
            bail!("inbound: listen допустим только `::`");
        }
    }
    if v.get("listen_port") != Some(&json!(S_PORT)) {
        bail!("inbound: listen_port должен быть ровно `{{{{port}}}}`");
    }
    walk_keys(v, &|k, x| (k == "certificate_path" && x == &json!(S_CERT)) || (k == "key_path" && x == &json!(S_KEY)))
}

fn check_outbound(v: &Value) -> Result<()> {
    check_type(v, "outbound")?;
    if v.get("tag") != Some(&json!(S_TAG)) || v.get("server") != Some(&json!(S_HOST)) || v.get("server_port") != Some(&json!(S_PORT)) {
        bail!("outbound: tag, server и server_port должны быть ровно `{{{{tag}}}}`, `{{{{host}}}}`, `{{{{port}}}}`");
    }
    walk_keys(v, &|_, _| false)
}

// ---------- diff ----------

/// Построчный diff (наибольшая общая подпоследовательность). Файлы ограничены 16 КиБ, поэтому квадратичная память не страшна.
pub fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut t = vec![vec![0u16; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            t[i][j] = if a[i] == b[j] { t[i + 1][j + 1] + 1 } else { t[i + 1][j].max(t[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, String::new());
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || t[i + 1][j] >= t[i][j + 1]) {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    out
}

// ---------- установка ----------

pub struct InstallPlan {
    pub candidate: Candidate,
    /// уже установлена версия с этим id
    pub replaces: bool,
    /// содержимое отличается от установленного (для нового профиля всегда true)
    pub changed: bool,
    /// diff по файлам, пустой, если ничего не изменилось
    pub diff: String,
}

impl InstallPlan {
    /// Что профиль будет делать, человеческим языком (показывается перед подтверждением).
    pub fn summary(&self) -> Vec<String> {
        let m = &self.candidate.profile.manifest;
        let (st, ct) = self.candidate.profile.templates();
        let ty = |v: &Value| v.get("type").and_then(Value::as_str).unwrap_or("?").to_string();
        vec![
            format!("{} (`{}`), отпечаток {}", m.name, m.id, &self.candidate.files.digest()[..16]),
            format!("сервер: inbound {} на порту {} по умолчанию", ty(st), m.default_port),
            format!("клиент: outbound {}", ty(ct)),
            if m.needs_cert { "читает сертификат и ключ сервера, которые создаёт Eleutheria".into() } else { "сертификат не нужен".into() },
        ]
    }
}

pub fn plan_install_in(root: &Path, src: &Path) -> Result<InstallPlan> {
    let candidate = load_dir(src)?;
    let id = &candidate.profile.manifest.id;
    let installed = root.join(id);
    let old = if installed.exists() { Some(load_dir(&installed).or_else(|_| raw_files(&installed))?) } else { None };
    let (mut diff, mut changed) = (String::new(), old.is_none());
    for n in FILES {
        let before = old.as_ref().map(|c| c.files.get(n)).unwrap_or("");
        let after = candidate.files.get(n);
        if before != after {
            changed = true;
            diff.push_str(&format!("=== {n}\n{}", line_diff(before, after)));
        }
    }
    Ok(InstallPlan { candidate, replaces: old.is_some(), changed, diff })
}

/// Установленная версия могла испортиться или устареть: для diff её содержимое нужно и без успешной проверки.
fn raw_files(dir: &Path) -> Result<Candidate> {
    let files = Files {
        meta: read_regular(&dir.join("meta.yaml")).unwrap_or_default(),
        server: read_regular(&dir.join("server.json.tpl")).unwrap_or_default(),
        client: read_regular(&dir.join("client.json.tpl")).unwrap_or_default(),
    };
    let profile = Profile::parse(&files.meta, &files.server, &files.client)?;
    Ok(Candidate { profile, files })
}

/// Записывает профиль. Вызывать только после подтверждения пользователя. Замена атомарна: старая папка
/// переименовывается в сторону и удаляется после успешной установки новой.
pub fn commit_in(root: &Path, plan: &InstallPlan) -> Result<PathBuf> {
    let id = &plan.candidate.profile.manifest.id;
    // защита от подмены между планом и записью
    validate(&plan.candidate.files)?;
    fs::create_dir_all(root)?;
    let tmp = root.join(format!(".new-{id}"));
    let old = root.join(format!(".old-{id}"));
    let dst = root.join(id);
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::remove_dir_all(&old);
    fs::create_dir(&tmp)?;
    for n in FILES {
        fs::write(tmp.join(n), plan.candidate.files.get(n))?;
    }
    if dst.exists() {
        fs::rename(&dst, &old)?;
    }
    if let Err(e) = fs::rename(&tmp, &dst) {
        if old.exists() {
            let _ = fs::rename(&old, &dst);
        }
        return Err(e).context("не удалось поставить профиль на место, прежняя версия возвращена");
    }
    let _ = fs::remove_dir_all(&old);
    Ok(dst)
}

/// Установленные сторонние профили. Испорченные возвращаются ошибкой, а не пропускаются молча.
pub fn list_in(root: &Path) -> Vec<(String, Result<Candidate>)> {
    let Ok(rd) = fs::read_dir(root) else { return Vec::new() };
    let mut v: Vec<_> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.'))
        .map(|n| {
            let r = load_dir(&root.join(&n)).and_then(|c| {
                if c.profile.manifest.id == n { Ok(c) } else { Err(anyhow!("имя папки `{n}` не совпадает с id `{}`", c.profile.manifest.id)) }
            });
            (n, r)
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// Один установленный профиль: проверка при каждом чтении, имя папки обязано совпасть с id.
pub fn load_installed_in(root: &Path, id: &str) -> Result<Candidate> {
    if !profiles::valid_id(id) {
        bail!("недопустимый id `{id}`");
    }
    let c = load_dir(&root.join(id))?;
    if c.profile.manifest.id != id {
        bail!("имя папки `{id}` не совпадает с id `{}`", c.profile.manifest.id);
    }
    Ok(c)
}

/// Проверяет присланные файлы профилей (как при установке) и собирает набор для генератора конфигов.
/// Ограничения нужны helper'у, который получает их по IPC: число профилей, размер файлов, уникальность id.
pub fn profile_set(files: &[Files]) -> Result<crate::client::config::ProfileSet> {
    if files.len() > 16 {
        bail!("слишком много сторонних профилей (не больше 16)");
    }
    let mut set = crate::client::config::ProfileSet::new();
    for f in files {
        if FILES.iter().any(|n| f.get(n).len() as u64 > MAX_FILE) {
            bail!("файл стороннего профиля больше {} КиБ", MAX_FILE / 1024);
        }
        let p = validate(f)?;
        let id = p.manifest.id.clone();
        if set.insert(id.clone(), p).is_some() {
            bail!("профиль `{id}` передан дважды");
        }
    }
    Ok(set)
}

/// Файлы установленных сторонних профилей, которые нужны серверам из списка (для helper'а: он проверяет их сам).
pub fn files_for_servers(root: &Path, servers: &[crate::client::profile::Server]) -> Result<Vec<Files>> {
    let mut ids: Vec<&str> = servers.iter().filter_map(|s| s.profile.as_deref()).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter().map(|id| Ok(load_installed_in(root, id)?.files)).collect()
}

pub fn remove_in(root: &Path, id: &str) -> Result<()> {
    if !profiles::valid_id(id) {
        bail!("недопустимый id `{id}`");
    }
    let d = root.join(id);
    if !d.exists() {
        bail!("профиль `{id}` не установлен");
    }
    fs::remove_dir_all(&d).with_context(|| format!("не удалось удалить {}", d.display()))
}

pub fn schema() -> u32 {
    SCHEMA
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("elt-up-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const META: &str = "schema: 1\nid: demo-trojan\nname: Demo Trojan\ntransport: tcp\ndefault_port: 9443\nneeds_cert: true\npassword: hex32\n";
    const SERVER: &str = r#"{"type":"trojan","tag":"demo-trojan","listen":"::","listen_port":"{{port}}",
        "users":{"$each":"users","as":"u","do":{"name":"{{u.name}}","password":"{{u.password}}"}},
        "tls":{"enabled":true,"server_name":"{{sni}}","certificate_path":"{{cert_path}}","key_path":"{{key_path}}"}}"#;
    const CLIENT: &str = r#"{"type":"trojan","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","password":"{{password}}",
        "tls":{"enabled":true,"server_name":"{{sni}}","certificate_public_key_sha256":"{{?pin_list}}"}}"#;

    fn files(m: &str, s: &str, c: &str) -> Files {
        Files { meta: m.into(), server: s.into(), client: c.into() }
    }

    fn write_dir(d: &Path, f: &Files) {
        fs::create_dir_all(d).unwrap();
        for n in FILES {
            fs::write(d.join(n), f.get(n)).unwrap();
        }
    }

    fn err(f: &Files) -> String {
        format!("{:#}", validate(f).unwrap_err())
    }

    #[test]
    fn server_key_must_match_between_meta_and_server_template() {
        let keyed_srv = SERVER.replace("\"{{u.password}}\"", "\"{{u.password}}\",\"key\":\"{{server_key}}\"");
        // шаблон использует ключ, а манифест его не объявляет: provisioner его не создаст
        assert!(err(&files(META, &keyed_srv, CLIENT)).contains("server_key"));
        // манифест объявляет, а шаблон не использует: ключ создавался бы зря
        let keyed_meta = format!("{META}server_key: base64-16\n");
        assert!(err(&files(&keyed_meta, SERVER, CLIENT)).contains("server_key"));
        validate(&files(&keyed_meta, &keyed_srv, CLIENT)).expect("согласованная пара проходит");
    }

    #[test]
    fn ws_path_is_not_available_to_third_party_profiles() {
        assert!(err(&files(META, &SERVER.replace("{{sni}}", "{{ws_path}}"), CLIENT)).contains("ws_path"));
        assert!(err(&files(META, SERVER, &CLIENT.replace("{{sni}}", "{{ws_path}}"))).contains("ws_path"));
    }

    #[test]
    fn good_profile_passes() {
        assert!(validate(&files(META, SERVER, CLIENT)).is_ok());
    }

    #[test]
    fn builtin_and_reserved_ids_are_refused() {
        for id in ["hysteria2", "tuic", "vless-ws", "reality", "direct"] {
            let m = META.replace("demo-trojan", id);
            let s = SERVER.replace("demo-trojan", id);
            assert!(err(&files(&m, &s, CLIENT)).contains("занят"), "{id}");
        }
    }

    #[test]
    fn dangerous_types_are_refused() {
        for t in ["tun", "direct", "socks", "http", "mixed", "redirect", "tproxy"] {
            let s = SERVER.replace("\"trojan\"", &format!("\"{t}\""));
            assert!(err(&files(META, &s, CLIENT)).contains("не разрешён"), "server {t}");
            let c = CLIENT.replace("\"trojan\"", &format!("\"{t}\""));
            assert!(err(&files(META, SERVER, &c)).contains("не разрешён"), "client {t}");
        }
    }

    #[test]
    fn forbidden_keys_are_refused_at_any_depth() {
        for k in ["detour", "fallback", "acme", "domain_resolver", "routing_mark"] {
            let s = SERVER.replace("\"enabled\":true,\"server_name\"", &format!("\"enabled\":true,\"x\":{{\"{k}\":\"a\"}},\"server_name\""));
            assert!(err(&files(META, &s, CLIENT)).contains("запрещён"), "server {k}");
            let c = CLIENT.replace("\"password\"", &format!("\"{k}\":\"srv-1\",\"password\""));
            assert!(err(&files(META, SERVER, &c)).contains("запрещён"), "client {k}");
        }
    }

    #[test]
    fn file_reading_keys_are_refused() {
        let s = SERVER.replace("\"{{cert_path}}\"", "\"/etc/shadow\"");
        assert!(err(&files(META, &s, CLIENT)).contains("читает файл"));
        let s = SERVER.replace("\"enabled\":true,", "\"enabled\":true,\"ca_path\":\"/etc/passwd\",");
        assert!(err(&files(META, &s, CLIENT)).contains("читает файл"));
        let c = CLIENT.replace("\"enabled\":true,", "\"enabled\":true,\"certificate_path\":\"/home/u/.ssh/id\",");
        assert!(err(&files(META, SERVER, &c)).contains("читает файл"));
    }

    #[test]
    fn listen_port_tag_and_unknown_vars_are_enforced() {
        assert!(err(&files(META, &SERVER.replace("\"{{port}}\"", "22"), CLIENT)).contains("listen_port"));
        assert!(err(&files(META, &SERVER.replace("\"::\"", "\"127.0.0.1\""), CLIENT)).contains("listen"));
        assert!(err(&files(META, &SERVER.replace("\"tag\":\"demo-trojan\"", "\"tag\":\"vless-reality\""), CLIENT)).contains("tag"));
        assert!(err(&files(META, &SERVER.replace("{{sni}}", "{{secret_key}}"), CLIENT)).contains("неизвестная переменная"));
        assert!(err(&files(META, SERVER, &CLIENT.replace("{{?pin_list}}", "{{?pin_lst}}"))).contains("неизвестная переменная"));
        assert!(err(&files(META, SERVER, &CLIENT.replace("{{host}}", "198.51.100.1"))).contains("outbound"));
    }

    #[test]
    fn each_is_limited_to_users_on_server() {
        let s = SERVER.replace("\"$each\":\"users\"", "\"$each\":\"param\"");
        assert!(err(&files(META, &s, CLIENT)).contains("$each"));
        let c = r#"{"type":"trojan","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","x":{"$each":"users","as":"u","do":1}}"#;
        assert!(err(&files(META, SERVER, c)).contains("$each"));
    }

    #[test]
    fn extra_files_install_sh_and_symlinks_are_refused() {
        let d = tmp().join("p");
        write_dir(&d, &files(META, SERVER, CLIENT));
        assert!(load_dir(&d).is_ok());
        fs::write(d.join("install.sh"), "#!/bin/sh\nrm -rf /\n").unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("не поддерживается"));
        fs::remove_file(d.join("install.sh")).unwrap();
        fs::write(d.join("notes.txt"), "x").unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("лишний файл"));
        fs::remove_file(d.join("notes.txt")).unwrap();
        #[cfg(unix)]
        {
            fs::remove_file(d.join("client.json.tpl")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", d.join("client.json.tpl")).unwrap();
            assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("не обычный файл"));
        }
    }

    #[test]
    fn oversized_file_is_refused() {
        let d = tmp().join("p");
        let big = format!("{}{}", SERVER, " ".repeat(20_000));
        write_dir(&d, &files(META, &big, CLIENT));
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("КиБ"));
    }

    #[test]
    fn line_diff_shows_only_changes() {
        assert_eq!(line_diff("a\nb\nc\n", "a\nB\nc\n"), "- b\n+ B\n");
        assert_eq!(line_diff("", "x\ny\n"), "+ x\n+ y\n");
        assert_eq!(line_diff("x\n", "x\n"), "");
        assert_eq!(line_diff("a\nb\n", "a\n"), "- b\n");
    }

    #[test]
    fn install_update_list_remove_roundtrip() {
        let base = tmp();
        let (src, root) = (base.join("src"), base.join("profiles"));
        write_dir(&src, &files(META, SERVER, CLIENT));

        let plan = plan_install_in(&root, &src).unwrap();
        assert!(!plan.replaces && plan.changed);
        assert!(plan.diff.contains("=== server.json.tpl") && plan.summary()[1].contains("trojan"));
        assert!(!root.join("demo-trojan").exists(), "до подтверждения ничего не записано");
        commit_in(&root, &plan).unwrap();
        assert!(list_in(&root).iter().all(|(n, r)| n == "demo-trojan" && r.is_ok()));

        let again = plan_install_in(&root, &src).unwrap();
        assert!(again.replaces && !again.changed && again.diff.is_empty());

        fs::write(src.join("meta.yaml"), META.replace("9443", "9444")).unwrap();
        let upd = plan_install_in(&root, &src).unwrap();
        assert!(upd.replaces && upd.changed);
        assert_eq!(upd.diff, "=== meta.yaml\n- default_port: 9443\n+ default_port: 9444\n");
        commit_in(&root, &upd).unwrap();
        assert_eq!(list_in(&root)[0].1.as_ref().unwrap().profile.manifest.default_port, 9444);
        assert!(fs::read_dir(&root).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.')), "временных папок не осталось");

        remove_in(&root, "demo-trojan").unwrap();
        assert!(list_in(&root).is_empty());
        assert!(remove_in(&root, "demo-trojan").is_err() && remove_in(&root, "../x").is_err());
    }

    #[test]
    fn tampered_installed_profile_is_reported_not_skipped() {
        let base = tmp();
        let (src, root) = (base.join("src"), base.join("profiles"));
        write_dir(&src, &files(META, SERVER, CLIENT));
        commit_in(&root, &plan_install_in(&root, &src).unwrap()).unwrap();
        fs::write(root.join("demo-trojan/server.json.tpl"), SERVER.replace("\"trojan\"", "\"tun\"")).unwrap();
        let l = list_in(&root);
        assert_eq!(l.len(), 1);
        assert!(l[0].1.is_err());
        // diff при обновлении испорченной версии всё равно считается
        assert!(plan_install_in(&root, &src).unwrap().diff.contains("server.json.tpl"));
    }

    #[test]
    fn digest_changes_with_content() {
        let a = files(META, SERVER, CLIENT);
        let mut b = a.clone();
        b.client.push(' ');
        assert_ne!(a.digest(), b.digest());
        assert_eq!(a.digest(), a.clone().digest());
    }
}
