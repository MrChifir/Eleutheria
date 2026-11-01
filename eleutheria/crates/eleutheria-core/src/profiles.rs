//! Профили протоколов: папка `meta.yaml` + `server.json.tpl` + `client.json.tpl`. Встроенные профили (Hysteria2,
//! TUIC, SS-2022) лежат в `crates/eleutheria-core/profiles/` и разбираются тем же кодом, что будет разбирать
//! пользовательские профили (M6).
//!
//! Шаблон это JSON, подстановка идёт по значениям, а не по тексту: значение переменной не может изменить
//! структуру конфига. Синтаксис:
//! - строка ровно `"{{имя}}"` заменяется значением переменной с сохранением типа (число остаётся числом);
//! - `{{имя}}` внутри строки подставляется как текст (только скаляры);
//! - `"{{?имя}}"` целиком в значении поля: поле удаляется, если переменной нет, она null или пустой массив;
//! - `{"$each": "users", "as": "u", "do": {...}}` превращается в массив: `do` для каждого элемента списка;
//! - `имя.поле` обращается внутрь объекта.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::state::{Proto, ProtoState, State};

#[derive(Clone, Copy, Debug, serde::Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    Both,
}

/// Вид пароля пользователя, который выводится из его секрета.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum PasswordFormat {
    #[serde(rename = "hex32")]
    Hex32,
    #[serde(rename = "base64-16")]
    Base64_16,
    #[serde(rename = "base64-32")]
    Base64_32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub transport: Transport,
    pub default_port: u16,
    /// нужен ли сертификат (файлы на сервере и закрепление ключа в клиенте)
    #[serde(default)]
    pub needs_cert: bool,
    pub password: PasswordFormat,
    /// общий ключ сервера (как у SS-2022): provisioner создаёт его при включении профиля, в серверном шаблоне он
    /// доступен как `{{server_key}}`, а клиент отправляет пароль в виде `ключ_сервера:пароль_пользователя`
    #[serde(default)]
    pub server_key: Option<PasswordFormat>,
    /// константы профиля, доступны в шаблонах как `param.<имя>`
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub manifest: Manifest,
    server_tpl: Value,
    client_tpl: Value,
}

pub const SCHEMA: u32 = 1;

pub fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_var(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
}

/// Все ли `{{` в строках дерева закрыты и содержат допустимые имена; возвращает найденные имена.
pub(crate) fn scan(v: &Value, out: &mut Vec<String>) -> Result<()> {
    match v {
        Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("{{") {
                let after = &rest[i + 2..];
                let j = after.find("}}").ok_or_else(|| anyhow!("в `{s}` нет закрывающей }}}}"))?;
                let name = after[..j].trim_start_matches('?');
                if !valid_var(name) {
                    bail!("недопустимое имя переменной `{}` в `{s}`", &after[..j]);
                }
                out.push(name.to_string());
                rest = &after[j + 2..];
            }
            if rest.contains("}}") {
                bail!("лишняя }}}} в `{s}`");
            }
        }
        Value::Array(a) => a.iter().try_for_each(|x| scan(x, out))?,
        Value::Object(m) => m.values().try_for_each(|x| scan(x, out))?,
        _ => {}
    }
    Ok(())
}

impl Profile {
    pub fn parse(meta_yaml: &str, server_tpl: &str, client_tpl: &str) -> Result<Profile> {
        let manifest: Manifest = serde_yaml_ng::from_str(meta_yaml).context("meta.yaml: ошибка разбора")?;
        if manifest.schema != SCHEMA {
            bail!("meta.yaml: schema {} не поддерживается (нужна {SCHEMA})", manifest.schema);
        }
        if !valid_id(&manifest.id) {
            bail!("meta.yaml: недопустимый id `{}` (a-z, 0-9, -, до 32 символов)", manifest.id);
        }
        if manifest.name.trim().is_empty() || manifest.name.chars().count() > 64 || manifest.name.chars().any(char::is_control) {
            bail!("meta.yaml: недопустимое name");
        }
        if manifest.default_port == 0 {
            bail!("meta.yaml: default_port 0");
        }
        if let Some(k) = manifest.params.keys().find(|k| !valid_var(k) || k.contains('.')) {
            bail!("meta.yaml: недопустимое имя параметра `{k}`");
        }
        let parse_tpl = |what: &str, raw: &str| -> Result<Value> {
            let v: Value = serde_json::from_str(raw).with_context(|| format!("{what}: не JSON"))?;
            scan(&v, &mut Vec::new()).with_context(|| what.to_string())?;
            Ok(v)
        };
        Ok(Profile {
            server_tpl: parse_tpl("server.json.tpl", server_tpl)?,
            client_tpl: parse_tpl("client.json.tpl", client_tpl)?,
            manifest,
        })
    }

    /// Сырые деревья шаблонов (для проверки сторонних профилей).
    pub(crate) fn templates(&self) -> (&Value, &Value) {
        (&self.server_tpl, &self.client_tpl)
    }

    pub fn render_server(&self, vars: &Value) -> Result<Value> {
        render(&self.server_tpl, &with_params(vars, &self.manifest))
            .with_context(|| format!("профиль {}: server.json.tpl", self.manifest.id))
    }

    pub fn render_client(&self, vars: &Value) -> Result<Value> {
        render(&self.client_tpl, &with_params(vars, &self.manifest))
            .with_context(|| format!("профиль {}: client.json.tpl", self.manifest.id))
    }
}

fn with_params(vars: &Value, m: &Manifest) -> Value {
    let mut v = vars.clone();
    if let Value::Object(o) = &mut v {
        o.insert("param".into(), json!(m.params));
    }
    v
}

fn lookup<'a>(vars: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(vars, |v, k| v.get(k))
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn is_empty_value(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

fn exact_var(s: &str) -> Option<(&str, bool)> {
    let inner = s.strip_prefix("{{")?.strip_suffix("}}")?;
    if inner.contains("{{") || inner.contains("}}") {
        return None;
    }
    Some(match inner.strip_prefix('?') {
        Some(n) => (n, true),
        None => (inner, false),
    })
}

pub fn render(tpl: &Value, vars: &Value) -> Result<Value> {
    match tpl {
        Value::String(s) => {
            if let Some((name, optional)) = exact_var(s) {
                if optional {
                    bail!("`{s}`: необязательная переменная допустима только как значение поля объекта");
                }
                return lookup(vars, name).cloned().ok_or_else(|| anyhow!("нет переменной `{name}`"));
            }
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find("{{") {
                out.push_str(&rest[..i]);
                let after = &rest[i + 2..];
                let j = after.find("}}").ok_or_else(|| anyhow!("нет закрывающей }}}} в `{s}`"))?;
                let name = &after[..j];
                let val = lookup(vars, name).ok_or_else(|| anyhow!("нет переменной `{name}`"))?;
                out.push_str(&scalar_text(val).ok_or_else(|| anyhow!("переменная `{name}` не скаляр, в текст её не вставить"))?);
                rest = &after[j + 2..];
            }
            out.push_str(rest);
            Ok(Value::String(out))
        }
        Value::Array(a) => Ok(Value::Array(a.iter().map(|x| render(x, vars)).collect::<Result<_>>()?)),
        Value::Object(m) if m.contains_key("$each") => {
            let keys: Vec<&str> = m.keys().map(String::as_str).collect();
            if keys.len() != 3 || !["$each", "as", "do"].iter().all(|k| keys.contains(k)) {
                bail!("`$each` требует ровно ключи $each, as, do");
            }
            let (Some(src), Some(alias)) = (m["$each"].as_str(), m["as"].as_str()) else { bail!("`$each` и `as` должны быть строками") };
            if !valid_var(alias) || alias.contains('.') {
                bail!("недопустимое имя `as`: `{alias}`");
            }
            let items = lookup(vars, src).and_then(Value::as_array).ok_or_else(|| anyhow!("`$each`: `{src}` не список"))?;
            let mut out = Vec::new();
            for it in items {
                let mut scope = vars.clone();
                scope.as_object_mut().ok_or_else(|| anyhow!("переменные должны быть объектом"))?.insert(alias.into(), it.clone());
                out.push(render(&m["do"], &scope)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                if let Some((name, true)) = v.as_str().and_then(exact_var) {
                    let val = lookup(vars, name);
                    if is_empty_value(val) {
                        continue;
                    }
                    out.insert(k.clone(), val.cloned().unwrap_or(Value::Null));
                } else {
                    out.insert(k.clone(), render(v, vars)?);
                }
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

// ---------- пароли ----------

/// Пароль протокола для пользователя: детерминированно выводится из секрета, у разных протоколов разный.
pub fn derive_password(secret: &str, profile_id: &str, fmt: PasswordFormat) -> String {
    let d = Sha256::digest(format!("eleutheria/v1/{profile_id}/{secret}"));
    match fmt {
        PasswordFormat::Hex32 => hex::encode(&d[..16]),
        PasswordFormat::Base64_16 => STANDARD.encode(&d[..16]),
        PasswordFormat::Base64_32 => STANDARD.encode(d),
    }
}

/// Пароль пользователя для протокола `p` (без ключа сервера).
pub fn user_password(p: &Proto, u: &crate::state::User) -> Result<String> {
    let prof = get(p)?;
    let secret = u.secret.as_deref().with_context(|| format!("у пользователя `{}` нет секрета для {}", u.name, prof.manifest.name))?;
    Ok(derive_password(secret, &prof.manifest.id, prof.manifest.password))
}

// ---------- встроенные профили ----------

macro_rules! builtin {
    ($id:literal) => {
        (
            $id,
            include_str!(concat!("../profiles/", $id, "/meta.yaml")),
            include_str!(concat!("../profiles/", $id, "/server.json.tpl")),
            include_str!(concat!("../profiles/", $id, "/client.json.tpl")),
        )
    };
}

const BUILTIN_SRC: [(&str, &str, &str, &str); 4] = [builtin!("hysteria2"), builtin!("tuic"), builtin!("ss2022"), builtin!("vless-ws")];

fn builtins() -> &'static [Profile] {
    static ALL: OnceLock<Vec<Profile>> = OnceLock::new();
    ALL.get_or_init(|| {
        BUILTIN_SRC
            .iter()
            .map(|(id, m, s, c)| Profile::parse(m, s, c).unwrap_or_else(|e| panic!("встроенный профиль {id}: {e:#}")))
            .collect()
    })
}

/// Встроенный профиль по идентификатору (None для сторонних).
pub fn builtin(p: &Proto) -> Option<&'static Profile> {
    builtins().iter().find(|x| x.manifest.id == p.id())
}

/// Профиль протокола: встроенный или установленный сторонний (проверяется заново при каждом чтении).
pub fn get(p: &Proto) -> Result<Cow<'static, Profile>> {
    get_in(p, &crate::userprofiles::root())
}

pub fn get_in(p: &Proto, user_root: &std::path::Path) -> Result<Cow<'static, Profile>> {
    if let Some(b) = builtin(p) {
        return Ok(Cow::Borrowed(b));
    }
    crate::userprofiles::load_installed_in(user_root, p.id())
        .map(|c| Cow::Owned(c.profile))
        .with_context(|| format!("профиль `{}` не встроен и не установлен на этом компьютере (`eleutheria profile list`)", p.id()))
}

/// `hysteria2,tuic`, `all` -> список протоколов без повторов. Профиль должен существовать: опечатка не должна
/// превращаться в «сторонний профиль» молча.
pub fn parse_protocols(names: &[String]) -> Result<Vec<Proto>> {
    let mut out: Vec<Proto> = Vec::new();
    for n in names.iter().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        let found: Vec<Proto> = if n.eq_ignore_ascii_case("all") {
            Proto::self_contained().to_vec()
        } else {
            let p = Proto::new(n).ok_or_else(|| anyhow!("недопустимое имя протокола `{n}` (a-z, 0-9, -)"))?;
            get(&p).map_err(|_| {
                anyhow!("неизвестный протокол `{n}`: встроенные hysteria2, tuic, ss2022, vless-ws (и `all` без vless-ws, ему нужен --cdn-host); сторонние ставятся командой `eleutheria profile install`")
            })?;
            vec![p]
        };
        for p in found {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    Ok(out)
}

// ---------- переменные для шаблонов ----------

/// Куда на сервере кладётся сертификат QUIC-протоколов.
pub const CERT_DIR: &str = "/etc/eleutheria";

/// Переменные серверного шаблона. Ошибка, если у пользователя нет секрета (его выдаёт provisioner).
pub fn server_vars(p: &Proto, st: &State, ps: &ProtoState, cert_dir: &str) -> Result<Value> {
    let prof = get(p)?;
    let mut users = Vec::new();
    for u in &st.users {
        users.push(json!({ "name": u.name, "uuid": u.uuid, "password": user_password(p, u)? }));
    }
    let sni = st.protocols.tls.as_ref().map(|t| t.sni.clone()).unwrap_or_default();
    if prof.manifest.needs_cert && sni.is_empty() {
        bail!("для {} нужен сертификат, а его в состоянии сервера нет", prof.manifest.name);
    }
    if prof.manifest.server_key.is_some() && ps.server_key.as_deref().unwrap_or("").is_empty() {
        bail!("для {} в состоянии сервера нет ключа сервера", prof.manifest.name);
    }
    let ws_path = ps.ws_path.clone().unwrap_or_default();
    if *p == Proto::VlessWs && !crate::client::profile::valid_ws_path(&ws_path) {
        bail!("для {} нет допустимого пути WebSocket в состоянии сервера", prof.manifest.name);
    }
    Ok(json!({
        "port": ps.port,
        "sni": sni,
        "ws_path": ws_path,
        "cert_path": format!("{cert_dir}/cert.pem"),
        "key_path": format!("{cert_dir}/key.pem"),
        "server_key": ps.server_key.clone().unwrap_or_default(),
        "users": users,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{TlsInfo, User};

    fn bi(p: Proto) -> &'static Profile {
        builtin(&p).unwrap()
    }

    fn state_with_all() -> State {
        let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[]}"#).unwrap();
        st.users = vec![
            User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("s1".into()) },
            User { name: "bob".into(), uuid: "b158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("s2".into()) },
        ];
        st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: "p=".into(), cert_sha256: "c".into() });
        st
    }

    #[test]
    fn builtins_parse_and_ids_match_proto() {
        for p in Proto::all_builtin() {
            let b = bi(p.clone());
            assert_eq!(b.manifest.id, p.id());
            assert_eq!(b.manifest.schema, SCHEMA);
        }
        assert_eq!(bi(Proto::Hysteria2).manifest.transport, Transport::Udp);
        assert_eq!(bi(Proto::Ss2022).manifest.transport, Transport::Both);
        assert!(!bi(Proto::Ss2022).manifest.needs_cert);
    }

    #[test]
    fn server_render_hysteria2_has_typed_port_and_one_entry_per_user() {
        let st = state_with_all();
        let ps = ProtoState::new(4443);
        let v = bi(Proto::Hysteria2).render_server(&server_vars(&Proto::Hysteria2, &st, &ps, "/c").unwrap()).unwrap();
        assert_eq!(v["listen_port"], json!(4443), "порт остаётся числом");
        let users = v["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[1]["name"], "bob");
        assert_eq!(users[0]["password"].as_str().unwrap().len(), 32);
        assert_ne!(users[0]["password"], users[1]["password"]);
        assert_eq!(v["tls"]["certificate_path"], "/c/cert.pem");
        assert_eq!(v["tls"]["server_name"], "www.bing.com");
    }

    #[test]
    fn passwords_differ_per_protocol_and_are_stable() {
        let a = derive_password("s", "hysteria2", PasswordFormat::Hex32);
        assert_eq!(a, derive_password("s", "hysteria2", PasswordFormat::Hex32));
        assert_ne!(a, derive_password("s", "tuic", PasswordFormat::Hex32));
        assert_eq!(STANDARD.decode(derive_password("s", "ss2022", PasswordFormat::Base64_16)).unwrap().len(), 16);
        assert_eq!(STANDARD.decode(derive_password("s", "ss2022", PasswordFormat::Base64_32)).unwrap().len(), 32);
    }

    #[test]
    fn ss2022_uses_method_param_and_needs_no_cert() {
        let mut st = state_with_all();
        st.protocols.tls = None;
        let ps = ProtoState { server_key: Some("SERVERKEY==".into()), ..ProtoState::new(8388) };
        let v = bi(Proto::Ss2022).render_server(&server_vars(&Proto::Ss2022, &st, &ps, "/c").unwrap()).unwrap();
        assert_eq!(v["method"], "2022-blake3-aes-128-gcm");
        assert_eq!(v["password"], "SERVERKEY==");
        assert!(bi(Proto::Hysteria2).render_server(&server_vars(&Proto::Hysteria2, &st, &ps, "/c").unwrap_or(json!({}))).is_err());
    }

    #[test]
    fn user_without_secret_is_an_error() {
        let mut st = state_with_all();
        st.users[1].secret = None;
        let ps = ProtoState::new(443);
        let e = server_vars(&Proto::Tuic, &st, &ps, "/c").unwrap_err().to_string();
        assert!(e.contains("bob"), "{e}");
    }

    #[test]
    fn value_substitution_cannot_change_structure() {
        // имя пользователя с кавычками и JSON не ломает конфиг: подстановка по значениям
        let tpl = json!({ "name": "x-{{n}}", "who": "{{n}}" });
        let evil = r#"a","admin":true,"z":""#;
        let out = render(&tpl, &json!({ "n": evil })).unwrap();
        assert_eq!(out.as_object().unwrap().len(), 2);
        assert_eq!(out["who"], evil);
    }

    #[test]
    fn optional_member_is_dropped_when_missing_null_or_empty() {
        let tpl = json!({ "a": 1, "pins": "{{?pin_list}}" });
        for vars in [json!({}), json!({ "pin_list": null }), json!({ "pin_list": [] })] {
            assert!(render(&tpl, &vars).unwrap().get("pins").is_none());
        }
        assert_eq!(render(&tpl, &json!({ "pin_list": ["x"] })).unwrap()["pins"], json!(["x"]));
    }

    #[test]
    fn missing_required_variable_and_non_scalar_interpolation_fail() {
        assert!(render(&json!({ "a": "{{nope}}" }), &json!({})).is_err());
        assert!(render(&json!({ "a": "x{{l}}" }), &json!({ "l": [1] })).is_err());
        assert!(render(&json!(["{{?a}}"]), &json!({ "a": 1 })).is_err());
        assert!(render(&json!({ "$each": "l", "as": "u", "do": 1, "extra": 2 }), &json!({ "l": [] })).is_err());
    }

    fn meta(extra: &str) -> String {
        format!("schema: 1\nid: demo\nname: Demo\ntransport: tcp\ndefault_port: 1000\npassword: hex32\n{extra}")
    }

    #[test]
    fn manifest_validation() {
        let ok = |m: &str, s: &str| Profile::parse(m, s, "{}");
        assert!(ok(&meta(""), "{}").is_ok());
        assert!(ok(&meta("unknown_field: 1\n"), "{}").is_err(), "лишние поля запрещены");
        assert!(ok(&meta("").replace("schema: 1", "schema: 2"), "{}").is_err());
        assert!(ok(&meta("").replace("id: demo", "id: ../demo"), "{}").is_err());
        assert!(ok(&meta("").replace("default_port: 1000", "default_port: 0"), "{}").is_err());
        assert!(ok(&meta(""), "{not json").is_err());
        assert!(ok(&meta(""), r#"{"a":"{{oops"}"#).is_err());
        assert!(ok(&meta(""), r#"{"a":"{{Bad Name}}"}"#).is_err());
    }

    #[test]
    fn vless_ws_server_config_has_secret_path_cert_and_users_by_uuid() {
        let st = state_with_all();
        let ps = ProtoState { cdn_host: Some("cdn.example.com".into()), ws_path: Some("/abc123".into()), ..ProtoState::new(8443) };
        let v = bi(Proto::VlessWs).render_server(&server_vars(&Proto::VlessWs, &st, &ps, "/c").unwrap()).unwrap();
        assert_eq!((v["type"].clone(), v["listen_port"].clone()), (json!("vless"), json!(8443)));
        assert_eq!(v["transport"], json!({ "type": "ws", "path": "/abc123" }));
        assert_eq!(v["tls"]["certificate_path"], "/c/cert.pem");
        let users = v["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[1], json!({ "name": "bob", "uuid": "b158cda3-0b3d-424b-a8f8-26a6462c8349" }));
        assert!(bi(Proto::VlessWs).manifest.needs_cert && Proto::VlessWs.needs_domain());
    }

    #[test]
    fn vless_ws_without_valid_path_is_refused() {
        let st = state_with_all();
        for path in [None, Some("".to_string()), Some("no-slash".to_string()), Some("/a\"b".to_string())] {
            let ps = ProtoState { cdn_host: Some("cdn.example.com".into()), ws_path: path, ..ProtoState::new(8443) };
            assert!(server_vars(&Proto::VlessWs, &st, &ps, "/c").is_err());
        }
    }

    #[test]
    fn vless_ws_client_sends_host_header_equal_to_sni() {
        let vars = json!({ "tag": "t", "host": "cdn.example.com", "port": 443, "uuid": "u", "sni": "cdn.example.com", "ws_path": "/p" });
        let v = bi(Proto::VlessWs).render_client(&vars).unwrap();
        assert_eq!(v["transport"], json!({ "type": "ws", "path": "/p", "headers": { "Host": "cdn.example.com" } }));
        assert_eq!(v["tls"]["server_name"], "cdn.example.com");
        assert!(v.get("flow").is_none() && v["tls"].get("reality").is_none());
    }
}
