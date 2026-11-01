//! Состояние сервера (/etc/eleutheria/state.json). v2: несколько пользователей, общий ключ Reality.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uuid: String,
    /// Корень паролей для протоколов с паролями (Hysteria2, TUIC, SS-2022): пароль каждого протокола
    /// выводится из него (`profiles::derive_password`). У пользователей, созданных до M3, поля нет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl User {
    pub fn new(name: impl Into<String>, uuid: impl Into<String>) -> User {
        User { name: name.into(), uuid: uuid.into(), secret: None }
    }
}

/// Идентификатор профиля протокола сервера (кроме VLESS+Reality, он есть всегда): встроенного (`hysteria2`, `tuic`,
/// `ss2022`, `vless-ws`) или стороннего (M6.2). В `state.json` это обычная строка, поэтому файлы, записанные
/// до M6.2, читаются без миграции. Допустим только вид `a-z0-9-` (до 32 символов): значение приходит с сервера.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proto(Cow<'static, str>);

/// Встроенные профили. Имена в стиле вариантов enum сохранены, чтобы не менять сотни мест использования.
#[allow(non_upper_case_globals)]
impl Proto {
    pub const Hysteria2: Proto = Proto(Cow::Borrowed("hysteria2"));
    pub const Tuic: Proto = Proto(Cow::Borrowed("tuic"));
    pub const Ss2022: Proto = Proto(Cow::Borrowed("ss2022"));
    /// VLESS + WebSocket + TLS за CDN (Cloudflare): входной IP сервера не виден клиенту и DPI
    pub const VlessWs: Proto = Proto(Cow::Borrowed("vless-ws"));
}

impl Proto {
    pub fn all_builtin() -> [Proto; 4] {
        [Proto::Hysteria2, Proto::Tuic, Proto::Ss2022, Proto::VlessWs]
    }

    /// Идентификатор профиля (имя папки с meta.yaml).
    pub fn id(&self) -> &str {
        &self.0
    }

    /// Протоколы, которые включаются без доп. данных (`all` означает именно их): у VLESS-WS нужен домен CDN.
    pub fn self_contained() -> [Proto; 3] {
        [Proto::Hysteria2, Proto::Tuic, Proto::Ss2022]
    }

    pub fn needs_domain(&self) -> bool {
        *self == Proto::VlessWs
    }

    pub fn is_builtin(&self) -> bool {
        Proto::all_builtin().contains(self)
    }

    /// Только встроенные профили (по имени без учёта регистра и пробелов по краям).
    pub fn from_id(s: &str) -> Option<Proto> {
        let s = s.trim().to_ascii_lowercase();
        Proto::all_builtin().into_iter().find(|p| p.id() == s)
    }

    /// Любой синтаксически допустимый идентификатор (встроенный или чужой). Существует ли такой профиль, решает
    /// `profiles::get`.
    pub fn new(s: &str) -> Option<Proto> {
        let s = s.trim().to_ascii_lowercase();
        if let Some(b) = Proto::from_id(&s) {
            return Some(b);
        }
        crate::profiles::valid_id(&s).then(|| Proto(Cow::Owned(s)))
    }
}

/// Порядок как у прежнего enum (hysteria2, tuic, ss2022, vless-ws), затем сторонние по имени: порядок inbound'ов
/// в серверном конфиге и записей в списке серверов не меняется от обновления.
impl Ord for Proto {
    fn cmp(&self, o: &Proto) -> std::cmp::Ordering {
        let rank = |p: &Proto| Proto::all_builtin().iter().position(|b| b == p).unwrap_or(usize::MAX);
        rank(self).cmp(&rank(o)).then_with(|| self.id().cmp(o.id()))
    }
}

impl PartialOrd for Proto {
    fn partial_cmp(&self, o: &Proto) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Serialize for Proto {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.id())
    }
}

impl<'de> Deserialize<'de> for Proto {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Proto, D::Error> {
        let s = String::deserialize(de)?;
        // без trim и приведения регистра: в state.json идентификатор записан ровно так, как его пишет Eleutheria
        if !crate::profiles::valid_id(&s) {
            return Err(serde::de::Error::custom(format!("недопустимый идентификатор протокола `{}`", s.chars().take(40).collect::<String>())));
        }
        Ok(Proto::from_id(&s).unwrap_or(Proto(Cow::Owned(s))))
    }
}

/// Сертификат для QUIC-протоколов: сам файл лежит на сервере, здесь только то, что нужно клиентам.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsInfo {
    pub sni: String,
    /// SHA-256 от SPKI, base64 (закрепление ключа в нашем клиенте)
    pub spki_sha256: String,
    /// SHA-256 от сертификата, hex (`pinSHA256` в ссылках hysteria2://)
    pub cert_sha256: String,
}

/// Включённый протокол: порт (Hysteria2 и TUIC слушают UDP, SS-2022 и TCP, и UDP).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtoState {
    pub port: u16,
    /// только SS-2022: ключ сервера (base64), к нему добавляется ключ пользователя
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_key: Option<String>,
    /// только VLESS-WS: домен, который смотрит на CDN (клиенты подключаются к нему)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdn_host: Option<String>,
    /// только VLESS-WS: секретный путь WebSocket (без него запрос к серверу отвергается)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    /// только сторонние профили: транспорт, под который открыты порты (у встроенных его знает сам профиль).
    /// Сохраняется при включении, чтобы статус и файрвол не зависели от того, стоит ли профиль на этом компьютере.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<crate::profiles::Transport>,
}

impl ProtoState {
    pub fn new(port: u16) -> ProtoState {
        ProtoState { port, server_key: None, cdn_host: None, ws_path: None, transport: None }
    }

    /// Транспорт протокола `p`: записанный при включении или у встроенного профиля; иначе TCP и UDP сразу
    /// (лучше открыть лишнее, чем потерять порт).
    pub fn transport_of(&self, p: &Proto) -> crate::profiles::Transport {
        use crate::profiles::Transport;
        self.transport.or_else(|| crate::profiles::builtin(p).map(|b| b.manifest.transport)).unwrap_or(Transport::Both)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Protocols {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub enabled: std::collections::BTreeMap<Proto, ProtoState>,
}

impl Protocols {
    pub fn is_empty(&self) -> bool {
        self.tls.is_none() && self.enabled.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub version: u32,
    pub singbox: String,
    pub profile: String,
    pub private_key: String,
    pub public_key: String,
    pub short_id: String,
    pub sni: String,
    pub port: u16,
    pub users: Vec<User>,
    /// Hysteria2 / TUIC / SS-2022 (M3). Пусто у серверов, поставленных раньше.
    #[serde(default, skip_serializing_if = "Protocols::is_empty")]
    pub protocols: Protocols,
}

pub fn valid_user_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl State {
    /// Разбор state.json, включая миграцию с v1 (один `uuid` без списка пользователей).
    pub fn parse(raw: &str) -> Option<State> {
        let v: Value = serde_json::from_str(raw).ok()?;
        if v.get("users").is_some() {
            return serde_json::from_value(v).ok();
        }
        let g = |k: &str| v.get(k)?.as_str().map(str::to_string);
        Some(State {
            version: 2,
            singbox: g("singbox").unwrap_or_default(),
            profile: "Eleutheria".into(),
            private_key: g("private_key")?,
            public_key: g("public_key")?,
            short_id: g("short_id")?,
            sni: g("sni")?,
            port: v.get("port")?.as_u64()? as u16,
            users: vec![User::new("default", g("uuid")?)],
            protocols: Protocols::default(),
        })
    }

    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_v1() {
        let raw = r#"{"version":1,"singbox":"1.14.3","uuid":"u-1","private_key":"p","public_key":"q","short_id":"s","sni":"x.com","port":443}"#;
        let s = State::parse(raw).unwrap();
        assert_eq!(s.users, vec![User::new("default", "u-1")]);
        assert_eq!(s.version, 2);
        assert_eq!(s.port, 443);
    }

    #[test]
    fn roundtrips_v2() {
        let s = State {
            version: 2, singbox: "1.14.3".into(), profile: "eleutheria".into(),
            private_key: "p".into(), public_key: "q".into(), short_id: "s".into(),
            sni: "x.com".into(), port: 4443,
            users: vec![User::new("a", "1"), User::new("b", "2")],
            protocols: Protocols::default(),
        };
        let raw = serde_json::to_string(&s).unwrap();
        assert_eq!(State::parse(&raw).unwrap(), s);
    }

    #[test]
    fn v2_file_without_protocols_serializes_without_new_fields() {
        let raw = r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[{"name":"a","uuid":"1"}]}"#;
        let s = State::parse(raw).unwrap();
        assert!(s.protocols.is_empty() && s.users[0].secret.is_none());
        let out = serde_json::to_string(&s).unwrap();
        assert!(!out.contains("protocols") && !out.contains("secret"), "{out}");
    }

    #[test]
    fn protocols_roundtrip() {
        let mut s = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[{"name":"a","uuid":"1","secret":"ff"}]}"#).unwrap();
        s.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: "pin=".into(), cert_sha256: "ab".into() });
        s.protocols.enabled.insert(Proto::Hysteria2, ProtoState::new(443));
        s.protocols.enabled.insert(Proto::Ss2022, ProtoState { server_key: Some("k=".into()), ..ProtoState::new(8388) });
        let back = State::parse(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        assert_eq!(Proto::from_id(" TUIC "), Some(Proto::Tuic));
        assert_eq!(Proto::from_id("vless"), None);
    }

    /// state.json, записанный до M6.2 (встроенные протоколы строками), читается и пишется байт в байт так же.
    #[test]
    fn pre_m6_2_state_with_builtin_protocols_reads_and_writes_unchanged() {
        let raw = r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[{"name":"a","uuid":"1","secret":"ff"}],"protocols":{"tls":{"sni":"www.bing.com","spki_sha256":"pin=","cert_sha256":"ab"},"enabled":{"hysteria2":{"port":443},"ss2022":{"port":8388,"server_key":"k="},"tuic":{"port":8443},"vless-ws":{"port":8444,"cdn_host":"cdn.example.com","ws_path":"/abc"}}}}"#;
        let s = State::parse(raw).expect("старый state.json должен читаться");
        assert_eq!(s.protocols.enabled.len(), 4);
        assert!(s.protocols.enabled.contains_key(&Proto::VlessWs) && s.protocols.enabled.contains_key(&Proto::Hysteria2));
        let back: serde_json::Value = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(raw).unwrap(), "новых полей у встроенных профилей не появляется");
    }

    #[test]
    fn custom_protocol_id_roundtrips_and_garbage_ids_are_refused() {
        let mk = |key: &str| format!(r#"{{"version":2,"singbox":"1","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[],"protocols":{{"enabled":{{"{key}":{{"port":9443}}}}}}}}"#);
        let s = State::parse(&mk("demo-trojan")).unwrap();
        let p = Proto::new("demo-trojan").unwrap();
        assert!(!p.is_builtin() && s.protocols.enabled.contains_key(&p));
        assert_eq!(State::parse(&serde_json::to_string(&s).unwrap()).unwrap(), s);
        // state.json приходит с сервера: чужой текст как идентификатор не принимается
        for bad in ["", "../etc", "Upper", "a b", "x\"y", "ключ", &"x".repeat(33)] {
            assert!(State::parse(&mk(bad.replace('"', "\\\"").as_str())).is_none(), "`{bad}` должен отвергаться");
        }
        let mut order = vec![Proto::new("zzz").unwrap(), Proto::VlessWs, Proto::new("aaa").unwrap(), Proto::Ss2022, Proto::Tuic, Proto::Hysteria2];
        order.sort();
        assert_eq!(order.iter().map(Proto::id).collect::<Vec<_>>(), ["hysteria2", "tuic", "ss2022", "vless-ws", "aaa", "zzz"]);
        assert_eq!(Proto::new(" TUIC "), Some(Proto::Tuic));
        assert_eq!(Proto::new("Demo-X").map(|p| p.id().to_string()), Some("demo-x".into()));
        assert!(Proto::new("a/b").is_none() && Proto::from_id("demo-trojan").is_none());
    }

    #[test]
    fn transport_is_stored_only_for_custom_and_defaults_to_both() {
        use crate::profiles::Transport;
        assert_eq!(ProtoState::new(1).transport_of(&Proto::Hysteria2), Transport::Udp);
        assert_eq!(ProtoState::new(1).transport_of(&Proto::new("unknown-x").unwrap()), Transport::Both);
        let ps = ProtoState { transport: Some(Transport::Tcp), ..ProtoState::new(1) };
        assert_eq!(ps.transport_of(&Proto::new("unknown-x").unwrap()), Transport::Tcp);
        assert!(!serde_json::to_string(&ProtoState::new(1)).unwrap().contains("transport"));
    }

    #[test]
    fn user_name_validation() {
        assert!(valid_user_name("alice_1"));
        assert!(!valid_user_name(""));
        assert!(!valid_user_name("a b"));
        assert!(!valid_user_name("имя"));
        assert!(!valid_user_name(&"x".repeat(33)));
    }
}
