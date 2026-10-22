//! Состояние сервера (/etc/eleutheria/state.json). v2: несколько пользователей, общий ключ Reality.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uuid: String,
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
            users: vec![User { name: "default".into(), uuid: g("uuid")? }],
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
        assert_eq!(s.users, vec![User { name: "default".into(), uuid: "u-1".into() }]);
        assert_eq!(s.version, 2);
        assert_eq!(s.port, 443);
    }

    #[test]
    fn roundtrips_v2() {
        let s = State {
            version: 2, singbox: "1.14.3".into(), profile: "eleutheria".into(),
            private_key: "p".into(), public_key: "q".into(), short_id: "s".into(),
            sni: "x.com".into(), port: 4443,
            users: vec![User { name: "a".into(), uuid: "1".into() }, User { name: "b".into(), uuid: "2".into() }],
        };
        let raw = serde_json::to_string(&s).unwrap();
        assert_eq!(State::parse(&raw).unwrap(), s);
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
