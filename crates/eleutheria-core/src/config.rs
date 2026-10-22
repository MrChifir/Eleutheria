//! Генерация серверного конфига sing-box и клиентских ссылок.

use serde_json::{json, Value};

use crate::state::{State, User};

pub fn server_config(s: &State) -> Value {
    let users: Vec<Value> = s
        .users
        .iter()
        .map(|u| json!({ "name": u.name, "uuid": u.uuid, "flow": "xtls-rprx-vision" }))
        .collect();
    json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "vless",
            "tag": "vless-reality",
            "listen": "::",
            "listen_port": s.port,
            "users": users,
            "tls": {
                "enabled": true,
                "server_name": s.sni,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": s.sni, "server_port": 443 },
                    "private_key": s.private_key,
                    "short_id": [s.short_id]
                }
            }
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
}

/// Ссылка vless:// для пользователя (v2rayN, Hiddify, Happ, Streisand, v2rayTun и др.).
pub fn vless_link(host: &str, s: &State, u: &User) -> String {
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let label = if u.name == "default" { s.profile.clone() } else { format!("{}-{}", s.profile, u.name) };
    format!(
        "vless://{uuid}@{host}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp#{label}",
        uuid = u.uuid,
        port = s.port,
        sni = urlencoding::encode(&s.sni),
        pbk = s.public_key,
        sid = s.short_id,
        label = urlencoding::encode(&label),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        State {
            version: 2, singbox: "1.14.3".into(), profile: "eleutheria server".into(),
            private_key: "priv".into(), public_key: "pub".into(), short_id: "5bb5899f0cb12edf".into(),
            sni: "www.microsoft.com".into(), port: 443,
            users: vec![
                User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into() },
                User { name: "alice".into(), uuid: "b2".into() },
            ],
        }
    }

    #[test]
    fn link_has_required_params() {
        let s = sample();
        let l = vless_link("203.0.113.5", &s, &s.users[0]);
        assert!(l.starts_with("vless://a158cda3-0b3d-424b-a8f8-26a6462c8349@203.0.113.5:443?"));
        assert!(l.contains("security=reality") && l.contains("pbk=pub") && l.contains("sid=5bb5899f0cb12edf"));
        assert!(l.ends_with("#eleutheria%20server"));
    }

    #[test]
    fn named_user_gets_suffix_in_label() {
        let s = sample();
        assert!(vless_link("1.2.3.4", &s, &s.users[1]).ends_with("#eleutheria%20server-alice"));
    }

    #[test]
    fn ipv6_host_is_bracketed() {
        let s = sample();
        assert!(vless_link("2001:db8::1", &s, &s.users[0]).contains("@[2001:db8::1]:443?"));
    }

    #[test]
    fn server_config_lists_all_users() {
        let c = server_config(&sample());
        let users = c["inbounds"][0]["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[1]["name"], "alice");
    }
}
