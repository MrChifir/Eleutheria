//! Генерация серверного конфига sing-box и клиентских ссылок.

use serde_json::{json, Value};

use anyhow::{bail, Context, Result};

use crate::profiles;
use crate::state::{Proto, State, User};

/// Серверный конфиг: VLESS+Reality всегда, остальное по включённым протоколам.
pub fn server_config(s: &State) -> Result<Value> {
    server_config_in(s, profiles::CERT_DIR)
}

/// То же с другим каталогом сертификата (нужно проверкам на локальной машине).
pub fn server_config_in(s: &State, cert_dir: &str) -> Result<Value> {
    let mut cfg = reality_config(s);
    for (p, ps) in &s.protocols.enabled {
        let inbound = profiles::get(p)?
            .render_server(&profiles::server_vars(p, s, ps, cert_dir)?)
            .with_context(|| format!("не удалось собрать inbound {}", p.id()))?;
        cfg["inbounds"].as_array_mut().expect("inbounds").push(inbound);
    }
    Ok(cfg)
}

fn reality_config(s: &State) -> Value {
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

fn bracket(host: &str) -> String {
    if host.contains(':') { format!("[{host}]") } else { host.to_string() }
}

fn label_of(s: &State, u: &User) -> String {
    if u.name == "default" { s.profile.clone() } else { format!("{}-{}", s.profile, u.name) }
}

/// Ссылка vless:// для пользователя (v2rayN, Hiddify, Happ, Streisand, v2rayTun и др.).
pub fn vless_link(host: &str, s: &State, u: &User) -> String {
    let host = bracket(host);
    let label = label_of(s, u);
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

/// Пароль, который клиент отправляет серверу. Если профиль задаёт ключ сервера (SS-2022), это
/// `ключ_сервера:ключ_пользователя`.
pub fn client_password(p: &Proto, s: &State, u: &User) -> Result<String> {
    if *p == Proto::VlessWs {
        bail!("у VLESS-WS нет пароля: пользователь входит по uuid");
    }
    let pw = profiles::user_password(p, u)?;
    Ok(if profiles::get(p)?.manifest.server_key.is_some() {
        let key = s.protocols.enabled.get(p).and_then(|x| x.server_key.clone()).with_context(|| format!("нет ключа сервера для {}", p.id()))?;
        format!("{key}:{pw}")
    } else {
        pw
    })
}

/// Ссылка протокола `p`. Для Hysteria2 и TUIC в ссылку входит `pinSPKI`: наш клиент по нему закрепляет ключ
/// сервера; сторонние клиенты берут `pinSHA256` (отпечаток сертификата) и `insecure=1`. Сторонние профили
/// ссылок не имеют: у них нет общепринятой схемы URI, они работают только в этом клиенте.
pub fn proto_link(p: &Proto, host: &str, s: &State, u: &User) -> Result<String> {
    let ps = s.protocols.enabled.get(p).with_context(|| format!("{} на сервере не включён", p.id()))?;
    if !p.is_builtin() {
        bail!("у стороннего профиля `{}` нет ссылки: он работает только в клиенте Eleutheria", p.id());
    }
    let (h, label) = (bracket(host), urlencoding::encode(&format!("{} {}", label_of(s, u), p.id())).into_owned());
    let pw = if *p == Proto::VlessWs { String::new() } else { urlencoding::encode(&client_password(p, s, u)?).into_owned() };
    let tls = || s.protocols.tls.as_ref().context("нет сертификата в состоянии сервера");
    Ok(if *p == Proto::Hysteria2 {
        let t = tls()?;
        format!(
            "hysteria2://{pw}@{h}:{port}/?sni={sni}&insecure=1&pinSHA256={cert}&pinSPKI={spki}#{label}",
            port = ps.port, sni = urlencoding::encode(&t.sni), cert = t.cert_sha256, spki = urlencoding::encode(&t.spki_sha256),
        )
    } else if *p == Proto::Tuic {
        let t = tls()?;
        format!(
            "tuic://{uuid}:{pw}@{h}:{port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={sni}&allow_insecure=1&pinSPKI={spki}#{label}",
            uuid = u.uuid, port = ps.port, sni = urlencoding::encode(&t.sni), spki = urlencoding::encode(&t.spki_sha256),
        )
    } else if *p == Proto::VlessWs {
        let cdn = ps.cdn_host.as_deref().context("для VLESS-WS в состоянии сервера нет домена CDN")?;
        let path = ps.ws_path.as_deref().context("для VLESS-WS в состоянии сервера нет пути")?;
        format!(
            "vless://{uuid}@{cdn}:{port}?encryption=none&security=tls&sni={cdn}&fp=chrome&type=ws&host={cdn}&path={path}#{label}",
            uuid = u.uuid, port = crate::client::profile::CDN_EDGE_PORT, path = urlencoding::encode(path),
        )
    } else {
        let method = profiles::get(p)?.manifest.params.get("method").cloned().context("в профиле ss2022 нет param.method")?;
        format!("ss://{}:{pw}@{h}:{port}#{label}", urlencoding::encode(&method), port = ps.port)
    })
}

pub struct UserLink {
    /// "vless", "hysteria2", "tuic", "ss2022"
    pub proto: String,
    pub url: String,
}

/// Все ссылки пользователя: Reality первой, затем включённые встроенные протоколы (у сторонних ссылок нет).
pub fn all_links(host: &str, s: &State, u: &User) -> Result<Vec<UserLink>> {
    let mut out = vec![UserLink { proto: "vless".into(), url: vless_link(host, s, u) }];
    for p in s.protocols.enabled.keys().filter(|p| p.is_builtin()) {
        out.push(UserLink { proto: p.id().to_string(), url: proto_link(p, host, s, u)? });
    }
    Ok(out)
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
                User::new("default", "a158cda3-0b3d-424b-a8f8-26a6462c8349"),
                User::new("alice", "b2"),
            ],
            protocols: Default::default(),
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
        let c = server_config(&sample()).unwrap();
        let users = c["inbounds"][0]["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[1]["name"], "alice");
    }
}
