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
        let rendered = profiles::get(p)?
            .render_server(&profiles::server_vars(p, s, ps, cert_dir)?)
            .with_context(|| crate::tr!(format!("не удалось собрать inbound {}", p.id()), format!("failed to build inbound {}", p.id())))?;
        // у ShadowTLS два inbound (сам ShadowTLS и внутренний Shadowsocks), у остальных один
        cfg["inbounds"].as_array_mut().expect("inbounds").extend(profiles::into_list(rendered));
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
        bail!("{}", crate::tr!("у VLESS-WS нет пароля: пользователь входит по uuid", "VLESS-WS has no password: the user signs in by uuid"));
    }
    let pw = profiles::user_password(p, u)?;
    Ok(if profiles::get(p)?.manifest.server_key.is_some() {
        let key = s.protocols.enabled.get(p).and_then(|x| x.server_key.clone()).with_context(|| crate::tr!(format!("нет ключа сервера для {}", p.id()), format!("no server key for {}", p.id())))?;
        format!("{key}:{pw}")
    } else {
        pw
    })
}

/// Ссылка протокола `p`. Для Hysteria2 и TUIC в ссылку входит `pinSPKI`: наш клиент по нему закрепляет ключ
/// сервера; сторонние клиенты берут `pinSHA256` (отпечаток сертификата) и `insecure=1`. Сторонние профили
/// ссылок не имеют: у них нет общепринятой схемы URI, они работают только в этом клиенте.
pub fn proto_link(p: &Proto, host: &str, s: &State, u: &User) -> Result<String> {
    let ps = s.protocols.enabled.get(p).with_context(|| crate::tr!(format!("{} на сервере не включён", p.id()), format!("{} is not enabled on the server", p.id())))?;
    if !p.is_builtin() {
        bail!("{}", crate::tr!(format!("у стороннего профиля `{}` нет ссылки: он работает только в клиенте Eleutheria", p.id()), format!("third-party profile `{}` has no link: it only works in the Eleutheria client", p.id())));
    }
    if !p.has_link() {
        bail!("{}", crate::tr!(format!("у {} нет общепринятой ссылки: он работает только в клиенте Eleutheria", p.id()), format!("{} has no standard link: it only works in the Eleutheria client", p.id())));
    }
    let (h, label) = (bracket(host), urlencoding::encode(&format!("{} {}", label_of(s, u), p.id())).into_owned());
    let pw = if *p == Proto::VlessWs { String::new() } else { urlencoding::encode(&client_password(p, s, u)?).into_owned() };
    let tls = || s.protocols.tls.as_ref().context(crate::tr!("нет сертификата в состоянии сервера", "no certificate in the server state"));
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
    } else if *p == Proto::Trojan {
        let t = tls()?;
        format!(
            "trojan://{pw}@{h}:{port}?security=tls&type=tcp&sni={sni}&allowInsecure=1&pinSPKI={spki}#{label}",
            port = ps.port, sni = urlencoding::encode(&t.sni), spki = urlencoding::encode(&t.spki_sha256),
        )
    } else if *p == Proto::AnyTls {
        let t = tls()?;
        format!(
            "anytls://{pw}@{h}:{port}?sni={sni}&insecure=1&pinSPKI={spki}#{label}",
            port = ps.port, sni = urlencoding::encode(&t.sni), spki = urlencoding::encode(&t.spki_sha256),
        )
    } else if *p == Proto::VlessWs {
        let cdn = ps.cdn_host.as_deref().context(crate::tr!("для VLESS-WS в состоянии сервера нет домена CDN", "no CDN domain for VLESS-WS in the server state"))?;
        let path = ps.ws_path.as_deref().context(crate::tr!("для VLESS-WS в состоянии сервера нет пути", "no path for VLESS-WS in the server state"))?;
        format!(
            "vless://{uuid}@{cdn}:{port}?encryption=none&security=tls&sni={cdn}&fp=chrome&type=ws&host={cdn}&path={path}#{label}",
            uuid = u.uuid, port = crate::client::profile::CDN_EDGE_PORT, path = urlencoding::encode(path),
        )
    } else {
        let method = profiles::get(p)?.manifest.params.get("method").cloned().context(crate::tr!("в профиле ss2022 нет param.method", "the ss2022 profile has no param.method"))?;
        format!("ss://{}:{pw}@{h}:{port}#{label}", urlencoding::encode(&method), port = ps.port)
    })
}

pub struct UserLink {
    /// "vless", "hysteria2", "tuic", "ss2022", "vless-ws", "trojan", "anytls"
    pub proto: String,
    pub url: String,
}

/// Все ссылки пользователя: Reality первой, затем включённые встроенные протоколы со ссылкой (у сторонних и у
/// ShadowTLS ссылок нет: они работают только в клиенте Eleutheria).
pub fn all_links(host: &str, s: &State, u: &User) -> Result<Vec<UserLink>> {
    let mut out = vec![UserLink { proto: "vless".into(), url: vless_link(host, s, u) }];
    for p in s.protocols.enabled.keys().filter(|p| p.has_link()) {
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

    fn state_with_new_protocols() -> State {
        use crate::state::{ProtoState, TlsInfo};
        let mut s = sample();
        for u in &mut s.users {
            u.secret = Some(format!("secret-{}", u.name));
        }
        s.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: "AbC+/=PIN".into(), cert_sha256: "ab".into() });
        s.protocols.enabled.insert(Proto::Trojan, ProtoState::new(2083));
        s.protocols.enabled.insert(Proto::AnyTls, ProtoState::new(4443));
        s.protocols.enabled.insert(Proto::ShadowTls, ProtoState { server_key: Some("BBBBBBBBBBBBBBBBBBBBBA==".into()), ..ProtoState::new(9443) });
        s
    }

    #[test]
    fn server_config_adds_one_inbound_per_new_protocol_and_two_for_shadowtls() {
        let s = state_with_new_protocols();
        let c = server_config(&s).unwrap();
        let ins = c["inbounds"].as_array().unwrap();
        let tags: Vec<&str> = ins.iter().map(|i| i["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["vless-reality", "trojan", "anytls", "shadowtls", "shadowtls-ss"]);
        let tls = &ins[3];
        assert_eq!(tls["handshake"]["server"], "www.microsoft.com");
        assert_eq!(tls["detour"], ins[4]["tag"]);
        assert_eq!(ins[4]["users"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn trojan_and_anytls_links_carry_password_sni_and_pin_but_shadowtls_has_none() {
        let s = state_with_new_protocols();
        let u = &s.users[0];
        let t = proto_link(&Proto::Trojan, "203.0.113.5", &s, u).unwrap();
        assert!(t.starts_with("trojan://") && t.contains("@203.0.113.5:2083?") && t.contains("sni=www.bing.com") && t.contains("pinSPKI=AbC%2B%2F%3DPIN"), "{t}");
        let a = proto_link(&Proto::AnyTls, "203.0.113.5", &s, u).unwrap();
        assert!(a.starts_with("anytls://") && a.contains("@203.0.113.5:4443?") && a.contains("insecure=1"), "{a}");
        assert!(proto_link(&Proto::ShadowTls, "203.0.113.5", &s, u).is_err());
        let all = all_links("203.0.113.5", &s, u).unwrap();
        assert_eq!(all.iter().map(|l| l.proto.as_str()).collect::<Vec<_>>(), ["vless", "trojan", "anytls"], "у ShadowTLS ссылки нет");
    }

    /// Настоящая проверка ядром: SING_BOX=/путь/к/sing-box cargo test singbox_accepts_new
    #[test]
    fn singbox_accepts_new_protocol_server_config() {
        let Ok(bin) = std::env::var("SING_BOX") else { return };
        let dir = std::env::temp_dir().join(format!("el-new-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = crate::tlscert::generate("www.bing.com").unwrap();
        std::fs::write(dir.join("cert.pem"), cert.cert_pem).unwrap();
        std::fs::write(dir.join("key.pem"), cert.key_pem).unwrap();
        let mut s = state_with_new_protocols();
        s.private_key = "-F27ryXWXtDI0Jn1xNAL2u2TgoUr9fXvOycRwe6LxlU".into();
        s.short_id = "abcd1234".into();
        let c = server_config_in(&s, dir.to_str().unwrap()).unwrap();
        let path = dir.join("server.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
        let out = std::process::Command::new(&bin).args(["check", "-c"]).arg(&path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn server_config_lists_all_users() {
        let c = server_config(&sample()).unwrap();
        let users = c["inbounds"][0]["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[1]["name"], "alice");
    }
}
