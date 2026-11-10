//! Серверы клиента: разбор vless://, подписки и локальное хранилище профилей.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::client_password;
use crate::profiles;
use crate::secrets::{default_store, SecretStore};
use crate::state::{Proto, State, User};
use crate::store::config_dir;
use crate::tr;

/// Протокол сервера. У записей, сохранённых до M3, поля нет: они все VLESS.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Vless,
    Hysteria2,
    Tuic,
    Ss2022,
    /// Внешний exit: SOCKS5-прокси, к которому трафик идёт цепочкой через один из своих серверов (`via`)
    #[serde(rename = "socks5")]
    Socks5,
    /// VLESS + WebSocket + TLS через CDN
    #[serde(rename = "vless-ws")]
    VlessWs,
    /// Trojan поверх TLS
    Trojan,
    /// AnyTLS
    #[serde(rename = "anytls")]
    AnyTls,
    /// ShadowTLS v3 с Shadowsocks 2022 внутри (в конфиге это два outbound, см. `client::config`)
    #[serde(rename = "shadowtls")]
    ShadowTls,
    /// Сторонний профиль (M6.2): идентификатор в `Server::profile`, outbound собирается по шаблону профиля
    #[serde(rename = "custom")]
    Custom,
}

impl Kind {
    pub fn proto(self) -> Option<Proto> {
        match self {
            Kind::Vless => None,
            Kind::Hysteria2 => Some(Proto::Hysteria2),
            Kind::Tuic => Some(Proto::Tuic),
            Kind::Ss2022 => Some(Proto::Ss2022),
            Kind::VlessWs => Some(Proto::VlessWs),
            Kind::Trojan => Some(Proto::Trojan),
            Kind::AnyTls => Some(Proto::AnyTls),
            Kind::ShadowTls => Some(Proto::ShadowTls),
            Kind::Socks5 | Kind::Custom => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Vless => "vless",
            Kind::Hysteria2 => "hysteria2",
            Kind::Tuic => "tuic",
            Kind::Ss2022 => "ss2022",
            Kind::VlessWs => "vless-ws",
            Kind::Trojan => "trojan",
            Kind::AnyTls => "anytls",
            Kind::ShadowTls => "shadowtls",
            Kind::Socks5 => "socks5",
            Kind::Custom => "custom",
        }
    }
}

/// Порт, на котором клиент приходит к CDN (Cloudflare принимает HTTPS на 443; на сервере слушает другой порт).
pub const CDN_EDGE_PORT: u16 = 443;

pub const SS_METHODS: [&str; 3] = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// VLESS и TUIC; у остальных пусто (у стороннего профиля это uuid пользователя)
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub kind: Kind,
    /// Hysteria2, TUIC, Trojan, AnyTLS: пароль; SS-2022 и ShadowTLS: `ключ_сервера:ключ_пользователя`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// SS-2022 и ShadowTLS (внутренний Shadowsocks): шифр
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Hysteria2, TUIC, Trojan, AnyTLS: SHA-256 от SPKI сервера (base64). Нет: сертификат проверяется обычным способом
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    pub flow: Option<String>,
    /// "reality" или "tls"
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    /// VLESS-WS: путь WebSocket
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    /// Откуда трафик выходит в интернет, если это не `host`: у пути через CDN это адрес сервера-источника.
    /// Пробер по нему отличает «другой выходной IP» от «тот же сервер другим путём».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Внешний exit: имя своего сервера, через который идёт цепочка «клиент → via → этот прокси»
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Внешний exit: имя пользователя SOCKS5 (пароль в `password`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Сторонний профиль: его идентификатор (только при `kind = custom`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl Server {
    /// Профиль протокола: у встроенных видов по `kind`, у сторонних по `profile`.
    pub fn proto(&self) -> Option<Proto> {
        match self.kind {
            Kind::Custom => self.profile.as_deref().and_then(Proto::new),
            k => k.proto(),
        }
    }

    /// Подпись вида для интерфейса: у стороннего профиля это его идентификатор.
    pub fn kind_label(&self) -> String {
        match (self.kind, &self.profile) {
            (Kind::Custom, Some(p)) => p.clone(),
            (k, _) => k.label().to_string(),
        }
    }

    /// Внешний exit (цепочка через свой сервер)? Такие пути никогда не берут весь трафик сами: только точечно для категорий.
    pub fn is_external_exit(&self) -> bool {
        self.kind == Kind::Socks5
    }

    pub fn from_state(host: &str, s: &State, u: &User) -> Server {
        Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name: host.to_string(),
            host: host.to_string(),
            port: s.port,
            uuid: u.uuid.clone(),
            kind: Kind::Vless,
            password: None,
            method: None,
            pin: None,
            flow: Some("xtls-rprx-vision".into()),
            security: "reality".into(),
            sni: s.sni.clone(),
            fingerprint: "chrome".into(),
            public_key: Some(s.public_key.clone()),
            short_id: Some(s.short_id.clone()),
        }
    }

    /// Запись для дополнительного протокола сервера.
    pub fn for_proto(p: &Proto, host: &str, st: &State, u: &User) -> Result<Server> {
        let ps = st.protocols.enabled.get(p).with_context(|| tr!(format!("{} на сервере не включён", p.id()), format!("{} is not enabled on the server", p.id())))?;
        let prof = profiles::get(p)?;
        let name = format!("{host} {}", p.id());
        let base = Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name,
            host: host.to_string(),
            port: ps.port,
            uuid: String::new(),
            kind: Kind::Vless,
            password: if *p == Proto::VlessWs { None } else { Some(client_password(p, st, u)?) },
            method: None,
            pin: None,
            flow: None,
            security: "tls".into(),
            sni: host.to_string(),
            fingerprint: "chrome".into(),
            public_key: None,
            short_id: None,
        };
        let tls = || st.protocols.tls.as_ref().context(tr!("нет сертификата в состоянии сервера", "no certificate in the server state"));
        Ok(if *p == Proto::Hysteria2 {
            Server { kind: Kind::Hysteria2, sni: tls()?.sni.clone(), pin: Some(tls()?.spki_sha256.clone()), ..base }
        } else if *p == Proto::Tuic {
            Server { kind: Kind::Tuic, uuid: u.uuid.clone(), sni: tls()?.sni.clone(), pin: Some(tls()?.spki_sha256.clone()), ..base }
        } else if *p == Proto::VlessWs {
            let cdn = ps.cdn_host.clone().context(tr!("для VLESS-WS в состоянии сервера нет домена CDN", "no CDN domain for VLESS-WS in the server state"))?;
            Server {
                name: format!("{cdn} vless-ws"),
                host: cdn.clone(),
                port: CDN_EDGE_PORT,
                kind: Kind::VlessWs,
                uuid: u.uuid.clone(),
                sni: cdn,
                ws_path: Some(ps.ws_path.clone().context(tr!("для VLESS-WS в состоянии сервера нет пути", "no path for VLESS-WS in the server state"))?),
                origin: Some(host.to_string()),
                ..base
            }
        } else if *p == Proto::Trojan {
            Server { kind: Kind::Trojan, sni: tls()?.sni.clone(), pin: Some(tls()?.spki_sha256.clone()), ..base }
        } else if *p == Proto::AnyTls {
            Server { kind: Kind::AnyTls, sni: tls()?.sni.clone(), pin: Some(tls()?.spki_sha256.clone()), ..base }
        } else if *p == Proto::ShadowTls {
            // sni здесь имя сайта для рукопожатия (тот же, что маскирует Reality), а не имя в сертификате: сертификата нет
            Server { kind: Kind::ShadowTls, sni: st.sni.clone(), method: prof.manifest.params.get("method").cloned(), ..base }
        } else if *p == Proto::Ss2022 {
            Server { kind: Kind::Ss2022, security: "none".into(), method: prof.manifest.params.get("method").cloned(), ..base }
        } else {
            // сторонний профиль: все данные берутся из состояния сервера и манифеста, шаблон решает, что из них нужно
            let (sni, pin, security) = if prof.manifest.needs_cert {
                (tls()?.sni.clone(), Some(tls()?.spki_sha256.clone()), "tls")
            } else {
                (host.to_string(), None, "none")
            };
            Server {
                kind: Kind::Custom,
                profile: Some(p.id().to_string()),
                uuid: u.uuid.clone(),
                sni,
                pin,
                security: security.into(),
                method: prof.manifest.params.get("method").cloned(),
                ..base
            }
        })
    }

    /// Проверка данных сервера. Обязательна для привилегированного helper'а: эти поля попадают в конфиг,
    /// который исполняется от root, поэтому допускаем только узкий набор символов.
    pub fn validate(&self) -> Result<()> {
        let charset = |s: &str, extra: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c));
        if self.name.is_empty() || self.name.chars().count() > 64 || self.name.chars().any(|c| c.is_control()) {
            bail!(tr!("недопустимое имя сервера", "invalid server name"));
        }
        if self.host.is_empty() || self.host.len() > 253 || !charset(&self.host, ".:-") {
            bail!("{}", tr!(format!("недопустимый хост `{}`", self.host), format!("invalid host `{}`", self.host)));
        }
        if self.port == 0 {
            bail!(tr!("порт 0", "port 0"));
        }
        let sni_ok = |s: &str| !s.is_empty() && s.len() <= 253 && charset(s, ".-");
        let uuid_ok = |u: &str| u.len() == 36 && charset(u, "-");
        let password_ok = |p: &Option<String>| matches!(p, Some(p) if !p.is_empty() && p.len() <= 256 && p.bytes().all(|b| b.is_ascii_graphic()));
        let pin_ok = |p: &Option<String>| match p {
            None => true,
            Some(p) => p.len() == 44 && charset(p, "+/="),
        };
        match self.kind {
            Kind::Vless => {
                if !uuid_ok(&self.uuid) {
                    bail!(tr!("недопустимый uuid", "invalid uuid"));
                }
                if !sni_ok(&self.sni) {
                    bail!(tr!("недопустимый sni", "invalid sni"));
                }
                if !matches!(self.fingerprint.as_str(), "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized") {
                    bail!("{}", tr!(format!("недопустимый fingerprint `{}`", self.fingerprint), format!("invalid fingerprint `{}`", self.fingerprint)));
                }
                if let Some(f) = &self.flow {
                    if f != "xtls-rprx-vision" {
                        bail!(tr!("недопустимый flow", "invalid flow"));
                    }
                }
                match self.security.as_str() {
                    "reality" => {
                        let pbk = self.public_key.as_deref().unwrap_or("");
                        let sid = self.short_id.as_deref().unwrap_or("");
                        if pbk.is_empty() || pbk.len() > 64 || !charset(pbk, "-_") {
                            bail!(tr!("недопустимый public_key", "invalid public_key"));
                        }
                        if sid.len() > 16 || sid.len() % 2 != 0 || !sid.chars().all(|c| c.is_ascii_hexdigit()) {
                            bail!(tr!("недопустимый short_id", "invalid short_id"));
                        }
                    }
                    "tls" => {}
                    other => bail!("{}", tr!(format!("недопустимый security `{other}`"), format!("invalid security `{other}`"))),
                }
            }
            Kind::Hysteria2 | Kind::Tuic | Kind::Trojan | Kind::AnyTls => {
                if self.kind == Kind::Tuic && !uuid_ok(&self.uuid) {
                    bail!(tr!("недопустимый uuid", "invalid uuid"));
                }
                if !password_ok(&self.password) {
                    bail!(tr!("недопустимый пароль", "invalid password"));
                }
                if !sni_ok(&self.sni) {
                    bail!(tr!("недопустимый sni", "invalid sni"));
                }
                if !pin_ok(&self.pin) {
                    bail!(tr!("недопустимый pin сертификата", "invalid certificate pin"));
                }
            }
            Kind::VlessWs => {
                if !uuid_ok(&self.uuid) {
                    bail!(tr!("недопустимый uuid", "invalid uuid"));
                }
                if !sni_ok(&self.sni) {
                    bail!(tr!("недопустимый sni", "invalid sni"));
                }
                match &self.ws_path {
                    Some(p) if valid_ws_path(p) => {}
                    _ => bail!(tr!("недопустимый путь WebSocket", "invalid WebSocket path")),
                }
                if let Some(o) = &self.origin {
                    if o.is_empty() || o.len() > 253 || !charset(o, ".:-") {
                        bail!(tr!("недопустимый адрес сервера-источника", "invalid origin server address"));
                    }
                }
            }
            Kind::Socks5 => {
                // только IP-адрес: имя пришлось бы разрешать на клиенте (утечка DNS мимо цепочки)
                if self.host.parse::<std::net::IpAddr>().is_err() {
                    bail!(tr!("адрес внешнего exit должен быть IP-адресом, не именем", "external exit address must be an IP address, not a name"));
                }
                if !matches!(&self.via, Some(v) if !v.is_empty()) {
                    bail!(tr!("внешний exit должен идти через свой сервер (via): напрямую с клиента его IP-адрес был бы виден прокси", "external exit must go through your own server (via): connecting directly from the client would expose its IP address to the proxy"));
                }
                let cred_ok = |c: &str| !c.is_empty() && c.len() <= 255 && c.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
                match (&self.username, &self.password) {
                    (None, None) => {}
                    (Some(u), Some(p)) if cred_ok(u) && cred_ok(p) => {}
                    _ => bail!(tr!("логин и пароль внешнего exit задаются вместе (печатные ASCII-символы, до 255 байт)", "external exit username and password must be set together (printable ASCII, up to 255 bytes)")),
                }
            }
            Kind::Custom => {
                if !matches!(&self.profile, Some(p) if crate::profiles::valid_id(p)) {
                    bail!(tr!("недопустимый идентификатор стороннего профиля", "invalid third-party profile identifier"));
                }
                if !uuid_ok(&self.uuid) {
                    bail!(tr!("недопустимый uuid", "invalid uuid"));
                }
                if !password_ok(&self.password) {
                    bail!(tr!("недопустимый пароль", "invalid password"));
                }
                if !sni_ok(&self.sni) {
                    bail!(tr!("недопустимый sni", "invalid sni"));
                }
                if !pin_ok(&self.pin) {
                    bail!(tr!("недопустимый pin сертификата", "invalid certificate pin"));
                }
                if !matches!(self.security.as_str(), "tls" | "none") {
                    bail!("{}", tr!(format!("недопустимый security `{}`", self.security), format!("invalid security `{}`", self.security)));
                }
                if let Some(m) = &self.method {
                    if m.is_empty() || m.len() > 64 || !charset(m, "-_.") {
                        bail!(tr!("недопустимый method", "invalid method"));
                    }
                }
                if self.ws_path.is_some() || self.origin.is_some() || self.via.is_some() || self.username.is_some() {
                    bail!(tr!("у стороннего профиля нет ws_path, origin, via и username", "a third-party profile must not have ws_path, origin, via or username"));
                }
            }
            Kind::ShadowTls => {
                if !matches!(&self.method, Some(m) if SS_METHODS.contains(&m.as_str())) {
                    bail!(tr!("недопустимый шифр ShadowTLS (внутренний Shadowsocks 2022)", "invalid ShadowTLS cipher (inner Shadowsocks 2022)"));
                }
                match &self.password {
                    Some(p) if !p.is_empty() && p.len() <= 256 && charset(p, "+/=:") => {}
                    _ => bail!(tr!("недопустимый пароль ShadowTLS", "invalid ShadowTLS password")),
                }
                if !sni_ok(&self.sni) {
                    bail!(tr!("недопустимый сайт для рукопожатия ShadowTLS", "invalid ShadowTLS handshake site"));
                }
                if self.pin.is_some() {
                    bail!(tr!("у ShadowTLS нет закрепления сертификата", "ShadowTLS has no certificate pinning"));
                }
            }
            Kind::Ss2022 => {
                if !matches!(&self.method, Some(m) if SS_METHODS.contains(&m.as_str())) {
                    bail!(tr!("недопустимый шифр SS-2022", "invalid SS-2022 cipher"));
                }
                match &self.password {
                    Some(p) if !p.is_empty() && p.len() <= 256 && charset(p, "+/=:") => {}
                    _ => bail!(tr!("недопустимый пароль SS-2022", "invalid SS-2022 password")),
                }
            }
        }
        Ok(())
    }

    fn same_endpoint(&self, o: &Server) -> bool {
        self.host == o.host && self.port == o.port && self.uuid == o.uuid && self.kind == o.kind && self.profile == o.profile && self.password == o.password
    }
}

/// Проверка цепочек во всём списке серверов: у внешнего exit есть живой свой сервер-вход, который сам не внешний.
pub fn check_chains(servers: &[Server]) -> Result<()> {
    for s in servers.iter().filter(|s| s.is_external_exit()) {
        let v = s.via.as_deref().unwrap_or("");
        match servers.iter().find(|x| x.name == v) {
            None => bail!("{}", tr!(format!("у внешнего exit `{}` нет сервера-входа `{v}` в списке", s.name), format!("external exit `{}` has no entry server `{v}` in the list", s.name))),
            Some(e) if e.is_external_exit() => bail!("{}", tr!(format!("внешний exit `{}` идёт через другой внешний exit `{v}`: цепочки из нескольких прокси не поддерживаются", s.name), format!("external exit `{}` goes through another external exit `{v}`: chains of multiple proxies are not supported", s.name))),
            Some(_) => {}
        }
    }
    if servers.iter().all(|s| s.is_external_exit()) && !servers.is_empty() {
        bail!(tr!("в списке только внешние exit: нужен хотя бы один свой сервер", "the list contains only external exits: at least one of your own servers is required"));
    }
    Ok(())
}

/// Путь WebSocket: `/` и дальше безопасные символы (он попадает в конфиг от root и в заголовки).
pub fn valid_ws_path(p: &str) -> bool {
    p.len() >= 2 && p.len() <= 128 && p.starts_with('/') && p[1..].chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)) && !p.contains("..")
}

/// Все серверные записи пользователя: Reality и каждый включённый протокол.
pub fn servers_from_state(host: &str, st: &State, u: &User) -> Result<Vec<Server>> {
    let mut v = vec![Server::from_state(host, st, u)];
    for p in st.protocols.enabled.keys() {
        v.push(Server::for_proto(p, host, st, u)?);
    }
    Ok(v)
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').context(tr!("в IPv6-адресе нет закрывающей ]", "missing closing ] in IPv6 address"))?;
        (h.to_string(), tail.strip_prefix(':').context(tr!("нет порта после IPv6-адреса", "no port after the IPv6 address"))?)
    } else {
        let (h, p) = s.rsplit_once(':').context(tr!("нет порта в host:port", "no port in host:port"))?;
        (h.to_string(), p)
    };
    let port: u16 = port.parse().context(tr!("порт не число", "port is not a number"))?;
    if host.is_empty() || port == 0 {
        bail!(tr!("пустой хост или порт 0", "empty host or port 0"));
    }
    Ok((host, port))
}

pub fn parse_vless(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("vless://").context(tr!("это не vless:// ссылка", "not a vless:// link"))?;
    let (main, label) = match rest.split_once('#') {
        Some((m, l)) => (m, Some(urlencoding::decode(l)?.into_owned())),
        None => (rest, None),
    };
    let (auth_host, query) = main.split_once('?').unwrap_or((main, ""));
    let (uuid, hostport) = auth_host.split_once('@').context(tr!("нет uuid@host в ссылке", "no uuid@host in the link"))?;
    if uuid.len() != 36 {
        bail!("{}", tr!(format!("uuid выглядит неверно: `{uuid}`"), format!("uuid looks invalid: `{uuid}`")));
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
            bail!("{}", tr!(format!("encryption=`{e}` не поддерживается"), format!("encryption=`{e}` is not supported")));
        }
    }
    let ws = match get("type") {
        None | Some("tcp") => false,
        Some("ws") => true,
        Some(t) => bail!("{}", tr!(format!("транспорт `{t}` пока не поддерживается (tcp и ws)"), format!("transport `{t}` is not supported yet (tcp and ws)"))),
    };
    let flow = match get("flow") {
        None => None,
        Some("xtls-rprx-vision") => Some("xtls-rprx-vision".to_string()),
        Some(f) => bail!("{}", tr!(format!("flow `{f}` не поддерживается"), format!("flow `{f}` is not supported"))),
    };
    let security = get("security").unwrap_or("none");
    let (security, public_key, short_id) = match security {
        "reality" => {
            let pbk = get("pbk").context(tr!("для reality нужен pbk", "reality requires pbk"))?.to_string();
            ("reality".to_string(), Some(pbk), Some(get("sid").unwrap_or("").to_string()))
        }
        "tls" => ("tls".to_string(), None, None),
        other => bail!("{}", tr!(format!("security=`{other}` не поддерживается (нужны reality или tls)"), format!("security=`{other}` is not supported (reality or tls required)"))),
    };

    let ws_path = if ws {
        if security != "tls" {
            bail!(tr!("транспорт ws поддерживается только с security=tls", "ws transport is supported only with security=tls"));
        }
        if let Some(h) = get("host") {
            if h != get("sni").unwrap_or(&host) {
                bail!("{}", tr!(format!("заголовок Host (`{h}`) отличается от sni: такое не поддерживается"), format!("Host header (`{h}`) differs from sni: this is not supported")));
            }
        }
        let p = get("path").unwrap_or("/");
        if !valid_ws_path(p) && p != "/" {
            bail!("{}", tr!(format!("путь WebSocket `{p}` содержит недопустимые символы"), format!("WebSocket path `{p}` contains invalid characters")));
        }
        Some(p.to_string())
    } else {
        None
    };
    Ok(Server {
        ws_path,
        origin: None,
        via: None,
        username: None,
        profile: None,
        name: label.filter(|l| !l.is_empty()).unwrap_or_else(|| host.clone()),
        sni: get("sni").unwrap_or(&host).to_string(),
        fingerprint: get("fp").unwrap_or("chrome").to_string(),
        host,
        port,
        uuid: uuid.to_string(),
        kind: if ws { Kind::VlessWs } else { Kind::Vless },
        password: None,
        method: None,
        pin: None,
        flow,
        security,
        public_key,
        short_id,
    })
}

fn parse_query(query: &str) -> Result<HashMap<String, String>> {
    let mut q = HashMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        q.insert(k.to_string(), urlencoding::decode(v)?.into_owned());
    }
    Ok(q)
}

/// `схема://userinfo@host:port[/путь][?query][#имя]` -> (userinfo, host, port, query, имя)
type Parts = (String, String, u16, HashMap<String, String>, Option<String>);

fn split_url(rest: &str) -> Result<Parts> {
    let (main, label) = match rest.split_once('#') {
        Some((m, l)) => (m, Some(urlencoding::decode(l)?.into_owned()).filter(|l| !l.is_empty())),
        None => (rest, None),
    };
    let (auth_host, query) = main.split_once('?').unwrap_or((main, ""));
    let (userinfo, hostpath) = auth_host.rsplit_once('@').context(tr!("в ссылке нет данных входа перед @", "no login data before @ in the link"))?;
    let hostport = hostpath.split('/').next().unwrap_or("");
    let (host, port) = split_host_port(hostport)?;
    Ok((userinfo.to_string(), host, port, parse_query(query)?, label))
}

fn pin_from_query(q: &HashMap<String, String>, insecure_keys: &[&str]) -> Result<Option<String>> {
    let pin = q.get("pinSPKI").filter(|v| !v.is_empty()).cloned();
    let insecure = insecure_keys.iter().any(|k| q.get(*k).map(String::as_str) == Some("1"));
    if insecure && pin.is_none() {
        bail!(tr!(
            "ссылка требует отключить проверку сертификата (insecure=1) без закрепления ключа; такое не поддерживается. \
               Закрепление по pinSHA256 тоже не поддерживается: нужен pinSPKI из ссылки, которую выдаёт Eleutheria",
            "the link requires disabling certificate verification (insecure=1) without key pinning; this is not supported. \
               Pinning by pinSHA256 is not supported either: a pinSPKI from a link issued by Eleutheria is required"
        ));
    }
    Ok(pin)
}

pub fn parse_hysteria2(link: &str) -> Result<Server> {
    let t = link.trim();
    let rest = t.strip_prefix("hysteria2://").or_else(|| t.strip_prefix("hy2://")).context(tr!("это не hysteria2:// ссылка", "not a hysteria2:// link"))?;
    let (auth, host, port, q, label) = split_url(rest)?;
    for k in ["obfs", "mport"] {
        if q.get(k).is_some_and(|v| !v.is_empty()) {
            bail!("{}", tr!(format!("параметр `{k}` пока не поддерживается"), format!("parameter `{k}` is not supported yet")));
        }
    }
    let pin = pin_from_query(&q, &["insecure"])?;
    let password = urlencoding::decode(&auth)?.into_owned();
    Ok(Server {
        ws_path: None, origin: None, via: None, username: None, profile: None,
        name: label.unwrap_or_else(|| host.clone()),
        sni: q.get("sni").filter(|v| !v.is_empty()).cloned().unwrap_or_else(|| host.clone()),
        host,
        port,
        uuid: String::new(),
        kind: Kind::Hysteria2,
        password: Some(password),
        method: None,
        pin,
        flow: None,
        security: "tls".into(),
        fingerprint: "chrome".into(),
        public_key: None,
        short_id: None,
    })
}

pub fn parse_tuic(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("tuic://").context(tr!("это не tuic:// ссылка", "not a tuic:// link"))?;
    let (auth, host, port, q, label) = split_url(rest)?;
    let (uuid, pw) = auth.split_once(':').context(tr!("в tuic:// нужны uuid:пароль", "tuic:// requires uuid:password"))?;
    if uuid.len() != 36 {
        bail!("{}", tr!(format!("uuid выглядит неверно: `{uuid}`"), format!("uuid looks invalid: `{uuid}`")));
    }
    let pin = pin_from_query(&q, &["allow_insecure", "insecure"])?;
    Ok(Server {
        ws_path: None, origin: None, via: None, username: None, profile: None,
        name: label.unwrap_or_else(|| host.clone()),
        sni: q.get("sni").filter(|v| !v.is_empty()).cloned().unwrap_or_else(|| host.clone()),
        host,
        port,
        uuid: uuid.to_string(),
        kind: Kind::Tuic,
        password: Some(urlencoding::decode(pw)?.into_owned()),
        method: None,
        pin,
        flow: None,
        security: "tls".into(),
        fingerprint: "chrome".into(),
        public_key: None,
        short_id: None,
    })
}

/// `trojan://пароль@host:port?security=tls&sni=..&pinSPKI=..#имя`. Только TCP+TLS: ws, grpc и прочие транспорты
/// не поддерживаются.
pub fn parse_trojan(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("trojan://").context(tr!("это не trojan:// ссылка", "not a trojan:// link"))?;
    let (auth, host, port, q, label) = split_url(rest)?;
    let get = |k: &str| q.get(k).map(String::as_str).filter(|v| !v.is_empty());
    if let Some(t) = get("type").filter(|t| *t != "tcp") {
        bail!("{}", tr!(format!("транспорт `{t}` не поддерживается (только tcp)"), format!("transport `{t}` is not supported (tcp only)")));
    }
    if let Some(sec) = get("security").filter(|s| *s != "tls") {
        bail!("{}", tr!(format!("security=`{sec}` не поддерживается (нужен tls)"), format!("security=`{sec}` is not supported (tls required)")));
    }
    if get("plugin").is_some() {
        bail!(tr!("плагины Trojan не поддерживаются", "Trojan plugins are not supported"));
    }
    let pin = pin_from_query(&q, &["allowInsecure", "allow_insecure", "insecure"])?;
    Ok(Server {
        ws_path: None, origin: None, via: None, username: None, profile: None,
        name: label.unwrap_or_else(|| host.clone()),
        sni: get("sni").or_else(|| get("peer")).map(str::to_string).unwrap_or_else(|| host.clone()),
        host,
        port,
        uuid: String::new(),
        kind: Kind::Trojan,
        password: Some(urlencoding::decode(&auth)?.into_owned()),
        method: None,
        pin,
        flow: None,
        security: "tls".into(),
        fingerprint: "chrome".into(),
        public_key: None,
        short_id: None,
    })
}

/// `anytls://пароль@host:port?sni=..&insecure=1&pinSPKI=..#имя`.
pub fn parse_anytls(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("anytls://").context(tr!("это не anytls:// ссылка", "not an anytls:// link"))?;
    let (auth, host, port, q, label) = split_url(rest)?;
    let pin = pin_from_query(&q, &["insecure", "allowInsecure", "allow_insecure"])?;
    Ok(Server {
        ws_path: None, origin: None, via: None, username: None, profile: None,
        name: label.unwrap_or_else(|| host.clone()),
        sni: q.get("sni").filter(|v| !v.is_empty()).cloned().unwrap_or_else(|| host.clone()),
        host,
        port,
        uuid: String::new(),
        kind: Kind::AnyTls,
        password: Some(urlencoding::decode(&auth)?.into_owned()),
        method: None,
        pin,
        flow: None,
        security: "tls".into(),
        fingerprint: "chrome".into(),
        public_key: None,
        short_id: None,
    })
}

/// `ss://method:password@host:port` (SIP002; userinfo либо в процентном кодировании, либо base64url).
/// Поддерживаются только шифры SS-2022.
pub fn parse_ss(link: &str) -> Result<Server> {
    let rest = link.trim().strip_prefix("ss://").context(tr!("это не ss:// ссылка", "not an ss:// link"))?;
    let (userinfo, host, port, q, label) = split_url(rest)?;
    if q.contains_key("plugin") {
        bail!(tr!("плагины Shadowsocks не поддерживаются", "Shadowsocks plugins are not supported"));
    }
    let plain = urlencoding::decode(&userinfo)?.into_owned();
    let pair = if SS_METHODS.iter().any(|m| plain.starts_with(&format!("{m}:"))) {
        plain
    } else {
        let raw = b64_decode(&userinfo).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
        if raw.is_empty() { plain } else { raw }
    };
    let (method, password) = pair.split_once(':').context(tr!("в ss:// нужны шифр:пароль", "ss:// requires cipher:password"))?;
    if !SS_METHODS.contains(&method) {
        bail!("{}", tr!(format!("шифр `{method}` не поддерживается (нужен один из SS-2022: {})", SS_METHODS.join(", ")), format!("cipher `{method}` is not supported (one of SS-2022 required: {})", SS_METHODS.join(", "))));
    }
    Ok(Server {
        ws_path: None, origin: None, via: None, username: None, profile: None,
        name: label.unwrap_or_else(|| host.clone()),
        sni: host.clone(),
        host,
        port,
        uuid: String::new(),
        kind: Kind::Ss2022,
        password: Some(password.to_string()),
        method: Some(method.to_string()),
        pin: None,
        flow: None,
        security: "none".into(),
        fingerprint: "chrome".into(),
        public_key: None,
        short_id: None,
    })
}

/// Разбор одной ссылки любого поддерживаемого протокола.
pub fn parse_link(link: &str) -> Result<Server> {
    let t = link.trim();
    let s = if t.starts_with("vless://") {
        parse_vless(t)?
    } else if t.starts_with("hysteria2://") || t.starts_with("hy2://") {
        parse_hysteria2(t)?
    } else if t.starts_with("tuic://") {
        parse_tuic(t)?
    } else if t.starts_with("ss://") {
        parse_ss(t)?
    } else if t.starts_with("trojan://") {
        parse_trojan(t)?
    } else if t.starts_with("anytls://") {
        parse_anytls(t)?
    } else {
        bail!("{}", tr!(format!("схема `{}` не поддерживается (vless, hysteria2, tuic, ss, trojan, anytls)", t.split("://").next().unwrap_or("?")), format!("scheme `{}` is not supported (vless, hysteria2, tuic, ss, trojan, anytls)", t.split("://").next().unwrap_or("?"))));
    };
    s.validate()?;
    Ok(s)
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
        let scheme = line.split("://").next().unwrap_or("?");
        if matches!(scheme, "vless" | "hysteria2" | "hy2" | "tuic" | "ss" | "trojan" | "anytls") {
            match parse_link(line) {
                Ok(s) => servers.push(s),
                Err(e) => skipped.push(format!("{}: {e:#}", line.chars().take(40).collect::<String>())),
            }
        } else {
            skipped.push(tr!(format!("схема `{scheme}` пока не поддерживается"), format!("scheme `{scheme}` is not supported yet")));
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
        .with_context(|| tr!(format!("не удалось скачать подписку {url}"), format!("failed to download subscription {url}")))?
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
        Some(raw) => Ok(Some(serde_json::from_slice(&raw).context(tr!("повреждён индекс серверов в хранилище секретов", "server index in the secret store is corrupted"))?)),
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
    let raw = fs::read_to_string(&path).with_context(|| tr!(format!("не удалось прочитать {}", path.display()), format!("failed to read {}", path.display())))?;
    let legacy: LegacyFile = serde_json::from_str(&raw).with_context(|| tr!(format!("{} повреждён, перенос отменён", path.display()), format!("{} is corrupted, migration cancelled", path.display())))?;
    save_all(store, &legacy.servers)?;
    if load_from(store)? != legacy.servers {
        bail!("{}", tr!(format!("перенос серверов в {}: проверка записи не прошла, {} не тронут", store.kind(), path.display()), format!("migrating servers to {}: write verification failed, {} left untouched", store.kind(), path.display())));
    }
    if let Err(e) = fs::remove_file(&path) {
        eprintln!("{}", tr!(format!("Предупреждение: серверы перенесены, но удалить {} не удалось: {e}. Удали файл вручную.", path.display()), format!("Warning: servers were migrated, but {} could not be deleted: {e}. Delete the file manually.", path.display())));
    }
    Ok(())
}

fn load_from(store: &dyn SecretStore) -> Result<Vec<Server>> {
    let mut out = Vec::new();
    for n in read_index(store)?.unwrap_or_default() {
        match store.get(&entry_name(&n))? {
            Some(raw) => out.push(serde_json::from_slice(&raw).with_context(|| tr!(format!("повреждена запись сервера `{n}`"), format!("server record `{n}` is corrupted")))?),
            None => eprintln!("{}", tr!(format!("Предупреждение: сервер `{n}` есть в индексе, но его записи нет в хранилище; пропускаю."), format!("Warning: server `{n}` is in the index but its record is missing from the store; skipping."))),
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

/// Добавить внешний exit. Имя занято или такой прокси уже есть: ошибка (суффикс, как у импорта, тут вреден:
/// имя входит в команды и правила). Цепочка проверяется вместе со всем списком.
fn add_exit_in(dir: &Path, store: &dyn SecretStore, s: Server) -> Result<String> {
    anyhow::ensure!(s.is_external_exit(), tr!("это не внешний exit", "not an external exit"));
    s.validate()?;
    let mut all = try_load_in(dir, store)?;
    if all.iter().any(|x| x.name == s.name) {
        bail!("{}", tr!(format!("имя `{}` уже занято", s.name), format!("name `{}` is already taken", s.name)));
    }
    if all.iter().any(|x| x.is_external_exit() && x.host == s.host && x.port == s.port && x.via == s.via) {
        bail!("{}", tr!(format!("такой внешний exit через `{}` уже добавлен", s.via.as_deref().unwrap_or("")), format!("this external exit via `{}` has already been added", s.via.as_deref().unwrap_or(""))));
    }
    all.push(s.clone());
    check_chains(&all)?;
    save_all(store, &all)?;
    Ok(s.name)
}

/// Разобрать `socks5://[логин:пароль@]IP:порт` в запись внешнего exit. Имена вместо IP не принимаются.
pub fn parse_socks_exit(url: &str, name: &str, via: &str) -> Result<Server> {
    let rest = url.strip_prefix("socks5://").context(tr!("нужна ссылка вида socks5://[логин:пароль@]IP:порт", "a link like socks5://[user:password@]IP:port is required"))?;
    let (cred, addr) = match rest.rsplit_once('@') {
        Some((c, a)) => (Some(c), a),
        None => (None, rest),
    };
    let (host, port) = match addr.strip_prefix('[') {
        Some(r) => {
            let (h, p) = r.split_once("]:").context(tr!("после IPv6-адреса в скобках нужен :порт", "a :port is required after the bracketed IPv6 address"))?;
            (h, p)
        }
        None => addr.rsplit_once(':').context(tr!("нужен порт: socks5://IP:порт", "port required: socks5://IP:port"))?,
    };
    let port: u16 = port.parse().context(tr!("порт не число", "port is not a number"))?;
    let (username, password) = match cred {
        None => (None, None),
        Some(c) => {
            let (u, p) = c.split_once(':').context(tr!("логин и пароль задаются как логин:пароль", "username and password must be given as user:password"))?;
            let dec = |x: &str| urlencoding::decode(x).map(|c| c.into_owned()).context(tr!("логин или пароль не раскодировались", "failed to decode username or password"));
            (Some(dec(u)?), Some(dec(p)?))
        }
    };
    let s = Server {
        ws_path: None, origin: None, via: Some(via.to_string()), username, profile: None,
        name: name.to_string(), host: host.to_string(), port, uuid: String::new(), kind: Kind::Socks5,
        password, method: None, pin: None, flow: None, security: "none".into(),
        sni: String::new(), fingerprint: "chrome".into(), public_key: None, short_id: None,
    };
    s.validate()?;
    Ok(s)
}

fn remove_in(dir: &Path, store: &dyn SecretStore, name: &str) -> Result<bool> {
    let mut all = try_load_in(dir, store)?;
    let dependents: Vec<&str> = all.iter().filter(|x| x.is_external_exit() && x.via.as_deref() == Some(name)).map(|x| x.name.as_str()).collect();
    if !dependents.is_empty() {
        bail!("{}", tr!(format!("`{name}` служит входом для внешнего exit ({}): сначала удали его", dependents.join(", ")), format!("`{name}` is the entry for an external exit ({}): remove that first", dependents.join(", "))));
    }
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
        eprintln!("{}", tr!(format!("Не удалось прочитать список серверов: {e:#}"), format!("Failed to read the server list: {e:#}")));
        Vec::new()
    })
}
pub fn upsert(s: Server) -> Result<String> {
    upsert_in(&config_dir(), default_store()?, s)
}
pub fn remove(name: &str) -> Result<bool> {
    remove_in(&config_dir(), default_store()?, name)
}
pub fn add_exit(s: Server) -> Result<String> {
    add_exit_in(&config_dir(), default_store()?, s)
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
            users: vec![User::new("default", U)],
            protocols: Default::default(),
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

    // ---------- M3: Hysteria2 / TUIC / SS-2022 ----------

    fn full_state() -> State {
        use crate::state::{ProtoState, TlsInfo};
        let mut st = State {
            version: 2, singbox: "1.14.3".into(), profile: "Eleutheria".into(),
            private_key: "p".into(), public_key: "PUBKEY".into(), short_id: "5bb5899f0cb12edf".into(),
            sni: "www.microsoft.com".into(), port: 443,
            users: vec![User { name: "default".into(), uuid: U.into(), secret: Some("s3cr3t".into()) }],
            protocols: Default::default(),
        };
        st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: "13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo=".into(), cert_sha256: "ab".repeat(32) });
        st.protocols.enabled.insert(Proto::Hysteria2, ProtoState::new(443));
        st.protocols.enabled.insert(Proto::Tuic, ProtoState::new(8443));
        st.protocols.enabled.insert(Proto::Ss2022, ProtoState { server_key: Some("AAAAAAAAAAAAAAAAAAAAAA==".into()), ..ProtoState::new(8388) });
        st
    }

    #[test]
    fn own_links_roundtrip_through_parsers_for_every_protocol() {
        let st = full_state();
        let u = &st.users[0];
        let all = servers_from_state("203.0.113.5", &st, u).unwrap();
        assert_eq!(all.len(), 4);
        for l in crate::config::all_links("203.0.113.5", &st, u).unwrap() {
            let parsed = parse_link(&l.url).unwrap_or_else(|e| panic!("{}: {e:#}", l.proto));
            let want = all.iter().find(|s| s.kind_label() == (if l.proto == "vless" { "vless" } else { l.proto.as_str() })).unwrap();
            assert_eq!((parsed.host.as_str(), parsed.port, parsed.kind), (want.host.as_str(), want.port, want.kind), "{}", l.proto);
            assert_eq!((&parsed.password, &parsed.pin, &parsed.method, &parsed.uuid), (&want.password, &want.pin, &want.method, &want.uuid), "{}", l.proto);
            assert_eq!(parsed.sni, want.sni, "{}", l.proto);
            parsed.validate().unwrap();
        }
    }

    #[test]
    fn foreign_hysteria2_link_with_real_certificate_is_accepted_but_unpinned_insecure_is_not() {
        let ok = parse_link("hy2://pa%24%24@vpn.example.com:8443/?sni=vpn.example.com#Mine").unwrap();
        assert_eq!((ok.kind, ok.password.as_deref(), ok.pin.as_deref(), ok.name.as_str()), (Kind::Hysteria2, Some("pa$$"), None, "Mine"));
        let e = parse_link("hysteria2://x@h.example:443/?insecure=1&pinSHA256=AB:CD").unwrap_err().to_string();
        assert!(e.contains("pinSPKI"), "{e}");
        assert!(parse_link("hysteria2://x@h.example:443/?obfs=salamander&obfs-password=y").unwrap_err().to_string().contains("obfs"));
        assert!(parse_link(&format!("tuic://{U}:pw@h.example:443?allow_insecure=1")).is_err());
        assert!(parse_link(&format!("tuic://{U}:pw@h.example:443?allow_insecure=0")).is_ok());
    }

    #[test]
    fn ss_link_forms_and_rejections() {
        let m = "2022-blake3-aes-128-gcm";
        let plain = parse_link(&format!("ss://{m}:abc%2Bdef%3D@h.example:8388#n")).unwrap();
        assert_eq!((plain.method.as_deref(), plain.password.as_deref(), plain.port), (Some(m), Some("abc+def="), 8388));
        // base64url(method:password), форма SIP002 для старых клиентов
        let b64 = {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let src = format!("{m}:abc+def=");
            let mut o = String::new();
            for ch in src.as_bytes().chunks(3) {
                let n = ch.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
                for i in 0..=ch.len() { o.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char) }
            }
            o
        };
        assert_eq!(parse_link(&format!("ss://{b64}@h.example:8388")).unwrap().password.as_deref(), Some("abc+def="));
        assert!(parse_link("ss://aes-256-gcm:pw@h.example:8388").unwrap_err().to_string().contains("SS-2022"));
        assert!(parse_link(&format!("ss://{m}:pw@h.example:8388?plugin=obfs-local")).is_err());
    }

    #[test]
    fn subscription_mixes_protocols() {
        let st = full_state();
        let body: String = crate::config::all_links("203.0.113.5", &st, &st.users[0]).unwrap().into_iter().map(|l| l.url + "\n").collect::<String>() + "vmess://zzz\n";
        let (servers, skipped) = parse_subscription(&body);
        assert_eq!(servers.iter().map(|s| s.kind).collect::<Vec<_>>(), vec![Kind::Vless, Kind::Hysteria2, Kind::Tuic, Kind::Ss2022]);
        assert_eq!(skipped.len(), 1);
    }

    fn new_protocols_state() -> State {
        use crate::state::ProtoState;
        let mut st = full_state();
        st.protocols.enabled.insert(Proto::Trojan, ProtoState::new(2083));
        st.protocols.enabled.insert(Proto::AnyTls, ProtoState::new(4443));
        st.protocols.enabled.insert(Proto::ShadowTls, ProtoState { server_key: Some("BBBBBBBBBBBBBBBBBBBBBA==".into()), ..ProtoState::new(9443) });
        st
    }

    #[test]
    fn trojan_anytls_shadowtls_records_come_from_state_and_validate() {
        let st = new_protocols_state();
        let all = servers_from_state("203.0.113.5", &st, &st.users[0]).unwrap();
        let by = |k: Kind| all.iter().find(|s| s.kind == k).unwrap_or_else(|| panic!("{k:?}")).clone();
        all.iter().for_each(|s| s.validate().unwrap());
        let (tj, at, stls) = (by(Kind::Trojan), by(Kind::AnyTls), by(Kind::ShadowTls));
        for s in [&tj, &at] {
            assert_eq!((s.port, s.sni.as_str(), s.pin.as_deref()), (if s.kind == Kind::Trojan { 2083 } else { 4443 }, "www.bing.com", Some("13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo=")));
            assert_eq!(s.password.as_deref().map(str::len), Some(32), "hex32 пароль пользователя");
        }
        assert_eq!((stls.port, stls.sni.as_str(), stls.method.as_deref()), (9443, "www.microsoft.com", Some("2022-blake3-aes-128-gcm")));
        assert!(stls.pin.is_none());
        let pw = stls.password.as_deref().unwrap();
        assert!(pw.starts_with("BBBBBBBBBBBBBBBBBBBBBA==:"), "ключ сервера:ключ пользователя, {pw}");
        assert_eq!((tj.proto(), at.proto(), stls.proto()), (Some(Proto::Trojan), Some(Proto::AnyTls), Some(Proto::ShadowTls)));
        assert_eq!((tj.kind_label(), at.kind_label(), stls.kind_label()), ("trojan".to_string(), "anytls".to_string(), "shadowtls".to_string()));
    }

    #[test]
    fn trojan_and_anytls_own_links_roundtrip_and_shadowtls_has_no_link() {
        let st = new_protocols_state();
        let u = &st.users[0];
        let all = servers_from_state("203.0.113.5", &st, u).unwrap();
        let links = crate::config::all_links("203.0.113.5", &st, u).unwrap();
        assert!(links.iter().all(|l| l.proto != "shadowtls"));
        for l in links.iter().filter(|l| l.proto == "trojan" || l.proto == "anytls") {
            let parsed = parse_link(&l.url).unwrap_or_else(|e| panic!("{}: {e:#}", l.proto));
            let want = all.iter().find(|s| s.kind_label() == l.proto).unwrap();
            assert_eq!((parsed.host.as_str(), parsed.port, parsed.kind), (want.host.as_str(), want.port, want.kind), "{}", l.proto);
            assert_eq!((&parsed.password, &parsed.pin, &parsed.sni), (&want.password, &want.pin, &want.sni), "{}", l.proto);
            parsed.validate().unwrap();
        }
    }

    #[test]
    fn foreign_trojan_and_anytls_links_are_strict_about_certificates_and_transports() {
        let ok = parse_link("trojan://pa%24%24@vpn.example.com:443?security=tls&sni=vpn.example.com&type=tcp#Mine").unwrap();
        assert_eq!((ok.kind, ok.password.as_deref(), ok.pin.as_deref(), ok.name.as_str(), ok.sni.as_str()), (Kind::Trojan, Some("pa$$"), None, "Mine", "vpn.example.com"));
        assert_eq!(parse_link("trojan://x@h.example:443").unwrap().sni, "h.example", "без sni берётся хост");
        assert!(parse_link("trojan://x@h.example:443?allowInsecure=1").unwrap_err().to_string().contains("pinSPKI"));
        assert!(parse_link("trojan://x@h.example:443?type=ws&path=%2Fa").unwrap_err().to_string().contains("ws"));
        assert!(parse_link("trojan://x@h.example:443?security=reality").is_err());
        let pinned = parse_link("trojan://x@h.example:443?allowInsecure=1&pinSPKI=13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo%3D").unwrap();
        assert_eq!(pinned.pin.as_deref(), Some("13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo="));
        let a = parse_link("anytls://pw@h.example:4443?sni=front.example#A").unwrap();
        assert_eq!((a.kind, a.sni.as_str(), a.password.as_deref(), a.pin.is_none()), (Kind::AnyTls, "front.example", Some("pw"), true));
        assert!(parse_link("anytls://pw@h.example:4443?insecure=1").is_err());
        assert!(parse_link("anytls://h.example:4443").is_err(), "нет пароля перед @");
    }

    #[test]
    fn new_kinds_validate_and_serialize_under_their_ids() {
        let st = new_protocols_state();
        let all = servers_from_state("203.0.113.5", &st, &st.users[0]).unwrap();
        let stls = all.iter().find(|s| s.kind == Kind::ShadowTls).unwrap().clone();
        let bad = |f: &dyn Fn(&mut Server)| { let mut s = stls.clone(); f(&mut s); s.validate().is_err() };
        assert!(bad(&|s| s.method = None));
        assert!(bad(&|s| s.method = Some("aes-256-gcm".into())));
        assert!(bad(&|s| s.password = Some("a\"b".into())));
        assert!(bad(&|s| s.sni = "x y".into()));
        assert!(bad(&|s| s.pin = Some("13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo=".into())));
        let tj = all.iter().find(|s| s.kind == Kind::Trojan).unwrap().clone();
        let bad_tj = |f: &dyn Fn(&mut Server)| { let mut s = tj.clone(); f(&mut s); s.validate().is_err() };
        assert!(bad_tj(&|s| s.password = None));
        assert!(bad_tj(&|s| s.pin = Some("short".into())));
        for (k, id) in [(Kind::Trojan, "trojan"), (Kind::AnyTls, "anytls"), (Kind::ShadowTls, "shadowtls")] {
            let s = all.iter().find(|s| s.kind == k).unwrap();
            let json = serde_json::to_string(s).unwrap();
            assert!(json.contains(&format!("\"kind\":\"{id}\"")), "{json}");
            assert_eq!(&serde_json::from_str::<Server>(&json).unwrap(), s);
        }
    }

    #[test]
    fn validate_per_kind() {
        let st = full_state();
        let all = servers_from_state("203.0.113.5", &st, &st.users[0]).unwrap();
        all.iter().for_each(|s| s.validate().unwrap());
        let hy = all[1].clone();
        let bad = |f: &dyn Fn(&mut Server)| { let mut s = hy.clone(); f(&mut s); s.validate().is_err() };
        assert!(bad(&|s| s.password = None));
        assert!(bad(&|s| s.password = Some("a b".into())));
        assert!(bad(&|s| s.pin = Some("short".into())));
        assert!(bad(&|s| s.sni = "x y".into()));
        let ss = all.iter().find(|s| s.kind == Kind::Ss2022).unwrap().clone();
        let bad_ss = |f: &dyn Fn(&mut Server)| { let mut s = ss.clone(); f(&mut s); s.validate().is_err() };
        assert!(bad_ss(&|s| s.method = Some("aes-256-gcm".into())));
        assert!(bad_ss(&|s| s.password = Some("a\"b".into())));
        let tu = all.iter().find(|s| s.kind == Kind::Tuic).unwrap().clone();
        let mut t = tu.clone();
        t.uuid = "short".into();
        assert!(t.validate().is_err());
    }

    #[test]
    fn records_saved_before_m3_still_load_as_vless() {
        let old = r#"{"name":"n","host":"203.0.113.5","port":443,"uuid":"a158cda3-0b3d-424b-a8f8-26a6462c8349","flow":"xtls-rprx-vision","security":"reality","sni":"x.com","fingerprint":"chrome","public_key":"PUB","short_id":"abcd"}"#;
        let s: Server = serde_json::from_str(old).unwrap();
        assert_eq!(s.kind, Kind::Vless);
        s.validate().unwrap();
        assert!(!serde_json::to_string(&s).unwrap().contains("password"));
    }

    fn cdn_state() -> State {
        use crate::state::ProtoState;
        let mut st = full_state();
        st.protocols.enabled.insert(
            Proto::VlessWs,
            ProtoState { cdn_host: Some("cdn.example.com".into()), ws_path: Some("/a1b2c3d4e5f60718".into()), ..ProtoState::new(8443) },
        );
        st
    }

    #[test]
    fn cdn_server_connects_to_the_domain_but_exits_at_the_origin() {
        let st = cdn_state();
        let s = Server::for_proto(&Proto::VlessWs, "203.0.113.5", &st, &st.users[0]).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.sni.as_str()), ("cdn.example.com", CDN_EDGE_PORT, "cdn.example.com"));
        assert_eq!((s.kind, s.ws_path.as_deref(), s.origin.as_deref()), (Kind::VlessWs, Some("/a1b2c3d4e5f60718"), Some("203.0.113.5")));
        assert!(s.password.is_none() && s.pin.is_none(), "у пути через CDN нет ни пароля, ни закрепления ключа");
        s.validate().unwrap();
    }

    #[test]
    fn cdn_link_roundtrips_and_other_protocols_are_unaffected() {
        let st = cdn_state();
        let u = &st.users[0];
        let links = crate::config::all_links("203.0.113.5", &st, u).unwrap();
        assert_eq!(links.len(), 5);
        let l = links.iter().find(|l| l.proto == "vless-ws").unwrap();
        assert!(l.url.contains("type=ws") && l.url.contains("security=tls") && l.url.contains("%2Fa1b2c3d4e5f60718"), "{}", l.url);
        assert!(!l.url.contains("203.0.113.5"), "адрес сервера-источника в ссылку не попадает: {}", l.url);
        let p = parse_link(&l.url).unwrap();
        assert_eq!((p.kind, p.host.as_str(), p.port, p.ws_path.as_deref(), p.uuid.as_str()), (Kind::VlessWs, "cdn.example.com", 443, Some("/a1b2c3d4e5f60718"), U));
        assert!(p.origin.is_none(), "по чужой ссылке источник неизвестен");
        p.validate().unwrap();
    }

    #[test]
    fn websocket_links_are_strict() {
        let base = format!("vless://{U}@cdn.example.com:443?encryption=none&type=ws&security=tls&sni=cdn.example.com&path=%2Fx1");
        assert_eq!(parse_vless(&base).unwrap().kind, Kind::VlessWs);
        assert!(parse_vless(&base.replace("security=tls", "security=none")).is_err(), "ws без TLS не берём");
        assert!(parse_vless(&format!("{base}&host=other.example.com")).is_err(), "Host не равен sni: не поддерживается");
        assert!(parse_vless(&format!("{base}&host=cdn.example.com")).is_ok());
        assert!(parse_vless(&base.replace("%2Fx1", "%2Fa%20b")).is_err(), "пробел в пути");
        assert!(parse_vless(&base.replace("type=ws", "type=grpc")).is_err());
        // путь по умолчанию
        assert_eq!(parse_vless(&base.replace("&path=%2Fx1", "")).unwrap().ws_path.as_deref(), Some("/"));
    }

    #[test]
    fn ws_path_validation() {
        for ok in ["/a", "/a1b2c3", "/api/v1/stream", "/a-b_c.d"] {
            assert!(valid_ws_path(ok), "{ok}");
        }
        for bad in ["", "/", "a", "/a b", "/a?x=1", "/../etc", "/a\"b", "/\n", &format!("/{}", "x".repeat(200))] {
            assert!(!valid_ws_path(bad), "{bad:?}");
        }
        let st = cdn_state();
        let mut s = Server::for_proto(&Proto::VlessWs, "203.0.113.5", &st, &st.users[0]).unwrap();
        s.ws_path = Some("/x\",\"y".into());
        assert!(s.validate().is_err());
        s.ws_path = None;
        assert!(s.validate().is_err());
    }

    #[test]
    fn cdn_server_without_domain_in_state_is_an_error() {
        let mut st = cdn_state();
        st.protocols.enabled.get_mut(&Proto::VlessWs).unwrap().cdn_host = None;
        assert!(Server::for_proto(&Proto::VlessWs, "203.0.113.5", &st, &st.users[0]).is_err());
        assert!(crate::config::all_links("203.0.113.5", &st, &st.users[0]).is_err());
    }

    #[test]
    fn external_exit_validation() {
        let mk = |f: &dyn Fn(&mut Server)| {
            let mut s = Server {
                ws_path: None, origin: None, via: Some("h".into()), username: Some("u".into()), profile: None,
                name: "exit".into(), host: "198.51.100.7".into(), port: 1080, uuid: String::new(), kind: Kind::Socks5,
                password: Some("p".into()), method: None, pin: None, flow: None, security: "none".into(),
                sni: String::new(), fingerprint: "chrome".into(), public_key: None, short_id: None,
            };
            f(&mut s);
            s.validate()
        };
        assert!(mk(&|_| {}).is_ok());
        assert!(mk(&|s| { s.username = None; s.password = None; }).is_ok(), "прокси без пароля допустим");
        assert!(mk(&|s| s.host = "proxy.example.com".into()).is_err(), "только IP: имя утекло бы в DNS клиента");
        assert!(mk(&|s| s.via = None).is_err(), "без входного сервера IP клиента виден прокси");
        assert!(mk(&|s| s.via = Some(String::new())).is_err());
        assert!(mk(&|s| s.password = None).is_err(), "логин без пароля");
        assert!(mk(&|s| s.username = Some("a\nb".into())).is_err(), "управляющие символы нельзя");
        assert!(mk(&|s| s.username = Some("a b".into())).is_ok(), "пробел допустим: в конфиг идёт JSON-строкой");
        assert!(mk(&|s| s.password = Some("p\"q".into())).is_ok(), "кавычка в пароле допустима: в конфиг идёт как JSON-строка");
        assert!(mk(&|s| s.password = Some("x".repeat(300))).is_err());
        assert!(mk(&|s| s.port = 0).is_err());
    }

    #[test]
    fn external_exit_is_a_normal_looking_record_for_chain_checks() {
        let mut a = parse_vless(&reality_link()).unwrap();
        a.name = "a".into();
        let mut x = a.clone();
        x.name = "x".into();
        x.kind = Kind::Socks5;
        x.via = Some("a".into());
        assert!(check_chains(&[a.clone(), x.clone()]).is_ok());
        assert!(check_chains(&[a.clone()]).is_ok());
        assert!(check_chains(&[]).is_ok());
        x.via = Some("zzz".into());
        assert!(check_chains(&[a, x]).is_err());
    }

    #[test]
    fn socks_exit_url_parsing() {
        let s = parse_socks_exit("socks5://user:p%40ss@198.51.100.7:1080", "ex", "a").unwrap();
        assert_eq!((s.host.as_str(), s.port, s.username.as_deref(), s.password.as_deref(), s.via.as_deref(), s.kind), ("198.51.100.7", 1080, Some("user"), Some("p@ss"), Some("a"), Kind::Socks5));
        let s = parse_socks_exit("socks5://[2001:db8::7]:1080", "ex", "a").unwrap();
        assert_eq!((s.host.as_str(), s.username.is_none()), ("2001:db8::7", true));
        for bad in ["http://1.2.3.4:1080", "socks5://1.2.3.4", "socks5://proxy.example.com:1080", "socks5://u@1.2.3.4:1080", "socks5://u:p@1.2.3.4:0", "socks5://1.2.3.4:notaport", "socks5://[::1]1080"] {
            assert!(parse_socks_exit(bad, "ex", "a").is_err(), "{bad}");
        }
        assert!(parse_socks_exit("socks5://1.2.3.4:1080", "ex", "").is_err(), "без входа нельзя");
    }

    #[test]
    fn exit_store_rules_name_dedupe_entry_and_dependents() {
        let (dir, st) = (tmpdir("exit"), MemStore::new());
        let mut a = parse_vless(&reality_link()).unwrap();
        a.name = "a".into();
        upsert_in(&dir, &st, a).unwrap();
        let x = parse_socks_exit("socks5://u:p@198.51.100.7:1080", "ex", "a").unwrap();
        assert_eq!(add_exit_in(&dir, &st, x.clone()).unwrap(), "ex");
        assert!(add_exit_in(&dir, &st, x.clone()).is_err(), "то же имя");
        let mut same = x.clone();
        same.name = "ex2".into();
        assert!(add_exit_in(&dir, &st, same).is_err(), "тот же прокси через тот же вход");
        let nowhere = parse_socks_exit("socks5://u:p@198.51.100.8:1080", "ex3", "zzz").unwrap();
        assert!(add_exit_in(&dir, &st, nowhere).is_err(), "входа нет в списке");
        let mut chained = parse_socks_exit("socks5://u:p@198.51.100.9:1080", "ex4", "ex").unwrap();
        chained.name = "ex4".into();
        assert!(add_exit_in(&dir, &st, chained).is_err(), "через другой внешний exit нельзя");
        let loaded = try_load_in(&dir, &st).unwrap();
        assert_eq!(loaded.len(), 2, "отказы ничего не записали");
        assert_eq!(loaded[1].password.as_deref(), Some("p"), "пароль прокси сохранился");
        // вход нельзя удалить, пока от него зависит внешний exit; сам exit удаляется
        assert!(remove_in(&dir, &st, "a").unwrap_err().to_string().contains("ex"));
        assert!(remove_in(&dir, &st, "ex").unwrap());
        assert!(remove_in(&dir, &st, "a").unwrap());
        // не-exit нельзя подсунуть через add_exit
        assert!(add_exit_in(&dir, &st, parse_vless(&reality_link()).unwrap()).is_err());
    }
}
