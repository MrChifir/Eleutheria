//! Сервисный слой для GUI. Tauri-команды остаются тонкими обёртками над этими функциями,
//! поэтому вся логика проверяется обычными тестами без окна и без WebView.
//!
//! Опрос состояния разделён на две части: `overview` дешёвый (читает файлы и спрашивает helper) и годится
//! для вызова раз в пару секунд; `latency` дорогой (замеряет задержку каждого сервера через Clash API).

pub mod elevate;
pub mod partners;
pub mod server;
pub mod update;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use eleutheria_core::client::categories;
use eleutheria_core::client::config::RuDirect;
use eleutheria_core::client::prober::{FailClass, Health};
use eleutheria_core::client::watch::{self, WatchCfg, Watcher};
use eleutheria_core::client::profile::{self, Server};
use eleutheria_core::client::runtime::{self, ConnectOpts, Status, DEFAULT_TEST_URL};
use eleutheria_core::ipc::{self, Request, Response, StartParams};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PROXY_PORT: u16 = 7890;
pub const DEFAULT_CLASH_PORT: u16 = 9090;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// локальный прокси (HTTP и SOCKS5), права не нужны
    Proxy,
    /// системный VPN через TUN, нужен helper
    Tun,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerDto {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub security: String,
    /// vless | hysteria2 | tuic | ss2022
    pub kind: String,
}

impl From<&Server> for ServerDto {
    fn from(s: &Server) -> Self {
        ServerDto { name: s.name.clone(), host: s.host.clone(), port: s.port, security: s.security.clone(), kind: s.kind_label() }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDto {
    pub mode: Mode,
    pub pid: u32,
    /// порт локального прокси; для TUN его нет
    pub listen_port: Option<u16>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HelperDto {
    pub running: bool,
    pub version: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub servers: Vec<ServerDto>,
    pub connection: Option<ConnectionDto>,
    pub helper: HelperDto,
    /// версия приложения (она же ожидаемая версия helper)
    pub app_version: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiveServer {
    pub name: String,
    pub delay_ms: Option<u64>,
    pub error: Option<String>,
    pub active: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Latency {
    /// "авто" или имя выбранного сервера
    pub route: String,
    pub servers: Vec<LiveServer>,
}

impl From<&Status> for Latency {
    fn from(st: &Status) -> Self {
        Latency {
            route: st.mode.clone(),
            servers: st
                .servers
                .iter()
                .map(|s| LiveServer { name: s.name.clone(), delay_ms: s.delay_ms, error: s.error.clone(), active: s.active })
                .collect(),
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    pub mode: Mode,
    /// None = авто (по задержке)
    pub server: Option<String>,
    #[serde(default = "default_ru")]
    pub ru_direct: RuDirect,
}

fn default_ru() -> RuDirect {
    RuDirect::Minimal
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResult {
    pub mode: Mode,
    pub pid: u32,
    pub listen_port: Option<u16>,
    pub delay_ms: Option<u64>,
    pub warning: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub added: Vec<String>,
    pub skipped: Vec<String>,
}

/// Что пользователь вставил в поле импорта.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceKind {
    Link(String),
    Subscription(String),
}

fn is_link(t: &str) -> bool {
    ["vless://", "hysteria2://", "hy2://", "tuic://", "ss://"].iter().any(|p| t.starts_with(p))
}

/// Из вставленного текста (с пробелами, переводами строк, иногда с лишним текстом вокруг) берётся первая ссылка.
pub fn classify_source(input: &str) -> Result<SourceKind> {
    let tok = input
        .split_whitespace()
        .find(|t| is_link(t) || t.starts_with("http://") || t.starts_with("https://"))
        .ok_or_else(|| anyhow!("нужна ссылка (vless://, hysteria2://, tuic://, ss://) или URL подписки (http/https)"))?;
    Ok(if is_link(tok) { SourceKind::Link(tok.to_string()) } else { SourceKind::Subscription(tok.to_string()) })
}

/// Проверка запроса на подключение до любых действий в системе.
pub fn validate_connect(servers: &[Server], req: &ConnectRequest) -> Result<()> {
    if servers.is_empty() {
        bail!("нет серверов: добавь сервер (ссылка vless:// или подписка)");
    }
    if let Some(name) = &req.server {
        if !servers.iter().any(|s| &s.name == name) {
            bail!("сервера `{name}` нет в списке");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn helper_socket() -> Option<PathBuf> {
    let p = ipc::default_socket_path();
    p.exists().then_some(p)
}

/// Windows: наличие pipe через файловую систему не проверяем, недоступность видна по ошибке подключения.
#[cfg(windows)]
fn helper_socket() -> Option<PathBuf> {
    Some(ipc::default_socket_path())
}

async fn helper_request(req: &Request) -> Result<Response> {
    let sock = helper_socket().ok_or_else(|| anyhow!("helper не установлен или не запущен"))?;
    tokio::time::timeout(Duration::from_secs(5), ipc::request(&sock, req))
        .await
        .map_err(|_| anyhow!("helper не ответил за 5 секунд"))?
}

async fn helper_info() -> HelperDto {
    match helper_request(&Request::Ping).await {
        Ok(Response::Pong { version }) => HelperDto { running: true, version: Some(version) },
        _ => HelperDto { running: false, version: None },
    }
}

/// Работает ли туннель через helper (TUN): (pid)
async fn helper_tunnel() -> Option<u32> {
    match helper_request(&Request::Status).await {
        Ok(Response::Status(info)) if info.running => Some(info.pid.unwrap_or(0)),
        _ => None,
    }
}

/// Дешёвый снимок состояния для частого опроса.
pub async fn overview() -> Overview {
    let servers = profile::load().iter().map(ServerDto::from).collect();
    let helper = helper_info().await;
    let connection = if let Some((pid, port)) = runtime::running_info() {
        Some(ConnectionDto { mode: Mode::Proxy, pid, listen_port: Some(port) })
    } else if helper.running {
        helper_tunnel().await.map(|pid| ConnectionDto { mode: Mode::Tun, pid, listen_port: None })
    } else {
        None
    };
    Overview { servers, connection, helper, app_version: env!("CARGO_PKG_VERSION").to_string() }
}

/// Замер задержки каждого сервера через Clash API (дорого: вызывать по запросу или редко).
pub async fn latency() -> Result<Option<Latency>> {
    if let Some(st) = runtime::status().await? {
        return Ok(Some(Latency::from(&st)));
    }
    if let Ok(Response::Status(info)) = helper_request(&Request::Status).await {
        if let Some(st) = runtime::status_from_helper(&info).await? {
            return Ok(Some(Latency::from(&st)));
        }
    }
    Ok(None)
}

pub async fn connect(req: ConnectRequest) -> Result<ConnectResult> {
    let servers = profile::load();
    validate_connect(&servers, &req)?;
    match req.mode {
        Mode::Proxy => {
            let o = ConnectOpts {
                listen_port: DEFAULT_PROXY_PORT,
                clash_port: DEFAULT_CLASH_PORT,
                test_url: DEFAULT_TEST_URL.to_string(),
                ru_direct: req.ru_direct,
                selected: req.server,
                probes: true,
            };
            let info = runtime::connect(&servers, &o).await?;
            Ok(ConnectResult { mode: Mode::Proxy, pid: info.pid, listen_port: Some(info.listen_port), delay_ms: info.delay_ms, warning: info.warning })
        }
        Mode::Tun => {
            let profiles = eleutheria_core::userprofiles::files_for_servers(&eleutheria_core::userprofiles::root(), &servers)?;
            let params = StartParams { servers, ru_direct: req.ru_direct, selected: req.server, test_url: DEFAULT_TEST_URL.to_string(), categories: categories::load(), probes: true, profiles };
            match helper_request(&Request::Start(params)).await? {
                Response::Started { pid } => Ok(ConnectResult { mode: Mode::Tun, pid, listen_port: None, delay_ms: None, warning: None }),
                Response::Error { message } => bail!("{message}"),
                other => bail!("неожиданный ответ helper'а: {other:?}"),
            }
        }
    }
}

// ───────────────────────── категории и пробер ─────────────────────────

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CategoryDto {
    pub id: String,
    pub title: String,
    pub enabled: bool,
    pub domains: Vec<String>,
}

pub fn categories_list() -> Vec<CategoryDto> {
    categories::load().into_iter().map(|c| CategoryDto { id: c.id, title: c.title, enabled: c.enabled, domains: c.domains }).collect()
}

/// Тумблер категории. Переключатели sing-box создаются при подключении, поэтому действует со следующего подключения.
pub fn set_category(id: &str, enabled: bool) -> Result<()> {
    categories::set_enabled(id, enabled)
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PairDto {
    /// `canary` (общий туннель) или id категории
    pub category: String,
    pub server: String,
    /// healthy | suspect | failed
    pub health: String,
    /// PROTOCOL_BLOCKED | SERVER_IP_BLOCKED | EXIT_BLOCKED_BY_SITE | UNCLASSIFIED
    pub class: Option<String>,
    pub degraded: bool,
    pub ms: Option<u64>,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EventDto {
    pub at: u64,
    pub text: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProberDto {
    pub updated: u64,
    pub round: u64,
    pub pairs: Vec<PairDto>,
    pub events: Vec<EventDto>,
}

impl From<&watch::Snapshot> for ProberDto {
    fn from(s: &watch::Snapshot) -> Self {
        ProberDto {
            updated: s.updated,
            round: s.round,
            pairs: s
                .pairs
                .iter()
                .map(|p| PairDto {
                    category: p.category.clone(),
                    server: p.name.clone(),
                    health: match p.health {
                        Health::Healthy => "healthy",
                        Health::Suspect => "suspect",
                        Health::Failed => "failed",
                    }
                    .to_string(),
                    class: p.class.map(|c: FailClass| c.as_str().to_string()),
                    degraded: p.degraded,
                    ms: p.ms,
                    reason: p.reason.clone(),
                })
                .collect(),
            events: s.events.iter().map(|e| EventDto { at: e.at, text: e.text.clone() }).collect(),
        }
    }
}

/// Последний снимок пробера (его пишет `watch_loop`); None, пока цикл не сделал ни одного раунда.
pub fn prober_status() -> Option<ProberDto> {
    watch::load_snapshot().as_ref().map(ProberDto::from)
}

async fn current_link() -> Option<watch::Link> {
    if let Some(l) = runtime::link() {
        return Some(l);
    }
    if let Ok(Response::Status(info)) = helper_request(&Request::Status).await {
        return runtime::link_from_helper(&info);
    }
    None
}

/// Фоновый цикл пробера и автопереключения. Заканчивается сам, когда sing-box перестаёт отвечать;
/// GUI запускает его после подключения и прерывает при отключении (`JoinHandle::abort`).
pub async fn watch_loop(interval: Duration) {
    // дать sing-box подняться и первому замеру urltest завершиться
    tokio::time::sleep(Duration::from_secs(3)).await;
    let Some(link) = current_link().await else { return };
    watch::clear_snapshot();
    let mut w = Watcher::new(link.clone(), WatchCfg::default());
    let mut dead = 0u32;
    loop {
        if w.step().await.is_err() {
            dead += 1;
        }
        if watch::alive(&link).await {
            dead = 0;
        } else {
            dead += 1;
        }
        if dead >= 3 {
            watch::clear_snapshot();
            return;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Остановить и локальный прокси, и туннель helper'а. Возвращает, было ли что останавливать.
pub async fn disconnect() -> Result<bool> {
    watch::clear_snapshot();
    let mut was = runtime::disconnect().await?;
    if helper_socket().is_some() {
        if let Ok(Response::Stopped { was_running: true }) = helper_request(&Request::Stop).await {
            was = true;
        }
    }
    Ok(was)
}

pub async fn import(source: &str, name: Option<String>) -> Result<ImportResult> {
    let (mut servers, skipped) = match classify_source(source)? {
        SourceKind::Link(l) => (vec![profile::parse_link(&l)?], vec![]),
        SourceKind::Subscription(u) => profile::parse_subscription(&profile::fetch_subscription(&u).await?),
    };
    if let (Some(n), 1) = (name.filter(|n| !n.trim().is_empty()), servers.len()) {
        servers[0].name = n.trim().to_string();
    }
    let mut added = Vec::new();
    for s in servers {
        added.push(profile::upsert(s)?);
    }
    Ok(ImportResult { added, skipped })
}

pub fn remove_server(name: &str) -> Result<()> {
    if profile::remove(name)? {
        Ok(())
    } else {
        bail!("сервера `{name}` нет в списке")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(name: &str) -> Server {
        Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name: name.into(),
            host: "203.0.113.5".into(),
            port: 443,
            uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(),
            kind: eleutheria_core::client::profile::Kind::Vless,
            password: None,
            method: None,
            pin: None,
            flow: Some("xtls-rprx-vision".into()),
            security: "reality".into(),
            sni: "www.microsoft.com".into(),
            fingerprint: "chrome".into(),
            public_key: Some("k".into()),
            short_id: Some("ab".into()),
        }
    }

    fn req(server: Option<&str>) -> ConnectRequest {
        ConnectRequest { mode: Mode::Proxy, server: server.map(String::from), ru_direct: RuDirect::Minimal }
    }

    #[test]
    fn source_classification_takes_first_link_from_messy_input() {
        assert_eq!(classify_source("  vless://abc#x \n").unwrap(), SourceKind::Link("vless://abc#x".into()));
        assert_eq!(
            classify_source("Моя подписка: https://example.com/sub?t=1\nспасибо").unwrap(),
            SourceKind::Subscription("https://example.com/sub?t=1".into())
        );
        assert_eq!(classify_source("http://a.b/s").unwrap(), SourceKind::Subscription("http://a.b/s".into()));
        for bad in ["", "   ", "ssh://x", "example.com", "vmess://abc"] {
            assert!(classify_source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn source_classification_accepts_every_supported_scheme() {
        for l in ["hysteria2://p@h.example:443/?sni=h.example", "hy2://p@h.example:443", "tuic://u:p@h.example:443", "ss://m:p@h.example:8388"] {
            assert_eq!(classify_source(&format!(" текст {l} ещё")).unwrap(), SourceKind::Link(l.into()));
        }
    }

    #[test]
    fn connect_validation() {
        assert!(validate_connect(&[], &req(None)).is_err());
        assert!(validate_connect(&[srv("a")], &req(None)).is_ok());
        assert!(validate_connect(&[srv("a")], &req(Some("a"))).is_ok());
        let e = validate_connect(&[srv("a")], &req(Some("zzz"))).unwrap_err().to_string();
        assert!(e.contains("zzz"));
    }

    #[test]
    fn requests_deserialize_from_camel_case_json() {
        let r: ConnectRequest = serde_json::from_str(r#"{"mode":"tun","server":null,"ruDirect":"rulesets"}"#).unwrap();
        assert_eq!((r.mode, r.server, r.ru_direct), (Mode::Tun, None, RuDirect::RuleSets));
        // ruDirect необязателен: по умолчанию «минимум»
        let r: ConnectRequest = serde_json::from_str(r#"{"mode":"proxy","server":"s1"}"#).unwrap();
        assert_eq!((r.mode, r.server.as_deref(), r.ru_direct), (Mode::Proxy, Some("s1"), RuDirect::Minimal));
        assert!(serde_json::from_str::<ConnectRequest>(r#"{"mode":"vpn"}"#).is_err());
    }

    #[test]
    fn dtos_serialize_for_the_frontend_without_secrets() {
        let o = Overview {
            servers: vec![ServerDto::from(&srv("main"))],
            connection: Some(ConnectionDto { mode: Mode::Tun, pid: 7, listen_port: None }),
            helper: HelperDto { running: true, version: Some("0.1.0".into()) },
            app_version: "0.1.0".into(),
        };
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(j["connection"]["mode"], "tun");
        assert_eq!(j["connection"]["listenPort"], serde_json::Value::Null);
        assert_eq!(j["servers"][0]["name"], "main");
        // UUID, ключи и short id серверов во фронтенд не уходят
        let text = j.to_string();
        for secret in ["a158cda3", "xtls-rprx", "\"ab\""] {
            assert!(!text.contains(secret), "утечка {secret}");
        }
    }

    #[test]
    fn prober_dto_maps_states_and_hides_nothing_secret() {
        use eleutheria_core::client::watch::{Event, PairRow, Snapshot};
        let s = Snapshot {
            updated: 10,
            round: 3,
            pairs: vec![PairRow { category: "video".into(), tag: "srv-1".into(), name: "main".into(), health: Health::Failed, class: Some(FailClass::ExitBlockedBySite), degraded: false, ms: None, reason: "403".into() }],
            events: vec![Event { at: 9, text: "x".into() }],
        };
        let j = serde_json::to_value(ProberDto::from(&s)).unwrap();
        assert_eq!(j["pairs"][0]["health"], "failed");
        assert_eq!(j["pairs"][0]["class"], "EXIT_BLOCKED_BY_SITE");
        assert_eq!(j["pairs"][0]["server"], "main");
        assert_eq!(j["events"][0]["text"], "x");
        assert!(!j.to_string().contains("srv-1"), "внутренние теги не нужны фронтенду");
    }

    #[test]
    fn categories_list_has_builtin_set() {
        let c = categories_list();
        assert!(c.iter().any(|c| c.id == "video"));
        assert!(serde_json::to_value(&c[0]).unwrap().get("enabled").is_some());
    }

    #[test]
    fn latency_maps_status() {
        let st = Status {
            pid: 1,
            listen_port: 7890,
            mode: "авто".into(),
            servers: vec![
                runtime::ServerStatus { name: "a".into(), delay_ms: Some(42), error: None, active: true },
                runtime::ServerStatus { name: "b".into(), delay_ms: None, error: Some("timeout".into()), active: false },
            ],
        };
        let l = Latency::from(&st);
        assert_eq!(l.route, "авто");
        assert_eq!(l.servers[0], LiveServer { name: "a".into(), delay_ms: Some(42), error: None, active: true });
        assert_eq!(l.servers[1].error.as_deref(), Some("timeout"));
        let j = serde_json::to_value(&l).unwrap();
        assert_eq!(j["servers"][0]["delayMs"], 42);
    }
}
