//! Ввод-вывод пробера: пробы через локальные пробные входы sing-box, переключение через Clash API
//! (без перезапуска ядра), цикл наблюдения и снимок состояния для CLI/GUI.

use std::fs;
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::categories::Category;
use super::config::{server_tag, PROBE_USER};
use super::profile::Server;
use super::prober::*;
use crate::store::{config_dir, write_secret_file};

/// Как достучаться до запущенного sing-box.
#[derive(Clone, Debug)]
pub struct Link {
    pub clash_port: u16,
    pub secret: String,
    pub plan: ProbePlan,
}

/// План проб для набора серверов. Порты выбираются свободные (на момент выбора).
pub fn make_plan(servers: &[Server], selected: Option<&str>, categories: &[Category], canary_url: &str) -> Result<ProbePlan> {
    super::profile::check_chains(servers)?;
    let outbounds: Vec<OutboundInfo> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| OutboundInfo { tag: server_tag(i), name: s.name.clone(), host: s.host.clone(), exit: if s.is_external_exit() { s.host.clone() } else { s.origin.clone().unwrap_or_default() }, kind: s.kind_label() })
        .collect();
    let mut tags: Vec<String> = outbounds.iter().map(|o| o.tag.clone()).collect();
    tags.push(DIRECT.to_string());
    let ports = alloc_ports(&tags)?;
    let mut targets = vec![ProbeTarget { id: CANARY.into(), url: canary_url.into() }];
    // у одного сервера переключателей категорий нет, и пробы категорий ничего не решают
    if servers.len() > 1 {
        targets.extend(categories.iter().filter(|c| c.enabled).map(|c| ProbeTarget { id: c.id.clone(), url: c.probe_url.clone() }));
    }
    let pinned = match selected {
        Some(n) => Some(server_tag(servers.iter().position(|s| s.name == n).with_context(|| format!("сервера `{n}` нет в списке"))?)),
        None => None,
    };
    Ok(ProbePlan { ports, targets, outbounds, pinned })
}

fn alloc_ports(tags: &[String]) -> Result<Vec<ProbePort>> {
    // держим все слушатели открытыми, пока не выбрали все порты: иначе ОС может выдать один порт дважды
    let mut held = Vec::new();
    let mut ports = Vec::new();
    for t in tags {
        let l = TcpListener::bind(("127.0.0.1", 0)).context("нет свободного порта для пробного входа")?;
        ports.push(ProbePort { tag: t.clone(), port: l.local_addr()?.port() });
        held.push(l);
    }
    Ok(ports)
}

// ───────────────────────── пробы ─────────────────────────

/// Тип ошибки по тексту (цепочка причин reqwest). Порядок проверок важен: TLS и сброс раньше «прокси».
pub fn kind_from_message(msg: &str, timeout: bool) -> FailKind {
    let m = msg.to_lowercase();
    if timeout || m.contains("timed out") || m.contains("deadline") {
        FailKind::Timeout
    } else if m.contains("certificate") || m.contains("tls") || m.contains("handshake") || m.contains("ssl") {
        FailKind::Tls
    } else if m.contains("reset") || m.contains("eof") || m.contains("broken pipe") || m.contains("closed") || m.contains("aborted") {
        FailKind::Reset
    } else if m.contains("dns") || m.contains("resolve") || m.contains("lookup") {
        FailKind::Dns
    } else if m.contains("tunnel") || m.contains("proxy") || m.contains("refused") {
        FailKind::Proxy
    } else {
        FailKind::Other
    }
}

/// 502 без заголовка Date генерирует сам sing-box, когда не может дозвониться до сервера (у настоящих сайтов Date есть
/// всегда): это отказ пути, а не «болезнь сайта». Для https-целей (туннель CONNECT) такого ответа нет, там видна ошибка соединения.
pub fn outcome_from_response(status: u16, has_date: bool, ms: u64) -> Outcome {
    if status == 502 && !has_date {
        return Outcome::Fail { kind: FailKind::Proxy };
    }
    Outcome::from_status(status, ms)
}

async fn probe_one(port: u16, secret: &str, url: &str, timeout: Duration) -> Outcome {
    let build = || -> Result<reqwest::Client> {
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))?.basic_auth(PROBE_USER, secret);
        Ok(reqwest::Client::builder()
            .proxy(proxy)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
            .build()?)
    };
    let Ok(client) = build() else { return Outcome::Fail { kind: FailKind::Other } };
    let t0 = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(r) => outcome_from_response(r.status().as_u16(), r.headers().contains_key(reqwest::header::DATE), t0.elapsed().as_millis() as u64),
        Err(e) => {
            let mut chain = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                chain.push_str(": ");
                chain.push_str(&s.to_string());
                src = s.source();
            }
            Outcome::Fail { kind: kind_from_message(&chain, e.is_timeout()) }
        }
    }
}

/// Один раунд: каждая цель через каждый outbound и напрямую, всё параллельно.
/// Один раунд проб без внешних exit: их владелец видел бы адреса проб (канарейка и страницы категорий) каждый раунд,
/// хотя трафик на них не уходит. Проверять их нужно только при разрешении (`probe_round_with`).
pub async fn probe_round(link: &Link, timeout: Duration) -> Round {
    probe_round_with(link, timeout, false).await
}

pub async fn probe_round_with(link: &Link, timeout: Duration, include_external: bool) -> Round {
    let external: Vec<&str> = link.plan.outbounds.iter().filter(|o| o.is_external()).map(|o| o.tag.as_str()).collect();
    let skip = |tag: &str| !include_external && external.contains(&tag);
    let mut jobs = Vec::new();
    for pp in link.plan.ports.iter().filter(|pp| !skip(&pp.tag)) {
        for t in &link.plan.targets {
            let (tag, id, url, port, secret) = (pp.tag.clone(), t.id.clone(), t.url.clone(), pp.port, link.secret.clone());
            jobs.push(tokio::spawn(async move { (tag, id, probe_one(port, &secret, &url, timeout).await) }));
        }
    }
    let mut round = Round { outbounds: link.plan.outbounds.iter().filter(|o| !skip(&o.tag)).cloned().collect(), ..Default::default() };
    for j in jobs {
        if let Ok((tag, id, out)) = j.await {
            if tag == DIRECT {
                round.direct.insert(id, out);
            } else {
                round.results.insert((tag, id), out);
            }
        }
    }
    round
}

// ───────────────────────── Clash API ─────────────────────────

async fn clash(link: &Link, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
    let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build()?;
    let mut rb = c.request(method, format!("http://127.0.0.1:{}{path}", link.clash_port)).bearer_auth(&link.secret);
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    let r = rb.send().await?;
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("{}", v.get("message").and_then(|x| x.as_str()).unwrap_or(status.as_str()));
    }
    Ok(v)
}

async fn now_of(link: &Link, name: &str) -> Result<String> {
    let v = clash(link, reqwest::Method::GET, &format!("/proxies/{name}"), None).await?;
    Ok(v.get("now").and_then(|n| n.as_str()).unwrap_or("").to_string())
}

/// Раскрыть цепочку переключателей до настоящего outbound (`srv-N` или `direct`).
async fn resolve(link: &Link, name: &str) -> Option<String> {
    let mut cur = name.to_string();
    for _ in 0..5 {
        if cur == DIRECT || cur.starts_with("srv-") {
            return Some(cur);
        }
        cur = now_of(link, &cur).await.ok().filter(|n| !n.is_empty())?;
    }
    None
}

/// Жив ли Clash API (то есть sing-box).
pub async fn alive(link: &Link) -> bool {
    clash(link, reqwest::Method::GET, "/version", None).await.is_ok()
}

pub async fn set_selector(link: &Link, selector: &str, to: &str) -> Result<()> {
    clash(link, reqwest::Method::PUT, &format!("/proxies/{selector}"), Some(json!({ "name": to }))).await?;
    Ok(())
}

async fn selector_views(link: &Link) -> Vec<SelectorView> {
    let mut views = Vec::new();
    for t in link.plan.targets.iter().filter(|t| t.id != CANARY) {
        let sel = selector_tag(&t.id);
        let Ok(current) = now_of(link, &sel).await else { continue }; // переключателя нет (один сервер)
        views.push(SelectorView {
            category: t.id.clone(),
            selector: sel,
            effective: resolve(link, &current).await,
            home_effective: resolve(link, "proxy").await,
            current,
            home: "proxy".into(),
        });
    }
    // Пользователь закрепил сервер: общий переключатель тоже может уйти на запасной и вернуться
    if let Some(pin) = &link.plan.pinned {
        if let Ok(current) = now_of(link, "proxy").await {
            views.push(SelectorView {
                category: CANARY.into(),
                selector: "proxy".into(),
                effective: resolve(link, &current).await,
                home_effective: Some(pin.clone()),
                current,
                home: pin.clone(),
            });
        }
    }
    views
}

// ───────────────────────── цикл ─────────────────────────

#[derive(Clone, Debug)]
pub struct WatchCfg {
    pub timeout: Duration,
    pub degraded: DegradedPolicy,
    pub tracker: TrackerCfg,
    pub router: RouterCfg,
    /// применять решения роутера (иначе только наблюдаем и показываем, что сделали бы)
    pub switch: bool,
}

impl Default for WatchCfg {
    fn default() -> Self {
        WatchCfg { timeout: Duration::from_secs(8), degraded: DegradedPolicy::default(), tracker: TrackerCfg::default(), router: RouterCfg::default(), switch: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairRow {
    pub category: String,
    pub tag: String,
    pub name: String,
    pub health: Health,
    pub class: Option<FailClass>,
    pub degraded: bool,
    pub ms: Option<u64>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at: u64,
    pub text: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub updated: u64,
    pub round: u64,
    pub pairs: Vec<PairRow>,
    /// последние события (смены состояния и переключения), новые в конце
    pub events: Vec<Event>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn snapshot_path() -> std::path::PathBuf {
    config_dir().join("runtime").join("prober.json")
}

pub fn load_snapshot() -> Option<Snapshot> {
    serde_json::from_str(&fs::read_to_string(snapshot_path()).ok()?).ok()
}

pub fn clear_snapshot() {
    let _ = fs::remove_file(snapshot_path());
}

pub struct Watcher {
    pub link: Link,
    pub cfg: WatchCfg,
    pub tracker: Tracker,
    router: Router,
    round: u64,
    events: Vec<Event>,
    order: Vec<String>,
}

pub struct Step {
    pub round: Round,
    pub entries: Vec<Entry>,
    pub transitions: Vec<Transition>,
    pub actions: Vec<Action>,
    /// сообщения о применении действий (в том числе об ошибках)
    pub applied: Vec<String>,
}

impl Watcher {
    pub fn new(link: Link, cfg: WatchCfg) -> Self {
        let order = link.plan.outbounds.iter().map(|o| o.tag.clone()).collect();
        let mut cfg = cfg;
        cfg.router.external = link.plan.outbounds.iter().filter(|o| o.is_external()).map(|o| o.tag.clone()).collect();
        Watcher { tracker: Tracker::new(cfg.tracker.clone()), router: Router::new(cfg.router.clone()), link, cfg, round: 0, events: Vec::new(), order }
    }

    fn name_of(&self, tag: &str) -> String {
        self.link.plan.outbounds.iter().find(|o| o.tag == tag).map(|o| o.name.clone()).unwrap_or_else(|| tag.to_string())
    }

    fn log(&mut self, text: String) {
        self.events.push(Event { at: now_secs(), text });
        let n = self.events.len();
        if n > 40 {
            self.events.drain(..n - 40);
        }
    }

    /// Один раунд: пробы, диагноз, состояния, решения, применение.
    pub async fn step(&mut self) -> Result<Step> {
        self.round += 1;
        let cats: Vec<String> = self.link.plan.targets.iter().map(|t| t.id.clone()).filter(|id| id != CANARY).collect();
        let round = probe_round_with(&self.link, self.cfg.timeout, self.cfg.router.allow_external_exit).await;
        let entries = classify(&round, &cats, &self.cfg.degraded);
        let transitions = self.tracker.apply(&entries, &round);
        for t in &transitions {
            let what = if t.category == CANARY { "туннель".to_string() } else { format!("категория {}", t.category) };
            let class = t.class.map(|c| format!(" [{}]", c.as_str())).unwrap_or_default();
            self.log(format!("{} · {}: {:?} → {:?}{class}", self.name_of(&t.tag), what, t.from, t.to));
        }

        let views = selector_views(&self.link).await;
        let actions = self.router.decide(&self.tracker, &views, &self.order);
        let mut applied = Vec::new();
        for a in &actions {
            let (sel, to, why, verb) = match a {
                Action::Pin { selector, tag, reason, .. } => (selector, tag, reason, "переключено на"),
                Action::Release { selector, to, reason, .. } => (selector, to, reason, "возвращено на"),
            };
            let target = if to == "proxy" { "общий маршрут".to_string() } else { self.name_of(to) };
            if self.cfg.switch {
                match set_selector(&self.link, sel, to).await {
                    Ok(()) => {
                        let m = format!("{sel}: {verb} {target} ({why})");
                        self.log(m.clone());
                        applied.push(m);
                    }
                    Err(e) => applied.push(format!("{sel}: не удалось переключить на {target}: {e:#}")),
                }
            } else {
                applied.push(format!("{sel}: было бы {verb} {target} ({why})"));
            }
        }
        self.save();
        Ok(Step { round, entries, transitions, actions, applied })
    }

    pub fn snapshot(&self) -> Snapshot {
        let pairs = self
            .tracker
            .pairs()
            .map(|((cat, tag), st)| PairRow { category: cat.clone(), tag: tag.clone(), name: self.name_of(tag), health: st.health, class: st.class, degraded: st.degraded, ms: st.ms, reason: st.reason.clone() })
            .collect();
        Snapshot { updated: now_secs(), round: self.round, pairs, events: self.events.clone() }
    }

    fn save(&self) {
        let _ = fs::create_dir_all(snapshot_path().parent().unwrap());
        if let Ok(b) = serde_json::to_vec_pretty(&self.snapshot()) {
            let tmp = snapshot_path().with_extension("tmp");
            if write_secret_file(&tmp, &b).is_ok() {
                let _ = fs::rename(&tmp, snapshot_path());
            }
        }
    }
}

/// Текстовая таблица «outbound × цель» для CLI.
pub fn render_matrix(round: &Round, plan: &ProbePlan) -> String {
    let ids: Vec<&str> = plan.targets.iter().map(|t| t.id.as_str()).collect();
    let mut rows: Vec<Vec<String>> = vec![std::iter::once("".to_string()).chain(ids.iter().map(|s| s.to_string())).collect()];
    for o in &plan.outbounds {
        let mut r = vec![format!("{} ({})", o.name, o.kind)];
        r.extend(ids.iter().map(|id| round.results.get(&(o.tag.clone(), id.to_string())).map(Outcome::brief).unwrap_or_else(|| "-".into())));
        rows.push(r);
    }
    let mut r = vec!["напрямую".to_string()];
    r.extend(ids.iter().map(|id| round.direct.get(*id).map(Outcome::brief).unwrap_or_else(|| "-".into())));
    rows.push(r);
    let w: Vec<usize> = (0..rows[0].len()).map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0)).collect();
    rows.iter().map(|r| r.iter().zip(&w).map(|(s, w)| format!("{s:<w$}")).collect::<Vec<_>>().join("  ")).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::profile::Kind;

    fn srv(name: &str, host: &str) -> Server {
        Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name: name.into(), host: host.into(), port: 443, uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), kind: Kind::Vless,
            password: None, method: None, pin: None, flow: None, security: "reality".into(), sni: "x.com".into(), fingerprint: "chrome".into(),
            public_key: Some("k".into()), short_id: Some("ab".into()),
        }
    }

    #[test]
    fn plan_has_distinct_ports_canary_first_and_pinned_tag() {
        let cats = crate::client::categories::builtin();
        let p = make_plan(&[srv("a", "h1"), srv("b", "h2")], Some("b"), &cats, "https://c.example/").unwrap();
        let mut ports: Vec<u16> = p.ports.iter().map(|x| x.port).collect();
        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), 3, "два сервера и direct");
        assert!(p.ports.iter().any(|x| x.tag == DIRECT));
        assert_eq!(p.targets[0].id, CANARY);
        assert_eq!(p.targets.len(), 1 + cats.len());
        assert_eq!(p.pinned.as_deref(), Some("srv-2"));
        assert!(make_plan(&[srv("a", "h1")], Some("zzz"), &cats, "https://c.example/").is_err());
    }

    #[test]
    fn single_server_plan_has_no_category_probes() {
        let p = make_plan(&[srv("a", "h1")], None, &crate::client::categories::builtin(), "https://c.example/").unwrap();
        assert_eq!(p.targets.len(), 1);
    }

    #[test]
    fn disabled_categories_are_not_probed() {
        let mut cats = crate::client::categories::builtin();
        cats[0].enabled = false;
        let p = make_plan(&[srv("a", "h1"), srv("b", "h2")], None, &cats, "https://c.example/").unwrap();
        assert!(!p.targets.iter().any(|t| t.id == cats[0].id));
    }

    #[test]
    fn error_text_maps_to_kinds() {
        assert_eq!(kind_from_message("operation timed out", false), FailKind::Timeout);
        assert_eq!(kind_from_message("anything", true), FailKind::Timeout);
        assert_eq!(kind_from_message("error sending request: connection reset by peer", false), FailKind::Reset);
        assert_eq!(kind_from_message("invalid peer certificate: UnknownIssuer", false), FailKind::Tls);
        assert_eq!(kind_from_message("unsuccessful tunnel setup", false), FailKind::Proxy);
        assert_eq!(kind_from_message("dns error: failed to lookup address", false), FailKind::Dns);
        assert_eq!(kind_from_message("???", false), FailKind::Other);
    }

    #[test]
    fn proxy_generated_502_is_a_path_failure_but_site_502_is_not() {
        assert_eq!(outcome_from_response(502, false, 5), Outcome::Fail { kind: FailKind::Proxy });
        assert!(matches!(outcome_from_response(502, true, 5), Outcome::SiteError { status: 502 }));
        assert!(matches!(outcome_from_response(503, false, 5), Outcome::SiteError { .. }));
        assert!(matches!(outcome_from_response(200, false, 5), Outcome::Ok { ms: 5 }));
    }

    #[test]
    fn matrix_renders_all_rows_and_columns() {
        let p = make_plan(&[srv("alpha", "h1"), srv("b", "h2")], None, &crate::client::categories::builtin()[..1], "https://c.example/").unwrap();
        let mut r = Round { outbounds: p.outbounds.clone(), ..Default::default() };
        r.results.insert(("srv-1".into(), CANARY.into()), Outcome::Ok { ms: 42 });
        r.results.insert(("srv-2".into(), CANARY.into()), Outcome::Fail { kind: FailKind::Timeout });
        r.direct.insert(CANARY.into(), Outcome::Ok { ms: 7 });
        let t = render_matrix(&r, &p);
        assert_eq!(t.lines().count(), 4, "{t}");
        assert!(t.contains("42 мс") && t.contains("таймаут") && t.contains("7 мс") && t.contains("напрямую") && t.contains("alpha (vless)"), "{t}");
    }

    #[test]
    fn snapshot_serializes_and_round_trips() {
        let link = Link { clash_port: 1, secret: "s".into(), plan: make_plan(&[srv("a", "h1")], None, &[], "https://c.example/").unwrap() };
        let mut w = Watcher::new(link, WatchCfg::default());
        w.log("событие".into());
        let s = w.snapshot();
        let j = serde_json::to_string(&s).unwrap();
        assert!(!j.contains("\"s\""), "секрет не должен попадать в снимок");
        let back: Snapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(back.events[0].text, "событие");
    }
}
