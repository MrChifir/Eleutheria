//! Пробер и роутер (M4): чистая логика без ввода-вывода.
//!
//! Конвейер одного раунда: результаты проб (`Round`) → `classify` (вердикт для каждой пары
//! «категория × outbound») → `Tracker` (healthy / suspect / failed со счётчиками подряд идущих отказов
//! и гистерезисом восстановления) → `Router::decide` (какие переключатели категорий перевести на другой outbound).
//!
//! Главный принцип классификатора: диагноз ставится только по СРАВНЕНИЮ путей. Один отказ сам по себе ничего
//! не значит (сайт может лежать, отвечать 403 любым ботам или сеть может пропасть целиком), а вот «через этот
//! outbound не открывается, через соседний с другим IP открывается» это уже улика. Если сравнить не с чем
//! или все пути ведут себя одинаково, вердикт `Skip`, и состояние не меняется: ложное переключение хуже,
//! чем отсутствие переключения.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

/// Идентификатор «категории» общей проверки туннеля (нейтральный URL, не привязан к сайту).
pub const CANARY: &str = "canary";
/// Тег прямого выхода (мимо VPN) в пробах и переключателях.
pub const DIRECT: &str = "direct";

/// Класс отказа (названия совпадают с docs/PLAN.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailClass {
    /// этот протокол не проходит, а другой протокол того же сервера работает: взять другой профиль того же сервера
    ProtocolBlocked,
    /// сервер недоступен целиком (IP заблокирован или он лежит): другой сервер или CDN-профиль
    ServerIpBlocked,
    /// туннель жив, но конкретный сайт не пускает этот выходной IP: другой выходной IP для домена
    ExitBlockedBySite,
    /// отказ есть, а сравнить не с чем (единственный outbound или отказывают все пути)
    Unclassified,
}

impl FailClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FailClass::ProtocolBlocked => "PROTOCOL_BLOCKED",
            FailClass::ServerIpBlocked => "SERVER_IP_BLOCKED",
            FailClass::ExitBlockedBySite => "EXIT_BLOCKED_BY_SITE",
            FailClass::Unclassified => "UNCLASSIFIED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailKind {
    Timeout,
    Reset,
    Tls,
    Dns,
    /// ошибка самого локального прокси (порт пробы закрыт, неверный пароль)
    Proxy,
    Other,
}

/// Результат одной пробы (один URL через один outbound).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// получен ответ сайта (любой код, кроме отказных ниже)
    Ok { ms: u64 },
    /// сайт ответил отказом на доступ (403, 451): либо блокирует выходной IP, либо просто не любит ботов
    Denied { status: u16 },
    /// 5xx и прочее: сайт сам болен, к outbound это не относится
    SiteError { status: u16 },
    Fail { kind: FailKind },
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Ok { .. })
    }
    pub fn ms(&self) -> Option<u64> {
        match self {
            Outcome::Ok { ms } => Some(*ms),
            _ => None,
        }
    }
    /// Сводка кода ответа в исход: 403/451 отказ, 5xx болезнь сайта, остальное успех.
    pub fn from_status(status: u16, ms: u64) -> Outcome {
        match status {
            403 | 451 => Outcome::Denied { status },
            500..=599 => Outcome::SiteError { status },
            _ => Outcome::Ok { ms },
        }
    }
    /// Короткое описание для таблиц.
    pub fn brief(&self) -> String {
        match self {
            Outcome::Ok { ms } => format!("{ms} мс"),
            Outcome::Denied { status } => format!("отказ {status}"),
            Outcome::SiteError { status } => format!("сайт {status}"),
            Outcome::Fail { kind } => match kind {
                FailKind::Timeout => "таймаут",
                FailKind::Reset => "сброс",
                FailKind::Tls => "TLS",
                FailKind::Dns => "DNS",
                FailKind::Proxy => "прокси",
                FailKind::Other => "ошибка",
            }
            .to_string(),
        }
    }
}

/// Порт локального пробного входа: трафик с него идёт строго через один outbound (`srv-N` или `direct`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePort {
    pub tag: String,
    pub port: u16,
}

/// Цель пробы категории.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub id: String,
    pub url: String,
}

/// Что нужно прооберу, чтобы работать с запущенным sing-box: пробные порты и цели.
/// Пароль входов совпадает с секретом Clash API (отдельного хранилища нет).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePlan {
    pub ports: Vec<ProbePort>,
    /// первой идёт общая проверка туннеля (`canary`), затем включённые категории
    pub targets: Vec<ProbeTarget>,
    pub outbounds: Vec<OutboundInfo>,
    /// тег сервера, выбранного пользователем вручную (`--server`); None = авто
    #[serde(default)]
    pub pinned: Option<String>,
}

/// Имя переключателя категории в sing-box.
pub fn selector_tag(category: &str) -> String {
    format!("cat-{category}")
}

/// Один outbound-кандидат: сервер × протокол.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundInfo {
    pub tag: String,
    /// имя сервера в списке пользователя
    #[serde(default)]
    pub name: String,
    /// адрес, к которому подключается клиент (входной IP или домен CDN): пути с одним host имеют один входной IP
    pub host: String,
    /// откуда трафик выходит в интернет (у путей через CDN это сервер-источник, у обычных совпадает с `host`).
    /// Пусто = как `host`. Нужно, чтобы путь через CDN не принимали за «другой выходной IP».
    #[serde(default)]
    pub exit: String,
    /// vless | hysteria2 | tuic | ss2022
    pub kind: String,
}

impl OutboundInfo {
    /// Внешний exit (цепочка через свой сервер).
    pub fn is_external(&self) -> bool {
        self.kind == "socks5"
    }

    /// Идентификатор выходного IP.
    pub fn exit_id(&self) -> &str {
        if self.exit.is_empty() { &self.host } else { &self.exit }
    }
}

/// Все пробы одного раунда.
#[derive(Clone, Debug, Default)]
pub struct Round {
    pub outbounds: Vec<OutboundInfo>,
    /// пробы без VPN (id цели → исход)
    pub direct: HashMap<String, Outcome>,
    /// (tag, id цели) → исход
    pub results: HashMap<(String, String), Outcome>,
}

impl Round {
    fn res(&self, tag: &str, target: &str) -> Option<&Outcome> {
        self.results.get(&(tag.to_string(), target.to_string()))
    }
    fn tunnel_ok(&self, tag: &str) -> bool {
        self.res(tag, CANARY).is_some_and(Outcome::is_ok)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// работает, но заметно хуже остальных: понизить приоритет
    Degraded,
    Failed(FailClass),
    /// улик недостаточно: состояние не трогаем
    Skip,
    /// туннель до сервера не работает: отказ уже записан на уровне canary, категория не двигается
    Inherit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub category: String,
    pub tag: String,
    pub verdict: Verdict,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct DegradedPolicy {
    /// абсолютный порог задержки до ответа
    pub abs_ms: u64,
    /// и во сколько раз хуже лучшего соседа
    pub factor: u64,
}

impl Default for DegradedPolicy {
    fn default() -> Self {
        DegradedPolicy { abs_ms: 2500, factor: 2 }
    }
}

fn degraded(ms: u64, peers: &[u64], p: &DegradedPolicy) -> bool {
    match peers.iter().min() {
        Some(best) => ms >= p.abs_ms && ms >= best.saturating_mul(p.factor),
        None => ms >= p.abs_ms * 2, // сравнить не с чем: порог строже
    }
}

/// Диагноз раунда. `categories` без `canary`: он классифицируется всегда.
pub fn classify(round: &Round, categories: &[String], pol: &DegradedPolicy) -> Vec<Entry> {
    let mut out = Vec::new();
    let any_tunnel = round.outbounds.iter().any(|o| round.tunnel_ok(&o.tag));
    let direct_canary = round.direct.get(CANARY).is_some_and(Outcome::is_ok);

    // Нет сети вообще: не виним ни протоколы, ни серверы.
    if !any_tunnel && !direct_canary {
        for cat in std::iter::once(CANARY).chain(categories.iter().map(String::as_str)) {
            for o in &round.outbounds {
                out.push(Entry { category: cat.into(), tag: o.tag.clone(), verdict: Verdict::Skip, reason: "нет связи ни напрямую, ни через VPN: похоже, пропала сеть".into() });
            }
        }
        return out;
    }

    // 1. Туннель (canary)
    for o in &round.outbounds {
        let (verdict, reason) = match round.res(&o.tag, CANARY) {
            None => (Verdict::Skip, "проба не выполнялась".to_string()),
            Some(Outcome::Ok { ms }) => {
                let peers: Vec<u64> = round.outbounds.iter().filter(|p| p.tag != o.tag).filter_map(|p| round.res(&p.tag, CANARY)?.ms()).collect();
                if degraded(*ms, &peers, pol) { (Verdict::Degraded, format!("туннель медленный: {ms} мс")) } else { (Verdict::Ok, format!("{ms} мс")) }
            }
            Some(Outcome::SiteError { .. }) => (Verdict::Skip, "контрольный сайт вернул ошибку 5xx".to_string()),
            Some(fail) => classify_tunnel_failure(round, o, fail),
        };
        out.push(Entry { category: CANARY.into(), tag: o.tag.clone(), verdict, reason });
    }

    // 2. Категории
    for cat in categories {
        for o in &round.outbounds {
            let (verdict, reason) = classify_category(round, o, cat, pol);
            out.push(Entry { category: cat.clone(), tag: o.tag.clone(), verdict, reason });
        }
    }
    out
}

fn classify_tunnel_failure(round: &Round, o: &OutboundInfo, fail: &Outcome) -> (Verdict, String) {
    let alive = |p: &&OutboundInfo| p.tag != o.tag && round.tunnel_ok(&p.tag);
    let same_host = round.outbounds.iter().filter(alive).any(|p| p.host == o.host);
    let other_host: Vec<&OutboundInfo> = round.outbounds.iter().filter(alive).filter(|p| p.host != o.host).collect();
    if same_host {
        return (Verdict::Failed(FailClass::ProtocolBlocked), format!("{}: {}; другой протокол того же сервера работает", o.kind, fail.brief()));
    }
    if !other_host.is_empty() {
        let same_kind_works = other_host.iter().any(|p| p.kind == o.kind);
        let note = if same_kind_works { "" } else { " (или блокируется протокол: у рабочих серверов другие протоколы)" };
        return (Verdict::Failed(FailClass::ServerIpBlocked), format!("сервер {}: {}; другие серверы работают{note}", o.host, fail.brief()));
    }
    (Verdict::Failed(FailClass::Unclassified), format!("{}; рабочих путей для сравнения нет", fail.brief()))
}

fn classify_category(round: &Round, o: &OutboundInfo, cat: &str, pol: &DegradedPolicy) -> (Verdict, String) {
    if !round.tunnel_ok(&o.tag) {
        return (Verdict::Inherit, "туннель недоступен".into());
    }
    let Some(r) = round.res(&o.tag, cat) else { return (Verdict::Skip, "проба не выполнялась".into()) };
    match r {
        Outcome::SiteError { status } => (Verdict::Skip, format!("сайт отвечает {status}: проблема не в маршруте")),
        Outcome::Ok { ms } => {
            let peers: Vec<u64> = round.outbounds.iter().filter(|p| p.tag != o.tag && round.tunnel_ok(&p.tag)).filter_map(|p| round.res(&p.tag, cat)?.ms()).collect();
            if degraded(*ms, &peers, pol) { (Verdict::Degraded, format!("медленно: {ms} мс")) } else { (Verdict::Ok, format!("{ms} мс")) }
        }
        Outcome::Denied { .. } | Outcome::Fail { .. } => {
            let peers_ok: Vec<&OutboundInfo> = round.outbounds.iter().filter(|p| p.tag != o.tag && round.tunnel_ok(&p.tag) && round.res(&p.tag, cat).is_some_and(Outcome::is_ok)).collect();
            if peers_ok.iter().any(|p| p.exit_id() != o.exit_id()) {
                return (Verdict::Failed(FailClass::ExitBlockedBySite), format!("{}; через другой выход открывается: выходной IP {} не пускают", r.brief(), o.exit_id()));
            }
            if !peers_ok.is_empty() {
                return (Verdict::Failed(FailClass::ProtocolBlocked), format!("{}; через другой протокол того же сервера открывается", r.brief()));
            }
            // Ни один VPN-путь не открывает. Сравниваем с прямым доступом.
            match round.direct.get(cat) {
                Some(d) if d.is_ok() => (Verdict::Failed(FailClass::ExitBlockedBySite), format!("{}; напрямую открывается, через VPN нет: сайт не пускает выходные IP", r.brief())),
                Some(_) => (Verdict::Skip, format!("{}; недоступен и напрямую: проблема сайта или одинаковый отказ всем", r.brief())),
                None => (Verdict::Skip, format!("{}; сравнить не с чем", r.brief())),
            }
        }
    }
}

// ───────────────────────── состояние пар ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Suspect,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairState {
    pub health: Health,
    /// подряд идущие отказы
    pub fails: u32,
    /// подряд идущие успехи
    pub oks: u32,
    pub class: Option<FailClass>,
    pub degraded: bool,
    pub ms: Option<u64>,
    pub reason: String,
}

impl Default for PairState {
    fn default() -> Self {
        PairState { health: Health::Healthy, fails: 0, oks: 0, class: None, degraded: false, ms: None, reason: String::new() }
    }
}

#[derive(Clone, Debug)]
pub struct TrackerCfg {
    /// сколько отказов подряд переводят пару в failed (первый отказ даёт suspect)
    pub failed_after: u32,
    /// сколько успехов подряд нужно failed-паре, чтобы вернуться в healthy
    pub recover_after: u32,
}

impl Default for TrackerCfg {
    fn default() -> Self {
        TrackerCfg { failed_after: 3, recover_after: 2 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub category: String,
    pub tag: String,
    pub from: Health,
    pub to: Health,
    pub class: Option<FailClass>,
}

#[derive(Default)]
pub struct Tracker {
    pub cfg: TrackerCfg,
    pairs: BTreeMap<(String, String), PairState>,
    /// категория → открывается ли напрямую (из последнего раунда)
    direct_ok: HashMap<String, bool>,
}

impl Tracker {
    pub fn new(cfg: TrackerCfg) -> Self {
        Tracker { cfg, ..Default::default() }
    }

    pub fn get(&self, category: &str, tag: &str) -> PairState {
        self.pairs.get(&(category.to_string(), tag.to_string())).cloned().unwrap_or_default()
    }

    pub fn pairs(&self) -> impl Iterator<Item = (&(String, String), &PairState)> {
        self.pairs.iter()
    }

    pub fn direct_ok(&self, category: &str) -> bool {
        self.direct_ok.get(category).copied().unwrap_or(false)
    }

    pub fn note_direct(&mut self, round: &Round) {
        self.direct_ok = round.direct.iter().map(|(k, v)| (k.clone(), v.is_ok())).collect();
    }

    pub fn apply(&mut self, entries: &[Entry], round: &Round) -> Vec<Transition> {
        self.note_direct(round);
        let mut moves = Vec::new();
        for e in entries {
            if matches!(e.verdict, Verdict::Skip | Verdict::Inherit) {
                continue;
            }
            let ms = round.results.get(&(e.tag.clone(), e.category.clone())).and_then(Outcome::ms);
            let st = self.pairs.entry((e.category.clone(), e.tag.clone())).or_default();
            let from = st.health;
            st.reason = e.reason.clone();
            match &e.verdict {
                Verdict::Ok | Verdict::Degraded => {
                    st.fails = 0;
                    st.oks += 1;
                    st.class = None;
                    st.degraded = e.verdict == Verdict::Degraded;
                    st.ms = ms;
                    if st.health == Health::Suspect || (st.health == Health::Failed && st.oks >= self.cfg.recover_after) {
                        st.health = Health::Healthy;
                    }
                }
                Verdict::Failed(class) => {
                    st.oks = 0;
                    st.fails += 1;
                    st.class = Some(*class);
                    st.ms = None;
                    st.health = if st.fails >= self.cfg.failed_after { Health::Failed } else { Health::Suspect };
                }
                Verdict::Skip | Verdict::Inherit => {}
            }
            if st.health != from {
                moves.push(Transition { category: e.category.clone(), tag: e.tag.clone(), from, to: st.health, class: st.class });
            }
        }
        moves
    }

    /// Здоров ли путь для категории: туннель не failed и пара категории не failed.
    pub fn usable(&self, category: &str, tag: &str) -> bool {
        self.get(CANARY, tag).health != Health::Failed && self.get(category, tag).health != Health::Failed
    }

    /// Ключ сортировки кандидатов: меньше значит лучше.
    fn rank(&self, category: &str, tag: &str, order: usize) -> (u8, u8, u64, usize) {
        let c = self.get(category, tag);
        let t = self.get(CANARY, tag);
        let suspect = (c.health == Health::Suspect || t.health == Health::Suspect) as u8;
        let slow = (c.degraded || t.degraded) as u8;
        (suspect, slow, c.ms.or(t.ms).unwrap_or(u64::MAX), order)
    }
}

// ───────────────────────── решения роутера ─────────────────────────

/// Один управляемый переключатель sing-box.
#[derive(Clone, Debug)]
pub struct SelectorView {
    /// id категории в трекере (для общего переключателя `proxy` это `canary`)
    pub category: String,
    /// тег переключателя в sing-box (`cat-video`, `proxy`)
    pub selector: String,
    /// куда он указывает сейчас (тег серверов, `proxy`, `auto`, `direct`)
    pub current: String,
    /// куда он должен указывать, когда всё хорошо
    pub home: String,
    /// настоящий outbound, куда сейчас уходит трафик (`current`, раскрытый через цепочку переключателей); `direct` = мимо VPN
    pub effective: Option<String>,
    /// настоящий outbound, куда ведёт `home`
    pub home_effective: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// перевести переключатель на сервер
    Pin { selector: String, category: String, tag: String, reason: String },
    /// вернуть переключатель домой
    Release { selector: String, category: String, to: String, reason: String },
}

#[derive(Clone, Debug)]
pub struct RouterCfg {
    /// не переключать одну категорию чаще, чем раз в столько раундов
    pub min_dwell: u64,
    /// сколько здоровых раундов подряд должен показать «домашний» путь, прежде чем вернуть на него трафик
    pub release_after: u32,
    /// разрешить для категории выход мимо VPN, если ни один VPN-путь не открывается, а напрямую открывается
    pub allow_direct: bool,
    /// разрешить для категории выход через внешний exit (чужой прокси, который видит трафик этой категории):
    /// только если сайт не пускает выходной IP всех своих серверов, а через внешний exit открывается
    pub allow_external_exit: bool,
    /// теги внешних exit (заполняет наблюдатель по плану)
    pub external: Vec<String>,
}

impl Default for RouterCfg {
    fn default() -> Self {
        RouterCfg { min_dwell: 3, release_after: 3, allow_direct: false, allow_external_exit: false, external: Vec::new() }
    }
}

#[derive(Default)]
pub struct Router {
    pub cfg: RouterCfg,
    round: u64,
    last_switch: HashMap<String, u64>,
}

impl Router {
    pub fn new(cfg: RouterCfg) -> Self {
        Router { cfg, ..Default::default() }
    }

    /// `order` задаёт приоритет серверов при равенстве (порядок в списке пользователя).
    pub fn decide(&mut self, tr: &Tracker, views: &[SelectorView], order: &[String]) -> Vec<Action> {
        self.round += 1;
        let mut acts = Vec::new();
        for v in views {
            let Some(act) = self.decide_one(tr, v, order) else { continue };
            self.last_switch.insert(v.selector.clone(), self.round);
            acts.push(act);
        }
        acts
    }

    fn decide_one(&self, tr: &Tracker, v: &SelectorView, order: &[String]) -> Option<Action> {
        if let Some(r) = self.last_switch.get(&v.selector) {
            if self.round.saturating_sub(*r) < self.cfg.min_dwell {
                return None;
            }
        }
        let cat = v.category.as_str();
        let pos = |t: &str| order.iter().position(|x| x == t).unwrap_or(usize::MAX);
        let on_direct = v.effective.as_deref() == Some(DIRECT) && v.current == DIRECT;
        let eff_usable = match v.effective.as_deref() {
            Some(DIRECT) => true, // на прямом выходе ничего не «ломается»: вернуться решаем ниже
            Some(t) => tr.usable(cat, t),
            None => true, // не удалось выяснить, куда идёт трафик: не трогаем
        };

        if eff_usable && !on_direct {
            // Сидим на запасном пути, а дом починился и стабильно здоров: вернуться.
            if v.current != v.home {
                if let Some(h) = v.home_effective.as_deref().filter(|h| *h != DIRECT) {
                    let hs = tr.get(cat, h);
                    let ts = tr.get(CANARY, h);
                    if hs.health == Health::Healthy && ts.health == Health::Healthy && hs.oks >= self.cfg.release_after && ts.oks >= self.cfg.release_after && !hs.degraded {
                        return Some(Action::Release { selector: v.selector.clone(), category: v.category.clone(), to: v.home.clone(), reason: format!("{h} снова стабильно работает") });
                    }
                }
            }
            return None;
        }

        // Текущий путь сломан (или мы на прямом выходе): ищем лучший VPN-путь.
        let cur = v.effective.as_deref().unwrap_or("");
        let is_ext = |t: &str| self.cfg.external.iter().any(|x| x == t);
        // внешние exit сюда не попадают: до них доходим только отдельным правилом ниже
        let mut cands: Vec<&String> = order.iter().filter(|t| t.as_str() != cur && !is_ext(t) && tr.usable(cat, t)).collect();
        cands.sort_by_key(|t| tr.rank(cat, t, pos(t)));
        if let Some(best) = cands.first() {
            if on_direct && !self.cfg.allow_direct {
                return None;
            }
            let why = tr.get(cat, cur).class.or(tr.get(CANARY, cur).class).map(FailClass::as_str).unwrap_or("отказ");
            // если лучший путь совпал с домом, это возврат, а не закрепление
            if v.home_effective.as_deref() == Some(best.as_str()) && v.current != v.home {
                return Some(Action::Release { selector: v.selector.clone(), category: v.category.clone(), to: v.home.clone(), reason: format!("{cur}: {why}") });
            }
            if v.current == **best {
                return None;
            }
            return Some(Action::Pin { selector: v.selector.clone(), category: v.category.clone(), tag: (*best).clone(), reason: format!("{cur}: {why}") });
        }
        // Свои пути не открывают категорию. Если классификатор говорит «сайт не пускает наш выходной IP», а внешний
        // exit категорию уверенно открывает, это единственный случай, когда трафик уходит на чужой прокси
        if self.cfg.allow_external_exit && cat != CANARY && !on_direct && tr.get(cat, cur).class == Some(FailClass::ExitBlockedBySite) {
            let mut ex: Vec<&String> = order
                .iter()
                .filter(|t| is_ext(t) && t.as_str() != cur && tr.get(cat, t).health == Health::Healthy && tr.get(cat, t).oks >= 1 && tr.get(CANARY, t).health == Health::Healthy && tr.get(CANARY, t).oks >= 1)
                .collect();
            ex.sort_by_key(|t| tr.rank(cat, t, pos(t)));
            if let Some(best) = ex.first() {
                if v.current != **best {
                    return Some(Action::Pin { selector: v.selector.clone(), category: v.category.clone(), tag: (*best).clone(), reason: format!("{cur}: сайт не пускает выходной IP, через внешний exit открывается") });
                }
                return None;
            }
        }
        // VPN-путей не осталось
        if self.cfg.allow_direct && cat != CANARY && tr.direct_ok(cat) && v.current != DIRECT {
            return Some(Action::Pin { selector: v.selector.clone(), category: v.category.clone(), tag: DIRECT.into(), reason: "ни один VPN-путь не открывает, напрямую открывается".into() });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ob(tag: &str, host: &str, kind: &str) -> OutboundInfo {
        OutboundInfo { tag: tag.into(), name: tag.into(), host: host.into(), exit: String::new(), kind: kind.into() }
    }
    fn ok(ms: u64) -> Outcome {
        Outcome::Ok { ms }
    }
    fn timeout() -> Outcome {
        Outcome::Fail { kind: FailKind::Timeout }
    }

    /// builder: (tag, target, outcome)
    fn round(obs: Vec<OutboundInfo>, res: &[(&str, &str, Outcome)], direct: &[(&str, Outcome)]) -> Round {
        Round {
            outbounds: obs,
            results: res.iter().map(|(t, c, o)| ((t.to_string(), c.to_string()), o.clone())).collect(),
            direct: direct.iter().map(|(c, o)| (c.to_string(), o.clone())).collect(),
        }
    }
    fn cats() -> Vec<String> {
        vec!["video".into()]
    }
    fn verdict(es: &[Entry], cat: &str, tag: &str) -> Verdict {
        es.iter().find(|e| e.category == cat && e.tag == tag).unwrap().verdict.clone()
    }

    // ── классификатор ──

    #[test]
    fn everything_fine_is_ok() {
        let r = round(vec![ob("a", "h1", "vless")], &[("a", CANARY, ok(100)), ("a", "video", ok(150))], &[(CANARY, ok(30)), ("video", ok(40))]);
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Ok);
        assert_eq!(verdict(&es, "video", "a"), Verdict::Ok);
    }

    #[test]
    fn protocol_blocked_when_sibling_protocol_on_same_host_works() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h1", "hysteria2")],
            &[("a", CANARY, timeout()), ("b", CANARY, ok(90)), ("b", "video", ok(100))],
            &[(CANARY, ok(20))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Failed(FailClass::ProtocolBlocked));
        assert_eq!(verdict(&es, CANARY, "b"), Verdict::Ok);
        assert_eq!(verdict(&es, "video", "a"), Verdict::Inherit, "категория на мёртвом туннеле не двигается");
    }

    #[test]
    fn server_ip_blocked_when_all_paths_of_the_host_die_but_other_host_lives() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h1", "hysteria2"), ob("c", "h2", "vless")],
            &[("a", CANARY, timeout()), ("b", CANARY, timeout()), ("c", CANARY, ok(80))],
            &[(CANARY, ok(20))],
        );
        let es = classify(&r, &[], &DegradedPolicy::default());
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Failed(FailClass::ServerIpBlocked));
        assert_eq!(verdict(&es, CANARY, "b"), Verdict::Failed(FailClass::ServerIpBlocked));
        assert_eq!(verdict(&es, CANARY, "c"), Verdict::Ok);
        // у рабочего сервера тот же протокол, что у a: протокол не виноват, примечания нет
        let a = es.iter().find(|e| e.tag == "a").unwrap();
        assert!(!a.reason.contains("или блокируется протокол"));
        // а b (hysteria2) сравнивается с vless-сервером: допускаем, что виноват протокол
        let b = es.iter().find(|e| e.tag == "b").unwrap();
        assert!(b.reason.contains("или блокируется протокол"));
    }

    #[test]
    fn single_outbound_failure_is_unclassified_but_still_a_failure() {
        let r = round(vec![ob("a", "h1", "vless")], &[("a", CANARY, timeout())], &[(CANARY, ok(20))]);
        let es = classify(&r, &[], &DegradedPolicy::default());
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Failed(FailClass::Unclassified));
    }

    #[test]
    fn no_network_at_all_blames_nobody() {
        let r = round(vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")], &[("a", CANARY, timeout()), ("b", CANARY, timeout())], &[(CANARY, timeout())]);
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert!(es.iter().all(|e| e.verdict == Verdict::Skip), "{es:?}");
    }

    #[test]
    fn exit_blocked_by_site_when_other_exit_ip_opens_it() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("a", "video", Outcome::Denied { status: 403 }), ("b", "video", ok(200))],
            &[(CANARY, ok(10))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ExitBlockedBySite));
        assert_eq!(verdict(&es, "video", "b"), Verdict::Ok);
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Ok, "сам туннель a исправен");
    }

    #[test]
    fn same_host_other_protocol_opens_site_is_protocol_not_exit() {
        // у одного хоста один выходной IP: «другой выход» тут не причина
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h1", "tuic")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("a", "video", timeout()), ("b", "video", ok(100))],
            &[],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ProtocolBlocked));
    }

    fn ob_cdn(tag: &str, cdn: &str, origin: &str) -> OutboundInfo {
        OutboundInfo { exit: origin.into(), ..ob(tag, cdn, "vless-ws") }
    }

    #[test]
    fn cdn_path_shares_the_exit_ip_of_its_origin_server() {
        // a: Reality на сервере h1, b: тот же сервер через CDN (вход cdn.example, выход h1).
        // Сайт не пускает h1: открывается ли он через b, ничего не говорит о другом выходе
        let r = round(
            vec![ob("a", "h1", "vless"), ob_cdn("b", "cdn.example", "h1")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(90)), ("a", "video", Outcome::Denied { status: 403 }), ("b", "video", Outcome::Denied { status: 403 })],
            &[(CANARY, ok(10)), ("video", Outcome::Denied { status: 403 })],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Skip, "403 всем и напрямую: вердикта нет");
        // если бы пути различались только входом, выход всё равно один и тот же
        let r = round(
            vec![ob("a", "h1", "vless"), ob_cdn("b", "cdn.example", "h1")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(90)), ("a", "video", timeout()), ("b", "video", ok(100))],
            &[],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ProtocolBlocked), "другой выход тут не причина");
    }

    #[test]
    fn cdn_path_of_another_origin_is_another_exit() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob_cdn("b", "cdn.example", "h2")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(90)), ("a", "video", Outcome::Denied { status: 403 }), ("b", "video", ok(100))],
            &[(CANARY, ok(10))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ExitBlockedBySite));
    }

    #[test]
    fn dead_origin_ip_with_working_cdn_path_is_server_ip_blocked() {
        // Reality на h1 умер, а тот же сервер через CDN жив: заблокирован входной IP, лечится CDN-профилем
        let r = round(
            vec![ob("a", "h1", "vless"), ob_cdn("b", "cdn.example", "h1")],
            &[("a", CANARY, timeout()), ("b", CANARY, ok(120))],
            &[(CANARY, ok(10))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, CANARY, "a"), Verdict::Failed(FailClass::ServerIpBlocked));
        assert_eq!(verdict(&es, CANARY, "b"), Verdict::Ok);
    }

    #[test]
    fn uniform_denial_everywhere_including_direct_is_not_blamed_on_us() {
        // Cloudflare-стена: всем ботам 403, напрямую тоже
        let d = Outcome::Denied { status: 403 };
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("a", "video", d.clone()), ("b", "video", d.clone())],
            &[(CANARY, ok(10)), ("video", d)],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Skip);
        assert_eq!(verdict(&es, "video", "b"), Verdict::Skip);
    }

    #[test]
    fn site_open_directly_but_closed_on_every_vpn_exit_is_exit_blocked() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("a", "video", timeout()), ("b", "video", timeout())],
            &[(CANARY, ok(10)), ("video", ok(30))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ExitBlockedBySite));
    }

    #[test]
    fn site_down_everywhere_is_skipped_and_5xx_is_not_our_fault() {
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("a", "video", timeout()), ("b", "video", timeout())],
            &[(CANARY, ok(10)), ("video", timeout())],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Skip);
        let r = round(vec![ob("a", "h1", "vless")], &[("a", CANARY, ok(50)), ("a", "video", Outcome::from_status(503, 40))], &[]);
        assert_eq!(verdict(&classify(&r, &cats(), &DegradedPolicy::default()), "video", "a"), Verdict::Skip);
    }

    #[test]
    fn degraded_needs_both_absolute_and_relative_slowness() {
        let pol = DegradedPolicy::default();
        let mk = |a: u64, b: u64| round(vec![ob("a", "h1", "vless"), ob("b", "h2", "vless")], &[("a", CANARY, ok(a)), ("b", CANARY, ok(b))], &[(CANARY, ok(10))]);
        assert_eq!(verdict(&classify(&mk(3000, 400), &[], &pol), CANARY, "a"), Verdict::Degraded);
        assert_eq!(verdict(&classify(&mk(3000, 2900), &[], &pol), CANARY, "a"), Verdict::Ok, "все медленно: не вина конкретного пути");
        assert_eq!(verdict(&classify(&mk(900, 100), &[], &pol), CANARY, "a"), Verdict::Ok, "медленнее, но в пределах нормы");
    }

    #[test]
    fn status_mapping() {
        assert!(matches!(Outcome::from_status(200, 5), Outcome::Ok { .. }));
        assert!(matches!(Outcome::from_status(302, 5), Outcome::Ok { .. }));
        assert!(matches!(Outcome::from_status(404, 5), Outcome::Ok { .. }), "404 значит, что сайт достижим");
        assert!(matches!(Outcome::from_status(403, 5), Outcome::Denied { .. }));
        assert!(matches!(Outcome::from_status(451, 5), Outcome::Denied { .. }));
        assert!(matches!(Outcome::from_status(502, 5), Outcome::SiteError { .. }));
    }

    // ── трекер ──

    fn entry(cat: &str, tag: &str, v: Verdict) -> Entry {
        Entry { category: cat.into(), tag: tag.into(), verdict: v, reason: String::new() }
    }
    fn feed(t: &mut Tracker, cat: &str, tag: &str, v: Verdict) -> Vec<Transition> {
        t.apply(&[entry(cat, tag, v)], &Round::default())
    }

    #[test]
    fn tracker_suspect_then_failed_after_n_consecutive_failures() {
        let mut t = Tracker::new(TrackerCfg { failed_after: 3, recover_after: 2 });
        let f = Verdict::Failed(FailClass::ServerIpBlocked);
        assert_eq!(feed(&mut t, "video", "a", f.clone())[0].to, Health::Suspect);
        assert!(feed(&mut t, "video", "a", f.clone()).is_empty());
        assert_eq!(feed(&mut t, "video", "a", f.clone())[0].to, Health::Failed);
        assert_eq!(t.get("video", "a").class, Some(FailClass::ServerIpBlocked));
    }

    #[test]
    fn single_failure_between_successes_never_reaches_failed() {
        let mut t = Tracker::default();
        for _ in 0..10 {
            feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified));
            feed(&mut t, "video", "a", Verdict::Ok);
        }
        assert_ne!(t.get("video", "a").health, Health::Failed);
    }

    #[test]
    fn failed_pair_recovers_only_after_k_successes() {
        let mut t = Tracker::new(TrackerCfg { failed_after: 1, recover_after: 3 });
        feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified));
        assert_eq!(t.get("video", "a").health, Health::Failed);
        feed(&mut t, "video", "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Ok);
        assert_eq!(t.get("video", "a").health, Health::Failed);
        let m = feed(&mut t, "video", "a", Verdict::Ok);
        assert_eq!(m[0].to, Health::Healthy);
        // отказ в середине серии сбрасывает прогресс восстановления
        feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified));
        feed(&mut t, "video", "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified));
        feed(&mut t, "video", "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Ok);
        assert_eq!(t.get("video", "a").health, Health::Failed);
    }

    #[test]
    fn skip_and_inherit_leave_state_untouched() {
        let mut t = Tracker::new(TrackerCfg { failed_after: 2, recover_after: 1 });
        feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified));
        for _ in 0..5 {
            assert!(feed(&mut t, "video", "a", Verdict::Skip).is_empty());
            assert!(feed(&mut t, "video", "a", Verdict::Inherit).is_empty());
        }
        let s = t.get("video", "a");
        assert_eq!((s.health, s.fails), (Health::Suspect, 1));
    }

    #[test]
    fn degraded_flag_follows_latest_round() {
        let mut t = Tracker::default();
        feed(&mut t, "video", "a", Verdict::Degraded);
        assert!(t.get("video", "a").degraded);
        feed(&mut t, "video", "a", Verdict::Ok);
        assert!(!t.get("video", "a").degraded);
    }

    // ── роутер ──

    fn order() -> Vec<String> {
        vec!["a".into(), "b".into(), "c".into()]
    }
    fn view(cur: &str, eff: &str, home_eff: &str) -> SelectorView {
        SelectorView { category: "video".into(), selector: "cat-video".into(), current: cur.into(), home: "proxy".into(), effective: Some(eff.into()), home_effective: Some(home_eff.into()) }
    }
    fn fail(t: &mut Tracker, cat: &str, tag: &str) {
        for _ in 0..t.cfg.failed_after {
            feed(t, cat, tag, Verdict::Failed(FailClass::ExitBlockedBySite));
        }
    }

    #[test]
    fn router_leaves_healthy_selector_alone_and_ignores_suspect() {
        let mut r = Router::default();
        let mut t = Tracker::default();
        assert!(r.decide(&t, &[view("proxy", "a", "a")], &order()).is_empty());
        feed(&mut t, "video", "a", Verdict::Failed(FailClass::Unclassified)); // suspect
        assert!(r.decide(&t, &[view("proxy", "a", "a")], &order()).is_empty(), "suspect: ждём подтверждения");
    }

    #[test]
    fn router_pins_to_best_healthy_candidate_when_effective_fails() {
        let mut r = Router::default();
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        feed(&mut t, "video", "b", Verdict::Degraded);
        feed(&mut t, "video", "c", Verdict::Ok);
        let acts = r.decide(&t, &[view("proxy", "a", "a")], &order());
        // b медленный, c нормальный: выбираем c, хотя b раньше в списке
        assert!(matches!(&acts[..], [Action::Pin { tag, selector, .. }] if tag == "c" && selector == "cat-video"), "{acts:?}");
    }

    #[test]
    fn router_never_picks_a_candidate_with_dead_tunnel() {
        let mut r = Router::default();
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        fail(&mut t, CANARY, "b"); // туннель b мёртв (категория b при этом «Inherit», то есть не failed)
        let acts = r.decide(&t, &[view("proxy", "a", "a")], &order());
        assert!(matches!(&acts[..], [Action::Pin { tag, .. }] if tag == "c"), "{acts:?}");
    }

    #[test]
    fn router_does_nothing_when_no_alternative_exists() {
        let mut r = Router::default();
        let mut t = Tracker::default();
        for tag in ["a", "b", "c"] {
            fail(&mut t, "video", tag);
        }
        assert!(r.decide(&t, &[view("proxy", "a", "a")], &order()).is_empty());
    }

    #[test]
    fn router_dwell_prevents_flapping_between_two_bad_paths() {
        let mut r = Router::new(RouterCfg { min_dwell: 3, ..Default::default() });
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        assert_eq!(r.decide(&t, &[view("proxy", "a", "a")], &order()).len(), 1);
        // теперь b тоже отказал, пока мы на нём; в окне dwell переключений нет
        fail(&mut t, "video", "b");
        assert!(r.decide(&t, &[view("cat-pinned", "b", "a")], &order()).is_empty());
        assert!(r.decide(&t, &[view("cat-pinned", "b", "a")], &order()).is_empty());
        assert!(!r.decide(&t, &[view("cat-pinned", "b", "a")], &order()).is_empty(), "после dwell можно");
    }

    #[test]
    fn router_releases_back_home_only_after_stable_recovery() {
        let mut r = Router::new(RouterCfg { min_dwell: 1, release_after: 3, ..Default::default() });
        let mut t = Tracker::new(TrackerCfg { failed_after: 1, recover_after: 1 });
        fail(&mut t, "video", "a");
        feed(&mut t, "video", "b", Verdict::Ok);
        let v = view("b", "b", "a"); // пин на b, дом (proxy) раскрывается в a
        // a ещё failed
        assert!(r.decide(&t, &[v.clone()], &order()).is_empty());
        // a вернулся: 1-2 успеха мало
        feed(&mut t, CANARY, "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Ok);
        assert!(r.decide(&t, &[v.clone()], &order()).is_empty());
        feed(&mut t, CANARY, "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Ok);
        assert!(r.decide(&t, &[v.clone()], &order()).is_empty());
        feed(&mut t, CANARY, "a", Verdict::Ok);
        feed(&mut t, "video", "a", Verdict::Ok);
        let acts = r.decide(&t, &[v], &order());
        assert!(matches!(&acts[..], [Action::Release { to, .. }] if to == "proxy"), "{acts:?}");
    }

    #[test]
    fn router_goes_direct_only_when_explicitly_allowed_and_directly_reachable() {
        let mk = |allow| Router::new(RouterCfg { allow_direct: allow, ..Default::default() });
        let mut t = Tracker::default();
        for tag in ["a", "b", "c"] {
            fail(&mut t, "video", tag);
        }
        t.note_direct(&round(vec![], &[], &[("video", ok(30))]));
        assert!(mk(false).decide(&t, &[view("proxy", "a", "a")], &order()).is_empty());
        let acts = mk(true).decide(&t, &[view("proxy", "a", "a")], &order());
        assert!(matches!(&acts[..], [Action::Pin { tag, .. }] if tag == DIRECT), "{acts:?}");
        // напрямую тоже закрыто: ничего не делаем даже при allow_direct
        t.note_direct(&round(vec![], &[], &[("video", timeout())]));
        assert!(mk(true).decide(&t, &[view("proxy", "a", "a")], &order()).is_empty());
    }

    #[test]
    fn router_unknown_effective_path_is_left_alone() {
        let mut r = Router::default();
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        let mut v = view("proxy", "a", "a");
        v.effective = None;
        assert!(r.decide(&t, &[v], &order()).is_empty());
    }

    #[test]
    fn fail_class_names_match_the_plan() {
        assert_eq!(FailClass::ProtocolBlocked.as_str(), "PROTOCOL_BLOCKED");
        assert_eq!(FailClass::ServerIpBlocked.as_str(), "SERVER_IP_BLOCKED");
        assert_eq!(FailClass::ExitBlockedBySite.as_str(), "EXIT_BLOCKED_BY_SITE");
        assert_eq!(serde_json::to_string(&FailClass::ExitBlockedBySite).unwrap(), "\"EXIT_BLOCKED_BY_SITE\"");
    }

    fn ext_router(allow: bool) -> Router {
        Router::new(RouterCfg { allow_external_exit: allow, external: vec!["x".into()], min_dwell: 1, ..Default::default() })
    }
    fn order_x() -> Vec<String> {
        vec!["a".into(), "b".into(), "x".into()]
    }
    fn prove(t: &mut Tracker, tag: &str) {
        feed(t, CANARY, tag, Verdict::Ok);
        feed(t, "video", tag, Verdict::Ok);
    }

    #[test]
    fn external_exit_is_used_only_when_allowed_and_own_exits_are_blocked_by_the_site() {
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        fail(&mut t, "video", "b");
        prove(&mut t, "x");
        assert!(ext_router(false).decide(&t, &[view("proxy", "a", "a")], &order_x()).is_empty(), "без разрешения чужой прокси не берём");
        let acts = ext_router(true).decide(&t, &[view("proxy", "a", "a")], &order_x());
        assert!(matches!(&acts[..], [Action::Pin { tag, reason, .. }] if tag == "x" && reason.contains("внешний exit")), "{acts:?}");
    }

    #[test]
    fn own_server_always_beats_external_exit() {
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        feed(&mut t, "video", "b", Verdict::Ok);
        prove(&mut t, "x");
        let acts = ext_router(true).decide(&t, &[view("proxy", "a", "a")], &order_x());
        assert!(matches!(&acts[..], [Action::Pin { tag, .. }] if tag == "b"), "{acts:?}");
    }

    #[test]
    fn external_exit_needs_proof_it_works_and_a_site_block_diagnosis() {
        // внешний exit ещё не проверялся: уверенности нет, трафик не уводим
        let mut t = Tracker::default();
        fail(&mut t, "video", "a");
        fail(&mut t, "video", "b");
        assert!(ext_router(true).decide(&t, &[view("proxy", "a", "a")], &order_x()).is_empty());
        // внешний exit не открывает категорию
        fail(&mut t, "video", "x");
        assert!(ext_router(true).decide(&t, &[view("proxy", "a", "a")], &order_x()).is_empty());
        // свои пути отказали не из-за блокировки выхода (например, умер протокол): внешний exit не подходит
        let mut t = Tracker::default();
        for tag in ["a", "b"] {
            for _ in 0..t.cfg.failed_after {
                feed(&mut t, "video", tag, Verdict::Failed(FailClass::ProtocolBlocked));
            }
        }
        prove(&mut t, "x");
        assert!(ext_router(true).decide(&t, &[view("proxy", "a", "a")], &order_x()).is_empty());
    }

    #[test]
    fn external_exit_is_never_taken_for_the_canary_or_while_going_direct() {
        let mut t = Tracker::default();
        for _ in 0..t.cfg.failed_after {
            feed(&mut t, CANARY, "a", Verdict::Failed(FailClass::ExitBlockedBySite));
            feed(&mut t, CANARY, "b", Verdict::Failed(FailClass::ExitBlockedBySite));
        }
        prove(&mut t, "x");
        let mut v = view("proxy", "a", "a");
        v.category = CANARY.into();
        v.selector = "proxy".into();
        assert!(ext_router(true).decide(&t, &[v], &order_x()).is_empty(), "общий переключатель на внешний exit не переводим");
    }

    #[test]
    fn pinned_external_exit_goes_home_when_own_exit_recovers() {
        let mut r = Router::new(RouterCfg { allow_external_exit: true, external: vec!["x".into()], min_dwell: 1, release_after: 2, ..Default::default() });
        let mut t = Tracker::new(TrackerCfg { failed_after: 1, recover_after: 1 });
        fail(&mut t, "video", "a");
        prove(&mut t, "x");
        let v = view("x", "x", "a"); // закреплён внешний exit, дом раскрывается в a
        assert!(r.decide(&t, &[v.clone()], &order_x()).is_empty());
        for _ in 0..2 {
            prove(&mut t, "a");
        }
        let acts = r.decide(&t, &[v], &order_x());
        assert!(matches!(&acts[..], [Action::Release { to, .. }] if to == "proxy"), "{acts:?}");
    }

    #[test]
    fn external_exit_is_its_own_exit_identity_in_the_classifier() {
        // a и b: свои серверы; x: внешний exit (вход через свой сервер, выход у прокси). Сайт не пускает свои IP
        let mut x = ob("x", "198.51.100.7", "socks5");
        x.exit = "198.51.100.7".into();
        let r = round(
            vec![ob("a", "h1", "vless"), ob("b", "h2", "vless"), x],
            &[("a", CANARY, ok(50)), ("b", CANARY, ok(60)), ("x", CANARY, ok(200)), ("a", "video", Outcome::Denied { status: 403 }), ("b", "video", Outcome::Denied { status: 403 }), ("x", "video", ok(300))],
            &[(CANARY, ok(10))],
        );
        let es = classify(&r, &cats(), &DegradedPolicy::default());
        assert_eq!(verdict(&es, "video", "a"), Verdict::Failed(FailClass::ExitBlockedBySite));
        assert_eq!(verdict(&es, "video", "b"), Verdict::Failed(FailClass::ExitBlockedBySite));
        assert_eq!(verdict(&es, "video", "x"), Verdict::Ok);
        assert!(ob("x", "h", "socks5").is_external() && !ob("a", "h", "vless").is_external());
    }
}
