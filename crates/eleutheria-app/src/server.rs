//! Управление сервером из GUI: проверка ключа хоста, установка (provision), пользователи.
//!
//! Подтверждение незнакомого ключа хоста двухшаговое: `probe_host_key` показывает fingerprint, пользователь
//! сверяет его (например, с панелью хостера) и подтверждает, после чего тот же fingerprint передаётся в
//! `SshConn::trusted_fingerprint`. Незнакомый ключ без такого подтверждения всегда отклоняется.

use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use eleutheria_core::client::profile::{self, Server};
use eleutheria_core::config::vless_link;
use eleutheria_core::harden::{self, HardenCtx, HardenOpts};
use eleutheria_core::provision::{self, Options, UpdateNeed};
use eleutheria_core::singbox;
use eleutheria_core::ssh::{Auth, AuthRejected, HostKeyVerifier, Ssh, Target};
use eleutheria_core::state::{valid_user_name, State};
use eleutheria_core::store::{self, HostCheck};
use eleutheria_core::users;
use serde::{Deserialize, Serialize};

/// Сообщения о ходе работы (в GUI уходят событием).
pub type Progress<'a> = &'a (dyn Fn(&str) + Sync);

fn default_user() -> String {
    "root".into()
}
fn default_ssh_port() -> u16 {
    22
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SshConn {
    pub host: String,
    #[serde(default = "default_user")]
    pub user: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// пароль живёт только в памяти на время вызова; в логи и Debug не попадает
    pub password: Option<String>,
    pub key_path: Option<String>,
    /// fingerprint, который пользователь явно подтвердил после `probe_host_key`
    pub trusted_fingerprint: Option<String>,
}

impl fmt::Debug for SshConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConn")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("ssh_port", &self.ssh_port)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("key_path", &self.key_path)
            .field("trusted_fingerprint", &self.trusted_fingerprint)
            .finish()
    }
}

pub fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['-', '.'])
        && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
}

pub fn valid_ssh_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && !u.starts_with('-') && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// SNI для Reality: обычное имя сайта.
pub fn valid_sni(s: &str) -> bool {
    valid_host(s) && !s.contains(':') && s.contains('.') && !s.ends_with('.')
}

impl SshConn {
    /// Проверка полей до любых сетевых действий. `has_saved_key`: для хоста уже есть сохранённый ключ.
    pub fn validate(&self, has_saved_key: bool) -> Result<()> {
        if !valid_host(&self.host) {
            bail!("некорректный адрес сервера");
        }
        if !valid_ssh_user(&self.user) {
            bail!("некорректное имя пользователя SSH");
        }
        if self.ssh_port == 0 {
            bail!("порт SSH должен быть от 1 до 65535");
        }
        let has_pw = self.password.as_deref().is_some_and(|p| !p.is_empty());
        let has_key = self.key_path.as_deref().is_some_and(|p| !p.trim().is_empty());
        if !has_pw && !has_key && !has_saved_key {
            bail!("укажи пароль SSH или путь к ключу");
        }
        Ok(())
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HostKeyStatus {
    /// ключ уже сохранён и совпадает
    Known,
    /// сервер видим впервые: нужно подтверждение пользователя
    Unknown,
    /// ключ отличается от сохранённого: переустановка сервера или перехват соединения
    #[serde(rename_all = "camelCase")]
    Changed { previous: String },
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyProbe {
    pub fingerprint: String,
    pub status: HostKeyStatus,
}

pub fn classify_host(c: HostCheck) -> HostKeyStatus {
    match c {
        HostCheck::Match => HostKeyStatus::Known,
        HostCheck::Unknown => HostKeyStatus::Unknown,
        HostCheck::Mismatch(previous) => HostKeyStatus::Changed { previous },
    }
}

/// (принять ключ, запомнить его). Незнакомый ключ принимается только если он равен подтверждённому пользователем.
pub fn host_decision(check: &HostCheck, fp: &str, trusted: Option<&str>) -> (bool, bool) {
    match check {
        HostCheck::Match => (true, false),
        HostCheck::Mismatch(_) => (false, false),
        HostCheck::Unknown => {
            let ok = trusted == Some(fp);
            (ok, ok)
        }
    }
}

fn verifier(host: &str, port: u16, trusted: Option<String>) -> HostKeyVerifier {
    let id = store::host_id(host, port);
    Box::new(move |fp: &str| {
        let (accept, remember) = host_decision(&store::check_host(&id, fp), fp, trusted.as_deref());
        if remember {
            let _ = store::remember_host(&id, fp);
        }
        accept
    })
}

/// Получить fingerprint ключа сервера, не входя на него. Соединение намеренно обрывается на проверке ключа.
pub async fn probe_host_key(host: &str, port: u16) -> Result<HostKeyProbe> {
    if !valid_host(host) || port == 0 {
        bail!("некорректный адрес или порт");
    }
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let s2 = seen.clone();
    let v: HostKeyVerifier = Box::new(move |fp: &str| {
        *s2.lock().unwrap() = Some(fp.to_string());
        false
    });
    let target = Target { host: host.to_string(), port, user: "probe".into(), auth: Auth::Password(String::new()) };
    let r = Ssh::connect(&target, v).await;
    let fp = seen.lock().unwrap().clone();
    match fp {
        Some(fp) => {
            let status = classify_host(store::check_host(&store::host_id(host, port), &fp));
            Ok(HostKeyProbe { fingerprint: fp, status })
        }
        None => Err(match r {
            Err(e) => e.context("не удалось получить ключ сервера"),
            Ok(_) => anyhow!("не удалось получить ключ сервера"),
        }),
    }
}

async fn connect(c: &SshConn) -> Result<Ssh> {
    let saved = store::saved_key(&c.host)?;
    c.validate(saved.is_some())?;
    let mk = || verifier(&c.host, c.ssh_port, c.trusted_fingerprint.clone());
    let target = |auth| Target { host: c.host.clone(), port: c.ssh_port, user: c.user.clone(), auth };
    if let Some(path) = c.key_path.as_deref().filter(|p| !p.trim().is_empty()) {
        return Ssh::connect(&target(Auth::KeyFile { path: path.to_string(), passphrase: None }), mk()).await;
    }
    if let Some(pw) = c.password.clone().filter(|p| !p.is_empty()) {
        return Ssh::connect(&target(Auth::Password(pw)), mk()).await;
    }
    let Some(saved) = saved else { bail!("нет сохранённого ключа и пароля для входа") };
    match Ssh::connect(&target(Auth::KeyPem { pem: saved.pem }), mk()).await {
        Err(e) if e.downcast_ref::<AuthRejected>().is_some() => {
            bail!("сохранённый ключ не подошёл (сервер переустановлен?): введи пароль SSH")
        }
        other => other,
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRequest {
    pub port: Option<u16>,
    pub sni: Option<String>,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default = "default_first_user")]
    pub user_name: String,
    #[serde(default = "yes")]
    pub harden_ssh: bool,
    #[serde(default = "yes")]
    pub bbr: bool,
    #[serde(default = "yes")]
    pub firewall: bool,
}

fn default_profile() -> String {
    "Eleutheria".into()
}
fn default_first_user() -> String {
    "default".into()
}
fn yes() -> bool {
    true
}

impl ProvisionRequest {
    pub fn validate(&self) -> Result<()> {
        if self.port == Some(0) {
            bail!("порт VPN должен быть от 1 до 65535");
        }
        if let Some(s) = &self.sni {
            if !valid_sni(s) {
                bail!("некорректный сайт для маскировки (нужно имя вида example.com)");
            }
        }
        let p = self.profile.trim();
        if p.is_empty() || p.chars().count() > 64 || p.chars().any(char::is_control) || p.contains(['#', '?', '&', '/']) {
            bail!("некорректное название профиля");
        }
        if !valid_user_name(&self.user_name) {
            bail!("недопустимое имя пользователя (латиница, цифры, _ и -, до 32 символов)");
        }
        Ok(())
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NoteDto {
    pub ok: bool,
    pub text: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserLink {
    pub name: String,
    pub link: String,
    /// QR-код ссылки (SVG); None, если ссылка не помещается в QR
    pub qr_svg: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub notes: Vec<NoteDto>,
    /// имя, под которым сервер сохранён в списке клиента
    pub saved_as: Option<String>,
    pub links: Vec<UserLink>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsersDto {
    pub users: Vec<String>,
}

pub fn users_dto(st: &State) -> UsersDto {
    UsersDto { users: st.users.iter().map(|u| u.name.clone()).collect() }
}

/// Пользователи сервера и их ссылки (ссылка содержит UUID: показывается только владельцу и по явному запросу).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsersView {
    pub users: Vec<String>,
    pub links: Vec<UserLink>,
}

pub fn users_view(host: &str, st: &State) -> UsersView {
    UsersView { users: users_dto(st).users, links: links_for(host, st) }
}

pub fn links_for(host: &str, st: &State) -> Vec<UserLink> {
    st.users
        .iter()
        .map(|u| {
            let link = vless_link(host, st, u);
            let qr_svg = eleutheria_core::qr_svg(&link).ok();
            UserLink { name: u.name.clone(), link, qr_svg }
        })
        .collect()
}

pub async fn provision(c: &SshConn, req: &ProvisionRequest, progress: Progress<'_>) -> Result<ProvisionResult> {
    req.validate()?;
    let ssh = connect(c).await?;
    let opts = Options { port: req.port, sni: req.sni.clone(), profile: req.profile.trim().to_string(), user_name: req.user_name.clone() };
    let state = match provision::provision(&ssh, &opts, progress).await {
        Ok(r) => r.state,
        Err(e) => {
            let _ = ssh.close().await;
            return Err(e);
        }
    };
    let ctx = HardenCtx { host: c.host.clone(), ssh_port: c.ssh_port, ssh_user: c.user.clone(), vpn_port: state.port };
    let hopts = HardenOpts { ssh_key: req.harden_ssh, bbr: req.bbr, firewall: req.firewall };
    let (host, port, trusted) = (c.host.clone(), c.ssh_port, c.trusted_fingerprint.clone());
    let notes = harden::run(&ssh, &ctx, &hopts, &move || verifier(&host, port, trusted.clone()), progress).await;
    let _ = ssh.close().await;

    let saved_as = state.users.first().map(|u| profile::upsert(Server::from_state(&c.host, &state, u))).transpose()?;
    Ok(ProvisionResult {
        notes: notes.into_iter().map(|n| NoteDto { ok: n.ok, text: n.text }).collect(),
        saved_as,
        links: links_for(&c.host, &state),
    })
}

/// Состояние серверной части относительно sing-box из бандла клиента.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerUpdateDto {
    /// версия sing-box на сервере (из state.json)
    pub installed: Option<String>,
    /// версия в бандле этого клиента
    pub bundled: String,
    /// notInstalled | upToDate | outdated | newer | unknown
    pub status: &'static str,
}

pub fn need_str(n: UpdateNeed) -> &'static str {
    match n {
        UpdateNeed::NotInstalled => "notInstalled",
        UpdateNeed::UpToDate => "upToDate",
        UpdateNeed::Outdated => "outdated",
        UpdateNeed::Newer => "newer",
        UpdateNeed::Unknown => "unknown",
    }
}

pub fn update_dto(installed: Option<String>) -> ServerUpdateDto {
    let status = need_str(provision::update_need(installed.as_deref(), singbox::VERSION));
    ServerUpdateDto { installed, bundled: singbox::VERSION.to_string(), status }
}

/// Нужно ли обновлять сервер (читает только state.json, ничего не меняет).
pub async fn server_update_status(c: &SshConn) -> Result<ServerUpdateDto> {
    let ssh = connect(c).await?;
    let r = provision::read_state(&ssh).await;
    let _ = ssh.close().await;
    Ok(update_dto(r?.map(|s| s.singbox)))
}

/// «Обновить сервер»: идемпотентный provision существующей установки (ключи и пользователи сохраняются,
/// конфиг проверяется до перезапуска, при сбое возвращаются прежние конфиг и бинарник).
pub async fn update_server(c: &SshConn, progress: Progress<'_>) -> Result<ServerUpdateDto> {
    let ssh = connect(c).await?;
    let r = provision::update(&ssh, progress).await;
    let _ = ssh.close().await;
    Ok(update_dto(Some(r?.singbox)))
}

/// Список пользователей и их ссылки.
pub async fn list_users(c: &SshConn) -> Result<UsersView> {
    let ssh = connect(c).await?;
    let r = users::load(&ssh).await;
    let _ = ssh.close().await;
    let st = r?;
    Ok(users_view(&c.host, &st))
}

pub async fn add_user(c: &SshConn, name: &str, progress: Progress<'_>) -> Result<UsersView> {
    if !valid_user_name(name) {
        bail!("недопустимое имя `{name}` (латиница, цифры, _ и -, до 32 символов)");
    }
    let ssh = connect(c).await?;
    let r = users::add(&ssh, name, progress).await;
    let _ = ssh.close().await;
    let (st, _) = r.context("не удалось добавить пользователя")?;
    Ok(users_view(&c.host, &st))
}

pub async fn remove_user(c: &SshConn, name: &str, progress: Progress<'_>) -> Result<UsersView> {
    let ssh = connect(c).await?;
    let r = users::remove(&ssh, name, progress).await;
    let _ = ssh.close().await;
    let st = r?;
    Ok(users_view(&c.host, &st))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eleutheria_core::state::User;

    fn conn() -> SshConn {
        SshConn { host: "203.0.113.5".into(), user: "root".into(), ssh_port: 22, password: Some("pw".into()), key_path: None, trusted_fingerprint: None }
    }

    #[test]
    fn host_user_sni_validation() {
        for ok in ["203.0.113.5", "vpn.example.com", "2001:db8::1", "my_host-1"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in ["", "-oProxyCommand=x", ".x", "a b", "a;b", "a$(x)", "a/b", &"a".repeat(254)] {
            assert!(!valid_host(bad), "{bad}");
        }
        assert!(valid_ssh_user("root") && valid_ssh_user("deploy.user"));
        assert!(!valid_ssh_user("-x") && !valid_ssh_user("a b") && !valid_ssh_user(""));
        assert!(valid_sni("www.microsoft.com"));
        for bad in ["localhost", "a.b:1", "bad host.com", "x.com.", "", "-a.com"] {
            assert!(!valid_sni(bad), "{bad}");
        }
    }

    #[test]
    fn conn_requires_some_credential() {
        assert!(conn().validate(false).is_ok());
        let mut c = conn();
        c.password = None;
        assert!(c.validate(false).is_err());
        assert!(c.validate(true).is_ok(), "сохранённый ключ заменяет пароль");
        c.key_path = Some("  ".into());
        assert!(c.validate(false).is_err(), "пустой путь не считается ключом");
        c.key_path = Some("/home/u/.ssh/id".into());
        assert!(c.validate(false).is_ok());
        let mut bad = conn();
        bad.ssh_port = 0;
        assert!(bad.validate(false).is_err());
        bad = conn();
        bad.host = "x;rm".into();
        assert!(bad.validate(false).is_err());
    }

    #[test]
    fn debug_never_prints_the_password() {
        let mut c = conn();
        c.password = Some("hunter2-secret".into());
        let d = format!("{c:?}");
        assert!(!d.contains("hunter2") && d.contains("***"));
    }

    #[test]
    fn unknown_host_key_needs_explicit_matching_confirmation() {
        let fp = "SHA256:abc";
        assert_eq!(host_decision(&HostCheck::Match, fp, None), (true, false));
        assert_eq!(host_decision(&HostCheck::Unknown, fp, None), (false, false));
        assert_eq!(host_decision(&HostCheck::Unknown, fp, Some("SHA256:other")), (false, false));
        assert_eq!(host_decision(&HostCheck::Unknown, fp, Some(fp)), (true, true));
        // подтверждение не отменяет смену ключа: подмена не проходит даже с «доверенным» fingerprint
        assert_eq!(host_decision(&HostCheck::Mismatch("SHA256:old".into()), fp, Some(fp)), (false, false));
    }

    #[test]
    fn host_status_serializes_for_the_frontend() {
        assert_eq!(classify_host(HostCheck::Match), HostKeyStatus::Known);
        let p = HostKeyProbe { fingerprint: "SHA256:x".into(), status: classify_host(HostCheck::Mismatch("SHA256:old".into())) };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["status"]["kind"], "changed");
        assert_eq!(j["status"]["previous"], "SHA256:old");
        assert_eq!(serde_json::to_value(HostKeyStatus::Unknown).unwrap()["kind"], "unknown");
    }

    #[test]
    fn provision_request_defaults_and_validation() {
        let r: ProvisionRequest = serde_json::from_str("{}").unwrap();
        assert!(r.harden_ssh && r.bbr && r.firewall);
        assert_eq!((r.profile.as_str(), r.user_name.as_str()), ("Eleutheria", "default"));
        assert!(r.validate().is_ok());
        let bad = |f: fn(&mut ProvisionRequest)| {
            let mut r: ProvisionRequest = serde_json::from_str("{}").unwrap();
            f(&mut r);
            assert!(r.validate().is_err());
        };
        bad(|r| r.port = Some(0));
        bad(|r| r.sni = Some("not a host".into()));
        bad(|r| r.profile = "  ".into());
        bad(|r| r.profile = "a#b".into());
        bad(|r| r.profile = "x".repeat(65));
        bad(|r| r.user_name = "bad name".into());
    }

    #[test]
    fn links_never_expose_other_users_state() {
        let st = State {
            version: 2,
            singbox: "1.14.3".into(),
            profile: "P".into(),
            private_key: "PRIVATE-KEY".into(),
            public_key: "pub".into(),
            short_id: "ab".into(),
            sni: "www.microsoft.com".into(),
            port: 443,
            users: vec![User { name: "a".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into() }, User { name: "b".into(), uuid: "b158cda3-0b3d-424b-a8f8-26a6462c8349".into() }],
        };
        assert_eq!(users_dto(&st).users, vec!["a", "b"]);
        let links = links_for("203.0.113.5", &st);
        assert_eq!(links.len(), 2);
        assert!(links[0].link.starts_with("vless://a158cda3"));
        assert!(links.iter().all(|l| !l.link.contains("PRIVATE-KEY")));
        assert!(links.iter().all(|l| l.qr_svg.as_deref().is_some_and(|s| s.contains("<svg"))));
        assert_ne!(links[0].qr_svg, links[1].qr_svg);
        assert!(serde_json::to_value(&links[0]).unwrap().get("qrSvg").is_some());
        // DTO списка пользователей содержит только имена
        assert!(!serde_json::to_string(&users_dto(&st)).unwrap().contains("158cda3"));
    }

    #[test]
    fn server_update_dto_statuses() {
        let cur = singbox::VERSION.to_string();
        assert_eq!(update_dto(None).status, "notInstalled");
        assert_eq!(update_dto(Some(cur.clone())).status, "upToDate");
        assert_eq!(update_dto(Some("0.0.1".into())).status, "outdated");
        assert_eq!(update_dto(Some("999.0.0".into())).status, "newer");
        assert_eq!(update_dto(Some("???".into())).status, "unknown");
        let j = serde_json::to_value(update_dto(Some("0.0.1".into()))).unwrap();
        assert_eq!(j["installed"], "0.0.1");
        assert_eq!(j["bundled"], cur);
    }
}
