//! Парк серверов (M5.2): несколько своих VPS под управлением одного человека.
//!
//! - Список серверов парка лежит в `fleet.json` (адреса и параметры SSH, секретов там нет: ключи SSH в keyring).
//! - Общий пользователь: одно имя, один uuid и один секрет на всех серверах парка, поэтому клиент получает
//!   по одной ссылке на каждый сервер/протокол и одну подписку на всех.
//! - «Обновить все»: идемпотентный `provision::update` по каждому серверу, сбой одного не останавливает остальных.
//!
//! Логика выбора действий (`plan_user`) чистая и проверяется тестами; ввод-вывод по SSH принимает
//! функцию подключения, чтобы CLI и GUI сами решали, как спрашивать пароль и проверять ключ хоста.

use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::config::all_links;
use crate::provision::{self, UpdateNeed};
use crate::ssh::Ssh;
use crate::state::{valid_user_name, State, User};
use crate::store::config_dir;
use crate::tx::Report;
use crate::users;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_ssh_user() -> String {
    "root".into()
}

impl Member {
    pub fn new(host: impl Into<String>, ssh_port: u16, ssh_user: impl Into<String>) -> Member {
        Member { host: host.into(), ssh_port, ssh_user: ssh_user.into() }
    }

    pub fn validate(&self) -> Result<()> {
        let ok = |s: &str, extra: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c));
        if self.host.is_empty() || self.host.len() > 253 || !ok(&self.host, ".:-") {
            bail!("недопустимый адрес сервера `{}`", self.host);
        }
        if self.ssh_port == 0 {
            bail!("порт SSH 0");
        }
        if self.ssh_user.is_empty() || self.ssh_user.len() > 32 || !ok(&self.ssh_user, "_-") {
            bail!("недопустимое имя пользователя SSH `{}`", self.ssh_user);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fleet {
    #[serde(default)]
    pub members: Vec<Member>,
}

fn path_in(dir: &Path) -> PathBuf {
    dir.join("fleet.json")
}

impl Fleet {
    pub fn load_in(dir: &Path) -> Result<Fleet> {
        match std::fs::read_to_string(path_in(dir)) {
            Ok(raw) => {
                let f: Fleet = serde_json::from_str(&raw).context("fleet.json: ошибка разбора")?;
                f.members.iter().try_for_each(Member::validate)?;
                Ok(f)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fleet::default()),
            Err(e) => Err(e).context("чтение fleet.json"),
        }
    }

    /// Запись через временный файл и переименование: оборванная запись не портит прежний список.
    pub fn save_in(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join("fleet.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path_in(dir))?;
        Ok(())
    }

    pub fn load() -> Result<Fleet> {
        Fleet::load_in(&config_dir())
    }

    pub fn save(&self) -> Result<()> {
        self.save_in(&config_dir())
    }

    /// Добавляет сервер; повторное добавление того же адреса обновляет порт и пользователя SSH. true = сервер новый.
    pub fn add(&mut self, m: Member) -> Result<bool> {
        m.validate()?;
        match self.members.iter_mut().find(|x| x.host.eq_ignore_ascii_case(&m.host)) {
            Some(x) => {
                *x = m;
                Ok(false)
            }
            None => {
                self.members.push(m);
                Ok(true)
            }
        }
    }

    pub fn remove(&mut self, host: &str) -> bool {
        let n = self.members.len();
        self.members.retain(|x| !x.host.eq_ignore_ascii_case(host));
        self.members.len() != n
    }
}

// ───────────────────────── общий пользователь ─────────────────────────

/// Что нужно сделать на сервере, чтобы пользователь совпал с общим.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserAction {
    /// пользователя нет: добавить
    Add,
    /// уже совпадает
    Present,
    /// есть с тем же uuid, но без секрета: дописать секрет
    FillSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPlan {
    /// общий пользователь, если он уже где-то есть; None = его нужно создать
    pub canonical: Option<User>,
    /// действие для каждого доступного сервера (адрес, действие)
    pub actions: Vec<(String, UserAction)>,
}

/// `seen`: адрес сервера и его пользователи (None = сервер недоступен, его пропускаем).
/// Расхождение (одно имя, разные uuid или разные секреты) это ошибка: молча чинить нельзя, потому что
/// у кого-то из клиентов ссылка перестала бы работать.
pub fn plan_user(name: &str, seen: &[(String, Option<Vec<User>>)]) -> Result<UserPlan> {
    if !valid_user_name(name) {
        bail!("недопустимое имя `{name}` (латиница, цифры, _ и -, до 32 символов)");
    }
    let found: Vec<(&String, &User)> = seen
        .iter()
        .filter_map(|(h, us)| us.as_ref().and_then(|us| us.iter().find(|u| u.name == name)).map(|u| (h, u)))
        .collect();
    if let Some((h0, u0)) = found.first() {
        if let Some((h, u)) = found.iter().find(|(_, u)| u.uuid != u0.uuid) {
            bail!("пользователь `{name}` на серверах разный: у {h0} uuid {}, у {h} uuid {}. Удали лишнего вручную (`eleutheria user remove`) и повтори", u0.uuid, u.uuid);
        }
        let secrets: Vec<&String> = found.iter().filter_map(|(_, u)| u.secret.as_ref()).collect();
        if let Some(s) = secrets.iter().find(|s| **s != secrets[0]) {
            let _ = s;
            bail!("у пользователя `{name}` на серверах разные секреты протоколов: ссылки Hysteria2/TUIC/SS-2022 разойдутся. Удали лишнего вручную и повтори");
        }
    }
    let canonical = found.first().map(|(_, u)| User { name: name.to_string(), uuid: u.uuid.clone(), secret: found.iter().find_map(|(_, u)| u.secret.clone()) });
    let mut actions = Vec::new();
    for (host, users) in seen {
        let Some(users) = users else { continue };
        let action = match (users.iter().find(|u| u.name == name), &canonical) {
            (None, _) => UserAction::Add,
            (Some(u), Some(c)) if u.secret.is_none() && c.secret.is_some() => UserAction::FillSecret,
            (Some(_), _) => UserAction::Present,
        };
        actions.push((host.clone(), action));
    }
    Ok(UserPlan { canonical, actions })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Unreachable(String),
    Present,
    Added,
    SecretFilled,
    UpToDate(String),
    Updated { from: String, to: String },
    Failed(String),
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        !matches!(self, Outcome::Unreachable(_) | Outcome::Failed(_))
    }

    pub fn describe(&self) -> String {
        match self {
            Outcome::Unreachable(e) => format!("недоступен: {e}"),
            Outcome::Present => "пользователь уже есть".into(),
            Outcome::Added => "пользователь добавлен".into(),
            Outcome::SecretFilled => "секрет дописан".into(),
            Outcome::UpToDate(v) => format!("sing-box {v} актуален"),
            Outcome::Updated { from, to } => format!("sing-box {from} → {to}"),
            Outcome::Failed(e) => format!("ошибка: {e}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberResult {
    pub host: String,
    pub outcome: Outcome,
}

/// Добавляет общего пользователя на все серверы парка. Недоступные серверы пропускаются (о них сказано в
/// результате): пользователя на них можно добавить повторным запуском, команда идемпотентна.
pub async fn add_user<F, Fut>(fleet: &Fleet, name: &str, connect: F, report: Report<'_>) -> Result<(Option<User>, Vec<MemberResult>)>
where
    F: Fn(Member) -> Fut,
    Fut: Future<Output = Result<Ssh>>,
{
    if fleet.members.is_empty() {
        bail!("в парке нет серверов: добавь командой `eleutheria fleet add <IP>`");
    }
    let mut live: Vec<(Member, Ssh, State)> = Vec::new();
    let mut results: Vec<MemberResult> = Vec::new();
    for m in &fleet.members {
        report(&format!("{}: подключаюсь…", m.host));
        match connect(m.clone()).await {
            Err(e) => results.push(MemberResult { host: m.host.clone(), outcome: Outcome::Unreachable(format!("{e:#}")) }),
            Ok(ssh) => match users::load(&ssh).await {
                Ok(st) => live.push((m.clone(), ssh, st)),
                Err(e) => {
                    let _ = ssh.close().await;
                    results.push(MemberResult { host: m.host.clone(), outcome: Outcome::Failed(format!("{e:#}")) });
                }
            },
        }
    }
    let seen: Vec<(String, Option<Vec<User>>)> = live.iter().map(|(m, _, st)| (m.host.clone(), Some(st.users.clone()))).collect();
    let plan = plan_user(name, &seen);
    let plan = match plan {
        Ok(p) => p,
        Err(e) => {
            for (_, ssh, _) in live {
                let _ = ssh.close().await;
            }
            return Err(e);
        }
    };
    if live.is_empty() {
        let why: Vec<String> = results.iter().map(|r| format!("{}: {}", r.host, r.outcome.describe())).collect();
        bail!("ни один сервер парка не отвечает ({})", why.join("; "));
    }
    // новый пользователь: uuid и секрет генерирует первый доступный сервер; секрет нужен всегда, чтобы
    // потом можно было включить пароль-протоколы на любом сервере парка
    let user = match plan.canonical.clone() {
        Some(u) => u,
        None => {
            let ssh = &live[0].1;
            let uuid = ssh.run_ok(&format!("{} generate uuid", provision::BIN)).await?;
            let secret = ssh.run_ok(&format!("{} generate rand --hex 16", provision::BIN)).await?;
            User { name: name.to_string(), uuid, secret: Some(secret) }
        }
    };
    for (m, ssh, _) in live {
        let action = plan.actions.iter().find(|(h, _)| *h == m.host).map(|(_, a)| a.clone()).unwrap_or(UserAction::Present);
        let outcome = match action {
            UserAction::Present => Outcome::Present,
            a => match users::add_existing(&ssh, &user, report).await {
                Ok(_) => if a == UserAction::Add { Outcome::Added } else { Outcome::SecretFilled },
                Err(e) => Outcome::Failed(format!("{e:#}")),
            },
        };
        let _ = ssh.close().await;
        results.push(MemberResult { host: m.host, outcome });
    }
    Ok((Some(user), results))
}

// ───────────────────────── обновить все ─────────────────────────

/// Обновляет sing-box на каждом сервере парка. Актуальные пропускаются, сбой одного не останавливает остальных.
pub async fn update_all<F, Fut>(fleet: &Fleet, connect: F, report: Report<'_>) -> Result<Vec<MemberResult>>
where
    F: Fn(Member) -> Fut,
    Fut: Future<Output = Result<Ssh>>,
{
    if fleet.members.is_empty() {
        bail!("в парке нет серверов: добавь командой `eleutheria fleet add <IP>`");
    }
    let mut out = Vec::new();
    for m in &fleet.members {
        report(&format!("{}: проверяю…", m.host));
        let outcome = match connect(m.clone()).await {
            Err(e) => Outcome::Unreachable(format!("{e:#}")),
            Ok(ssh) => {
                let r = update_one(&ssh, report).await;
                let _ = ssh.close().await;
                r.unwrap_or_else(|e| Outcome::Failed(format!("{e:#}")))
            }
        };
        out.push(MemberResult { host: m.host.clone(), outcome });
    }
    Ok(out)
}

async fn update_one(ssh: &Ssh, report: Report<'_>) -> Result<Outcome> {
    let Some(st) = provision::read_state(ssh).await? else {
        bail!("на сервере нет установки Eleutheria");
    };
    if provision::update_need(Some(&st.singbox), crate::singbox::VERSION) == UpdateNeed::UpToDate {
        return Ok(Outcome::UpToDate(st.singbox));
    }
    let new = provision::update(ssh, report).await?;
    Ok(Outcome::Updated { from: st.singbox, to: new.singbox })
}

// ───────────────────────── подписка ─────────────────────────

/// Тело подписки: ссылки через перевод строки в base64 (формат, который принимают v2rayN, Hiddify, Happ и наш импорт).
pub fn subscription_body(links: &[String]) -> String {
    STANDARD.encode(links.join("\n"))
}

/// Собирает ссылки пользователя со всех серверов парка. Недоступные серверы и серверы без этого пользователя
/// перечислены в результате, подписка строится из остальных.
pub async fn subscription<F, Fut>(fleet: &Fleet, name: &str, connect: F, report: Report<'_>) -> Result<(String, Vec<MemberResult>)>
where
    F: Fn(Member) -> Fut,
    Fut: Future<Output = Result<Ssh>>,
{
    if fleet.members.is_empty() {
        bail!("в парке нет серверов: добавь командой `eleutheria fleet add <IP>`");
    }
    let mut links: Vec<String> = Vec::new();
    let mut results = Vec::new();
    for m in &fleet.members {
        report(&format!("{}: читаю состояние…", m.host));
        let outcome = match connect(m.clone()).await {
            Err(e) => Outcome::Unreachable(format!("{e:#}")),
            Ok(ssh) => {
                let st = users::load(&ssh).await;
                let _ = ssh.close().await;
                match st {
                    Err(e) => Outcome::Failed(format!("{e:#}")),
                    Ok(st) => match st.user(name) {
                        None => Outcome::Failed(format!("пользователя `{name}` на этом сервере нет (`eleutheria fleet user-add {name}`)")),
                        Some(u) => match all_links(&m.host, &st, u) {
                            Ok(ls) => {
                                links.extend(ls.into_iter().map(|l| l.url));
                                Outcome::Present
                            }
                            Err(e) => Outcome::Failed(format!("{e:#}")),
                        },
                    },
                }
            }
        };
        results.push(MemberResult { host: m.host.clone(), outcome });
    }
    if links.is_empty() {
        let why: Vec<String> = results.iter().map(|r| format!("{}: {}", r.host, r.outcome.describe())).collect();
        bail!("ни одной ссылки собрать не удалось ({})", why.join("; "));
    }
    Ok((subscription_body(&links), results))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str, uuid: &str, secret: Option<&str>) -> User {
        User { name: name.into(), uuid: uuid.into(), secret: secret.map(Into::into) }
    }

    fn seen(v: Vec<(&str, Option<Vec<User>>)>) -> Vec<(String, Option<Vec<User>>)> {
        v.into_iter().map(|(h, us)| (h.to_string(), us)).collect()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("el-fleet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn new_user_is_added_everywhere_reachable_and_unreachable_is_skipped() {
        let p = plan_user("bob", &seen(vec![("a", Some(vec![u("default", "1", None)])), ("b", None), ("c", Some(vec![u("default", "2", None)]))])).unwrap();
        assert_eq!(p.canonical, None);
        assert_eq!(p.actions, vec![("a".to_string(), UserAction::Add), ("c".to_string(), UserAction::Add)]);
    }

    #[test]
    fn existing_user_becomes_canonical_and_is_spread_to_the_rest() {
        let p = plan_user("bob", &seen(vec![("a", Some(vec![u("bob", "U1", Some("S1"))])), ("b", Some(vec![]))])).unwrap();
        assert_eq!(p.canonical, Some(u("bob", "U1", Some("S1"))));
        assert_eq!(p.actions, vec![("a".to_string(), UserAction::Present), ("b".to_string(), UserAction::Add)]);
    }

    #[test]
    fn secret_is_filled_where_missing_and_taken_from_whoever_has_it() {
        let p = plan_user("bob", &seen(vec![("a", Some(vec![u("bob", "U1", None)])), ("b", Some(vec![u("bob", "U1", Some("S1"))]))])).unwrap();
        assert_eq!(p.canonical, Some(u("bob", "U1", Some("S1"))));
        assert_eq!(p.actions, vec![("a".to_string(), UserAction::FillSecret), ("b".to_string(), UserAction::Present)]);
    }

    #[test]
    fn same_name_with_different_uuid_or_secret_is_a_conflict_not_a_silent_fix() {
        let e = plan_user("bob", &seen(vec![("a", Some(vec![u("bob", "U1", None)])), ("b", Some(vec![u("bob", "U2", None)]))])).unwrap_err().to_string();
        assert!(e.contains("uuid") && e.contains('a') && e.contains('b'), "{e}");
        let e = plan_user("bob", &seen(vec![("a", Some(vec![u("bob", "U1", Some("S1"))])), ("b", Some(vec![u("bob", "U1", Some("S2"))]))])).unwrap_err().to_string();
        assert!(e.contains("секрет"), "{e}");
    }

    #[test]
    fn plan_rejects_bad_names_and_only_unreachable_gives_no_actions() {
        assert!(plan_user("a b", &[]).is_err());
        let p = plan_user("bob", &seen(vec![("a", None)])).unwrap();
        assert!(p.actions.is_empty() && p.canonical.is_none());
    }

    #[test]
    fn member_validation() {
        assert!(Member::new("203.0.113.5", 22, "root").validate().is_ok());
        assert!(Member::new("vpn.example.com", 2222, "admin_1").validate().is_ok());
        for bad in [Member::new("", 22, "root"), Member::new("a b", 22, "root"), Member::new("a;rm", 22, "root"), Member::new("h", 0, "root"), Member::new("h", 22, "ro ot"), Member::new("h", 22, "")] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fleet_add_dedupes_by_host_remove_and_persistence() {
        let d = tmp("store");
        assert_eq!(Fleet::load_in(&d).unwrap(), Fleet::default(), "нет файла = пустой парк");
        let mut f = Fleet::default();
        assert!(f.add(Member::new("1.1.1.1", 22, "root")).unwrap());
        assert!(f.add(Member::new("2.2.2.2", 22, "root")).unwrap());
        assert!(!f.add(Member::new("1.1.1.1", 2222, "admin")).unwrap(), "повтор обновляет, а не дублирует");
        assert_eq!(f.members.len(), 2);
        assert_eq!(f.members[0], Member::new("1.1.1.1", 2222, "admin"));
        assert!(f.add(Member::new("bad host", 22, "root")).is_err());
        f.save_in(&d).unwrap();
        assert_eq!(Fleet::load_in(&d).unwrap(), f);
        assert!(f.remove("2.2.2.2") && !f.remove("2.2.2.2"));
        assert_eq!(f.members.len(), 1);
    }

    #[test]
    fn corrupt_or_hostile_fleet_file_is_an_error() {
        let d = tmp("bad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("fleet.json"), "{not json").unwrap();
        assert!(Fleet::load_in(&d).is_err());
        std::fs::write(d.join("fleet.json"), r#"{"members":[{"host":"h; rm -rf /"}]}"#).unwrap();
        assert!(Fleet::load_in(&d).is_err(), "адрес с командой не принимается");
        std::fs::write(d.join("fleet.json"), r#"{"members":[{"host":"1.1.1.1"}]}"#).unwrap();
        assert_eq!(Fleet::load_in(&d).unwrap().members[0], Member::new("1.1.1.1", 22, "root"), "умолчания для порта и пользователя");
    }

    #[test]
    fn subscription_body_roundtrips_through_our_importer() {
        let u1 = "a158cda3-0b3d-424b-a8f8-26a6462c8349";
        let links = vec![
            format!("vless://{u1}@203.0.113.5:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=5bb5899f0cb12edf&type=tcp#a"),
            format!("vless://{u1}@203.0.113.6:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=5bb5899f0cb12edf&type=tcp#b"),
        ];
        let (servers, skipped) = crate::client::profile::parse_subscription(&subscription_body(&links));
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(servers.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(), ["203.0.113.5", "203.0.113.6"]);
    }
}
