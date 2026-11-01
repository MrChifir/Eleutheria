//! Управление пользователями сервера: у каждого свой UUID, отзыв по одному.

use anyhow::{bail, Result};

use crate::provision::{apply_config, read_state, BIN};
use crate::ssh::Ssh;
use crate::state::{valid_user_name, State, User};
use crate::tx::Report;

pub async fn load(ssh: &Ssh) -> Result<State> {
    match read_state(ssh).await? {
        Some(s) => Ok(s),
        None => bail!("на сервере нет состояния eleutheria. Сначала выполни `eleutheria provision`."),
    }
}

pub async fn add(ssh: &Ssh, name: &str, report: Report<'_>) -> Result<(State, User)> {
    if !valid_user_name(name) {
        bail!("недопустимое имя `{name}` (латиница, цифры, _ и -, до 32 символов)");
    }
    let mut st = load(ssh).await?;
    if st.user(name).is_some() {
        bail!("пользователь `{name}` уже существует");
    }
    let uuid = ssh.run_ok(&format!("{BIN} generate uuid")).await?;
    let secret = if st.protocols.enabled.is_empty() { None } else { Some(ssh.run_ok(&format!("{BIN} generate rand --hex 16")).await?) };
    let user = User { name: name.to_string(), uuid, secret };
    st.users.push(user.clone());
    report("Применяю конфиг…");
    apply_config(ssh, &st, report).await?;
    Ok((st, user))
}

/// Добавляет пользователя с уже известными uuid и секретом (общий пользователь парка серверов).
/// Идемпотентно: такой же пользователь уже есть, конфиг не трогается; нет только секрета, он дописывается;
/// то же имя с другим uuid или секретом это ошибка.
pub async fn add_existing(ssh: &Ssh, user: &User, report: Report<'_>) -> Result<State> {
    let mut st = load(ssh).await?;
    if !merge_user(&mut st, user)? {
        return Ok(st);
    }
    report("Применяю конфиг…");
    apply_config(ssh, &st, report).await?;
    Ok(st)
}

/// Вносит пользователя в состояние. true = состояние изменилось.
pub fn merge_user(st: &mut State, user: &User) -> Result<bool> {
    if !valid_user_name(&user.name) {
        bail!("недопустимое имя `{}`", user.name);
    }
    match st.users.iter_mut().find(|u| u.name == user.name) {
        None => {
            st.users.push(user.clone());
            Ok(true)
        }
        Some(u) if u.uuid != user.uuid => bail!("пользователь `{}` уже есть с другим uuid", user.name),
        Some(u) => match (&u.secret, &user.secret) {
            (Some(a), Some(b)) if a != b => bail!("у пользователя `{}` уже есть другой секрет", user.name),
            (None, Some(_)) => {
                u.secret = user.secret.clone();
                Ok(true)
            }
            _ => Ok(false),
        },
    }
}

pub async fn remove(ssh: &Ssh, name: &str, report: Report<'_>) -> Result<State> {
    let mut st = load(ssh).await?;
    if st.user(name).is_none() {
        bail!("пользователя `{name}` нет на сервере");
    }
    if st.users.len() == 1 {
        bail!("нельзя удалить последнего пользователя");
    }
    st.users.retain(|u| u.name != name);
    report("Применяю конфиг…");
    apply_config(ssh, &st, report).await?;
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> State {
        let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[]}"#).unwrap();
        st.users = vec![User { name: "default".into(), uuid: "U0".into(), secret: None }];
        st
    }

    fn user(name: &str, uuid: &str, secret: Option<&str>) -> User {
        User { name: name.into(), uuid: uuid.into(), secret: secret.map(Into::into) }
    }

    #[test]
    fn merge_adds_new_user_with_given_uuid_and_secret() {
        let mut s = st();
        assert!(merge_user(&mut s, &user("bob", "U1", Some("S1"))).unwrap());
        assert_eq!(s.user("bob").unwrap().uuid, "U1");
        assert_eq!(s.user("bob").unwrap().secret.as_deref(), Some("S1"));
    }

    #[test]
    fn merge_is_idempotent_and_fills_a_missing_secret() {
        let mut s = st();
        assert!(!merge_user(&mut s, &user("default", "U0", None)).unwrap(), "то же самое: без изменений");
        assert!(merge_user(&mut s, &user("default", "U0", Some("S"))).unwrap(), "секрета не было: дописан");
        assert!(!merge_user(&mut s, &user("default", "U0", Some("S"))).unwrap());
        assert!(!merge_user(&mut s, &user("default", "U0", None)).unwrap(), "пустой секрет не затирает имеющийся");
        assert_eq!(s.user("default").unwrap().secret.as_deref(), Some("S"));
    }

    #[test]
    fn merge_refuses_conflicts_and_bad_names() {
        let mut s = st();
        assert!(merge_user(&mut s, &user("default", "OTHER", None)).is_err());
        merge_user(&mut s, &user("default", "U0", Some("S"))).unwrap();
        assert!(merge_user(&mut s, &user("default", "U0", Some("T"))).is_err());
        assert!(merge_user(&mut s, &user("a b", "U9", None)).is_err());
        assert_eq!(s.users.len(), 1, "при отказе состояние не меняется");
    }
}
