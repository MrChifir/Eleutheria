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
    let user = User { name: name.to_string(), uuid };
    st.users.push(user.clone());
    report("Применяю конфиг…");
    apply_config(ssh, &st, report).await?;
    Ok((st, user))
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
