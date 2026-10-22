//! Hardening сервера: вход по SSH-ключу вместо пароля, BBR, ufw.
//! Каждый шаг независим, проверяется и откатывается при сбое. Потерять доступ к серверу нельзя:
//! пароль отключается только после того, как вход по ключу проверен новым подключением,
//! и после отключения проверяется ещё раз.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use crate::ssh::{shq, Auth, HostKeyVerifier, Ssh, Target};
use crate::store;
use crate::tx::{Report, Tx};

const SSHD: &str = "/usr/sbin/sshd";
const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/00-eleutheria.conf";
// Файл должен сортироваться раньше cloud-init (50-cloud-init.conf): sshd берёт первое найденное значение.
const SSHD_CONF: &str = "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n";
const SSHD_RELOAD: &str = "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload";

const BBR_CONF_PATH: &str = "/etc/sysctl.d/99-eleutheria-bbr.conf";
const BBR_MODULE_PATH: &str = "/etc/modules-load.d/eleutheria-bbr.conf";

pub struct HardenOpts {
    pub ssh_key: bool,
    pub bbr: bool,
    pub firewall: bool,
}

pub struct HardenCtx {
    pub host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub vpn_port: u16,
}

pub struct Note {
    pub ok: bool,
    pub text: String,
}

fn note(ok: bool, text: impl Into<String>) -> Note {
    Note { ok, text: text.into() }
}

pub type VerifierFactory<'a> = &'a (dyn Fn() -> HostKeyVerifier + Sync);

pub async fn run(
    ssh: &Ssh,
    ctx: &HardenCtx,
    o: &HardenOpts,
    make_verifier: VerifierFactory<'_>,
    report: Report<'_>,
) -> Vec<Note> {
    let mut notes = Vec::new();

    if o.ssh_key {
        report("Настраиваю вход по SSH-ключу…");
        match ssh_key_step(ssh, ctx, make_verifier, report).await {
            Ok(m) => notes.push(note(true, m)),
            Err(e) => notes.push(note(false, format!("SSH-ключ: {e:#}"))),
        }
    }
    if o.bbr {
        report("Включаю BBR…");
        let mut tx = Tx::new();
        match enable_bbr(ssh, &mut tx).await {
            Ok(Some(m)) => notes.push(note(true, m)),
            Ok(None) => notes.push(note(false, "BBR: ядро сервера не поддерживает (часто бывает на OpenVZ/LXC), пропущено")),
            Err(e) => {
                tx.rollback(ssh, report).await;
                notes.push(note(false, format!("BBR: {e:#}, откатил")));
            }
        }
    }
    if o.firewall {
        report("Настраиваю фаервол…");
        let mut tx = Tx::new();
        match firewall(ssh, ctx, &mut tx).await {
            Ok(m) => {
                // после включения фаервола убеждаемся, что SSH по-прежнему доступен
                match reconnect_ok(ctx, make_verifier).await {
                    Ok(()) => notes.push(note(true, m)),
                    Err(e) => {
                        tx.rollback(ssh, report).await;
                        notes.push(note(false, format!("Фаервол: после включения SSH недоступен ({e:#}), откатил")));
                    }
                }
            }
            Err(e) => {
                tx.rollback(ssh, report).await;
                notes.push(note(false, format!("Фаервол: {e:#}, откатил")));
            }
        }
    }
    notes
}

// ---------- SSH-ключ ----------

async fn ssh_key_step(
    ssh: &Ssh,
    ctx: &HardenCtx,
    mv: VerifierFactory<'_>,
    report: Report<'_>,
) -> Result<String> {
    let key = store::ensure_key(&ctx.host)?;

    let mut tx_key = Tx::new();
    if let Err(e) = install_ssh_key(ssh, &key.public, &mut tx_key).await {
        tx_key.rollback(ssh, report).await;
        return Err(e);
    }
    if let Err(e) = verify_key_login(ctx, &key.pem, mv).await {
        tx_key.rollback(ssh, report).await;
        bail!("вход по ключу не заработал ({e:#}). Ключ убран, пароль не трогал");
    }

    let mut tx_pw = Tx::new();
    let res = async {
        disable_password_auth(ssh, &mut tx_pw).await?;
        verify_key_login(ctx, &key.pem, mv).await
    }
    .await;
    if let Err(e) = res {
        tx_pw.rollback(ssh, report).await;
        bail!("не удалось безопасно отключить пароль ({e:#}). Откатил: пароль работает как раньше, ключ установлен");
    }
    Ok("вход по ключу (ключ в защищённом хранилище), вход по паролю отключён".to_string())
}

async fn install_ssh_key(ssh: &Ssh, pubkey: &str, tx: &mut Tx) -> Result<()> {
    let q = shq(pubkey);
    ssh.run_ok("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
        .await?;
    let present = ssh.run(&format!("grep -qxF {q} ~/.ssh/authorized_keys")).await?.code == 0;
    if !present {
        ssh.run_ok(&format!("printf '%s\\n' {q} >> ~/.ssh/authorized_keys")).await?;
        tx.push(
            "убрать добавленный SSH-ключ",
            format!(
                "grep -vxF {q} ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.eleutheria-tmp; \
                 cat ~/.ssh/authorized_keys.eleutheria-tmp > ~/.ssh/authorized_keys; rm -f ~/.ssh/authorized_keys.eleutheria-tmp"
            ),
        );
    }
    Ok(())
}

async fn verify_key_login(ctx: &HardenCtx, pem: &str, mv: VerifierFactory<'_>) -> Result<()> {
    let t = Target {
        host: ctx.host.clone(),
        port: ctx.ssh_port,
        user: ctx.ssh_user.clone(),
        auth: Auth::KeyPem { pem: pem.to_string() },
    };
    let s = Ssh::connect(&t, mv()).await?;
    let out = s.run("echo ok").await?;
    let _ = s.close().await;
    if out.stdout_str() != "ok" {
        bail!("неожиданный ответ сервера при проверке входа");
    }
    Ok(())
}

async fn reconnect_ok(ctx: &HardenCtx, mv: VerifierFactory<'_>) -> Result<()> {
    // Если ключ ещё не настроен (шаг отключён), проверять нечем: пропускаем.
    match store::saved_key(&ctx.host)? {
        Some(k) => verify_key_login(ctx, &k.pem, mv).await,
        None => Ok(()),
    }
}

async fn disable_password_auth(ssh: &Ssh, tx: &mut Tx) -> Result<()> {
    let inc = ssh
        .run("grep -Eqs '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/' /etc/ssh/sshd_config")
        .await?;
    if inc.code != 0 {
        bail!("основной sshd_config не подключает sshd_config.d, а править его вручную я не рискую");
    }
    ssh.run_ok("mkdir -p /etc/ssh/sshd_config.d").await?;
    ssh.upload(SSHD_DROPIN, SSHD_CONF.as_bytes(), 0o644).await?;
    tx.push(
        "вернуть прежние настройки sshd",
        format!("rm -f {SSHD_DROPIN}; {SSHD} -t && ({SSHD_RELOAD})"),
    );

    let t = ssh.run(&format!("{SSHD} -t")).await?;
    if t.code != 0 {
        bail!("sshd отклонил конфигурацию: {}", t.stderr_str());
    }
    ssh.run_ok(SSHD_RELOAD).await?;

    let eff = ssh
        .run_ok(&format!("{SSHD} -T | grep -i '^passwordauthentication' || true"))
        .await?;
    if eff.trim().to_lowercase() != "passwordauthentication no" {
        bail!("другой конфиг sshd переопределяет PasswordAuthentication (сейчас: `{}`)", eff.trim());
    }
    Ok(())
}

// ---------- BBR ----------

async fn enable_bbr(ssh: &Ssh, tx: &mut Tx) -> Result<Option<String>> {
    let cur = ssh.run("sysctl -n net.ipv4.tcp_congestion_control").await?.stdout_str();
    if cur == "bbr" {
        return Ok(Some("BBR уже включён".into()));
    }
    let _ = ssh.run("modprobe tcp_bbr 2>/dev/null").await?;
    let avail = ssh.run("sysctl -n net.ipv4.tcp_available_congestion_control").await?.stdout_str();
    if !avail.split_whitespace().any(|a| a == "bbr") {
        return Ok(None);
    }
    ssh.upload(BBR_CONF_PATH, b"net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n", 0o644)
        .await?;
    tx.push("убрать настройку BBR", format!("rm -f {BBR_CONF_PATH}"));
    ssh.run_ok(&format!("sysctl -p {BBR_CONF_PATH}")).await?;
    if ssh.run("sysctl -n net.ipv4.tcp_congestion_control").await?.stdout_str() != "bbr" {
        bail!("BBR не применился");
    }
    // чтобы модуль грузился после перезагрузки
    if ssh.run("test -d /etc/modules-load.d").await?.code == 0 {
        ssh.upload(BBR_MODULE_PATH, b"tcp_bbr\n", 0o644).await?;
        tx.push("убрать автозагрузку tcp_bbr", format!("rm -f {BBR_MODULE_PATH}"));
    }
    Ok(Some("BBR включён".into()))
}

// ---------- ufw ----------

/// Публично слушающие TCP-порты из вывода `ss -ltnH` (loopback игнорируем).
pub fn public_listen_ports(ss_out: &str) -> BTreeSet<u16> {
    ss_out
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3))
        .filter(|addr| !addr.starts_with("127.") && !addr.starts_with("[::1]"))
        .filter_map(|addr| addr.rsplit(':').next()?.parse::<u16>().ok())
        .collect()
}

async fn firewall(ssh: &Ssh, ctx: &HardenCtx, tx: &mut Tx) -> Result<String> {
    let installed = ssh.run("command -v ufw >/dev/null").await?.code == 0;
    let active = installed
        && ssh.run("ufw status | grep -q '^Status: active'").await?.code == 0;
    if active {
        return Ok("ufw уже активен, правила не менял".into());
    }

    let listening = ssh.run_ok("ss -ltnH || true").await?;
    let others: Vec<u16> = public_listen_ports(&listening)
        .into_iter()
        .filter(|p| *p != ctx.ssh_port && *p != ctx.vpn_port)
        .collect();
    if !others.is_empty() {
        return Ok(format!(
            "ufw не включал: на сервере слушают другие порты {others:?}, фаервол мог бы их закрыть"
        ));
    }

    if !installed {
        ssh.run_ok("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null")
            .await?;
    }
    let (sp, vp) = (ctx.ssh_port, ctx.vpn_port);
    ssh.run_ok(&format!(
        "ufw allow {sp}/tcp && ufw allow {vp}/tcp && ufw default deny incoming && ufw default allow outgoing"
    ))
    .await?;
    tx.push("выключить ufw", "ufw --force disable");
    ssh.run_ok("ufw --force enable").await?;
    Ok(format!("ufw включён: открыты {sp}/tcp (SSH) и {vp}/tcp (VPN), остальное закрыто"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_listeners() {
        let ss = "\
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 [::]:22 [::]:*
LISTEN 0 4096 *:443 *:*
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
LISTEN 0 5 127.0.0.1:8000 0.0.0.0:*
LISTEN 0 128 [::1]:631 [::]:*
LISTEN 0 511 0.0.0.0:8080 0.0.0.0:*
";
        let p = public_listen_ports(ss);
        assert_eq!(p.into_iter().collect::<Vec<_>>(), vec![22, 443, 8080]);
    }
}
