//! Provisioner: установка sing-box + VLESS/Reality. Идемпотентно: ключи и пользователи
//! берутся из /etc/eleutheria/state.json. Любая неудача после изменения сервера откатывается.

use anyhow::{bail, Context, Result};

use crate::config;
use crate::singbox;
use crate::ssh::Ssh;
use crate::state::{valid_user_name, State, User};
use crate::tx::{Report, Tx};
use crate::version;

pub const BIN: &str = "/usr/local/bin/sing-box";
pub const CONFIG: &str = "/etc/sing-box/config.json";
pub const BIN_PREV: &str = "/usr/local/bin/sing-box.prev";
pub const UNIT_NAME: &str = "eleutheria-sing-box";
pub const STATE: &str = "/etc/eleutheria/state.json";

const DEFAULT_PORT: u16 = 443;
const DEFAULT_SNI: &str = "www.microsoft.com";

const UNIT: &str = "[Unit]
Description=Eleutheria sing-box
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
";

pub struct Options {
    /// None = взять из состояния сервера, иначе 443
    pub port: Option<u16>,
    /// None = взять из состояния сервера, иначе www.microsoft.com
    pub sni: Option<String>,
    /// Название профиля в клиенте (используется в ссылках)
    pub profile: String,
    /// Имя первого пользователя при первичной установке
    pub user_name: String,
}

pub struct Provisioned {
    pub state: State,
}

pub async fn read_state(ssh: &Ssh) -> Result<Option<State>> {
    let raw = ssh.run(&format!("cat {STATE} 2>/dev/null")).await?.stdout_str();
    Ok(State::parse(&raw))
}

async fn wait_ready(ssh: &Ssh, port: u16) -> Result<bool> {
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let active = ssh.run(&format!("systemctl is-active --quiet {UNIT_NAME}")).await?.code == 0;
        let listen = ssh.run_ok(&format!("ss -ltnH 'sport = :{port}' || true")).await?;
        if active && !listen.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Записать конфиг для состояния `st`, проверить, перезапустить сервис. При неудаче вернуть прежний конфиг.
/// state.json пишется только после успешного старта.
pub async fn apply_config(ssh: &Ssh, st: &State, report: Report<'_>) -> Result<()> {
    apply_config_tracked(ssh, st, report).await.0
}

/// То же, что `apply_config`, но дополнительно сообщает, перезапускался ли сервис (нужно откату бинарника:
/// если сервис не трогали, перезапускать его при откате незачем).
async fn apply_config_tracked(ssh: &Ssh, st: &State, report: Report<'_>) -> (Result<()>, bool) {
    let mut restarted = false;
    let r = apply_config_inner(ssh, st, report, &mut restarted).await;
    (r, restarted)
}

async fn apply_config_inner(ssh: &Ssh, st: &State, report: Report<'_>, restarted: &mut bool) -> Result<()> {
    let cfg = serde_json::to_vec_pretty(&config::server_config(st))?;
    ssh.run_ok("mkdir -p /etc/sing-box /etc/eleutheria && chmod 700 /etc/eleutheria").await?;
    ssh.upload("/etc/sing-box/config.json.new", &cfg, 0o600).await?;
    let chk = ssh.run(&format!("{BIN} check -c /etc/sing-box/config.json.new")).await?;
    if chk.code != 0 {
        let _ = ssh.run("rm -f /etc/sing-box/config.json.new").await;
        bail!("sing-box отклонил конфиг: {}", chk.stderr_str());
    }
    let had_prev = ssh.run(&format!("test -f {CONFIG}")).await?.code == 0;
    if had_prev {
        ssh.run_ok(&format!("cp -p {CONFIG} {CONFIG}.bak")).await?;
    }
    ssh.run_ok(&format!("mv -f /etc/sing-box/config.json.new {CONFIG}")).await?;
    *restarted = true;
    ssh.run_ok(&format!("systemctl restart {UNIT_NAME}")).await?;

    if !wait_ready(ssh, st.port).await? {
        let logs = ssh
            .run(&format!("journalctl -u {UNIT_NAME} -n 20 --no-pager"))
            .await?
            .stdout_str();
        if had_prev {
            report("Сервис не поднялся с новым конфигом, возвращаю прежний…");
            ssh.run_ok(&format!("mv -f {CONFIG}.bak {CONFIG}")).await?;
            ssh.run_ok(&format!("systemctl restart {UNIT_NAME}")).await?;
            bail!("сервис не поднялся с новым конфигом, прежний конфиг восстановлен. Логи:\n{logs}");
        }
        bail!("сервис не поднялся. Логи:\n{logs}");
    }
    ssh.upload(STATE, &serde_json::to_vec_pretty(st)?, 0o600).await?;
    Ok(())
}

async fn sb_generate(ssh: &Ssh, what: &str) -> Result<String> {
    ssh.run_ok(&format!("{BIN} generate {what}")).await
}

/// Нужно ли обновлять серверную часть относительно бандла клиента.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateNeed {
    /// на сервере нет установки Eleutheria
    NotInstalled,
    UpToDate,
    Outdated,
    /// на сервере sing-box новее, чем в бандле: понижать версию автоматически не будем
    Newer,
    /// версию не удалось разобрать
    Unknown,
}

/// `installed`: поле `singbox` из state.json (None, если state.json нет).
pub fn update_need(installed: Option<&str>, bundled: &str) -> UpdateNeed {
    let Some(inst) = installed else { return UpdateNeed::NotInstalled };
    match version::compare(inst, bundled) {
        Some(std::cmp::Ordering::Equal) => UpdateNeed::UpToDate,
        Some(std::cmp::Ordering::Less) => UpdateNeed::Outdated,
        Some(std::cmp::Ordering::Greater) => UpdateNeed::Newer,
        None => UpdateNeed::Unknown,
    }
}

/// Кнопка «Обновить сервер»: тот же идемпотентный provision, но только для уже установленного сервера и без
/// понижения версии. Ключи, порт, SNI и пользователи берутся из state.json; hardening не запускается.
pub async fn update(ssh: &Ssh, report: Report<'_>) -> Result<State> {
    let Some(st) = read_state(ssh).await? else {
        bail!("на сервере нет установки Eleutheria: сначала выполни установку");
    };
    match update_need(Some(&st.singbox), singbox::VERSION) {
        UpdateNeed::Newer => bail!("на сервере sing-box {} новее, чем в этом клиенте ({}): обнови приложение", st.singbox, singbox::VERSION),
        UpdateNeed::UpToDate => report(&format!("sing-box {} уже актуален, переписываю конфиг без смены версии", st.singbox)),
        _ => {}
    }
    let opts = Options {
        port: None,
        sni: None,
        profile: st.profile.clone(),
        user_name: st.users.first().map(|u| u.name.clone()).unwrap_or_else(|| "default".into()),
    };
    Ok(provision(ssh, &opts, report).await?.state)
}

pub async fn provision(ssh: &Ssh, opts: &Options, report: Report<'_>) -> Result<Provisioned> {
    // 1. Предпроверки
    report("Проверяю сервер…");
    let uid = ssh.run_ok("id -u").await?;
    if uid != "0" {
        bail!("нужен root (сейчас uid={uid}). Подключись пользователем root.");
    }
    let arch = singbox::arch_from_uname(&ssh.run_ok("uname -m").await?)?;
    let os = ssh
        .run_ok(". /etc/os-release && echo \"$ID $VERSION_ID\"")
        .await
        .unwrap_or_default();
    let os_id = os.split_whitespace().next().unwrap_or("");
    if !matches!(os_id, "ubuntu" | "debian") {
        bail!("ОС `{os}` не поддерживается (нужны Ubuntu или Debian)");
    }
    if ssh.run("test -d /run/systemd/system").await?.code != 0 {
        bail!("на сервере нет systemd");
    }
    report(&format!("Сервер: {os}, {arch}"));

    let existing = read_state(ssh).await?;
    let port = opts
        .port
        .or(existing.as_ref().map(|s| s.port))
        .unwrap_or(DEFAULT_PORT);
    let sni = opts
        .sni
        .clone()
        .or(existing.as_ref().map(|s| s.sni.clone()))
        .unwrap_or_else(|| DEFAULT_SNI.to_string());

    // 2. Порт: занят чужим процессом?
    let listening = ssh.run_ok(&format!("ss -ltnH 'sport = :{port}' || true")).await?;
    let ours = ssh.run(&format!("systemctl is-active --quiet {UNIT_NAME}")).await?.code == 0;
    if !listening.is_empty() && !ours {
        bail!("порт {port}/tcp уже занят другим сервисом на сервере:\n{listening}\nОсвободи его или выбери другой порт (--port).");
    }

    // 3. Бинарник sing-box (скачиваем и проверяем хеш на клиенте, не на сервере).
    // Прежний бинарник сохраняется как sing-box.prev: если с новым сервис не поднимется, вернём его.
    let mut tx = Tx::new();
    let mut bin_backed_up = false;
    let installed_out = ssh
        .run(&format!("{BIN} version 2>/dev/null | head -1"))
        .await?
        .stdout_str();
    let installed = version::from_version_output(&installed_out);
    if installed.as_deref() == Some(singbox::VERSION) {
        report(&format!("sing-box {} уже установлен", singbox::VERSION));
    } else {
        report(&format!("Скачиваю sing-box {} и проверяю SHA256…", singbox::VERSION));
        let tgz = singbox::fetch_verified(arch).await?;
        report(&format!("Загружаю на сервер ({} МБ)…", tgz.len() / 1_000_000));
        ssh.upload("/tmp/eleutheria-sing-box.tgz", &tgz, 0o600).await?;
        let had_bin = ssh.run(&format!("test -x {BIN}")).await?.code == 0;
        if had_bin {
            ssh.run_ok(&format!("cp -p {BIN} {BIN_PREV}")).await.context("не удалось сохранить прежний бинарник sing-box")?;
        }
        let r = ssh
            .run_ok(
                "rm -rf /tmp/eleutheria-sb && mkdir -p /tmp/eleutheria-sb && \
                 tar -xzf /tmp/eleutheria-sing-box.tgz -C /tmp/eleutheria-sb --strip-components=1 --wildcards '*/sing-box' && \
                 install -m 0755 /tmp/eleutheria-sb/sing-box /usr/local/bin/sing-box && \
                 rm -rf /tmp/eleutheria-sb /tmp/eleutheria-sing-box.tgz",
            )
            .await
            .context("не удалось установить бинарник sing-box");
        if let Err(e) = r {
            if had_bin {
                let _ = ssh.run(&format!("mv -f {BIN_PREV} {BIN}")).await;
            }
            return Err(e);
        }
        bin_backed_up = had_bin;
    }

    // 4. Состояние: переиспользуем ключи и пользователей или создаём новые
    let state = match existing {
        Some(mut s) => {
            report("Нашёл прежнее состояние сервера (ключи и пользователи сохранены)");
            s.port = port;
            s.sni = sni;
            s.singbox = singbox::VERSION.to_string();
            s
        }
        None => {
            if !valid_user_name(&opts.user_name) {
                bail!("недопустимое имя пользователя `{}` (латиница, цифры, _ и -, до 32 символов)", opts.user_name);
            }
            report("Генерирую ключи Reality…");
            let kp = sb_generate(ssh, "reality-keypair").await?;
            let field = |name: &str| -> Result<String> {
                kp.lines()
                    .find_map(|l| l.strip_prefix(name))
                    .map(|v| v.trim().to_string())
                    .with_context(|| format!("не нашёл {name} в выводе generate reality-keypair"))
            };
            State {
                version: 2,
                singbox: singbox::VERSION.to_string(),
                profile: opts.profile.clone(),
                private_key: field("PrivateKey:")?,
                public_key: field("PublicKey:")?,
                short_id: sb_generate(ssh, "rand --hex 8").await?,
                sni,
                port,
                users: vec![User { name: opts.user_name.clone(), uuid: sb_generate(ssh, "uuid").await? }],
            }
        }
    };

    // 5. systemd + конфиг; при неудаче свежеустановленную службу убираем
    let unit_path = format!("/etc/systemd/system/{UNIT_NAME}.service");
    let fresh = ssh.run(&format!("test -f {unit_path}")).await?.code != 0;
    if fresh {
        tx.push(
            "удалить службу sing-box",
            format!("systemctl disable --now {UNIT_NAME} >/dev/null 2>&1; rm -f {unit_path}; systemctl daemon-reload"),
        );
    }
    ssh.upload(&unit_path, UNIT.as_bytes(), 0o644).await?;
    ssh.run_ok(&format!("systemctl daemon-reload && systemctl enable {UNIT_NAME} >/dev/null 2>&1")).await?;

    report("Записываю конфиг, проверяю и запускаю…");
    let (applied, restarted) = apply_config_tracked(ssh, &state, report).await;
    if let Err(e) = applied {
        // Откат идёт с конца: сначала вернуть бинарник, потом (если сервис успели перезапустить
        // с новым) перезапустить его ещё раз уже со старым. Если сервис не трогали, он продолжает работать.
        if restarted && !fresh && bin_backed_up {
            tx.push("перезапустить sing-box со старым бинарником", format!("systemctl restart {UNIT_NAME}"));
        }
        if bin_backed_up {
            tx.push("вернуть прежний бинарник sing-box", format!("mv -f {BIN_PREV} {BIN}"));
        }
        tx.rollback(ssh, report).await;
        return Err(e);
    }
    let _ = ssh.run(&format!("rm -f {BIN_PREV}")).await;

    // 6. Если ufw уже включён, открываем порт (включение ufw с нуля делает harden::firewall)
    let ufw_active = ssh
        .run("command -v ufw >/dev/null && ufw status | grep -q '^Status: active'")
        .await?
        .code
        == 0;
    if ufw_active {
        report(&format!("ufw активен, открываю {port}/tcp"));
        ssh.run_ok(&format!("ufw allow {port}/tcp")).await?;
    }

    Ok(Provisioned { state })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_need_cases() {
        assert_eq!(update_need(None, "1.14.3"), UpdateNeed::NotInstalled);
        assert_eq!(update_need(Some("1.14.3"), "1.14.3"), UpdateNeed::UpToDate);
        assert_eq!(update_need(Some("1.9.0"), "1.14.3"), UpdateNeed::Outdated);
        assert_eq!(update_need(Some("1.15.0"), "1.14.3"), UpdateNeed::Newer);
        assert_eq!(update_need(Some(""), "1.14.3"), UpdateNeed::Unknown);
        assert_eq!(update_need(Some("1.14.3-rc.1"), "1.14.3"), UpdateNeed::Outdated);
    }
}
