//! Provisioner: установка sing-box + VLESS/Reality. Идемпотентно: ключи и пользователи
//! берутся из /etc/eleutheria/state.json. Любая неудача после изменения сервера откатывается.

use anyhow::{bail, Context, Result};

use crate::tr;
use crate::config;
use crate::singbox;
use crate::ssh::Ssh;
use crate::profiles::{self, Transport};
use crate::state::{valid_user_name, Proto, ProtoState, State, TlsInfo, User};
use crate::tlscert;
use crate::tx::{Report, Tx};
use crate::version;

pub const BIN: &str = "/usr/local/bin/sing-box";
pub const CONFIG: &str = "/etc/sing-box/config.json";
pub const BIN_PREV: &str = "/usr/local/bin/sing-box.prev";
pub const UNIT_NAME: &str = "eleutheria-sing-box";
pub const STATE: &str = "/etc/eleutheria/state.json";

const DEFAULT_PORT: u16 = 443;
const DEFAULT_SNI: &str = "www.microsoft.com";
/// Имя в самоподписанном сертификате QUIC-протоколов (клиент всё равно закрепляет ключ, а не проверяет имя)
const DEFAULT_QUIC_SNI: &str = "www.bing.com";

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
    /// Дополнительные протоколы (Hysteria2, TUIC, SS-2022), которые нужно включить. Уже включённые не трогаются.
    pub extra: Vec<Proto>,
    /// Домен, проксируемый CDN, для VLESS-WS (нужен, если среди `extra` есть vless-ws и он ещё не включён)
    pub cdn_host: Option<String>,
}

/// Домен CDN: имя из латиницы, цифр, точек и дефисов, минимум две метки, не IP.
pub fn valid_cdn_host(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.parse::<std::net::IpAddr>().is_err()
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

pub struct Provisioned {
    pub state: State,
}

pub async fn read_state(ssh: &Ssh) -> Result<Option<State>> {
    let raw = ssh.run(&format!("cat {STATE} 2>/dev/null")).await?.stdout_str();
    Ok(State::parse(&raw))
}

/// Порты, которые должен слушать сервер при состоянии `st`: (порт, "tcp" | "udp").
pub fn listen_ports(st: &State) -> Vec<(u16, &'static str)> {
    let mut v = vec![(st.port, "tcp")];
    for (p, ps) in &st.protocols.enabled {
        match ps.transport_of(p) {
            Transport::Tcp => v.push((ps.port, "tcp")),
            Transport::Udp => v.push((ps.port, "udp")),
            Transport::Both => {
                v.push((ps.port, "tcp"));
                v.push((ps.port, "udp"));
            }
        }
    }
    v
}

fn ss_flag(proto: &str) -> &'static str {
    if proto == "udp" { "-lunH" } else { "-ltnH" }
}

async fn wait_ready(ssh: &Ssh, st: &State) -> Result<bool> {
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if ssh.run(&format!("systemctl is-active --quiet {UNIT_NAME}")).await?.code != 0 {
            continue;
        }
        let mut all = true;
        for (port, proto) in listen_ports(st) {
            if ssh.run_ok(&format!("ss {} 'sport = :{port}' || true", ss_flag(proto))).await?.is_empty() {
                all = false;
                break;
            }
        }
        if all {
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
    let cfg = serde_json::to_vec_pretty(&config::server_config(st)?)?;
    ssh.run_ok("mkdir -p /etc/sing-box /etc/eleutheria && chmod 700 /etc/eleutheria").await?;
    ssh.upload("/etc/sing-box/config.json.new", &cfg, 0o600).await?;
    let chk = ssh.run(&format!("{BIN} check -c /etc/sing-box/config.json.new")).await?;
    if chk.code != 0 {
        let _ = ssh.run("rm -f /etc/sing-box/config.json.new").await;
        bail!("{}", tr!(format!("sing-box отклонил конфиг: {}", chk.stderr_str()), format!("sing-box rejected the config: {}", chk.stderr_str())));
    }
    let had_prev = ssh.run(&format!("test -f {CONFIG}")).await?.code == 0;
    if had_prev {
        ssh.run_ok(&format!("cp -p {CONFIG} {CONFIG}.bak")).await?;
    }
    ssh.run_ok(&format!("mv -f /etc/sing-box/config.json.new {CONFIG}")).await?;
    *restarted = true;
    ssh.run_ok(&format!("systemctl restart {UNIT_NAME}")).await?;

    if !wait_ready(ssh, st).await? {
        let logs = ssh
            .run(&format!("journalctl -u {UNIT_NAME} -n 20 --no-pager"))
            .await?
            .stdout_str();
        if had_prev {
            report(tr!("Сервис не поднялся с новым конфигом, возвращаю прежний…", "The service failed to start with the new config, restoring the previous one…"));
            ssh.run_ok(&format!("mv -f {CONFIG}.bak {CONFIG}")).await?;
            ssh.run_ok(&format!("systemctl restart {UNIT_NAME}")).await?;
            bail!("{}", tr!(format!("сервис не поднялся с новым конфигом, прежний конфиг восстановлен. Логи:\n{logs}"), format!("the service failed to start with the new config, the previous config was restored. Logs:\n{logs}")));
        }
        bail!("{}", tr!(format!("сервис не поднялся. Логи:\n{logs}"), format!("the service failed to start. Logs:\n{logs}")));
    }
    ssh.upload(STATE, &serde_json::to_vec_pretty(st)?, 0o600).await?;
    Ok(())
}

async fn sb_generate(ssh: &Ssh, what: &str) -> Result<String> {
    ssh.run_ok(&format!("{BIN} generate {what}")).await
}

/// Занят ли порт чужим процессом (для нового протокола: наш сервис его ещё не слушает).
async fn port_busy(ssh: &Ssh, port: u16, proto: &str) -> Result<bool> {
    Ok(!ssh.run_ok(&format!("ss {} 'sport = :{port}' || true", ss_flag(proto))).await?.is_empty())
}

fn transports(p: &Proto, ps: &ProtoState) -> &'static [&'static str] {
    tr(ps.transport_of(p))
}

/// Пользователям без секрета (созданным до M3) выдаёт секрет: из него выводятся пароли новых протоколов.
async fn ensure_user_secrets(ssh: &Ssh, st: &mut State) -> Result<()> {
    for u in st.users.iter_mut().filter(|u| u.secret.is_none()) {
        u.secret = Some(sb_generate(ssh, "rand --hex 16").await?);
    }
    Ok(())
}

/// Включает протоколы в `st` (в памяти) и готовит сервер: сертификат на диск, ключ SS-2022, секреты пользователей,
/// проверка занятости портов. Конфиг и перезапуск делает вызывающий через `apply_config`.
async fn ensure_protocols(ssh: &Ssh, st: &mut State, want: &[Proto], cdn_host: Option<&str>, report: Report<'_>) -> Result<Vec<Proto>> {
    let new: Vec<Proto> = want.iter().filter(|p| !st.protocols.enabled.contains_key(*p)).cloned().collect();
    if new.contains(&Proto::VlessWs) {
        match cdn_host {
            Some(h) if valid_cdn_host(h) => {}
            Some(h) => bail!("{}", tr!(format!("`{h}` не похоже на домен (нужно имя вроде cdn.example.com, не IP)"), format!("`{h}` does not look like a domain (a name like cdn.example.com is required, not an IP)"))),
            None => bail!("{}", tr!("для VLESS-WS нужен домен, проксируемый CDN (--cdn-host cdn.example.com)", "VLESS-WS requires a domain proxied by a CDN (--cdn-host cdn.example.com)")),
        }
    }
    // профили читаются и проверяются до любых изменений на сервере
    let mut profs = Vec::new();
    for p in &new {
        profs.push(profiles::get(p)?.into_owned());
    }
    // порты, которые займут новые профили, не должны пересекаться ни с Reality, ни с включёнными, ни друг с другом
    let mut claimed: Vec<(u16, &'static str, String)> = vec![(st.port, "tcp", "VLESS+Reality".into())];
    for (q, qs) in &st.protocols.enabled {
        let name = profiles::get(q).map(|x| x.manifest.display_name().to_string()).unwrap_or_else(|_| q.id().to_string());
        claimed.extend(transports(q, qs).iter().map(|t| (qs.port, *t, name.clone())));
    }
    for (p, prof) in new.iter().zip(&profs) {
        let port = prof.manifest.default_port;
        for t in tr(prof.manifest.transport) {
            if let Some((_, _, who)) = claimed.iter().find(|(cp, ct, _)| *cp == port && ct == t) {
                bail!("{}", tr!(format!("порт {port}/{t} для {} уже занят протоколом {who} на этом сервере", prof.manifest.display_name()), format!("port {port}/{t} for {} is already used by {who} on this server", prof.manifest.display_name())));
            }
            if port_busy(ssh, port, t).await? {
                bail!("{}", tr!(format!("порт {port}/{t} для {} занят: освободи его на сервере", prof.manifest.display_name()), format!("port {port}/{t} for {} is busy: free it on the server", prof.manifest.display_name())));
            }
            claimed.push((port, t, prof.manifest.display_name().to_string()));
        }
        let _ = p;
    }
    if new.is_empty() {
        if !st.protocols.enabled.is_empty() {
            ensure_user_secrets(ssh, st).await?;
        }
        return Ok(new);
    }
    ensure_user_secrets(ssh, st).await?;
    ssh.run_ok("mkdir -p /etc/eleutheria && chmod 700 /etc/eleutheria").await?;
    if profs.iter().any(|x| x.manifest.needs_cert) && st.protocols.tls.is_none() {
        report(tr!("Создаю самоподписанный сертификат для QUIC-протоколов…", "Creating a self-signed certificate for QUIC protocols…"));
        let c = tlscert::generate(DEFAULT_QUIC_SNI)?;
        ssh.upload(&format!("{}/key.pem", profiles::CERT_DIR), c.key_pem.as_bytes(), 0o600).await?;
        ssh.upload(&format!("{}/cert.pem", profiles::CERT_DIR), c.cert_pem.as_bytes(), 0o600).await?;
        st.protocols.tls = Some(TlsInfo { sni: DEFAULT_QUIC_SNI.into(), spki_sha256: c.spki_sha256_b64, cert_sha256: c.cert_sha256_hex });
    }
    for (p, prof) in new.iter().zip(&profs) {
        let mut ps = ProtoState::new(prof.manifest.default_port);
        if let Some(f) = prof.manifest.server_key {
            ps.server_key = Some(sb_generate(ssh, key_cmd(f)).await?);
        }
        if *p == Proto::VlessWs {
            ps.cdn_host = cdn_host.map(str::to_ascii_lowercase);
            ps.ws_path = Some(format!("/{}", sb_generate(ssh, "rand --hex 8").await?.trim()));
        }
        if !p.is_builtin() {
            ps.transport = Some(prof.manifest.transport);
        }
        report(&tr!(format!("Включаю {} на порту {}", prof.manifest.display_name(), prof.manifest.default_port), format!("Enabling {} on port {}", prof.manifest.display_name(), prof.manifest.default_port)));
        st.protocols.enabled.insert(p.clone(), ps);
    }
    Ok(new)
}

fn tr(t: Transport) -> &'static [&'static str] {
    match t {
        Transport::Tcp => &["tcp"],
        Transport::Udp => &["udp"],
        Transport::Both => &["tcp", "udp"],
    }
}

/// Команда `sing-box generate` для ключа сервера нужного вида.
fn key_cmd(f: profiles::PasswordFormat) -> &'static str {
    match f {
        profiles::PasswordFormat::Hex32 => "rand --hex 16",
        profiles::PasswordFormat::Base64_16 => "rand --base64 16",
        profiles::PasswordFormat::Base64_32 => "rand --base64 32",
    }
}

/// Открыть в ufw порты протоколов, если ufw активен (включение ufw с нуля делает `harden`).
async fn open_firewall(ssh: &Ssh, st: &State, report: Report<'_>) -> Result<()> {
    let ufw_active = ssh.run("command -v ufw >/dev/null && ufw status | grep -q '^Status: active'").await?.code == 0;
    if !ufw_active {
        return Ok(());
    }
    for (port, proto) in listen_ports(st) {
        report(&tr!(format!("ufw активен, открываю {port}/{proto}"), format!("ufw is active, opening {port}/{proto}")));
        ssh.run_ok(&format!("ufw allow {port}/{proto}")).await?;
    }
    Ok(())
}

/// Включить протоколы на уже установленном сервере. Идемпотентно: включённые пропускаются.
pub async fn enable_protocols(ssh: &Ssh, protos: &[Proto], cdn_host: Option<&str>, report: Report<'_>) -> Result<State> {
    let Some(mut st) = read_state(ssh).await? else {
        bail!("{}", tr!("на сервере нет установки Eleutheria: сначала выполни установку", "Eleutheria is not installed on the server: run the installation first"));
    };
    let new = ensure_protocols(ssh, &mut st, protos, cdn_host, report).await?;
    if new.is_empty() {
        report(tr!("Эти протоколы уже включены", "These protocols are already enabled"));
        return Ok(st);
    }
    report(tr!("Записываю конфиг, проверяю и перезапускаю…", "Writing the config, checking and restarting…"));
    apply_config(ssh, &st, report).await?;
    open_firewall(ssh, &st, report).await?;
    Ok(st)
}

/// Выключить протоколы. Сертификат и пароли пользователей остаются на сервере (повторное включение не меняет ключи).
pub async fn disable_protocols(ssh: &Ssh, protos: &[Proto], report: Report<'_>) -> Result<State> {
    let Some(mut st) = read_state(ssh).await? else {
        bail!("{}", tr!("на сервере нет установки Eleutheria", "Eleutheria is not installed on the server"));
    };
    let gone: Vec<(Proto, ProtoState)> = protos.iter().filter_map(|p| st.protocols.enabled.remove(p).map(|ps| (p.clone(), ps))).collect();
    if gone.is_empty() {
        report(tr!("Эти протоколы и не были включены", "These protocols were not enabled"));
        return Ok(st);
    }
    report(tr!("Записываю конфиг, проверяю и перезапускаю…", "Writing the config, checking and restarting…"));
    apply_config(ssh, &st, report).await?;
    let ufw_active = ssh.run("command -v ufw >/dev/null && ufw status | grep -q '^Status: active'").await?.code == 0;
    if ufw_active {
        for (p, ps) in &gone {
            for t in transports(p, ps) {
                let _ = ssh.run(&format!("ufw delete allow {}/{t}", ps.port)).await;
            }
        }
    }
    Ok(st)
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
        bail!("{}", tr!("на сервере нет установки Eleutheria: сначала выполни установку", "Eleutheria is not installed on the server: run the installation first"));
    };
    match update_need(Some(&st.singbox), singbox::VERSION) {
        UpdateNeed::Newer => bail!("{}", tr!(format!("на сервере sing-box {} новее, чем в этом клиенте ({}): обнови приложение", st.singbox, singbox::VERSION), format!("the server has sing-box {}, which is newer than in this client ({}): update the app", st.singbox, singbox::VERSION))),
        UpdateNeed::UpToDate => report(&tr!(format!("sing-box {} уже актуален, переписываю конфиг без смены версии", st.singbox), format!("sing-box {} is already up to date, rewriting the config without changing the version", st.singbox))),
        _ => {}
    }
    let opts = Options {
        port: None,
        sni: None,
        profile: st.profile.clone(),
        user_name: st.users.first().map(|u| u.name.clone()).unwrap_or_else(|| "default".into()),
        extra: vec![],
        cdn_host: None,
    };
    Ok(provision(ssh, &opts, report).await?.state)
}

pub async fn provision(ssh: &Ssh, opts: &Options, report: Report<'_>) -> Result<Provisioned> {
    // 1. Предпроверки
    report(tr!("Проверяю сервер…", "Checking the server…"));
    let uid = ssh.run_ok("id -u").await?;
    if uid != "0" {
        bail!("{}", tr!(format!("нужен root (сейчас uid={uid}). Подключись пользователем root."), format!("root is required (current uid={uid}). Connect as root.")));
    }
    let arch = singbox::arch_from_uname(&ssh.run_ok("uname -m").await?)?;
    let os = ssh
        .run_ok(". /etc/os-release && echo \"$ID $VERSION_ID\"")
        .await
        .unwrap_or_default();
    let os_id = os.split_whitespace().next().unwrap_or("");
    if !matches!(os_id, "ubuntu" | "debian") {
        bail!("{}", tr!(format!("ОС `{os}` не поддерживается (нужны Ubuntu или Debian)"), format!("OS `{os}` is not supported (Ubuntu or Debian required)")));
    }
    if ssh.run("test -d /run/systemd/system").await?.code != 0 {
        bail!("{}", tr!("на сервере нет systemd", "systemd is not available on the server"));
    }
    report(&tr!(format!("Сервер: {os}, {arch}"), format!("Server: {os}, {arch}")));

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
        bail!("{}", tr!(format!("порт {port}/tcp уже занят другим сервисом на сервере:\n{listening}\nОсвободи его или выбери другой порт (--port)."), format!("port {port}/tcp is already used by another service on the server:\n{listening}\nFree it or choose another port (--port).")));
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
        report(&tr!(format!("sing-box {} уже установлен", singbox::VERSION), format!("sing-box {} is already installed", singbox::VERSION)));
    } else {
        report(&tr!(format!("Скачиваю sing-box {} и проверяю SHA256…", singbox::VERSION), format!("Downloading sing-box {} and verifying SHA256…", singbox::VERSION)));
        let tgz = singbox::fetch_verified(arch).await?;
        report(&tr!(format!("Загружаю на сервер ({} МБ)…", tgz.len() / 1_000_000), format!("Uploading to the server ({} MB)…", tgz.len() / 1_000_000)));
        ssh.upload("/tmp/eleutheria-sing-box.tgz", &tgz, 0o600).await?;
        let had_bin = ssh.run(&format!("test -x {BIN}")).await?.code == 0;
        if had_bin {
            ssh.run_ok(&format!("cp -p {BIN} {BIN_PREV}")).await.context(tr!("не удалось сохранить прежний бинарник sing-box", "failed to save the previous sing-box binary"))?;
        }
        let r = ssh
            .run_ok(
                "rm -rf /tmp/eleutheria-sb && mkdir -p /tmp/eleutheria-sb && \
                 tar -xzf /tmp/eleutheria-sing-box.tgz -C /tmp/eleutheria-sb --strip-components=1 --wildcards '*/sing-box' && \
                 install -m 0755 /tmp/eleutheria-sb/sing-box /usr/local/bin/sing-box && \
                 rm -rf /tmp/eleutheria-sb /tmp/eleutheria-sing-box.tgz",
            )
            .await
            .context(tr!("не удалось установить бинарник sing-box", "failed to install the sing-box binary"));
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
            report(tr!("Нашёл прежнее состояние сервера (ключи и пользователи сохранены)", "Found the server's previous state (keys and users preserved)"));
            s.port = port;
            s.sni = sni;
            s.singbox = singbox::VERSION.to_string();
            s
        }
        None => {
            if !valid_user_name(&opts.user_name) {
                bail!("{}", tr!(format!("недопустимое имя пользователя `{}` (латиница, цифры, _ и -, до 32 символов)", opts.user_name), format!("invalid user name `{}` (Latin letters, digits, _ and -, up to 32 characters)", opts.user_name)));
            }
            report(tr!("Генерирую ключи Reality…", "Generating Reality keys…"));
            let kp = sb_generate(ssh, "reality-keypair").await?;
            let field = |name: &str| -> Result<String> {
                kp.lines()
                    .find_map(|l| l.strip_prefix(name))
                    .map(|v| v.trim().to_string())
                    .with_context(|| tr!(format!("не нашёл {name} в выводе generate reality-keypair"), format!("could not find {name} in the generate reality-keypair output")))
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
                users: vec![User { name: opts.user_name.clone(), uuid: sb_generate(ssh, "uuid").await?, secret: None }],
                protocols: Default::default(),
            }
        }
    };

    let mut state = state;
    ensure_protocols(ssh, &mut state, &opts.extra, opts.cdn_host.as_deref(), report).await?;

    // 5. systemd + конфиг; при неудаче свежеустановленную службу убираем
    let unit_path = format!("/etc/systemd/system/{UNIT_NAME}.service");
    let fresh = ssh.run(&format!("test -f {unit_path}")).await?.code != 0;
    if fresh {
        tx.push(
            tr!("удалить службу sing-box", "remove the sing-box service"),
            format!("systemctl disable --now {UNIT_NAME} >/dev/null 2>&1; rm -f {unit_path}; systemctl daemon-reload"),
        );
    }
    ssh.upload(&unit_path, UNIT.as_bytes(), 0o644).await?;
    ssh.run_ok(&format!("systemctl daemon-reload && systemctl enable {UNIT_NAME} >/dev/null 2>&1")).await?;

    report(tr!("Записываю конфиг, проверяю и запускаю…", "Writing the config, checking and starting…"));
    let (applied, restarted) = apply_config_tracked(ssh, &state, report).await;
    if let Err(e) = applied {
        // Откат идёт с конца: сначала вернуть бинарник, потом (если сервис успели перезапустить
        // с новым) перезапустить его ещё раз уже со старым. Если сервис не трогали, он продолжает работать.
        if restarted && !fresh && bin_backed_up {
            tx.push(tr!("перезапустить sing-box со старым бинарником", "restart sing-box with the old binary"), format!("systemctl restart {UNIT_NAME}"));
        }
        if bin_backed_up {
            tx.push(tr!("вернуть прежний бинарник sing-box", "restore the previous sing-box binary"), format!("mv -f {BIN_PREV} {BIN}"));
        }
        tx.rollback(ssh, report).await;
        return Err(e);
    }
    let _ = ssh.run(&format!("rm -f {BIN_PREV}")).await;

    // 6. Если ufw уже включён, открываем порты (включение ufw с нуля делает harden::firewall)
    open_firewall(ssh, &state, report).await?;

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

    #[test]
    fn cdn_host_validation() {
        for ok in ["cdn.example.com", "a-b.example.org", "x1.y2.z3.example.io"] {
            assert!(valid_cdn_host(ok), "{ok}");
        }
        for bad in ["", "example", "203.0.113.5", "::1", "-a.example.com", "a..example.com", "a b.example.com", "a.example.com/", "ex\u{430}mple.com", "http://a.example.com", &format!("{}.com", "a".repeat(64))] {
            assert!(!valid_cdn_host(bad), "{bad:?}");
        }
    }
}
