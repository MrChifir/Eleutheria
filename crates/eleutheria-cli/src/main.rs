use std::io::{self, Write};

use anyhow::{anyhow, bail, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use eleutheria_core::client::config::RuDirect;
use eleutheria_core::tr;
use eleutheria_core::client::{categories, prober, watch};
use eleutheria_core::ipc::{self, Request, Response, StartParams};
use eleutheria_core::client::profile;
use eleutheria_core::client::runtime::{self, ConnectOpts, Status};
use eleutheria_core::helper_install;
use eleutheria_core::config::all_links;
use eleutheria_core::fleet::{self, Fleet, Member};
use eleutheria_core::harden::{self, HardenCtx, HardenOpts};
use eleutheria_core::provision::{self, Options};
use eleutheria_core::ssh::{Auth, AuthRejected, HostKeyVerifier, Ssh, Target};
use eleutheria_core::state::{Proto, State};
use eleutheria_core::store::{self, HostCheck};
use eleutheria_core::userprofiles;
use eleutheria_core::users;

#[derive(Parser)]
#[command(name = "eleutheria", version, about = "Install and manage a VPN on your own server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Server connection parameters
#[derive(Args, Clone)]
struct Conn {
    /// Server IP or domain
    host: String,
    #[arg(long, default_value = "root")]
    user: String,
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    /// Private SSH key (default: the key eleutheria saved for this server, otherwise a password)
    #[arg(long)]
    key: Option<String>,
    /// Name of the environment variable holding the SSH password (otherwise prompted interactively)
    #[arg(long)]
    password_env: Option<String>,
    /// Expected server key fingerprint (SHA256:...)
    #[arg(long)]
    host_key: Option<String>,
    /// Trust a new server key without asking (insecure)
    #[arg(long, short = 'y')]
    yes: bool,
}

/// How to connect to fleet servers (each has its own saved SSH key; a password is only needed the first time)
#[derive(Args, Clone)]
struct FleetConn {
    /// Name of the environment variable holding the SSH password (one for all servers; otherwise prompted for each)
    #[arg(long)]
    password_env: Option<String>,
    /// Trust new server keys without asking (insecure)
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Subcommand)]
enum ExitCmd {
    /// Add an external exit. Chain: client -> your server (--via) -> proxy. The proxy sees which sites are opened
    /// through it (and the content too for sites without HTTPS), so explicit consent via --accept-exit-risk is required.
    /// Only categories are routed to it automatically, and only with `watch --allow-external-exit`.
    Add {
        /// Entry name
        name: String,
        /// socks5://[login:password@]IP:port (IP address only)
        url: String,
        /// Name of your server the chain goes through (see `eleutheria servers`)
        #[arg(long)]
        via: String,
        /// I understand that the proxy owner sees which sites I open through it
        #[arg(long)]
        accept_exit_risk: bool,
    },
    /// List external exits
    List,
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Add a server to the fleet (it must already be installed via `provision`)
    Add {
        host: String,
        #[arg(long, default_value = "root")]
        user: String,
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
    },
    /// Remove a server from the fleet (the server itself is untouched)
    Remove { host: String },
    /// List fleet servers
    List,
    /// Add a shared user to all servers (same uuid and secret everywhere); safe to re-run
    UserAdd {
        name: String,
        #[command(flatten)]
        conn: FleetConn,
    },
    /// Update sing-box on all servers; up-to-date ones are skipped, one failure does not stop the others
    Update {
        #[command(flatten)]
        conn: FleetConn,
    },
    /// A user's unified subscription: links from all servers in base64 (to stdout or a file)
    Sub {
        name: String,
        /// Write to a file instead of stdout
        #[arg(long)]
        out: Option<String>,
        #[command(flatten)]
        conn: FleetConn,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Built-in and installed third-party protocol profiles
    List,
    /// Show what installing a profile folder would change (writes nothing)
    Diff { dir: std::path::PathBuf },
    /// Install or update a third-party profile from a folder: validation, diff, explicit confirmation
    Install {
        dir: std::path::PathBuf,
        /// Confirm without asking (the diff is still printed)
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove an installed third-party profile
    Remove { id: String },
}

#[derive(Subcommand)]
enum Cmd {
    /// Protocol profiles: built-in and third-party (M6)
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Install sing-box + VLESS/Reality, harden the server, print links
    Provision {
        #[command(flatten)]
        conn: Conn,
        /// VPN port (default 443, or the previous one if the server is already set up)
        #[arg(long)]
        port: Option<u16>,
        /// Site to masquerade as for Reality (must support TLS 1.3 and h2)
        #[arg(long)]
        sni: Option<String>,
        /// Profile name in the client
        #[arg(long, default_value = "Eleutheria")]
        name: String,
        /// Name of the first user
        #[arg(long, default_value = "default")]
        user_name: String,
        /// Do not switch to SSH key login and do not disable password login
        #[arg(long)]
        no_harden_ssh: bool,
        /// Do not enable BBR
        #[arg(long)]
        no_bbr: bool,
        /// Do not enable the ufw firewall
        #[arg(long)]
        no_firewall: bool,
        /// Additional protocols, comma-separated: hysteria2, tuic, ss2022, trojan, anytls, shadowtls, vless-ws (needs --cdn-host), the id of an installed third-party profile, or all (without vless-ws; VLESS+Reality is always present)
        #[arg(long, value_delimiter = ',')]
        protocols: Vec<String>,
        /// CDN-proxied (Cloudflare) domain for the vless-ws protocol
        #[arg(long)]
        cdn_host: Option<String>,
    },
    /// VPN users on the server
    #[command(subcommand)]
    User(UserCmd),
    /// Server component version and updating
    #[command(subcommand)]
    Server(ServerCmd),
    /// Server fleet: a shared user and a unified subscription across several of your VPSes, updating them all at once
    #[command(subcommand)]
    Fleet(FleetCmd),
    /// External exit: a third-party SOCKS5 proxy that traffic reaches via a chain through one of your servers
    #[command(subcommand)]
    Exit(ExitCmd),
    /// Forget a server's saved key (after reinstalling it)
    Forget { host: String },
    /// Where SSH keys and server profiles are stored; migrates old files to the protected store
    Secrets,
    /// Add server(s): a vless://, hysteria2://, tuic://, ss://, trojan://, anytls:// link or a subscription URL
    Import {
        source: String,
        /// Server name (single link only)
        #[arg(long)]
        name: Option<String>,
    },
    /// List saved servers
    Servers,
    /// Remove a server from the list
    RemoveServer { name: String },
    /// Connect: start a local proxy (HTTP+SOCKS5) through the saved servers
    Connect {
        /// Local proxy port
        #[arg(long, default_value_t = 7890)]
        port: u16,
        /// Control API port (localhost only)
        #[arg(long, default_value_t = 9090)]
        clash_port: u16,
        /// Use only this server (otherwise auto-select by latency)
        #[arg(long)]
        server: Option<String>,
        /// Russian resources directly, bypassing the VPN
        #[arg(long, value_enum, default_value = "minimal")]
        ru_direct: RuArg,
        /// URL used to check reachability through the server
        #[arg(long, default_value = runtime::DEFAULT_TEST_URL)]
        test_url: String,
        /// System-wide VPN via TUN (all traffic and DNS); requires the helper to be installed
        #[arg(long)]
        tun: bool,
        /// Do not open probe ports (the prober and auto-switching will not work)
        #[arg(long)]
        no_probes: bool,
    },
    /// Privileged helper service for TUN mode
    #[command(subcommand)]
    Helper(HelperCmd),
    /// Disconnect
    Disconnect,
    /// Connection state and latency to servers
    Status,
    /// One probe round: what opens through each server and directly, plus a diagnosis (switches nothing)
    Probe {
        /// Timeout of a single probe, seconds
        #[arg(long, default_value_t = 8)]
        timeout: u64,
    },
    /// Watch paths and automatically switch traffic categories on failures (Ctrl-C to stop)
    Watch {
        /// Pause between rounds, seconds
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Only observe and report what would be switched
        #[arg(long)]
        no_switch: bool,
        /// Allow a category to bypass the VPN if no VPN path opens the site but it opens directly
        #[arg(long)]
        allow_direct: bool,
        /// Allow a category to exit through an external exit (a third-party proxy will see that category's traffic) if the site blocks the exit IPs of all your servers
        #[arg(long)]
        allow_external_exit: bool,
        /// Stop after N rounds (0: unlimited)
        #[arg(long, default_value_t = 0)]
        rounds: u64,
    },
    /// Traffic categories (video, messengers, ...): list, enable, disable
    Categories {
        /// enable | disable
        action: Option<String>,
        /// Category id
        id: Option<String>,
    },
    /// Internal command: the app update rollback watchdog (launched by the app itself)
    #[command(hide = true)]
    UpdateWatchdog,
}

#[derive(Subcommand)]
enum HelperCmd {
    /// Install the service (sudo; on Windows, a terminal as administrator)
    Install {
        /// Who may access the helper (default: the user who ran sudo)
        #[cfg(unix)]
        #[arg(long)]
        allowed_uid: Option<u32>,
        /// Who may access the helper: user SID (default: the current user)
        #[cfg(windows)]
        #[arg(long)]
        allowed_sid: Option<String>,
    },
    /// Remove the service (sudo; on Windows, a terminal as administrator)
    Uninstall,
    /// Check that the helper responds
    Status,
}

#[derive(Clone, Copy)]
enum RuArg {
    Off,
    Minimal,
    Rulesets,
}

impl ValueEnum for RuArg {
    fn value_variants<'a>() -> &'a [Self] {
        &[RuArg::Off, RuArg::Minimal, RuArg::Rulesets]
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        use clap::builder::PossibleValue;
        Some(match self {
            RuArg::Off => PossibleValue::new("off").help(tr!("всё через VPN", "everything through the VPN")),
            RuArg::Minimal => PossibleValue::new("minimal").help(tr!("домены .ru/.su/.рф и приватные адреса напрямую", ".ru/.su/.рф domains and private addresses directly")),
            RuArg::Rulesets => PossibleValue::new("rulesets").help(tr!("+ наборы правил geoip-ru и geosite-category-ru (скачиваются через прокси)", "+ the geoip-ru and geosite-category-ru rule sets (downloaded through the proxy)")),
        })
    }
}

impl From<RuArg> for RuDirect {
    fn from(a: RuArg) -> Self {
        match a {
            RuArg::Off => RuDirect::Off,
            RuArg::Minimal => RuDirect::Minimal,
            RuArg::Rulesets => RuDirect::RuleSets,
        }
    }
}

#[derive(Subcommand)]
enum ServerCmd {
    /// sing-box version on the server and in this client
    Status { #[command(flatten)] conn: Conn },
    /// Update sing-box on the server (keys and users are kept, rolled back on failure)
    Update { #[command(flatten)] conn: Conn },
    /// Enable or disable additional protocols (hysteria2, tuic, ss2022, trojan, anytls, shadowtls, a third-party profile id, or all); shows the state when no flags are given
    Protocols {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_delimiter = ',')]
        enable: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        disable: Vec<String>,
        /// CDN-proxied domain, to enable vless-ws
        #[arg(long)]
        cdn_host: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Add a user and print their link
    Add { #[command(flatten)] conn: Conn, name: String },
    /// List users
    List { #[command(flatten)] conn: Conn },
    /// Show a user's link
    Link { #[command(flatten)] conn: Conn, name: String },
    /// Remove a user (their link stops working)
    Remove { #[command(flatten)] conn: Conn, name: String },
}

const CONN_PATHS: &[&str] = &["provision", "server status", "server update", "server protocols", "user add", "user list", "user link", "user remove"];
const FLEET_CONN_PATHS: &[&str] = &["fleet user-add", "fleet update", "fleet sub"];

/// Original Russian help, keyed by subcommand path (space-separated) and arg id ("" = the command's own `about`).
fn ru_help(path: &str, id: &str) -> Option<&'static str> {
    Some(match (path, id) {
        ("", "") => "Установка и управление VPN на твоём сервере",
        (p, "host") if CONN_PATHS.contains(&p) => "IP или домен сервера",
        (p, "key") if CONN_PATHS.contains(&p) => "Приватный SSH-ключ (по умолчанию: сохранённый eleutheria ключ для этого сервера, иначе пароль)",
        (p, "password_env") if CONN_PATHS.contains(&p) => "Имя переменной окружения с SSH-паролем (иначе спросим интерактивно)",
        (p, "host_key") if CONN_PATHS.contains(&p) => "Ожидаемый fingerprint ключа сервера (SHA256:...)",
        (p, "yes") if CONN_PATHS.contains(&p) => "Доверять новому ключу сервера без вопроса (небезопасно)",
        (p, "password_env") if FLEET_CONN_PATHS.contains(&p) => "Имя переменной окружения с SSH-паролем (один на все серверы; иначе спросим для каждого)",
        (p, "yes") if FLEET_CONN_PATHS.contains(&p) => "Доверять новым ключам серверов без вопроса (небезопасно)",
        ("profile", "") => "Профили протоколов: встроенные и сторонние (M6)",
        ("profile list", "") => "Встроенные и установленные сторонние профили протоколов",
        ("profile diff", "") => "Показать, что изменит установка папки с профилем (ничего не записывает)",
        ("profile install", "") => "Установить или обновить сторонний профиль из папки: проверка, diff, явное подтверждение",
        ("profile install", "yes") => "Подтвердить без вопроса (diff всё равно печатается)",
        ("profile remove", "") => "Удалить установленный сторонний профиль",
        ("provision", "") => "Установить sing-box + VLESS/Reality, укрепить сервер, вывести ссылки",
        ("provision", "port") => "Порт VPN (по умолчанию 443 или прежний, если сервер уже настроен)",
        ("provision", "sni") => "Сайт для маскировки Reality (должен поддерживать TLS 1.3 и h2)",
        ("provision", "name") => "Название профиля в клиенте",
        ("provision", "user_name") => "Имя первого пользователя",
        ("provision", "no_harden_ssh") => "Не переходить на вход по SSH-ключу и не отключать пароль",
        ("provision", "no_bbr") => "Не включать BBR",
        ("provision", "no_firewall") => "Не включать фаервол ufw",
        ("provision", "protocols") => "Дополнительные протоколы через запятую: hysteria2, tuic, ss2022, trojan, anytls, shadowtls, vless-ws (нужен --cdn-host) , id установленного стороннего профиля или all (без vless-ws; VLESS+Reality есть всегда)",
        ("provision", "cdn_host") => "Домен, проксируемый CDN (Cloudflare), для протокола vless-ws",
        ("user", "") => "Пользователи VPN на сервере",
        ("server", "") => "Версия серверной части и её обновление",
        ("fleet", "") => "Парк серверов: общий пользователь и единая подписка на нескольких своих VPS, обновление всех сразу",
        ("exit", "") => "Внешний exit: чужой SOCKS5-прокси, к которому трафик идёт цепочкой через один из твоих серверов",
        ("exit add", "") => "Добавить внешний exit. Цепочка: клиент → твой сервер (--via) → прокси. Прокси видит, какие сайты открываются через него (а для сайтов без HTTPS и содержимое), поэтому нужно явное согласие --accept-exit-risk. Автоматически на него уходят только категории и только с `watch --allow-external-exit`.",
        ("exit add", "name") => "Имя записи",
        ("exit add", "url") => "socks5://[логин:пароль@]IP:порт (только IP-адрес)",
        ("exit add", "via") => "Имя твоего сервера, через который идёт цепочка (см. `eleutheria servers`)",
        ("exit add", "accept_exit_risk") => "Я понимаю, что владелец прокси видит, какие сайты я через него открываю",
        ("exit list", "") => "Показать внешние exit",
        ("fleet add", "") => "Добавить сервер в парк (он должен быть уже установлен через `provision`)",
        ("fleet remove", "") => "Убрать сервер из парка (сам сервер не трогается)",
        ("fleet list", "") => "Показать серверы парка",
        ("fleet user-add", "") => "Добавить общего пользователя на все серверы (тот же uuid и секрет везде); повторный запуск безопасен",
        ("fleet update", "") => "Обновить sing-box на всех серверах; актуальные пропускаются, сбой одного не останавливает остальных",
        ("fleet sub", "") => "Единая подписка пользователя: ссылки со всех серверов в base64 (вывод в stdout или в файл)",
        ("fleet sub", "out") => "Записать в файл вместо вывода",
        ("server status", "") => "Версия sing-box на сервере и в этом клиенте",
        ("server update", "") => "Обновить sing-box на сервере (ключи и пользователи сохраняются, при сбое откат)",
        ("server protocols", "") => "Включить или выключить дополнительные протоколы (hysteria2, tuic, ss2022, trojan, anytls, shadowtls, id стороннего профиля или all); без флагов показывает состояние",
        ("server protocols", "cdn_host") => "Домен, проксируемый CDN, для включения vless-ws",
        ("user add", "") => "Добавить пользователя и вывести его ссылку",
        ("user list", "") => "Показать пользователей",
        ("user link", "") => "Показать ссылку пользователя",
        ("user remove", "") => "Удалить пользователя (его ссылка перестанет работать)",
        ("forget", "") => "Забыть сохранённый ключ сервера (после его переустановки)",
        ("secrets", "") => "Где лежат SSH-ключи и профили серверов; переносит старые файлы в защищённое хранилище",
        ("import", "") => "Добавить сервер(ы): ссылка vless://, hysteria2://, tuic://, ss://, trojan://, anytls:// или URL подписки",
        ("import", "name") => "Имя сервера (только для одиночной ссылки)",
        ("servers", "") => "Список сохранённых серверов",
        ("remove-server", "") => "Удалить сервер из списка",
        ("connect", "") => "Подключиться: поднять локальный прокси (HTTP+SOCKS5) через сохранённые серверы",
        ("connect", "port") => "Порт локального прокси",
        ("connect", "clash_port") => "Порт API управления (только localhost)",
        ("connect", "server") => "Использовать только этот сервер (иначе авто-выбор по задержке)",
        ("connect", "ru_direct") => "Российские ресурсы напрямую, минуя VPN",
        ("connect", "test_url") => "URL для проверки доступности через сервер",
        ("connect", "tun") => "Системный VPN через TUN (весь трафик и DNS); требует установленного helper",
        ("connect", "no_probes") => "Не открывать пробные порты (пробер и автопереключение работать не смогут)",
        ("helper", "") => "Привилегированная helper-служба для режима TUN",
        ("helper install", "") => "Установить службу (sudo; на Windows терминал от имени администратора)",
        ("helper install", "allowed_uid") => "Кому разрешён доступ к helper (по умолчанию: пользователь, запустивший sudo)",
        ("helper install", "allowed_sid") => "Кому разрешён доступ к helper: SID пользователя (по умолчанию: текущий пользователь)",
        ("helper uninstall", "") => "Удалить службу (sudo; на Windows терминал от имени администратора)",
        ("helper status", "") => "Проверить, что helper отвечает",
        ("disconnect", "") => "Отключиться",
        ("status", "") => "Состояние подключения и задержки до серверов",
        ("probe", "") => "Один раунд проб: что открывается через каждый сервер и напрямую, и диагноз (ничего не переключает)",
        ("probe", "timeout") => "Таймаут одной пробы, секунд",
        ("watch", "") => "Следить за путями и автоматически переключать категории трафика при отказах (Ctrl-C: остановить)",
        ("watch", "interval") => "Пауза между раундами, секунд",
        ("watch", "no_switch") => "Только наблюдать и сообщать, что было бы переключено",
        ("watch", "allow_direct") => "Разрешить категории выход мимо VPN, если ни один VPN-путь не открывает сайт, а напрямую он открывается",
        ("watch", "allow_external_exit") => "Разрешить категории выход через внешний exit (чужой прокси увидит трафик этой категории), если сайт не пускает выходной IP всех своих серверов",
        ("watch", "rounds") => "Остановиться после N раундов (0: без ограничения)",
        ("categories", "") => "Категории трафика (видео, мессенджеры, ...): список, включить, выключить",
        ("categories", "id") => "id категории",
        ("update-watchdog", "") => "Служебная команда: сторож отката обновления приложения (запускает само приложение)",
        _ => return None,
    })
}

/// Restore the original Russian help texts on a command tree (the derive attrs are English).
fn localize_ru(cmd: clap::Command) -> clap::Command {
    fn walk(mut cmd: clap::Command, path: &str) -> clap::Command {
        if let Some(t) = ru_help(path, "") {
            cmd = cmd.about(t);
        }
        let ids: Vec<String> = cmd.get_arguments().map(|a| a.get_id().to_string()).collect();
        for id in ids {
            if let Some(t) = ru_help(path, &id) {
                cmd = cmd.mut_arg(id, |a| a.help(t));
            }
        }
        let subs: Vec<String> = cmd.get_subcommands().map(|c| c.get_name().to_string()).collect();
        for name in subs {
            let sub_path = if path.is_empty() { name.clone() } else { format!("{path} {name}") };
            cmd = cmd.mut_subcommand(name, |c| walk(c, &sub_path));
        }
        cmd
    }
    walk(cmd, "")
}

fn make_verifier(c: &Conn) -> HostKeyVerifier {
    let id = store::host_id(&c.host, c.ssh_port);
    let host = c.host.clone();
    let pinned = c.host_key.clone();
    let yes = c.yes;
    Box::new(move |fp: &str| {
        if let Some(expected) = &pinned {
            if expected == fp {
                let _ = store::remember_host(&id, fp);
                return true;
            }
            eprintln!("{}", tr!(format!("Fingerprint сервера {fp} не совпал с --host-key {expected}"), format!("Server fingerprint {fp} does not match --host-key {expected}")));
            return false;
        }
        match store::check_host(&id, fp) {
            HostCheck::Match => true,
            HostCheck::Mismatch(old) => {
                eprintln!(
                    "{}",
                    tr!(
                        format!(
                            "ВНИМАНИЕ: ключ сервера {id} изменился.\n  был:    {old}\n  сейчас: {fp}\n\
                             Это переустановка сервера или перехват соединения. Если ты сам переустанавливал сервер: eleutheria forget {host}"
                        ),
                        format!(
                            "WARNING: the key of server {id} has changed.\n  was: {old}\n  now: {fp}\n\
                             This is either a server reinstall or a man-in-the-middle attack. If you reinstalled the server yourself: eleutheria forget {host}"
                        )
                    )
                );
                false
            }
            HostCheck::Unknown => {
                eprintln!("{}", tr!(format!("Новый сервер {id}. Fingerprint ключа: {fp}"), format!("New server {id}. Key fingerprint: {fp}")));
                let ok = yes || {
                    eprint!("{}", tr!("Доверять этому серверу? [y/N] ", "Trust this server? [y/N] "));
                    let _ = io::stderr().flush();
                    let mut s = String::new();
                    io::stdin().read_line(&mut s).ok();
                    matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да")
                };
                if ok {
                    let _ = store::remember_host(&id, fp);
                }
                ok
            }
        }
    })
}

fn prompt_password(c: &Conn) -> Result<String> {
    Ok(rpassword::prompt_password(tr!(format!("SSH-пароль для {}@{}: ", c.user, c.host), format!("SSH password for {}@{}: ", c.user, c.host)))?)
}

fn target(c: &Conn, auth: Auth) -> Target {
    Target { host: c.host.clone(), port: c.ssh_port, user: c.user.clone(), auth }
}

async fn connect(c: &Conn) -> Result<Ssh> {
    if let Some(path) = &c.key {
        return Ssh::connect(&target(c, Auth::KeyFile { path: path.clone(), passphrase: None }), make_verifier(c)).await;
    }
    if let Some(var) = &c.password_env {
        let pw = std::env::var(var).map_err(|_| anyhow!("{}", tr!(format!("переменная {var} не задана"), format!("variable {var} is not set"))))?;
        return Ssh::connect(&target(c, Auth::Password(pw)), make_verifier(c)).await;
    }
    if let Some(k) = store::saved_key(&c.host)? {
        let auth = Auth::KeyPem { pem: k.pem };
        match Ssh::connect(&target(c, auth), make_verifier(c)).await {
            Err(e) if e.downcast_ref::<AuthRejected>().is_some() => {
                eprintln!("{}", tr!("Сохранённый ключ не подошёл (сервер переустановлен?). Пробую пароль.", "The saved key was rejected (server reinstalled?). Trying password."));
            }
            other => return other,
        }
    }
    Ssh::connect(&target(c, Auth::Password(prompt_password(c)?)), make_verifier(c)).await
}

async fn current_link() -> Result<watch::Link> {
    if let Some(l) = runtime::link() {
        return Ok(l);
    }
    if let Some(sock) = helper_socket() {
        if let Ok(Response::Status(info)) = ipc::request(&sock, &Request::Status).await {
            if let Some(l) = runtime::link_from_helper(&info) {
                return Ok(l);
            }
        }
    }
    bail!("{}", tr!("нет подключения с пробами. Подключись: `eleutheria connect` (без --no-probes)", "no connection with probes. Connect first: `eleutheria connect` (without --no-probes)"))
}

fn verdict_line(e: &prober::Entry) -> String {
    use prober::Verdict::*;
    let v = match &e.verdict {
        Ok => "ok".to_string(),
        Degraded => tr!("медленно", "slow").to_string(),
        Failed(c) => tr!(format!("ОТКАЗ {}", c.as_str()), format!("FAILED {}", c.as_str())),
        Skip => "-".to_string(),
        Inherit => tr!("(туннель недоступен)", "(tunnel unavailable)").to_string(),
    };
    format!("{v}: {}", e.reason)
}

fn print_status(st: &Status) {
    let how = if st.listen_port == 0 {
        tr!("системный VPN (TUN)", "system VPN (TUN)").to_string()
    } else {
        tr!(format!("прокси 127.0.0.1:{}", st.listen_port), format!("proxy 127.0.0.1:{}", st.listen_port))
    };
    println!("{}", tr!(format!("Подключено (pid {}), {how}. Режим: {}.", st.pid, st.mode), format!("Connected (pid {}), {how}. Mode: {}.", st.pid, st.mode)));
    for s in &st.servers {
        let mark = if s.active { "*" } else { " " };
        match (s.delay_ms, &s.error) {
            (Some(ms), _) => println!("{}", tr!(format!(" {mark} {}\t{ms} мс", s.name), format!(" {mark} {}\t{ms} ms", s.name))),
            (None, e) => println!("{}", tr!(format!(" {mark} {}\tнедоступен: {}", s.name, e.clone().unwrap_or_default()), format!(" {mark} {}\tunavailable: {}", s.name, e.clone().unwrap_or_default()))),
        }
    }
}

#[cfg(unix)]
fn helper_socket() -> Option<std::path::PathBuf> {
    let p = ipc::default_socket_path();
    p.exists().then_some(p)
}

/// Windows: наличие named pipe через файловую систему не проверяем (проверка могла бы занять экземпляр pipe);
/// если службы нет, `ipc::request` вернёт понятную ошибку подключения.
#[cfg(windows)]
fn helper_socket() -> Option<std::path::PathBuf> {
    Some(ipc::default_socket_path())
}

fn install_hint() -> &'static str {
    if cfg!(windows) {
        tr!("eleutheria helper install (терминал от имени администратора)", "eleutheria helper install (terminal as administrator)")
    } else {
        "sudo eleutheria helper install"
    }
}

fn member_conn(m: &Member, f: &FleetConn) -> Conn {
    // Сохранённый ключ важнее пароля: после установки вход по паролю на сервере отключён, пароль нужен только
    // серверам, к которым ключ ещё не сохранён
    let password_env = if store::has_key(&m.host).unwrap_or(false) { None } else { f.password_env.clone() };
    Conn { host: m.host.clone(), user: m.ssh_user.clone(), ssh_port: m.ssh_port, key: None, password_env, host_key: None, yes: f.yes }
}

fn print_results(results: &[fleet::MemberResult]) -> bool {
    let mut all_ok = true;
    for r in results {
        println!("{} {}: {}", if r.outcome.is_ok() { "✓" } else { "✗" }, r.host, r.outcome.describe());
        all_ok &= r.outcome.is_ok();
    }
    all_ok
}

async fn run_fleet(cmd: FleetCmd) -> Result<()> {
    match cmd {
        FleetCmd::Add { host, user, ssh_port } => {
            let mut f = Fleet::load()?;
            let new = f.add(Member::new(host.clone(), ssh_port, user))?;
            f.save()?;
            let w = if new { tr!("Добавлен", "Added") } else { tr!("Обновлён", "Updated") };
            println!("{}", tr!(format!("{w} {host} ({} в парке)", f.members.len()), format!("{w} {host} ({} in fleet)", f.members.len())));
        }
        FleetCmd::Remove { host } => {
            let mut f = Fleet::load()?;
            if !f.remove(&host) {
                bail!("{}", tr!(format!("{host} нет в парке"), format!("{host} is not in the fleet")));
            }
            f.save()?;
            println!("{}", tr!(format!("Убран {host} (на самом сервере ничего не менялось). Осталось: {}", f.members.len()), format!("Removed {host} (nothing was changed on the server itself). Remaining: {}", f.members.len())));
        }
        FleetCmd::List => {
            let f = Fleet::load()?;
            if f.members.is_empty() {
                println!("{}", tr!("Парк пуст. Добавь сервер: eleutheria fleet add <IP>", "The fleet is empty. Add a server: eleutheria fleet add <IP>"));
            }
            for m in &f.members {
                println!("{}  (ssh {}@{}:{})", m.host, m.ssh_user, m.host, m.ssh_port);
            }
        }
        FleetCmd::UserAdd { name, conn } => {
            let f = Fleet::load()?;
            let (user, results) = fleet::add_user(&f, &name, |m| { let c = member_conn(&m, &conn); async move { connect(&c).await } }, &report).await?;
            let ok = print_results(&results);
            if let Some(u) = user {
                println!("{}", tr!(format!("Пользователь `{}` (uuid {}) общий на серверах парка. Ссылки: eleutheria fleet sub {}", u.name, u.uuid, u.name), format!("User `{}` (uuid {}) is shared across the fleet servers. Links: eleutheria fleet sub {}", u.name, u.uuid, u.name)));
            }
            if !ok {
                bail!("{}", tr!("не на всех серверах получилось (повтор безопасен: команда идемпотентна)", "not all servers succeeded (retrying is safe: the command is idempotent)"));
            }
        }
        FleetCmd::Update { conn } => {
            let f = Fleet::load()?;
            let results = fleet::update_all(&f, |m| { let c = member_conn(&m, &conn); async move { connect(&c).await } }, &report).await?;
            if !print_results(&results) {
                bail!("{}", tr!("не все серверы обновились", "not all servers were updated"));
            }
        }
        FleetCmd::Sub { name, out, conn } => {
            let f = Fleet::load()?;
            let (body, results) = fleet::subscription(&f, &name, |m| { let c = member_conn(&m, &conn); async move { connect(&c).await } }, &report).await?;
            // сводка в stderr, чтобы stdout остался чистой подпиской
            for r in &results {
                eprintln!("{} {}: {}", if r.outcome.is_ok() { "✓" } else { "✗" }, r.host, if r.outcome.is_ok() { tr!("ссылки собраны", "links collected").to_string() } else { r.outcome.describe() });
            }
            match out {
                Some(p) => {
                    store::write_secret_file(std::path::Path::new(&p), body.as_bytes())?;
                    eprintln!("{}", tr!(format!("Подписка записана в {p} (внутри ключи доступа: храни как пароль)"), format!("Subscription written to {p} (it contains access keys: keep it like a password)")));
                }
                None => println!("{body}"),
            }
        }
    }
    Ok(())
}

fn report(m: &str) {
    eprintln!("• {m}");
}

fn print_link(host: &str, st: &State, name: &str, qr: bool) -> Result<()> {
    let u = st.user(name).ok_or_else(|| anyhow!("{}", tr!(format!("пользователя `{name}` нет на сервере"), format!("user `{name}` does not exist on the server"))))?;
    println!("[{name}]");
    for l in all_links(host, st, u)? {
        println!("{}:\n{}\n", l.proto, l.url);
        if qr {
            // QR только там, где ссылка помещается в терминальный код
            match eleutheria_core::qr_text(&l.url) {
                Ok(q) => println!("{q}"),
                Err(_) => println!("{}\n", tr!("(ссылка слишком длинная для QR в терминале)", "(link is too long for a terminal QR code)")),
            }
        }
    }
    Ok(())
}

/// `hysteria2,tuic`, `all` -> список протоколов без повторов
fn parse_protos(names: &[String]) -> Result<Vec<Proto>> {
    eleutheria_core::profiles::parse_protocols(names)
}

/// Сохранить в списке клиента все протоколы пользователя; возвращает имена записей.
fn save_servers(host: &str, st: &State, u: &eleutheria_core::state::User) -> Result<Vec<String>> {
    profile::servers_from_state(host, st, u)?.into_iter().map(profile::upsert).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    eleutheria_core::i18n::set(eleutheria_core::i18n::from_env());
    let mut command = Cli::command();
    if !eleutheria_core::i18n::is_en() {
        command = localize_ru(command);
    }
    let cli = Cli::from_arg_matches(&command.get_matches()).unwrap_or_else(|e| e.exit());
    match cli.cmd {
        Cmd::Provision { conn, port, sni, name, user_name, no_harden_ssh, no_bbr, no_firewall, protocols, cdn_host } => {
            let extra = parse_protos(&protocols)?;
            let ssh = connect(&conn).await?;
            let opts = Options { port, sni, profile: name, user_name, extra, cdn_host };
            let res = provision::provision(&ssh, &opts, &report).await;
            let state = match res {
                Ok(r) => r.state,
                Err(e) => {
                    let _ = ssh.close().await;
                    bail!("{e:#}");
                }
            };

            let ctx = HardenCtx {
                host: conn.host.clone(),
                ssh_port: conn.ssh_port,
                ssh_user: conn.user.clone(),
                vpn_port: state.port,
                extra_ports: provision::listen_ports(&state).into_iter().filter(|(p, t)| !(*p == state.port && *t == "tcp")).collect(),
            };
            let hopts = HardenOpts { ssh_key: !no_harden_ssh, bbr: !no_bbr, firewall: !no_firewall };
            let notes = harden::run(&ssh, &ctx, &hopts, &|| make_verifier(&conn), &report).await;
            let _ = ssh.close().await;

            let saved = state.users.first().map(|u| save_servers(&conn.host, &state, u)).transpose()?;

            println!("\n{}", tr!("Укрепление сервера:", "Server hardening:"));
            for n in &notes {
                println!("  {} {}", if n.ok { "✓" } else { "⚠" }, n.text);
            }
            println!("\n{}\n", tr!("Готово. Ссылки для клиентов (Happ, Hiddify, v2rayN, Streisand, v2rayTun, sing-box):", "Done. Client links (Happ, Hiddify, v2rayN, Streisand, v2rayTun, sing-box):"));
            if let Some(n) = saved {
                println!("{}\n", tr!(format!("Сервер сохранён в списке клиента как `{}` (eleutheria connect).", n.join("`, `")), format!("Server saved in the client list as `{}` (eleutheria connect).", n.join("`, `"))));
            }
            let single = state.users.len() == 1;
            for u in &state.users {
                print_link(&conn.host, &state, &u.name, single)?;
            }
        }
        Cmd::Server(cmd) => match cmd {
            ServerCmd::Status { conn } => {
                let ssh = connect(&conn).await?;
                let r = provision::read_state(&ssh).await;
                let _ = ssh.close().await;
                let st = r?;
                let inst = st.as_ref().map(|s| s.singbox.clone());
                let need = provision::update_need(inst.as_deref(), eleutheria_core::singbox::VERSION);
                println!("{}", tr!(format!("На сервере: {}", inst.as_deref().unwrap_or("не установлено")), format!("On server: {}", inst.as_deref().unwrap_or("not installed"))));
                println!("{}", tr!(format!("В клиенте:  {}", eleutheria_core::singbox::VERSION), format!("In client:  {}", eleutheria_core::singbox::VERSION)));
                println!("{}{}", tr!("Статус: ", "Status: "), match need {
                    provision::UpdateNeed::NotInstalled => tr!("установки Eleutheria нет", "Eleutheria is not installed"),
                    provision::UpdateNeed::UpToDate => tr!("актуально", "up to date"),
                    provision::UpdateNeed::Outdated => tr!("нужно обновление (eleutheria server update)", "update needed (eleutheria server update)"),
                    provision::UpdateNeed::Newer => tr!("на сервере версия новее клиентской", "the server version is newer than the client's"),
                    provision::UpdateNeed::Unknown => tr!("версию разобрать не удалось", "could not parse the version"),
                });
                if let Some(st) = &st {
                    println!("{}vless-reality{}", tr!("Протоколы: ", "Protocols: "), st.protocols.enabled.keys().map(|p| format!(", {}", p.id())).collect::<String>());
                    println!("{}{}", tr!("Порты: ", "Ports: "), provision::listen_ports(st).into_iter().map(|(p, t)| format!("{p}/{t}")).collect::<Vec<_>>().join(", "));
                }
            }
            ServerCmd::Protocols { conn, enable, disable, cdn_host } => {
                let (en, dis) = (parse_protos(&enable)?, parse_protos(&disable)?);
                if let Some(p) = en.iter().find(|p| dis.contains(p)) {
                    bail!("{}", tr!(format!("{} одновременно в --enable и --disable", p.id()), format!("{} is in both --enable and --disable", p.id())));
                }
                let ssh = connect(&conn).await?;
                let mut res: Result<State> = users::load(&ssh).await;
                if res.is_ok() && !en.is_empty() {
                    res = provision::enable_protocols(&ssh, &en, cdn_host.as_deref(), &report).await;
                }
                if res.is_ok() && !dis.is_empty() {
                    res = provision::disable_protocols(&ssh, &dis, &report).await;
                }
                let _ = ssh.close().await;
                let st = res?;
                println!("{}vless-reality{}", tr!("Включено: ", "Enabled: "), st.protocols.enabled.keys().map(|p| format!(", {}", p.id())).collect::<String>());
                println!("{}{}", tr!("Порты: ", "Ports: "), provision::listen_ports(&st).into_iter().map(|(p, t)| format!("{p}/{t}")).collect::<Vec<_>>().join(", "));
                if !en.is_empty() {
                    if let Some(u) = st.users.first() {
                        let n = save_servers(&conn.host, &st, u)?;
                        println!("{}", tr!(format!("В списке клиента: `{}`.", n.join("`, `")), format!("In the client list: `{}`.", n.join("`, `"))));
                    }
                    println!("\n{}", tr!("Ссылки: eleutheria user link <сервер> <имя>", "Links: eleutheria user link <server> <name>"));
                }
            }
            ServerCmd::Update { conn } => {
                let ssh = connect(&conn).await?;
                let r = provision::update(&ssh, &report).await;
                let _ = ssh.close().await;
                let st = r?;
                println!("{}", tr!(format!("Готово: sing-box {} на сервере, пользователей: {}.", st.singbox, st.users.len()), format!("Done: sing-box {} on the server, users: {}.", st.singbox, st.users.len())));
            }
        },
        Cmd::User(cmd) => match cmd {
            UserCmd::Add { conn, name } => {
                let ssh = connect(&conn).await?;
                let r = users::add(&ssh, &name, &report).await;
                let _ = ssh.close().await;
                let (st, u) = r?;
                println!();
                print_link(&conn.host, &st, &u.name, true)?;
            }
            UserCmd::List { conn } => {
                let ssh = connect(&conn).await?;
                let r = users::load(&ssh).await;
                let _ = ssh.close().await;
                let st = r?;
                for u in &st.users {
                    println!("{}\t{}", u.name, u.uuid);
                }
            }
            UserCmd::Link { conn, name } => {
                let ssh = connect(&conn).await?;
                let r = users::load(&ssh).await;
                let _ = ssh.close().await;
                print_link(&conn.host, &r?, &name, true)?;
            }
            UserCmd::Remove { conn, name } => {
                let ssh = connect(&conn).await?;
                let r = users::remove(&ssh, &name, &report).await;
                let _ = ssh.close().await;
                r?;
                println!("{}", tr!(format!("Пользователь `{name}` удалён, его ссылка больше не работает."), format!("User `{name}` removed, their link no longer works.")));
            }
        },
        Cmd::Import { source, name } => {
            let (mut servers, skipped) = if ["vless://", "hysteria2://", "hy2://", "tuic://", "ss://", "trojan://", "anytls://"].iter().any(|p| source.starts_with(p)) {
                (vec![profile::parse_link(&source)?], vec![])
            } else if source.starts_with("http://") || source.starts_with("https://") {
                profile::parse_subscription(&profile::fetch_subscription(&source).await?)
            } else {
                if source.starts_with("socks5://") {
                    bail!("{}", tr!(format!("внешний exit добавляется отдельно, с явным согласием: eleutheria exit add <имя> {source} --via <сервер> --accept-exit-risk"), format!("an external exit is added separately, with explicit consent: eleutheria exit add <name> {source} --via <server> --accept-exit-risk")));
                }
                bail!("{}", tr!("нужна ссылка (vless://, hysteria2://, tuic://, ss://, trojan://, anytls://) или URL подписки (http/https)", "a link (vless://, hysteria2://, tuic://, ss://, trojan://, anytls://) or a subscription URL (http/https) is required"));
            };
            if let (Some(n), 1) = (name, servers.len()) {
                servers[0].name = n;
            }
            for s in servers {
                let n = profile::upsert(s)?;
                println!("{}", tr!(format!("Добавлен: {n}"), format!("Added: {n}")));
            }
            for r in &skipped {
                eprintln!("{}", tr!(format!("Пропущено: {r}"), format!("Skipped: {r}")));
            }
        }
        Cmd::Servers => {
            let all = profile::load();
            if all.is_empty() {
                println!("{}", tr!("Серверов нет. Добавь: eleutheria import <ссылка или подписка>", "No servers. Add one: eleutheria import <link or subscription>"));
            }
            for s in all {
                println!("{}\t{}:{}\t{}", s.name, s.host, s.port, s.kind_label());
            }
        }
        Cmd::RemoveServer { name } => {
            if profile::remove(&name)? {
                println!("{}", tr!(format!("Удалён: {name}"), format!("Removed: {name}")));
            } else {
                bail!("{}", tr!(format!("сервера `{name}` нет в списке"), format!("server `{name}` is not in the list")));
            }
        }
        Cmd::Connect { tun: true, server, ru_direct, test_url, no_probes, .. } => {
            let servers = profile::load();
            if servers.is_empty() {
                bail!("{}", tr!("нет серверов: добавь командой `eleutheria import <ссылка или подписка>`", "no servers: add one with `eleutheria import <link or subscription>`"));
            }
            let Some(sock) = helper_socket() else {
                bail!("{}", tr!(format!("helper не установлен или не запущен. Выполни: {}", install_hint()), format!("helper is not installed or not running. Run: {}", install_hint())));
            };
            let profiles = userprofiles::files_for_servers(&userprofiles::root(), &servers)?;
            let req = Request::Start(StartParams { servers, ru_direct: ru_direct.into(), selected: server, test_url, categories: categories::load(), probes: !no_probes, profiles });
            match ipc::request(&sock, &req).await? {
                Response::Started { pid } => println!("{}", tr!(format!("Туннель поднят (sing-box pid {pid})."), format!("Tunnel is up (sing-box pid {pid})."))),
                Response::Error { message } => bail!("{message}"),
                other => bail!("{}", tr!(format!("неожиданный ответ helper'а: {other:?}"), format!("unexpected helper response: {other:?}"))),
            }
            if let Response::Status(info) = ipc::request(&sock, &Request::Status).await? {
                if let Some(st) = runtime::status_from_helper(&info).await? {
                    print_status(&st);
                }
            }
            println!("{}", tr!("Весь трафик и DNS системы идут через VPN. Отключить: eleutheria disconnect", "All system traffic and DNS go through the VPN. Disconnect: eleutheria disconnect"));
        }
        Cmd::UpdateWatchdog => {
            use eleutheria_core::rollback::{self, Watch};
            let dir = store::config_dir();
            match rollback::watch(&dir, rollback::now_unix, std::thread::sleep) {
                Watch::Confirmed => {}
                Watch::RolledBack(p) => {
                    // прежняя версия возвращена: запускаем её, чтобы пользователь не остался без приложения
                    let _ = rollback::relaunch(&p);
                }
                Watch::Failed(e) => eprintln!("{}", tr!(format!("откат не удался: {e}"), format!("rollback failed: {e}"))),
            }
        }
        Cmd::Helper(cmd) => match cmd {
            HelperCmd::Install { #[cfg(unix)] allowed_uid, #[cfg(windows)] allowed_sid } => {
                let src = std::env::current_exe()?.with_file_name(format!("eleutheria-helper{}", std::env::consts::EXE_SUFFIX));
                #[cfg(unix)]
                {
                    let uid = allowed_uid
                        .or_else(|| std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok()))
                        .or_else(helper_install::current_uid)
                        .unwrap_or(0);
                    helper_install::install(uid, &src, &report).await?;
                }
                #[cfg(windows)]
                {
                    let sid = allowed_sid
                        .or_else(helper_install::current_user_sid)
                        .ok_or_else(|| anyhow!("{}", tr!("не удалось определить SID пользователя, укажи --allowed-sid", "could not determine the user SID, specify --allowed-sid")))?;
                    helper_install::install(&sid, &src, &report).await?;
                }
            }
            HelperCmd::Uninstall => helper_install::uninstall(&report)?,
            HelperCmd::Status => {
                let Some(sock) = helper_socket() else { bail!("{}", tr!(format!("helper не запущен (нет сокета {})", ipc::default_socket_path().display()), format!("helper is not running (no socket {})", ipc::default_socket_path().display()))) };
                match ipc::request(&sock, &Request::Ping).await? {
                    Response::Pong { version } => println!("{}", tr!(format!("helper работает, версия {version}"), format!("helper is running, version {version}"))),
                    Response::Error { message } => bail!("{message}"),
                    other => bail!("{}", tr!(format!("неожиданный ответ: {other:?}"), format!("unexpected response: {other:?}"))),
                }
            }
        },
        Cmd::Connect { port, clash_port, server, ru_direct, test_url, tun: false, no_probes } => {
            let servers = profile::load();
            let o = ConnectOpts { listen_port: port, clash_port, test_url, ru_direct: ru_direct.into(), selected: server, probes: !no_probes };
            let info = runtime::connect(&servers, &o).await?;
            println!("{}", tr!(format!("Подключено (pid {}). Локальный прокси: 127.0.0.1:{} (HTTP и SOCKS5).", info.pid, info.listen_port), format!("Connected (pid {}). Local proxy: 127.0.0.1:{} (HTTP and SOCKS5).", info.pid, info.listen_port)));
            match (info.delay_ms, &info.warning) {
                (Some(ms), _) => println!("{}", tr!(format!("Проверка через сервер: {ms} мс."), format!("Check through server: {ms} ms."))),
                (None, w) => eprintln!(
                    "{}",
                    tr!(
                        format!("Предупреждение: проверка через сервер не прошла ({}). Прокси поднят, смотри `eleutheria status`.", w.as_deref().unwrap_or("?")),
                        format!("Warning: the check through the server failed ({}). The proxy is up, see `eleutheria status`.", w.as_deref().unwrap_or("?"))
                    )
                ),
            }
            println!("{}", tr!(format!("Пока это локальный прокси, а не системный VPN: укажи его в браузере/системе\nили проверь: curl -x socks5h://127.0.0.1:{} https://example.com", info.listen_port), format!("For now this is a local proxy, not a system VPN: set it in your browser/system\nor test it: curl -x socks5h://127.0.0.1:{} https://example.com", info.listen_port)));
        }
        Cmd::Probe { timeout } => {
            let link = current_link().await?;
            let round = watch::probe_round(&link, std::time::Duration::from_secs(timeout)).await;
            println!("{}\n", watch::render_matrix(&round, &link.plan));
            let cats: Vec<String> = link.plan.targets.iter().map(|t| t.id.clone()).filter(|id| id != prober::CANARY).collect();
            let name = |tag: &str| link.plan.outbounds.iter().find(|o| o.tag == tag).map(|o| o.name.clone()).unwrap_or_default();
            for e in prober::classify(&round, &cats, &prober::DegradedPolicy::default()) {
                println!("{:<10} {:<16} {}", e.category, name(&e.tag), verdict_line(&e));
            }
        }
        Cmd::Watch { interval, no_switch, allow_direct, allow_external_exit, rounds } => {
            let link = current_link().await?;
            let cfg = watch::WatchCfg { switch: !no_switch, router: prober::RouterCfg { allow_direct, allow_external_exit, ..Default::default() }, ..Default::default() };
            let mut w = watch::Watcher::new(link.clone(), cfg);
            println!("{}", tr!(format!("Слежу за {} путями, раунд раз в {interval} с{}. Ctrl-C: остановить.", link.plan.outbounds.len(), if no_switch { " (только наблюдение)" } else { "" }), format!("Watching {} paths, one round every {interval} s{}. Ctrl-C to stop.", link.plan.outbounds.len(), if no_switch { " (observe only)" } else { "" })));
            let (mut n, mut dead) = (0u64, 0u32);
            loop {
                let step = w.step().await?;
                n += 1;
                for t in &step.transitions {
                    let who = link.plan.outbounds.iter().find(|o| o.tag == t.tag).map(|o| o.name.as_str()).unwrap_or(&t.tag);
                    println!("[{n}] {who} · {}: {:?} → {:?}{}", t.category, t.from, t.to, t.class.map(|c| format!(" [{}]", c.as_str())).unwrap_or_default());
                }
                for a in &step.applied {
                    println!("[{n}] {a}");
                }
                if rounds != 0 && n >= rounds {
                    break;
                }
                if watch::alive(&link).await { dead = 0 } else { dead += 1 }
                if dead >= 3 {
                    println!("{}", tr!("sing-box не отвечает: туннель остановлен, выхожу.", "sing-box is not responding: the tunnel has stopped, exiting."));
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
                    _ = tokio::signal::ctrl_c() => { println!("{}", tr!("Остановлено.", "Stopped.")); break; }
                }
            }
        }
        Cmd::Categories { action, id } => match (action.as_deref(), id) {
            (None, _) => {
                for c in categories::load() {
                    println!("{} {:<11} {:<14} {}", if c.enabled { "[x]" } else { "[ ]" }, c.id, c.title, c.domains.join(", "));
                }
            }
            (Some(a @ ("enable" | "disable")), Some(id)) => {
                categories::set_enabled(&id, a == "enable")?;
                println!("{}", tr!(format!("Категория `{id}`: {}. Вступит в силу при следующем подключении.", if a == "enable" { "включена" } else { "выключена" }), format!("Category `{id}`: {}. Takes effect on the next connection.", if a == "enable" { "enabled" } else { "disabled" })));
            }
            _ => bail!("{}", tr!("использование: eleutheria categories [enable|disable <id>]", "usage: eleutheria categories [enable|disable <id>]")),
        },
        Cmd::Disconnect => {
            let mut was = runtime::disconnect().await?;
            if let Some(sock) = helper_socket() {
                if let Ok(Response::Stopped { was_running: true }) = ipc::request(&sock, &Request::Stop).await {
                    was = true;
                }
            }
            println!("{}", if was { tr!("Отключено.", "Disconnected.") } else { tr!("Подключения не было.", "There was no connection.") });
        }
        Cmd::Status => {
            if let Some(st) = runtime::status().await? {
                print_status(&st);
            } else if let Some(sock) = helper_socket() {
                match ipc::request(&sock, &Request::Status).await {
                    Ok(Response::Status(info)) => match runtime::status_from_helper(&info).await? {
                        Some(st) => print_status(&st),
                        None => println!("{}", tr!("Не подключено.", "Not connected.")),
                    },
                    _ => println!("{}", tr!("Не подключено.", "Not connected.")),
                }
            } else {
                println!("{}", tr!("Не подключено.", "Not connected."));
            }
        }
        Cmd::Fleet(c) => run_fleet(c).await?,
        Cmd::Exit(ExitCmd::Add { name, url, via, accept_exit_risk }) => {
            if !accept_exit_risk {
                bail!("{}", tr!("внешний exit видит, какие сайты ты через него открываешь (а для сайтов без HTTPS и содержимое). Если это понятно и прокси твой или доверенный, повтори с --accept-exit-risk", "an external exit sees which sites you open through it (and, for sites without HTTPS, the content too). If you understand this and the proxy is yours or trusted, repeat with --accept-exit-risk"));
            }
            let s = profile::parse_socks_exit(&url, &name, &via)?;
            let n = profile::add_exit(s)?;
            println!("{}", tr!(format!("Добавлен внешний exit `{n}` через `{via}`. Основным сервером или автовыбором он не станет; на него могут уходить категории при `eleutheria watch --allow-external-exit`"), format!("External exit `{n}` added via `{via}`. It will not become the main server or be auto-selected; categories may go through it with `eleutheria watch --allow-external-exit`")));
        }
        Cmd::Exit(ExitCmd::List) => {
            let all: Vec<_> = profile::load().into_iter().filter(|s| s.is_external_exit()).collect();
            if all.is_empty() {
                println!("{}", tr!("Внешних exit нет. Добавь: eleutheria exit add <имя> socks5://IP:порт --via <сервер> --accept-exit-risk", "No external exits. Add one: eleutheria exit add <name> socks5://IP:port --via <server> --accept-exit-risk"));
            }
            for s in all {
                println!("{}", tr!(format!("{}\t{}:{}\tчерез {}", s.name, s.host, s.port, s.via.as_deref().unwrap_or("?")), format!("{}\t{}:{}\tvia {}", s.name, s.host, s.port, s.via.as_deref().unwrap_or("?"))));
            }
        }
        Cmd::Forget { host } => {
            let n = store::forget_host(&host)?;
            println!("{}", tr!(format!("Удалено записей: {n}"), format!("Entries removed: {n}")));
        }
        Cmd::Profile(c) => profile_cmd(c)?,
        Cmd::Secrets => {
            let st = eleutheria_core::secrets::default_store()?;
            let servers = profile::try_load()?; // заодно переносит старый profiles.json
            println!("{}", tr!(format!("Хранилище секретов: {}", st.kind()), format!("Secret store: {}", st.kind())));
            println!("{}", tr!(format!("Серверов в профилях: {}", servers.len()), format!("Servers in profiles: {}", servers.len())));
        }
    }
    Ok(())
}

fn profile_cmd(c: ProfileCmd) -> Result<()> {
    let root = userprofiles::root();
    match c {
        ProfileCmd::List => {
            for p in Proto::all_builtin() {
                let m = &eleutheria_core::profiles::builtin(&p).expect(tr!("встроенный", "built-in")).manifest;
                println!("{}{:<12} {}", tr!("встроенный  ", "built-in    "), m.id, m.name);
            }
            for (name, r) in userprofiles::list_in(&root) {
                match r {
                    Ok(c) => println!("{}{:<12} {}  [{}]", tr!("сторонний   ", "third-party "), name, c.profile.manifest.name, &c.files.digest()[..16]),
                    Err(e) => println!("{}", tr!(format!("сторонний   {name:<12} НЕ ПРОХОДИТ ПРОВЕРКУ: {e:#}"), format!("third-party {name:<12} FAILS VALIDATION: {e:#}"))),
                }
            }
            println!("\n{}", tr!("Сторонний профиль включается на сервере так же, как встроенный: `eleutheria server protocols <IP> --enable <id>`.", "A third-party profile is enabled on a server the same way as a built-in one: `eleutheria server protocols <IP> --enable <id>`."));
        }
        ProfileCmd::Diff { dir } => {
            let plan = userprofiles::plan_install_in(&root, &dir)?;
            print_plan(&plan);
        }
        ProfileCmd::Install { dir, yes } => {
            let plan = userprofiles::plan_install_in(&root, &dir)?;
            print_plan(&plan);
            if plan.replaces && !plan.changed {
                println!("{}", tr!("Установлена та же версия, ничего не делаю.", "The same version is already installed, doing nothing."));
                return Ok(());
            }
            let ok = yes || {
                eprint!("{} [y/N] ", if plan.replaces { tr!("Заменить установленный профиль этими изменениями?", "Replace the installed profile with these changes?") } else { tr!("Установить этот профиль?", "Install this profile?") });
                let _ = io::stderr().flush();
                let mut s = String::new();
                io::stdin().read_line(&mut s).ok();
                matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да")
            };
            if !ok {
                bail!("{}", tr!("отменено, ничего не записано", "cancelled, nothing written"));
            }
            let to = userprofiles::commit_in(&root, &plan)?;
            println!("{}", tr!(format!("Профиль установлен: {}", to.display()), format!("Profile installed: {}", to.display())));
        }
        ProfileCmd::Remove { id } => {
            userprofiles::remove_in(&root, &id)?;
            println!("{}", tr!(format!("Профиль `{id}` удалён."), format!("Profile `{id}` removed.")));
        }
    }
    Ok(())
}

fn print_plan(plan: &userprofiles::InstallPlan) {
    println!("{}", tr!("Профиль прошёл проверку:", "The profile passed validation:"));
    for l in plan.summary() {
        println!("  {l}");
    }
    if !plan.replaces {
        println!("\n{}", tr!("Новый профиль. Содержимое:", "New profile. Contents:"));
    } else if plan.changed {
        println!("\n{}", tr!("Изменения относительно установленной версии:", "Changes relative to the installed version:"));
    }
    if plan.changed {
        let shown = if plan.replaces { plan.diff.clone() } else { plan.candidate.files_listing() };
        print!("{shown}");
    }
}
