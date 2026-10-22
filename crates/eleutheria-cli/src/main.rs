use std::io::{self, Write};

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use eleutheria_core::client::config::RuDirect;
use eleutheria_core::ipc::{self, Request, Response, StartParams};
use eleutheria_core::client::profile::{self, Server};
use eleutheria_core::client::runtime::{self, ConnectOpts, Status};
use eleutheria_core::helper_install;
use eleutheria_core::config::vless_link;
use eleutheria_core::harden::{self, HardenCtx, HardenOpts};
use eleutheria_core::provision::{self, Options};
use eleutheria_core::ssh::{Auth, AuthRejected, HostKeyVerifier, Ssh, Target};
use eleutheria_core::state::State;
use eleutheria_core::store::{self, HostCheck};
use eleutheria_core::users;

#[derive(Parser)]
#[command(name = "eleutheria", version, about = "Установка и управление VPN на твоём сервере")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Параметры подключения к серверу
#[derive(Args, Clone)]
struct Conn {
    /// IP или домен сервера
    host: String,
    #[arg(long, default_value = "root")]
    user: String,
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    /// Приватный SSH-ключ (по умолчанию: сохранённый eleutheria ключ для этого сервера, иначе пароль)
    #[arg(long)]
    key: Option<String>,
    /// Имя переменной окружения с SSH-паролем (иначе спросим интерактивно)
    #[arg(long)]
    password_env: Option<String>,
    /// Ожидаемый fingerprint ключа сервера (SHA256:...)
    #[arg(long)]
    host_key: Option<String>,
    /// Доверять новому ключу сервера без вопроса (небезопасно)
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Установить sing-box + VLESS/Reality, укрепить сервер, вывести ссылки
    Provision {
        #[command(flatten)]
        conn: Conn,
        /// Порт VPN (по умолчанию 443 или прежний, если сервер уже настроен)
        #[arg(long)]
        port: Option<u16>,
        /// Сайт для маскировки Reality (должен поддерживать TLS 1.3 и h2)
        #[arg(long)]
        sni: Option<String>,
        /// Название профиля в клиенте
        #[arg(long, default_value = "Eleutheria")]
        name: String,
        /// Имя первого пользователя
        #[arg(long, default_value = "default")]
        user_name: String,
        /// Не переходить на вход по SSH-ключу и не отключать пароль
        #[arg(long)]
        no_harden_ssh: bool,
        /// Не включать BBR
        #[arg(long)]
        no_bbr: bool,
        /// Не включать фаервол ufw
        #[arg(long)]
        no_firewall: bool,
    },
    /// Пользователи VPN на сервере
    #[command(subcommand)]
    User(UserCmd),
    /// Версия серверной части и её обновление
    #[command(subcommand)]
    Server(ServerCmd),
    /// Забыть сохранённый ключ сервера (после его переустановки)
    Forget { host: String },
    /// Где лежат SSH-ключи и профили серверов; переносит старые файлы в защищённое хранилище
    Secrets,
    /// Добавить сервер(ы): ссылка vless:// или URL подписки
    Import {
        source: String,
        /// Имя сервера (только для одиночной ссылки)
        #[arg(long)]
        name: Option<String>,
    },
    /// Список сохранённых серверов
    Servers,
    /// Удалить сервер из списка
    RemoveServer { name: String },
    /// Подключиться: поднять локальный прокси (HTTP+SOCKS5) через сохранённые серверы
    Connect {
        /// Порт локального прокси
        #[arg(long, default_value_t = 7890)]
        port: u16,
        /// Порт API управления (только localhost)
        #[arg(long, default_value_t = 9090)]
        clash_port: u16,
        /// Использовать только этот сервер (иначе авто-выбор по задержке)
        #[arg(long)]
        server: Option<String>,
        /// Российские ресурсы напрямую, минуя VPN
        #[arg(long, value_enum, default_value = "minimal")]
        ru_direct: RuArg,
        /// URL для проверки доступности через сервер
        #[arg(long, default_value = runtime::DEFAULT_TEST_URL)]
        test_url: String,
        /// Системный VPN через TUN (весь трафик и DNS); требует установленного helper
        #[arg(long)]
        tun: bool,
    },
    /// Привилегированная helper-служба для режима TUN
    #[command(subcommand)]
    Helper(HelperCmd),
    /// Отключиться
    Disconnect,
    /// Состояние подключения и задержки до серверов
    Status,
    /// Служебная команда: сторож отката обновления приложения (запускает само приложение)
    #[command(hide = true)]
    UpdateWatchdog,
}

#[derive(Subcommand)]
enum HelperCmd {
    /// Установить службу (sudo; на Windows терминал от имени администратора)
    Install {
        /// Кому разрешён доступ к helper (по умолчанию: пользователь, запустивший sudo)
        #[cfg(unix)]
        #[arg(long)]
        allowed_uid: Option<u32>,
        /// Кому разрешён доступ к helper: SID пользователя (по умолчанию: текущий пользователь)
        #[cfg(windows)]
        #[arg(long)]
        allowed_sid: Option<String>,
    },
    /// Удалить службу (sudo; на Windows терминал от имени администратора)
    Uninstall,
    /// Проверить, что helper отвечает
    Status,
}

#[derive(Clone, Copy, ValueEnum)]
enum RuArg {
    /// всё через VPN
    Off,
    /// домены .ru/.su/.рф и приватные адреса напрямую
    Minimal,
    /// + наборы правил geoip-ru и geosite-category-ru (скачиваются через прокси)
    Rulesets,
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
    /// Версия sing-box на сервере и в этом клиенте
    Status { #[command(flatten)] conn: Conn },
    /// Обновить sing-box на сервере (ключи и пользователи сохраняются, при сбое откат)
    Update { #[command(flatten)] conn: Conn },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Добавить пользователя и вывести его ссылку
    Add { #[command(flatten)] conn: Conn, name: String },
    /// Показать пользователей
    List { #[command(flatten)] conn: Conn },
    /// Показать ссылку пользователя
    Link { #[command(flatten)] conn: Conn, name: String },
    /// Удалить пользователя (его ссылка перестанет работать)
    Remove { #[command(flatten)] conn: Conn, name: String },
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
            eprintln!("Fingerprint сервера {fp} не совпал с --host-key {expected}");
            return false;
        }
        match store::check_host(&id, fp) {
            HostCheck::Match => true,
            HostCheck::Mismatch(old) => {
                eprintln!(
                    "ВНИМАНИЕ: ключ сервера {id} изменился.\n  был:    {old}\n  сейчас: {fp}\n\
                     Это переустановка сервера или перехват соединения. Если ты сам переустанавливал сервер: eleutheria forget {host}"
                );
                false
            }
            HostCheck::Unknown => {
                eprintln!("Новый сервер {id}. Fingerprint ключа: {fp}");
                let ok = yes || {
                    eprint!("Доверять этому серверу? [y/N] ");
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
    Ok(rpassword::prompt_password(format!("SSH-пароль для {}@{}: ", c.user, c.host))?)
}

fn target(c: &Conn, auth: Auth) -> Target {
    Target { host: c.host.clone(), port: c.ssh_port, user: c.user.clone(), auth }
}

async fn connect(c: &Conn) -> Result<Ssh> {
    if let Some(path) = &c.key {
        return Ssh::connect(&target(c, Auth::KeyFile { path: path.clone(), passphrase: None }), make_verifier(c)).await;
    }
    if let Some(var) = &c.password_env {
        let pw = std::env::var(var).map_err(|_| anyhow!("переменная {var} не задана"))?;
        return Ssh::connect(&target(c, Auth::Password(pw)), make_verifier(c)).await;
    }
    if let Some(k) = store::saved_key(&c.host)? {
        let auth = Auth::KeyPem { pem: k.pem };
        match Ssh::connect(&target(c, auth), make_verifier(c)).await {
            Err(e) if e.downcast_ref::<AuthRejected>().is_some() => {
                eprintln!("Сохранённый ключ не подошёл (сервер переустановлен?). Пробую пароль.");
            }
            other => return other,
        }
    }
    Ssh::connect(&target(c, Auth::Password(prompt_password(c)?)), make_verifier(c)).await
}

fn print_status(st: &Status) {
    let how = if st.listen_port == 0 { "системный VPN (TUN)".to_string() } else { format!("прокси 127.0.0.1:{}", st.listen_port) };
    println!("Подключено (pid {}), {how}. Режим: {}.", st.pid, st.mode);
    for s in &st.servers {
        let mark = if s.active { "*" } else { " " };
        match (s.delay_ms, &s.error) {
            (Some(ms), _) => println!(" {mark} {}\t{ms} мс", s.name),
            (None, e) => println!(" {mark} {}\tнедоступен: {}", s.name, e.clone().unwrap_or_default()),
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
        "eleutheria helper install (терминал от имени администратора)"
    } else {
        "sudo eleutheria helper install"
    }
}

fn report(m: &str) {
    eprintln!("• {m}");
}

fn print_link(host: &str, st: &State, name: &str, qr: bool) -> Result<()> {
    let u = st.user(name).ok_or_else(|| anyhow!("пользователя `{name}` нет на сервере"))?;
    let link = vless_link(host, st, u);
    println!("[{name}]\n{link}\n");
    if qr {
        println!("{}", eleutheria_core::qr_text(&link)?);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Provision { conn, port, sni, name, user_name, no_harden_ssh, no_bbr, no_firewall } => {
            let ssh = connect(&conn).await?;
            let opts = Options { port, sni, profile: name, user_name };
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
            };
            let hopts = HardenOpts { ssh_key: !no_harden_ssh, bbr: !no_bbr, firewall: !no_firewall };
            let notes = harden::run(&ssh, &ctx, &hopts, &|| make_verifier(&conn), &report).await;
            let _ = ssh.close().await;

            let saved = state
                .users
                .first()
                .map(|u| profile::upsert(Server::from_state(&conn.host, &state, u)))
                .transpose()?;

            println!("\nУкрепление сервера:");
            for n in &notes {
                println!("  {} {}", if n.ok { "✓" } else { "⚠" }, n.text);
            }
            println!("\nГотово. Ссылки для клиентов (Happ, Hiddify, v2rayN, Streisand, v2rayTun, sing-box):\n");
            if let Some(n) = saved {
                println!("Сервер сохранён в списке клиента как `{n}` (eleutheria connect).\n");
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
                let inst = r?.map(|s| s.singbox);
                let need = provision::update_need(inst.as_deref(), eleutheria_core::singbox::VERSION);
                println!("На сервере: {}", inst.as_deref().unwrap_or("не установлено"));
                println!("В клиенте:  {}", eleutheria_core::singbox::VERSION);
                println!("Статус: {}", match need {
                    provision::UpdateNeed::NotInstalled => "установки Eleutheria нет",
                    provision::UpdateNeed::UpToDate => "актуально",
                    provision::UpdateNeed::Outdated => "нужно обновление (eleutheria server update)",
                    provision::UpdateNeed::Newer => "на сервере версия новее клиентской",
                    provision::UpdateNeed::Unknown => "версию разобрать не удалось",
                });
            }
            ServerCmd::Update { conn } => {
                let ssh = connect(&conn).await?;
                let r = provision::update(&ssh, &report).await;
                let _ = ssh.close().await;
                let st = r?;
                println!("Готово: sing-box {} на сервере, пользователей: {}.", st.singbox, st.users.len());
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
                println!("Пользователь `{name}` удалён, его ссылка больше не работает.");
            }
        },
        Cmd::Import { source, name } => {
            let (mut servers, skipped) = if source.starts_with("vless://") {
                (vec![profile::parse_vless(&source)?], vec![])
            } else if source.starts_with("http://") || source.starts_with("https://") {
                profile::parse_subscription(&profile::fetch_subscription(&source).await?)
            } else {
                bail!("нужна ссылка vless:// или URL подписки (http/https)");
            };
            if let (Some(n), 1) = (name, servers.len()) {
                servers[0].name = n;
            }
            for s in servers {
                let n = profile::upsert(s)?;
                println!("Добавлен: {n}");
            }
            for r in &skipped {
                eprintln!("Пропущено: {r}");
            }
        }
        Cmd::Servers => {
            let all = profile::load();
            if all.is_empty() {
                println!("Серверов нет. Добавь: eleutheria import <ссылка или подписка>");
            }
            for s in all {
                println!("{}\t{}:{}\t{}", s.name, s.host, s.port, s.security);
            }
        }
        Cmd::RemoveServer { name } => {
            if profile::remove(&name)? {
                println!("Удалён: {name}");
            } else {
                bail!("сервера `{name}` нет в списке");
            }
        }
        Cmd::Connect { tun: true, server, ru_direct, test_url, .. } => {
            let servers = profile::load();
            if servers.is_empty() {
                bail!("нет серверов: добавь командой `eleutheria import <ссылка или подписка>`");
            }
            let Some(sock) = helper_socket() else {
                bail!("helper не установлен или не запущен. Выполни: {}", install_hint());
            };
            let req = Request::Start(StartParams { servers, ru_direct: ru_direct.into(), selected: server, test_url });
            match ipc::request(&sock, &req).await? {
                Response::Started { pid } => println!("Туннель поднят (sing-box pid {pid})."),
                Response::Error { message } => bail!("{message}"),
                other => bail!("неожиданный ответ helper'а: {other:?}"),
            }
            if let Response::Status(info) = ipc::request(&sock, &Request::Status).await? {
                if let Some(st) = runtime::status_from_helper(&info).await? {
                    print_status(&st);
                }
            }
            println!("Весь трафик и DNS системы идут через VPN. Отключить: eleutheria disconnect");
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
                Watch::Failed(e) => eprintln!("откат не удался: {e}"),
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
                        .ok_or_else(|| anyhow!("не удалось определить SID пользователя, укажи --allowed-sid"))?;
                    helper_install::install(&sid, &src, &report).await?;
                }
            }
            HelperCmd::Uninstall => helper_install::uninstall(&report)?,
            HelperCmd::Status => {
                let Some(sock) = helper_socket() else { bail!("helper не запущен (нет сокета {})", ipc::default_socket_path().display()) };
                match ipc::request(&sock, &Request::Ping).await? {
                    Response::Pong { version } => println!("helper работает, версия {version}"),
                    Response::Error { message } => bail!("{message}"),
                    other => bail!("неожиданный ответ: {other:?}"),
                }
            }
        },
        Cmd::Connect { port, clash_port, server, ru_direct, test_url, tun: false } => {
            let servers = profile::load();
            let o = ConnectOpts { listen_port: port, clash_port, test_url, ru_direct: ru_direct.into(), selected: server };
            let info = runtime::connect(&servers, &o).await?;
            println!("Подключено (pid {}). Локальный прокси: 127.0.0.1:{} (HTTP и SOCKS5).", info.pid, info.listen_port);
            match (info.delay_ms, &info.warning) {
                (Some(ms), _) => println!("Проверка через сервер: {ms} мс."),
                (None, w) => eprintln!(
                    "Предупреждение: проверка через сервер не прошла ({}). Прокси поднят, смотри `eleutheria status`.",
                    w.as_deref().unwrap_or("?")
                ),
            }
            println!("Пока это локальный прокси, а не системный VPN: укажи его в браузере/системе\nили проверь: curl -x socks5h://127.0.0.1:{} https://example.com", info.listen_port);
        }
        Cmd::Disconnect => {
            let mut was = runtime::disconnect().await?;
            if let Some(sock) = helper_socket() {
                if let Ok(Response::Stopped { was_running: true }) = ipc::request(&sock, &Request::Stop).await {
                    was = true;
                }
            }
            println!("{}", if was { "Отключено." } else { "Подключения не было." });
        }
        Cmd::Status => {
            if let Some(st) = runtime::status().await? {
                print_status(&st);
            } else if let Some(sock) = helper_socket() {
                match ipc::request(&sock, &Request::Status).await {
                    Ok(Response::Status(info)) => match runtime::status_from_helper(&info).await? {
                        Some(st) => print_status(&st),
                        None => println!("Не подключено."),
                    },
                    _ => println!("Не подключено."),
                }
            } else {
                println!("Не подключено.");
            }
        }
        Cmd::Forget { host } => {
            let n = store::forget_host(&host)?;
            println!("Удалено записей: {n}");
        }
        Cmd::Secrets => {
            let st = eleutheria_core::secrets::default_store()?;
            let servers = profile::try_load()?; // заодно переносит старый profiles.json
            println!("Хранилище секретов: {}", st.kind());
            println!("Серверов в профилях: {}", servers.len());
        }
    }
    Ok(())
}
