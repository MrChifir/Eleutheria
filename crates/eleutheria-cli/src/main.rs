use std::io::{self, Write};

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use eleutheria_core::client::config::RuDirect;
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

/// Как подключаться к серверам парка (у каждого свой сохранённый ключ SSH; пароль нужен только первый раз)
#[derive(Args, Clone)]
struct FleetConn {
    /// Имя переменной окружения с SSH-паролем (один на все серверы; иначе спросим для каждого)
    #[arg(long)]
    password_env: Option<String>,
    /// Доверять новым ключам серверов без вопроса (небезопасно)
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Subcommand)]
enum ExitCmd {
    /// Добавить внешний exit. Цепочка: клиент → твой сервер (--via) → прокси. Прокси видит, какие сайты открываются
    /// через него (а для сайтов без HTTPS и содержимое), поэтому нужно явное согласие --accept-exit-risk.
    /// Автоматически на него уходят только категории и только с `watch --allow-external-exit`.
    Add {
        /// Имя записи
        name: String,
        /// socks5://[логин:пароль@]IP:порт (только IP-адрес)
        url: String,
        /// Имя твоего сервера, через который идёт цепочка (см. `eleutheria servers`)
        #[arg(long)]
        via: String,
        /// Я понимаю, что владелец прокси видит, какие сайты я через него открываю
        #[arg(long)]
        accept_exit_risk: bool,
    },
    /// Показать внешние exit
    List,
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Добавить сервер в парк (он должен быть уже установлен через `provision`)
    Add {
        host: String,
        #[arg(long, default_value = "root")]
        user: String,
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
    },
    /// Убрать сервер из парка (сам сервер не трогается)
    Remove { host: String },
    /// Показать серверы парка
    List,
    /// Добавить общего пользователя на все серверы (тот же uuid и секрет везде); повторный запуск безопасен
    UserAdd {
        name: String,
        #[command(flatten)]
        conn: FleetConn,
    },
    /// Обновить sing-box на всех серверах; актуальные пропускаются, сбой одного не останавливает остальных
    Update {
        #[command(flatten)]
        conn: FleetConn,
    },
    /// Единая подписка пользователя: ссылки со всех серверов в base64 (вывод в stdout или в файл)
    Sub {
        name: String,
        /// Записать в файл вместо вывода
        #[arg(long)]
        out: Option<String>,
        #[command(flatten)]
        conn: FleetConn,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Встроенные и установленные сторонние профили протоколов
    List,
    /// Показать, что изменит установка папки с профилем (ничего не записывает)
    Diff { dir: std::path::PathBuf },
    /// Установить или обновить сторонний профиль из папки: проверка, diff, явное подтверждение
    Install {
        dir: std::path::PathBuf,
        /// Подтвердить без вопроса (diff всё равно печатается)
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Удалить установленный сторонний профиль
    Remove { id: String },
}

#[derive(Subcommand)]
enum Cmd {
    /// Профили протоколов: встроенные и сторонние (M6)
    #[command(subcommand)]
    Profile(ProfileCmd),
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
        /// Дополнительные протоколы через запятую: hysteria2, tuic, ss2022, vless-ws (нужен --cdn-host) , id установленного стороннего профиля или all (без vless-ws; VLESS+Reality есть всегда)
        #[arg(long, value_delimiter = ',')]
        protocols: Vec<String>,
        /// Домен, проксируемый CDN (Cloudflare), для протокола vless-ws
        #[arg(long)]
        cdn_host: Option<String>,
    },
    /// Пользователи VPN на сервере
    #[command(subcommand)]
    User(UserCmd),
    /// Версия серверной части и её обновление
    #[command(subcommand)]
    Server(ServerCmd),
    /// Парк серверов: общий пользователь и единая подписка на нескольких своих VPS, обновление всех сразу
    #[command(subcommand)]
    Fleet(FleetCmd),
    /// Внешний exit: чужой SOCKS5-прокси, к которому трафик идёт цепочкой через один из твоих серверов
    #[command(subcommand)]
    Exit(ExitCmd),
    /// Забыть сохранённый ключ сервера (после его переустановки)
    Forget { host: String },
    /// Где лежат SSH-ключи и профили серверов; переносит старые файлы в защищённое хранилище
    Secrets,
    /// Добавить сервер(ы): ссылка vless://, hysteria2://, tuic://, ss:// или URL подписки
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
        /// Не открывать пробные порты (пробер и автопереключение работать не смогут)
        #[arg(long)]
        no_probes: bool,
    },
    /// Привилегированная helper-служба для режима TUN
    #[command(subcommand)]
    Helper(HelperCmd),
    /// Отключиться
    Disconnect,
    /// Состояние подключения и задержки до серверов
    Status,
    /// Один раунд проб: что открывается через каждый сервер и напрямую, и диагноз (ничего не переключает)
    Probe {
        /// Таймаут одной пробы, секунд
        #[arg(long, default_value_t = 8)]
        timeout: u64,
    },
    /// Следить за путями и автоматически переключать категории трафика при отказах (Ctrl-C: остановить)
    Watch {
        /// Пауза между раундами, секунд
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Только наблюдать и сообщать, что было бы переключено
        #[arg(long)]
        no_switch: bool,
        /// Разрешить категории выход мимо VPN, если ни один VPN-путь не открывает сайт, а напрямую он открывается
        #[arg(long)]
        allow_direct: bool,
        /// Разрешить категории выход через внешний exit (чужой прокси увидит трафик этой категории), если сайт не пускает выходной IP всех своих серверов
        #[arg(long)]
        allow_external_exit: bool,
        /// Остановиться после N раундов (0: без ограничения)
        #[arg(long, default_value_t = 0)]
        rounds: u64,
    },
    /// Категории трафика (видео, мессенджеры, ...): список, включить, выключить
    Categories {
        /// enable | disable
        action: Option<String>,
        /// id категории
        id: Option<String>,
    },
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
    /// Включить или выключить дополнительные протоколы (hysteria2, tuic, ss2022, id стороннего профиля или all); без флагов показывает состояние
    Protocols {
        #[command(flatten)]
        conn: Conn,
        #[arg(long, value_delimiter = ',')]
        enable: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        disable: Vec<String>,
        /// Домен, проксируемый CDN, для включения vless-ws
        #[arg(long)]
        cdn_host: Option<String>,
    },
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
    bail!("нет подключения с пробами. Подключись: `eleutheria connect` (без --no-probes)")
}

fn verdict_line(e: &prober::Entry) -> String {
    use prober::Verdict::*;
    let v = match &e.verdict {
        Ok => "ok".to_string(),
        Degraded => "медленно".to_string(),
        Failed(c) => format!("ОТКАЗ {}", c.as_str()),
        Skip => "-".to_string(),
        Inherit => "(туннель недоступен)".to_string(),
    };
    format!("{v}: {}", e.reason)
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
            println!("{} {host} ({} в парке)", if new { "Добавлен" } else { "Обновлён" }, f.members.len());
        }
        FleetCmd::Remove { host } => {
            let mut f = Fleet::load()?;
            if !f.remove(&host) {
                bail!("{host} нет в парке");
            }
            f.save()?;
            println!("Убран {host} (на самом сервере ничего не менялось). Осталось: {}", f.members.len());
        }
        FleetCmd::List => {
            let f = Fleet::load()?;
            if f.members.is_empty() {
                println!("Парк пуст. Добавь сервер: eleutheria fleet add <IP>");
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
                println!("Пользователь `{}` (uuid {}) общий на серверах парка. Ссылки: eleutheria fleet sub {}", u.name, u.uuid, u.name);
            }
            if !ok {
                bail!("не на всех серверах получилось (повтор безопасен: команда идемпотентна)");
            }
        }
        FleetCmd::Update { conn } => {
            let f = Fleet::load()?;
            let results = fleet::update_all(&f, |m| { let c = member_conn(&m, &conn); async move { connect(&c).await } }, &report).await?;
            if !print_results(&results) {
                bail!("не все серверы обновились");
            }
        }
        FleetCmd::Sub { name, out, conn } => {
            let f = Fleet::load()?;
            let (body, results) = fleet::subscription(&f, &name, |m| { let c = member_conn(&m, &conn); async move { connect(&c).await } }, &report).await?;
            // сводка в stderr, чтобы stdout остался чистой подпиской
            for r in &results {
                eprintln!("{} {}: {}", if r.outcome.is_ok() { "✓" } else { "✗" }, r.host, if r.outcome.is_ok() { "ссылки собраны".to_string() } else { r.outcome.describe() });
            }
            match out {
                Some(p) => {
                    store::write_secret_file(std::path::Path::new(&p), body.as_bytes())?;
                    eprintln!("Подписка записана в {p} (внутри ключи доступа: храни как пароль)");
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
    let u = st.user(name).ok_or_else(|| anyhow!("пользователя `{name}` нет на сервере"))?;
    println!("[{name}]");
    for l in all_links(host, st, u)? {
        println!("{}:\n{}\n", l.proto, l.url);
        if qr {
            // QR только там, где ссылка помещается в терминальный код
            match eleutheria_core::qr_text(&l.url) {
                Ok(q) => println!("{q}"),
                Err(_) => println!("(ссылка слишком длинная для QR в терминале)\n"),
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
    match Cli::parse().cmd {
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

            println!("\nУкрепление сервера:");
            for n in &notes {
                println!("  {} {}", if n.ok { "✓" } else { "⚠" }, n.text);
            }
            println!("\nГотово. Ссылки для клиентов (Happ, Hiddify, v2rayN, Streisand, v2rayTun, sing-box):\n");
            if let Some(n) = saved {
                println!("Сервер сохранён в списке клиента как `{}` (eleutheria connect).\n", n.join("`, `"));
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
                println!("На сервере: {}", inst.as_deref().unwrap_or("не установлено"));
                println!("В клиенте:  {}", eleutheria_core::singbox::VERSION);
                println!("Статус: {}", match need {
                    provision::UpdateNeed::NotInstalled => "установки Eleutheria нет",
                    provision::UpdateNeed::UpToDate => "актуально",
                    provision::UpdateNeed::Outdated => "нужно обновление (eleutheria server update)",
                    provision::UpdateNeed::Newer => "на сервере версия новее клиентской",
                    provision::UpdateNeed::Unknown => "версию разобрать не удалось",
                });
                if let Some(st) = &st {
                    println!("Протоколы: vless-reality{}", st.protocols.enabled.keys().map(|p| format!(", {}", p.id())).collect::<String>());
                    println!("Порты: {}", provision::listen_ports(st).into_iter().map(|(p, t)| format!("{p}/{t}")).collect::<Vec<_>>().join(", "));
                }
            }
            ServerCmd::Protocols { conn, enable, disable, cdn_host } => {
                let (en, dis) = (parse_protos(&enable)?, parse_protos(&disable)?);
                if let Some(p) = en.iter().find(|p| dis.contains(p)) {
                    bail!("{} одновременно в --enable и --disable", p.id());
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
                println!("Включено: vless-reality{}", st.protocols.enabled.keys().map(|p| format!(", {}", p.id())).collect::<String>());
                println!("Порты: {}", provision::listen_ports(&st).into_iter().map(|(p, t)| format!("{p}/{t}")).collect::<Vec<_>>().join(", "));
                if !en.is_empty() {
                    if let Some(u) = st.users.first() {
                        let n = save_servers(&conn.host, &st, u)?;
                        println!("В списке клиента: `{}`.", n.join("`, `"));
                    }
                    println!("\nСсылки: eleutheria user link <сервер> <имя>");
                }
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
            let (mut servers, skipped) = if ["vless://", "hysteria2://", "hy2://", "tuic://", "ss://"].iter().any(|p| source.starts_with(p)) {
                (vec![profile::parse_link(&source)?], vec![])
            } else if source.starts_with("http://") || source.starts_with("https://") {
                profile::parse_subscription(&profile::fetch_subscription(&source).await?)
            } else {
                if source.starts_with("socks5://") {
                    bail!("внешний exit добавляется отдельно, с явным согласием: eleutheria exit add <имя> {source} --via <сервер> --accept-exit-risk");
                }
                bail!("нужна ссылка (vless://, hysteria2://, tuic://, ss://) или URL подписки (http/https)");
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
                println!("{}\t{}:{}\t{}", s.name, s.host, s.port, s.kind_label());
            }
        }
        Cmd::RemoveServer { name } => {
            if profile::remove(&name)? {
                println!("Удалён: {name}");
            } else {
                bail!("сервера `{name}` нет в списке");
            }
        }
        Cmd::Connect { tun: true, server, ru_direct, test_url, no_probes, .. } => {
            let servers = profile::load();
            if servers.is_empty() {
                bail!("нет серверов: добавь командой `eleutheria import <ссылка или подписка>`");
            }
            let Some(sock) = helper_socket() else {
                bail!("helper не установлен или не запущен. Выполни: {}", install_hint());
            };
            let profiles = userprofiles::files_for_servers(&userprofiles::root(), &servers)?;
            let req = Request::Start(StartParams { servers, ru_direct: ru_direct.into(), selected: server, test_url, categories: categories::load(), probes: !no_probes, profiles });
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
        Cmd::Connect { port, clash_port, server, ru_direct, test_url, tun: false, no_probes } => {
            let servers = profile::load();
            let o = ConnectOpts { listen_port: port, clash_port, test_url, ru_direct: ru_direct.into(), selected: server, probes: !no_probes };
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
            println!("Слежу за {} путями, раунд раз в {interval} с{}. Ctrl-C: остановить.", link.plan.outbounds.len(), if no_switch { " (только наблюдение)" } else { "" });
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
                    println!("sing-box не отвечает: туннель остановлен, выхожу.");
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
                    _ = tokio::signal::ctrl_c() => { println!("Остановлено."); break; }
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
                println!("Категория `{id}`: {}. Вступит в силу при следующем подключении.", if a == "enable" { "включена" } else { "выключена" });
            }
            _ => bail!("использование: eleutheria categories [enable|disable <id>]"),
        },
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
        Cmd::Fleet(c) => run_fleet(c).await?,
        Cmd::Exit(ExitCmd::Add { name, url, via, accept_exit_risk }) => {
            if !accept_exit_risk {
                bail!("внешний exit видит, какие сайты ты через него открываешь (а для сайтов без HTTPS и содержимое). Если это понятно и прокси твой или доверенный, повтори с --accept-exit-risk");
            }
            let s = profile::parse_socks_exit(&url, &name, &via)?;
            let n = profile::add_exit(s)?;
            println!("Добавлен внешний exit `{n}` через `{via}`. Основным сервером или автовыбором он не станет; на него могут уходить категории при `eleutheria watch --allow-external-exit`");
        }
        Cmd::Exit(ExitCmd::List) => {
            let all: Vec<_> = profile::load().into_iter().filter(|s| s.is_external_exit()).collect();
            if all.is_empty() {
                println!("Внешних exit нет. Добавь: eleutheria exit add <имя> socks5://IP:порт --via <сервер> --accept-exit-risk");
            }
            for s in all {
                println!("{}\t{}:{}\tчерез {}", s.name, s.host, s.port, s.via.as_deref().unwrap_or("?"));
            }
        }
        Cmd::Forget { host } => {
            let n = store::forget_host(&host)?;
            println!("Удалено записей: {n}");
        }
        Cmd::Profile(c) => profile_cmd(c)?,
        Cmd::Secrets => {
            let st = eleutheria_core::secrets::default_store()?;
            let servers = profile::try_load()?; // заодно переносит старый profiles.json
            println!("Хранилище секретов: {}", st.kind());
            println!("Серверов в профилях: {}", servers.len());
        }
    }
    Ok(())
}

fn profile_cmd(c: ProfileCmd) -> Result<()> {
    let root = userprofiles::root();
    match c {
        ProfileCmd::List => {
            for p in Proto::all_builtin() {
                let m = &eleutheria_core::profiles::builtin(&p).expect("встроенный").manifest;
                println!("встроенный  {:<12} {}", m.id, m.name);
            }
            for (name, r) in userprofiles::list_in(&root) {
                match r {
                    Ok(c) => println!("сторонний   {:<12} {}  [{}]", name, c.profile.manifest.name, &c.files.digest()[..16]),
                    Err(e) => println!("сторонний   {name:<12} НЕ ПРОХОДИТ ПРОВЕРКУ: {e:#}"),
                }
            }
            println!("\nСторонний профиль включается на сервере так же, как встроенный: `eleutheria server protocols <IP> --enable <id>`.");
        }
        ProfileCmd::Diff { dir } => {
            let plan = userprofiles::plan_install_in(&root, &dir)?;
            print_plan(&plan);
        }
        ProfileCmd::Install { dir, yes } => {
            let plan = userprofiles::plan_install_in(&root, &dir)?;
            print_plan(&plan);
            if plan.replaces && !plan.changed {
                println!("Установлена та же версия, ничего не делаю.");
                return Ok(());
            }
            let ok = yes || {
                eprint!("{} [y/N] ", if plan.replaces { "Заменить установленный профиль этими изменениями?" } else { "Установить этот профиль?" });
                let _ = io::stderr().flush();
                let mut s = String::new();
                io::stdin().read_line(&mut s).ok();
                matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да")
            };
            if !ok {
                bail!("отменено, ничего не записано");
            }
            let to = userprofiles::commit_in(&root, &plan)?;
            println!("Профиль установлен: {}", to.display());
        }
        ProfileCmd::Remove { id } => {
            userprofiles::remove_in(&root, &id)?;
            println!("Профиль `{id}` удалён.");
        }
    }
    Ok(())
}

fn print_plan(plan: &userprofiles::InstallPlan) {
    println!("Профиль прошёл проверку:");
    for l in plan.summary() {
        println!("  {l}");
    }
    if !plan.replaces {
        println!("\nНовый профиль. Содержимое:");
    } else if plan.changed {
        println!("\nИзменения относительно установленной версии:");
    }
    if plan.changed {
        let shown = if plan.replaces { plan.diff.clone() } else { plan.candidate.files_listing() };
        print!("{shown}");
    }
}
