//! Проверка M5.3 на настоящем sing-box: внешний exit как цепочка «клиент → свой сервер → SOCKS5-прокси».
//! Серверный и клиентский конфиги генерирует наш код. Роль внешнего прокси играет второй sing-box с
//! SOCKS5-входом и паролем. Проверяется не только то, что запрос дошёл, а что он прошёл именно по цепочке:
//! по журналам прокси и сервера-входа.
//!
//! SINGBOX_BIN=/path/to/sing-box cargo run -p eleutheria-core --example e2e_exit
//! Нужна запись `127.0.0.1 target.test` в /etc/hosts (как у e2e_protocols).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eleutheria_core::client::config::{build, ClientOpts, RuDirect};
use eleutheria_core::client::profile::{parse_socks_exit, servers_from_state, Kind, Server};
use eleutheria_core::client::prober::ProbePort;
use eleutheria_core::config::server_config_in;
use eleutheria_core::state::{Proto, ProtoState, State, TlsInfo, User};
use eleutheria_core::tlscert;

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(bin: &str, cfg: &Path, log: &Path) -> Proc {
    let f = std::fs::File::create(log).unwrap();
    Proc(Command::new(bin).args(["run", "-c"]).arg(cfg).stdout(f.try_clone().unwrap()).stderr(f).spawn().expect("запуск sing-box"))
}

fn fetch(socks_port: u16) -> Option<String> {
    let out = Command::new("curl").args(["-s", "-m", "6", "--socks5-hostname", &format!("127.0.0.1:{socks_port}"), "http://target.test:28081/"]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Пробные входы клиента закрыты паролем (логин `probe`, пароль секрет клиента).
fn fetch_probe(port: u16) -> Option<String> {
    let out = Command::new("curl").args(["-s", "-m", "6", "-x", &format!("socks5h://probe:t@127.0.0.1:{port}"), "http://target.test:28081/"]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn count(log: &Path, needle: &str) -> usize {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter(|l| l.contains(needle)).count()
}

const LISTEN: u16 = 27940;
const PROBE_ENTRY: u16 = 27941;
const PROBE_EXIT: u16 = 27942;
const EXT_PORT: u16 = 24481;

fn run_client(bin: &str, dir: &Path, name: &str, servers: &[Server], listen: u16) -> anyhow::Result<Proc> {
    let o = ClientOpts {
        listen_port: listen, clash_port: listen + 100, secret: "t".into(), test_url: "http://target.test:28081/".into(),
        ru_direct: RuDirect::Off, selected: None, tun: false, ipv6: false, strict_route: false, categories: vec![],
        probe_ports: vec![ProbePort { tag: "srv-1".into(), port: listen + 1 }, ProbePort { tag: "srv-2".into(), port: listen + 2 }],
    };
    let cfg = build(servers, &o)?;
    let path = dir.join(format!("client-{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg)?)?;
    let chk = Command::new(bin).args(["check", "-c"]).arg(&path).output()?;
    anyhow::ensure!(chk.status.success(), "sing-box check клиента {name}: {}", String::from_utf8_lossy(&chk.stderr));
    let p = spawn(bin, &path, &dir.join(format!("client-{name}.log")));
    std::thread::sleep(Duration::from_millis(1500));
    Ok(p)
}

fn main() -> anyhow::Result<()> {
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let dir: PathBuf = std::env::temp_dir().join(format!("eleutheria-e2e-m53-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let mut failed = 0u32;
    let mut check = |ok: bool, what: &str| {
        println!("{} {what}", if ok { "✓" } else { "✗" });
        failed += (!ok) as u32;
    };

    // свой сервер-вход: Hysteria2 (работает без интернета, в отличие от Reality)
    let cert = tlscert::generate("www.bing.com")?;
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem)?;
    std::fs::write(dir.join("key.pem"), &cert.key_pem)?;
    let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"E2E","private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef","sni":"www.microsoft.com","port":24491,"users":[]}"#).unwrap();
    st.users = vec![User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret-1".into()) }];
    st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: cert.spki_sha256_b64.clone(), cert_sha256: cert.cert_sha256_hex.clone() });
    st.protocols.enabled.insert(Proto::Hysteria2, ProtoState::new(24443));
    let mut scfg = server_config_in(&st, dir.to_str().unwrap())?;
    scfg["log"]["level"] = "info".into();
    std::fs::write(dir.join("entry.json"), serde_json::to_vec_pretty(&scfg)?)?;

    // «внешний прокси»: чужой SOCKS5 с паролем
    let ext = serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "socks", "tag": "ext", "listen": "127.0.0.1", "listen_port": EXT_PORT, "users": [{ "username": "extuser", "password": "ext pass!" }] }],
        "outbounds": [{ "type": "direct", "tag": "d" }]
    });
    std::fs::write(dir.join("ext.json"), serde_json::to_vec_pretty(&ext)?)?;
    for f in ["entry.json", "ext.json"] {
        let chk = Command::new(&bin).args(["check", "-c"]).arg(dir.join(f)).output()?;
        anyhow::ensure!(chk.status.success(), "sing-box check {f}: {}", String::from_utf8_lossy(&chk.stderr));
    }

    std::fs::write(dir.join("index.html"), "e2e-ok")?;
    let _http = Proc(Command::new("python3").args(["-m", "http.server", "28081", "--bind", "127.0.0.1"]).current_dir(&dir).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let entry_log = dir.join("entry.log");
    let ext_log = dir.join("ext.log");
    let _entry = spawn(&bin, &dir.join("entry.json"), &entry_log);
    let _ext = spawn(&bin, &dir.join("ext.json"), &ext_log);
    std::thread::sleep(Duration::from_millis(1500));

    let mut entry = servers_from_state("127.0.0.1", &st, &st.users[0])?.into_iter().find(|s| s.kind == Kind::Hysteria2).expect("запись Hysteria2");
    entry.name = "entry".into();
    // пароль со спецсимволами приходит в ссылке в процентной кодировке
    let exit = parse_socks_exit("socks5://extuser:ext%20pass%21@127.0.0.1:24481", "exit", "entry")?;
    let target = "target.test:28081";
    let ext_hits = |_: ()| count(&ext_log, &format!("inbound connection to {target}"));
    let entry_to_ext = |_: ()| count(&entry_log, &format!("inbound connection to 127.0.0.1:{EXT_PORT}"));

    let _c = run_client(&bin, &dir, "chain", &[entry.clone(), exit.clone()], LISTEN)?;

    // 1. по умолчанию весь трафик идёт через свой сервер и до внешнего exit не доходит
    let got = fetch(LISTEN);
    check(got.as_deref() == Some("e2e-ok"), "основной вход: трафик идёт через свой сервер");
    check(ext_hits(()) == 0 && entry_to_ext(()) == 0, "внешний exit по умолчанию не получил ни одного запроса");

    // 2. через пробный вход своего сервера: тоже мимо внешнего exit
    let got = fetch_probe(PROBE_ENTRY);
    check(got.as_deref() == Some("e2e-ok") && ext_hits(()) == 0, "пробный вход своего сервера: внешний exit не задействован");

    // 3. через пробный вход внешнего exit: запрос прошёл цепочкой
    let got = fetch_probe(PROBE_EXIT);
    check(got.as_deref() == Some("e2e-ok"), "через внешний exit ответ получен");
    check(ext_hits(()) == 1, "прокси увидел запрос к цели (авторизация логином и паролем прошла)");
    check(entry_to_ext(()) == 1, "к прокси запрос пришёл от своего сервера-входа, а не напрямую с клиента (журнал сервера: подключение к прокси)");

    // 4. неверный пароль внешнего exit: запрос не проходит, а свой сервер продолжает работать
    let mut bad = exit.clone();
    bad.password = Some("wrong".into());
    let _c2 = run_client(&bin, &dir, "chain-badpw", &[entry.clone(), bad], LISTEN + 10)?;
    check(fetch_probe(LISTEN + 10 + 2).is_none(), "неверный пароль прокси: через внешний exit трафик не идёт");
    check(fetch(LISTEN + 10).as_deref() == Some("e2e-ok"), "при этом основной вход работает");

    // 5. цепочка действительно зависит от сервера-входа: упал вход, внешний exit недоступен
    drop(_entry);
    std::thread::sleep(Duration::from_millis(500));
    let before = ext_hits(());
    check(fetch_probe(PROBE_EXIT).is_none() && ext_hits(()) == before, "вход остановлен: до внешнего exit запрос не дошёл (клиент напрямую к нему не ходит)");

    println!("{}", if failed == 0 { "всё хорошо" } else { "ЕСТЬ ОШИБКИ" });
    anyhow::ensure!(failed == 0, "{failed} проверок не прошло");
    Ok(())
}
