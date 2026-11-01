//! Проверка M5.3 на настоящем sing-box: сайт не пускает выходные IP обоих своих серверов, а внешний exit
//! (SOCKS5 через сервер A, выходной IP 127.0.0.13) его открывает. Настоящий клиент, настоящий `Watcher`:
//! решает ли роутер уводить категорию на внешний exit, и только ли когда это разрешено.
//!
//! SINGBOX_BIN=/path/to/sing-box cargo run -p eleutheria-core --example e2e_exit_route
//! Нужна запись `127.0.0.1 target.test` в /etc/hosts (цель задана именем, чтобы правило «приватные адреса
//! напрямую» не обошло прокси). Выходные IP серверов различаются: A выходит с 127.0.0.11, B с 127.0.0.12.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eleutheria_core::client::categories::Category;
use eleutheria_core::client::config::{build, ClientOpts, RuDirect};
use eleutheria_core::client::profile::{parse_link, parse_socks_exit, Server};
use eleutheria_core::client::prober::*;
use eleutheria_core::client::watch::{make_plan, Link, WatchCfg, Watcher};
use eleutheria_core::config::all_links;
use eleutheria_core::config::server_config_in;
use eleutheria_core::state::{State, User};

const TARGET: u16 = 28081;
const LISTEN: u16 = 27890;
const CLASH: u16 = 29090;
const SECRET: &str = "e2e-prober-secret";

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

const TARGET_PY: &str = r#"
import http.server, os, sys
BLOCK = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        src = self.client_address[0]
        blocked = os.path.exists(BLOCK) and src in open(BLOCK).read().split()
        if self.path.startswith('/video') and blocked:
            self.send_response(403); self.end_headers(); self.wfile.write(b'denied ' + src.encode()); return
        self.send_response(200); self.end_headers(); self.wfile.write(('ok from ' + src).encode())
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('0.0.0.0', int(sys.argv[1])), H).serve_forever()
"#;

/// Локальный TLS 1.3 сервер вместо www.microsoft.com: Reality пересылает ему «чужие» рукопожатия (в песочнице нет интернета).
const TLS_PY: &str = r#"
import socketserver, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            s = ctx.wrap_socket(self.request, server_side=True)
            s.recv(1024)
        except Exception:
            pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
S(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
"#;

fn state(port: u16) -> State {
    let mut st = State::parse(&format!(r#"{{"version":2,"singbox":"1.14.3","profile":"E2E","private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef","sni":"www.microsoft.com","port":{port},"users":[]}}"#)).unwrap();
    st.users = vec![User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret".into()) }];
    st
}

fn server_proc(bin: &str, dir: &Path, name: &str, port: u16, exit_ip: &str) -> anyhow::Result<(Proc, Server)> {
    let st = state(port);
    let mut cfg = server_config_in(&st, dir.to_str().unwrap())?;
    for i in cfg["inbounds"].as_array_mut().unwrap() {
        if i["type"] == "vless" {
            i["tls"]["reality"]["handshake"]["server"] = "127.0.0.1".into();
            i["tls"]["reality"]["handshake"]["server_port"] = 28443.into();
        }
    }
    for o in cfg["outbounds"].as_array_mut().unwrap() {
        if o["type"] == "direct" {
            o["inet4_bind_address"] = exit_ip.into();
        }
    }
    let path = dir.join(format!("server-{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg)?)?;
    let chk = Command::new(bin).args(["check", "-c"]).arg(&path).output()?;
    anyhow::ensure!(chk.status.success(), "check сервера {name}: {}", String::from_utf8_lossy(&chk.stderr));
    let proc = spawn(bin, &path, &dir.join(format!("server-{name}.log")));
    let host = if name == "a" { "127.0.0.1" } else { "127.0.0.2" };
    let link = all_links(host, &st, &st.users[0])?.into_iter().find(|l| l.proto == "vless").unwrap();
    let mut s = parse_link(&link.url)?;
    s.name = name.into();
    Ok((proc, s))
}

fn curl_via_proxy(path: &str) -> Option<String> {
    // /video относится к категории (target.test), остальное идёт общим маршрутом (canary.test не входит ни в одну категорию)
    let host = if path.starts_with("/video") { "target.test" } else { "canary.test" };
    let out = Command::new("curl").args(["-s", "-m", "6", "--socks5-hostname", &format!("127.0.0.1:{LISTEN}"), &format!("http://{host}:{TARGET}{path}")]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

struct Check(u32);
impl Check {
    fn that(&mut self, ok: bool, what: &str) {
        println!("{} {what}", if ok { "✓" } else { "✗" });
        self.0 += (!ok) as u32;
    }
}

fn verdict_of(es: &[Entry], cat: &str, tag: &str) -> Verdict {
    es.iter().find(|e| e.category == cat && e.tag == tag).map(|e| e.verdict.clone()).unwrap_or(Verdict::Skip)
}

async fn rounds(w: &mut Watcher, n: u32) -> anyhow::Result<Vec<String>> {
    let mut log = Vec::new();
    for _ in 0..n {
        let st = w.step().await?;
        log.extend(st.applied);
    }
    Ok(log)
}


fn ext_proc(bin: &str, dir: &Path) -> anyhow::Result<Proc> {
    // чужой прокси: свой адрес 127.0.0.20 (чтобы не совпасть с сервером A), наружу выходит с 127.0.0.13
    let cfg = serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "socks", "tag": "ext", "listen": "127.0.0.20", "listen_port": 24482, "users": [{ "username": "u", "password": "p w" }] }],
        "outbounds": [{ "type": "direct", "tag": "d", "inet4_bind_address": "127.0.0.13" }]
    });
    let path = dir.join("ext.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg)?)?;
    let chk = Command::new(bin).args(["check", "-c"]).arg(&path).output()?;
    anyhow::ensure!(chk.status.success(), "check внешнего прокси: {}", String::from_utf8_lossy(&chk.stderr));
    Ok(spawn(bin, &path, &dir.join("ext.log")))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let dir: PathBuf = std::env::temp_dir().join(format!("eleutheria-e2e-m53r-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let block = dir.join("blocked.txt");
    std::fs::write(dir.join("target.py"), TARGET_PY)?;
    let _target = Proc(Command::new("python3").arg(dir.join("target.py")).arg(TARGET.to_string()).arg(&block).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let cert = eleutheria_core::tlscert::generate("www.bing.com")?;
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem)?;
    std::fs::write(dir.join("key.pem"), &cert.key_pem)?;
    std::fs::write(dir.join("tls.py"), TLS_PY)?;
    let _tls = Proc(Command::new("python3").arg(dir.join("tls.py")).arg("28443").arg(dir.join("cert.pem")).arg(dir.join("key.pem")).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let (_srv_a, a) = server_proc(&bin, &dir, "a", 24461, "127.0.0.11")?;
    let (_srv_b, b) = server_proc(&bin, &dir, "b", 24462, "127.0.0.12")?;
    let _ext = ext_proc(&bin, &dir)?;
    std::thread::sleep(Duration::from_millis(1500));

    let exit = parse_socks_exit("socks5://u:p%20w@127.0.0.20:24482", "exit", "a")?;
    let servers = vec![a, b, exit];
    let video = Category { id: "video".into(), title: "Видео".into(), domains: vec!["target.test".into()], probe_url: format!("http://target.test:{TARGET}/video"), enabled: true };
    let plan = make_plan(&servers, Some("a"), std::slice::from_ref(&video), &format!("http://canary.test:{TARGET}/canary"))?;
    let opts = ClientOpts {
        listen_port: LISTEN, clash_port: CLASH, secret: SECRET.into(), test_url: "https://www.gstatic.com/generate_204".into(), ru_direct: RuDirect::Off,
        selected: Some("a".into()), tun: false, ipv6: false, strict_route: false, categories: vec![video], probe_ports: plan.ports.clone(),
    };
    let ccfg = build(&servers, &opts)?;
    std::fs::write(dir.join("client.json"), serde_json::to_vec_pretty(&ccfg)?)?;
    let chk = Command::new(&bin).args(["check", "-c"]).arg(dir.join("client.json")).output()?;
    anyhow::ensure!(chk.status.success(), "check клиента: {}", String::from_utf8_lossy(&chk.stderr));
    let _client = spawn(&bin, &dir.join("client.json"), &dir.join("client.log"));
    std::thread::sleep(Duration::from_millis(1500));

    let link = Link { clash_port: CLASH, secret: SECRET.into(), plan: plan.clone() };
    let mk = |allow: bool| {
        Watcher::new(link.clone(), WatchCfg {
            timeout: Duration::from_secs(4),
            tracker: TrackerCfg { failed_after: 2, recover_after: 2 },
            router: RouterCfg { min_dwell: 1, release_after: 2, allow_external_exit: allow, ..Default::default() },
            ..Default::default()
        })
    };
    let mut c = Check(0);
    let mut w = mk(false);

    let ext_conns = || std::fs::read_to_string(dir.join("ext.log")).unwrap_or_default().lines().filter(|l| l.contains("inbound connection to")).count();

    // 1. всё исправно; без разрешения внешний exit даже не проверяется (его владелец не видит адреса проб)
    let st = w.step().await?;
    c.that(verdict_of(&st.entries, "video", "srv-3") == Verdict::Skip && ext_conns() == 0, "без разрешения внешний exit не получил ни одной пробы");
    c.that(st.actions.is_empty(), "исправная сеть: роутер ничего не переключает");
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.11"), "по умолчанию категория идёт через свой сервер A, не через внешний exit");

    // 2. сайт не пускает выходные IP обоих своих серверов; внешний exit запрещён
    std::fs::write(&block, "127.0.0.11\n127.0.0.12\n")?;
    let log = rounds(&mut w, 4).await?;
    c.that(ext_conns() == 0, "...и пока сайт блокирует свои IP, внешний exit по-прежнему не получил ни одной пробы");
    c.that(log.is_empty(), &format!("без разрешения роутер не уводит трафик на чужой прокси ({log:?})"));
    c.that(curl_via_proxy("/video").as_deref() == Some("denied 127.0.0.11"), "реальный трафик категории по-прежнему получает отказ через A");

    // 3. разрешение дано: категория уходит на внешний exit, остальной трафик остаётся на A
    let mut w2 = mk(true);
    let es = w2.step().await?.entries;
    c.that(ext_conns() > 0, "с разрешением внешний exit начал проверяться");
    c.that(verdict_of(&es, "video", "srv-1") == Verdict::Failed(FailClass::ExitBlockedBySite) && verdict_of(&es, "video", "srv-2") == Verdict::Failed(FailClass::ExitBlockedBySite), "оба своих IP: диагноз EXIT_BLOCKED_BY_SITE (внешний exit открывает, значит дело в нашем выходном IP)");
    c.that(verdict_of(&es, "video", "srv-3") == Verdict::Ok, "...внешний exit при этом открывает сайт");
    let log = rounds(&mut w2, 5).await?;
    c.that(log.iter().any(|l| l.contains("cat-video") && l.contains("exit")), &format!("с разрешением: cat-video переключён на внешний exit ({log:?})"));
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.13"), "реальный трафик категории выходит с IP внешнего exit (цепочка через A работает)");
    c.that(curl_via_proxy("/canary").as_deref() == Some("ok from 127.0.0.11"), "остальной трафик остался на своём сервере A: весь трафик на чужой прокси не уходит");
    let log = rounds(&mut w2, 3).await?;
    c.that(log.is_empty(), &format!("без дёрганий: пока сайт блокирует, переключений больше нет ({log:?})"));

    // 4. свой IP разблокирован: категория возвращается домой, чужой прокси больше не нужен
    std::fs::remove_file(&block)?;
    let log = rounds(&mut w2, 6).await?;
    c.that(log.iter().any(|l| l.contains("cat-video") && l.contains("возвращено")), &format!("свой путь починился: категория вернулась на общий маршрут ({log:?})"));
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.11"), "после возврата категория снова идёт через свой сервер");

    println!("\nлоги и конфиги: {}", dir.display());
    anyhow::ensure!(c.0 == 0, "провалено проверок: {}", c.0);
    println!("всё хорошо");
    Ok(())
}
