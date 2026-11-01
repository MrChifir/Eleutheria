//! Проверка M4 на настоящем sing-box: два сервера, цель, которая умеет «не пускать выходной IP»,
//! настоящий клиент с пробными входами и настоящий `Watcher` (пробы, классификатор, состояния, роутер, Clash API).
//!
//! SINGBOX_BIN=/path/to/sing-box cargo run -p eleutheria-core --example e2e_prober
//! Нужна запись `127.0.0.1 target.test` в /etc/hosts (цель задана именем, чтобы правило «приватные адреса
//! напрямую» не обошло прокси). Выходные IP серверов различаются: A выходит с 127.0.0.11, B с 127.0.0.12.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eleutheria_core::client::categories::Category;
use eleutheria_core::client::config::{build, ClientOpts, RuDirect};
use eleutheria_core::client::profile::{parse_link, Server};
use eleutheria_core::client::prober::*;
use eleutheria_core::client::watch::{make_plan, set_selector, Link, WatchCfg, Watcher};
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let dir: PathBuf = std::env::temp_dir().join(format!("eleutheria-e2e-m4-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let block = dir.join("blocked.txt");
    std::fs::write(dir.join("target.py"), TARGET_PY)?;
    let _target = Proc(Command::new("python3").arg(dir.join("target.py")).arg(TARGET.to_string()).arg(&block).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);

    let cert = eleutheria_core::tlscert::generate("www.bing.com")?;
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem)?;
    std::fs::write(dir.join("key.pem"), &cert.key_pem)?;
    std::fs::write(dir.join("tls.py"), TLS_PY)?;
    let _tls = Proc(Command::new("python3").arg(dir.join("tls.py")).arg("28443").arg(dir.join("cert.pem")).arg(dir.join("key.pem")).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let (srv_a, a) = server_proc(&bin, &dir, "a", 24461, "127.0.0.11")?;
    let (srv_b, b) = server_proc(&bin, &dir, "b", 24462, "127.0.0.12")?;
    std::thread::sleep(Duration::from_millis(1500));

    // клиент: закреплён сервер A (проверим и общий failover), категория video с настоящим переключателем
    let servers = vec![a, b];
    let video = Category { id: "video".into(), title: "Видео".into(), domains: vec!["target.test".into()], probe_url: format!("http://target.test:{TARGET}/video"), enabled: true };
    let mut plan = make_plan(&servers, Some("a"), std::slice::from_ref(&video), &format!("http://canary.test:{TARGET}/canary"))?;
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
    let cfg = WatchCfg {
        timeout: Duration::from_secs(4),
        tracker: TrackerCfg { failed_after: 2, recover_after: 2 },
        router: RouterCfg { min_dwell: 1, release_after: 2, ..Default::default() },
        ..Default::default()
    };
    let mut w = Watcher::new(link.clone(), cfg);
    let mut c = Check(0);

    // 1. всё исправно
    let st = w.step().await?;
    c.that(verdict_of(&st.entries, CANARY, "srv-1") == Verdict::Ok && verdict_of(&st.entries, CANARY, "srv-2") == Verdict::Ok, "исправная сеть: туннели обоих серверов ok");
    c.that(verdict_of(&st.entries, "video", "srv-1") == Verdict::Ok && verdict_of(&st.entries, "video", "srv-2") == Verdict::Ok, "исправная сеть: video через оба сервера ok");
    c.that(st.actions.is_empty(), "исправная сеть: роутер ничего не переключает");
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.11"), "трафик категории по умолчанию идёт через закреплённый A");

    // 2. цель перестаёт пускать выходной IP сервера A (только на /video)
    std::fs::write(&block, "127.0.0.11\n")?;
    let st = w.step().await?;
    c.that(verdict_of(&st.entries, "video", "srv-1") == Verdict::Failed(FailClass::ExitBlockedBySite), "сайт не пускает IP A: диагноз EXIT_BLOCKED_BY_SITE");
    c.that(verdict_of(&st.entries, "video", "srv-2") == Verdict::Ok && verdict_of(&st.entries, CANARY, "srv-1") == Verdict::Ok, "...при этом туннель A жив, а через B сайт открывается");
    c.that(st.actions.is_empty(), "первый отказ только suspect: ещё не переключаем");
    c.that(curl_via_proxy("/video").as_deref() == Some("denied 127.0.0.11"), "реальный трафик пока получает отказ через A");
    let log = rounds(&mut w, 1).await?;
    c.that(log.iter().any(|l| l.contains("cat-video") && l.contains("b")), &format!("второй отказ подряд: cat-video переключён на B ({log:?})"));
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.12"), "реальный трафик video теперь выходит с IP сервера B");
    c.that(curl_via_proxy("/canary").as_deref() == Some("ok from 127.0.0.11"), "остальной трафик остался на закреплённом A (переключилась только категория)");

    // 3. стабильность: пока A заблокирован, переключений больше нет
    let log = rounds(&mut w, 3).await?;
    c.that(log.is_empty(), &format!("без дёрганий: ещё 3 раунда без переключений ({log:?})"));

    // 4. A снова пускают: после стабильных раундов категория возвращается домой
    std::fs::remove_file(&block)?;
    let log = rounds(&mut w, 6).await?;
    c.that(log.iter().any(|l| l.contains("cat-video") && l.contains("возвращено")), &format!("A починился: категория возвращена на общий маршрут ({log:?})"));
    c.that(curl_via_proxy("/video").as_deref() == Some("ok from 127.0.0.11"), "после возврата video снова идёт через A");

    // 5. SERVER_IP_BLOCKED: сервер B пропал целиком
    drop(srv_b);
    std::thread::sleep(Duration::from_millis(300));
    let st = w.step().await?;
    c.that(verdict_of(&st.entries, CANARY, "srv-2") == Verdict::Failed(FailClass::ServerIpBlocked), "сервер B недоступен: диагноз SERVER_IP_BLOCKED");
    c.that(verdict_of(&st.entries, CANARY, "srv-1") == Verdict::Ok, "...а A в порядке");
    let _ = rounds(&mut w, 2).await?;
    c.that(w.tracker.get(CANARY, "srv-2").health == Health::Failed, "после N отказов подряд пара (туннель, B) = failed");

    // 6. общий failover закреплённого сервера: A умирает, B уже мёртв: нет альтернатив, ничего не ломаем
    drop(srv_a);
    std::thread::sleep(Duration::from_millis(300));
    let log = rounds(&mut w, 3).await?;
    c.that(log.is_empty(), &format!("нет живых путей: роутер ничего не переключает ({log:?})"));

    // 7. B возвращается, A мёртв: закреплённый общий маршрут уходит на B
    let (_srv_b2, _) = server_proc(&bin, &dir, "b", 24462, "127.0.0.12")?;
    std::thread::sleep(Duration::from_millis(1500));
    let log = rounds(&mut w, 5).await?;
    c.that(log.iter().any(|l| l.starts_with("proxy:") && l.contains("переключено")), &format!("закреплённый A мёртв, B жив: общий маршрут переключён на B ({log:?})"));
    c.that(curl_via_proxy("/canary").as_deref() == Some("ok from 127.0.0.12"), "общий трафик идёт через B");

    // 8. снимок для GUI
    let snap = w.snapshot();
    c.that(!snap.pairs.is_empty() && !snap.events.is_empty(), "снимок состояния содержит пары и события");
    c.that(!serde_json::to_string(&snap)?.contains(SECRET), "в снимке нет секрета");

    // уборка переключателя на случай повторных запусков вручную
    let _ = set_selector(&link, "proxy", "srv-1").await;
    println!("\nлоги и конфиги: {}", dir.display());
    anyhow::ensure!(c.0 == 0, "провалено проверок: {}", c.0);
    println!("всё хорошо");
    Ok(())
}
