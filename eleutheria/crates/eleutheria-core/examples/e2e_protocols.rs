//! Проверка M3 на настоящем sing-box: серверный конфиг и клиентские конфиги генерирует наш код, дальше
//! сервер и клиенты запускаются и пропускают HTTP-запрос через каждый протокол.
//!
//! SINGBOX_BIN=/path/to/sing-box cargo run -p eleutheria-core --example e2e_protocols
//! Нужна запись `127.0.0.1 target.test` в /etc/hosts: цель задана именем, чтобы клиентское правило
//! «приватные адреса напрямую» не обошло прокси, а резолвил и подключался сервер.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eleutheria_core::client::config::{build, ClientOpts, RuDirect};
use eleutheria_core::client::profile::{parse_link, servers_from_state, Kind, Server};
use eleutheria_core::config::{all_links, server_config_in};
use eleutheria_core::state::{Proto, ProtoState, State, TlsInfo, User};
use eleutheria_core::{profiles, tlscert};

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
    let out = Command::new("curl")
        .args(["-s", "-m", "6", "--socks5-hostname", &format!("127.0.0.1:{socks_port}"), "http://target.test:28080/"])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn client_opts(i: u16) -> ClientOpts {
    ClientOpts {
        listen_port: 27890 + i, clash_port: 29090 + i, secret: "t".into(),
        test_url: "http://target.test:28080/".into(), ru_direct: RuDirect::Off, selected: None,
        tun: false, ipv6: false, strict_route: false,
        categories: vec![], probe_ports: vec![],
    }
}

fn run_client(bin: &str, dir: &Path, name: &str, servers: &[Server], i: u16) -> anyhow::Result<Option<String>> {
    run_client_patched(bin, dir, name, servers, i, |_| {})
}

/// Как `run_client`, но с правкой готового конфига (нужна, чтобы в стенде подменить то, что в жизни делает CDN).
fn run_client_patched(bin: &str, dir: &Path, name: &str, servers: &[Server], i: u16, patch: impl FnOnce(&mut serde_json::Value)) -> anyhow::Result<Option<String>> {
    let mut cfg = build(servers, &client_opts(i))?;
    patch(&mut cfg);
    let path = dir.join(format!("client-{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg)?)?;
    let chk = Command::new(bin).args(["check", "-c"]).arg(&path).output()?;
    anyhow::ensure!(chk.status.success(), "sing-box check клиента {name}: {}", String::from_utf8_lossy(&chk.stderr));
    let _p = spawn(bin, &path, &dir.join(format!("client-{name}.log")));
    std::thread::sleep(Duration::from_millis(1500));
    Ok(fetch(27890 + i))
}

fn main() -> anyhow::Result<()> {
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let dir: PathBuf = std::env::temp_dir().join(format!("eleutheria-e2e-m3-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    // состояние сервера как после `enable_protocols`
    let cert = tlscert::generate("www.bing.com")?;
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem)?;
    std::fs::write(dir.join("key.pem"), &cert.key_pem)?;
    let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"E2E","private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef","sni":"www.microsoft.com","port":24446,"users":[]}"#).unwrap();
    st.users = vec![User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret-1".into()) }, User { name: "bob".into(), uuid: "b158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret-2".into()) }];
    st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: cert.spki_sha256_b64.clone(), cert_sha256: cert.cert_sha256_hex.clone() });
    st.protocols.enabled.insert(Proto::Hysteria2, ProtoState::new(24443));
    st.protocols.enabled.insert(Proto::Tuic, ProtoState::new(24444));
    st.protocols.enabled.insert(Proto::Ss2022, ProtoState { server_key: Some("AAAAAAAAAAAAAAAAAAAAAA==".into()), ..ProtoState::new(24445) });
    const WS_PATH: &str = "/e2e-path-123";
    st.protocols.enabled.insert(Proto::VlessWs, ProtoState { cdn_host: Some("cdn.example.com".into()), ws_path: Some(WS_PATH.into()), ..ProtoState::new(24447) });

    let mut scfg = server_config_in(&st, dir.to_str().unwrap())?;
    scfg["log"]["level"] = "info".into();
    std::fs::write(dir.join("server.json"), serde_json::to_vec_pretty(&scfg)?)?;
    let chk = Command::new(&bin).args(["check", "-c"]).arg(dir.join("server.json")).output()?;
    anyhow::ensure!(chk.status.success(), "sing-box check сервера: {}", String::from_utf8_lossy(&chk.stderr));
    println!("✓ sing-box check серверного конфига ({} inbound'а)", scfg["inbounds"].as_array().unwrap().len());

    let _http = Proc(Command::new("python3").args(["-m", "http.server", "28080", "--bind", "127.0.0.1"]).current_dir({
        std::fs::write(dir.join("index.html"), "e2e-ok")?;
        &dir
    }).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let _srv = spawn(&bin, &dir.join("server.json"), &dir.join("server.log"));
    std::thread::sleep(Duration::from_millis(1500));

    // ссылки в состоянии «как пользователь получил»: разбираем свои же ссылки обратно
    let mut failed = 0;
    let mut i = 0u16;
    for u in &st.users {
        let links = all_links("127.0.0.1", &st, u)?;
        for l in links.iter().filter(|l| l.proto != "vless" && l.proto != "vless-ws") {
            i += 1;
            let server = parse_link(&l.url)?;
            let got = run_client(&bin, &dir, &format!("{}-{}", l.proto, u.name), &[server], i)?;
            let ok = got.as_deref() == Some("e2e-ok");
            println!("{} {} / {}: {}", if ok { "✓" } else { "✗" }, l.proto, u.name, got.as_deref().unwrap_or("нет ответа"));
            failed += (!ok) as u32;
        }
    }

    // записи, собранные прямо из состояния, в одном конфиге с urltest
    let all: Vec<Server> = servers_from_state("127.0.0.1", &st, &st.users[0])?.into_iter().filter(|s| s.kind != Kind::Vless && s.kind != Kind::VlessWs).collect();
    let got = run_client(&bin, &dir, "auto", &all, 90)?;
    let ok = got.as_deref() == Some("e2e-ok");
    println!("{} urltest по трём протоколам: {}", if ok { "✓" } else { "✗" }, got.as_deref().unwrap_or("нет ответа"));
    failed += (!ok) as u32;

    // негативные: неверный пин и неверный пароль не должны пропускать трафик
    let mut wrong_pin = all[0].clone();
    wrong_pin.pin = Some(tlscert::generate("www.bing.com")?.spki_sha256_b64);
    let mut wrong_pw = all[1].clone();
    wrong_pw.password = Some("0".repeat(32));
    let mut wrong_ss = all[2].clone();
    wrong_ss.password = Some("AAAAAAAAAAAAAAAAAAAAAA==:BBBBBBBBBBBBBBBBBBBBBB==".into());
    for (n, s, k) in [("wrong-pin", wrong_pin, 91), ("wrong-password", wrong_pw, 92), ("wrong-ss-key", wrong_ss, 93)] {
        let got = run_client(&bin, &dir, n, &[s], k)?;
        let ok = got.is_none();
        println!("{} {n}: {}", if ok { "✓ отклонено" } else { "✗ ПРОПУЩЕНО" }, got.as_deref().unwrap_or("нет ответа"));
        failed += (!ok) as u32;
    }

    // VLESS-WS: в жизни клиент приходит на домен CDN:443, а CDN сам заходит на сервер по TLS на порт сервера.
    // В стенде CDN нет: клиент идёт прямо на порт сервера, а проверку сертификата (в жизни её проходит
    // настоящий сертификат CDN) отключаем только в этой тестовой правке. Проверяется то, что наше: путь,
    // заголовок Host, uuid и шаблоны профиля на настоящем sing-box.
    let to_origin = |s: &mut Server| {
        s.host = "127.0.0.1".into();
        s.port = 24447;
    };
    let insecure = |c: &mut serde_json::Value| {
        for o in c["outbounds"].as_array_mut().unwrap() {
            if o["type"] == "vless" {
                o["tls"]["insecure"] = true.into();
            }
        }
    };
    let mut ws_n = 0u16;
    for u in &st.users {
        let link = all_links("127.0.0.1", &st, u)?.into_iter().find(|l| l.proto == "vless-ws").expect("ссылка vless-ws");
        let mut server = parse_link(&link.url)?;
        anyhow::ensure!(server.host == "cdn.example.com" && server.port == 443, "ссылка ведёт на домен CDN, а не на адрес сервера");
        to_origin(&mut server);
        ws_n += 1;
        let got = run_client_patched(&bin, &dir, &format!("vless-ws-{}", u.name), &[server], 60 + ws_n, insecure)?;
        let ok = got.as_deref() == Some("e2e-ok");
        println!("{} vless-ws / {}: {}", if ok { "✓" } else { "✗" }, u.name, got.as_deref().unwrap_or("нет ответа"));
        failed += (!ok) as u32;
    }
    let good_ws = {
        let mut s = servers_from_state("127.0.0.1", &st, &st.users[0])?.into_iter().find(|s| s.kind == Kind::VlessWs).unwrap();
        anyhow::ensure!(s.origin.as_deref() == Some("127.0.0.1"), "origin должен быть адресом сервера");
        to_origin(&mut s);
        s
    };
    let mut wrong_path = good_ws.clone();
    wrong_path.ws_path = Some("/not-the-path".into());
    let mut wrong_uuid = good_ws.clone();
    wrong_uuid.uuid = "c158cda3-0b3d-424b-a8f8-26a6462c8349".into();
    // Заголовок Host входящее sing-box не проверяет (проверено: с чужим Host соединение проходит), поэтому
    // защита сервера от чужих запросов через CDN это секретный путь и uuid, а не имя хоста.
    for (n, srv, k) in [("ws-wrong-path", wrong_path, 94), ("ws-wrong-uuid", wrong_uuid, 95)] {
        let got = run_client_patched(&bin, &dir, n, &[srv], k, insecure)?;
        let ok = got.is_none();
        println!("{} {n}: {}", if ok { "✓ отклонено" } else { "✗ ПРОПУЩЕНО" }, got.as_deref().unwrap_or("нет ответа"));
        failed += (!ok) as u32;
    }

    // сервер действительно видел соединения по каждому протоколу и от каждого пользователя
    let log: String = {
        let raw = std::fs::read_to_string(dir.join("server.log"))?;
        let mut out = String::new();
        let mut it = raw.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\u{1b}' {
                for d in it.by_ref() { if d == 'm' { break; } }
            } else {
                out.push(c);
            }
        }
        out
    };
    for (kind, tag) in [("hysteria2", "hysteria2"), ("tuic", "tuic"), ("shadowsocks", "ss2022"), ("vless", "vless-ws")] {
        for u in &st.users {
            let seen = log.lines().any(|l| l.contains(&format!("inbound/{kind}[{tag}]: [{}] inbound connection to target.test", u.name)));
            println!("{} сервер принял трафик через {tag} от пользователя {}", if seen { "✓" } else { "✗" }, u.name);
            failed += (!seen) as u32;
        }
    }
    let _ = profiles::builtin(&Proto::Tuic);
    println!("\nлоги и конфиги: {}", dir.display());
    anyhow::ensure!(failed == 0, "провалено проверок: {failed}");
    println!("всё хорошо");
    Ok(())
}
