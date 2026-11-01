//! Проверка M6.2 на настоящем sing-box: два сторонних профиля (trojan с сертификатом, SS-2022-подобный с ключом
//! сервера) ставятся как у пользователя, сервер и клиент собираются нашим кодом по их шаблонам, трафик идёт
//! через оба, а неверный пароль, пин и ключ его не пропускают.
//!
//! SINGBOX_BIN=/path/to/sing-box cargo run -p eleutheria-core --example e2e_custom
//! Нужна запись `127.0.0.1 target.test` в /etc/hosts (см. e2e_protocols).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eleutheria_core::client::config::{build_with_profiles, ClientOpts, ProfileSet, RuDirect};
use eleutheria_core::client::profile::{servers_from_state, Kind, Server};
use eleutheria_core::config::server_config_in;
use eleutheria_core::state::{Proto, ProtoState, State, TlsInfo, User};
use eleutheria_core::{profiles, tlscert, userprofiles};

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
        .args(["-s", "-m", "6", "--socks5-hostname", &format!("127.0.0.1:{socks_port}"), "http://target.test:28081/"])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn run_client(bin: &str, dir: &Path, name: &str, servers: &[Server], set: &ProfileSet, i: u16) -> anyhow::Result<Option<String>> {
    let o = ClientOpts {
        listen_port: 27990 + i, clash_port: 29190 + i, secret: "t".into(), test_url: "http://target.test:28081/".into(),
        ru_direct: RuDirect::Off, selected: None, tun: false, ipv6: false, strict_route: false, categories: vec![], probe_ports: vec![],
    };
    let cfg = build_with_profiles(servers, &o, set)?;
    let path = dir.join(format!("client-{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg)?)?;
    let chk = Command::new(bin).args(["check", "-c"]).arg(&path).output()?;
    anyhow::ensure!(chk.status.success(), "sing-box check клиента {name}: {}", String::from_utf8_lossy(&chk.stderr));
    let _p = spawn(bin, &path, &dir.join(format!("client-{name}.log")));
    std::thread::sleep(Duration::from_millis(1500));
    Ok(fetch(27990 + i))
}

const TROJAN: [&str; 3] = [
    "schema: 1\nid: e2e-trojan\nname: E2E Trojan\ntransport: tcp\ndefault_port: 24543\nneeds_cert: true\npassword: hex32\n",
    r#"{"type":"trojan","tag":"e2e-trojan","listen":"::","listen_port":"{{port}}",
  "users":{"$each":"users","as":"u","do":{"name":"{{u.name}}","password":"{{u.password}}"}},
  "tls":{"enabled":true,"server_name":"{{sni}}","certificate_path":"{{cert_path}}","key_path":"{{key_path}}"}}"#,
    r#"{"type":"trojan","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","password":"{{password}}",
  "tls":{"enabled":true,"server_name":"{{sni}}","certificate_public_key_sha256":"{{?pin_list}}"}}"#,
];
const KEYED: [&str; 3] = [
    "schema: 1\nid: e2e-ss\nname: E2E SS\ntransport: both\ndefault_port: 24544\npassword: base64-16\nserver_key: base64-16\nparams:\n  method: 2022-blake3-aes-128-gcm\n",
    r#"{"type":"shadowsocks","tag":"e2e-ss","listen":"::","listen_port":"{{port}}","method":"{{param.method}}","password":"{{server_key}}",
  "users":{"$each":"users","as":"u","do":{"name":"{{u.name}}","password":"{{u.password}}"}}}"#,
    r#"{"type":"shadowsocks","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","method":"{{method}}","password":"{{password}}"}"#,
];

fn main() -> anyhow::Result<()> {
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let dir: PathBuf = std::env::temp_dir().join(format!("eleutheria-e2e-m62-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    // SAFETY: до запуска потоков
    unsafe { std::env::set_var("ELEUTHERIA_CONFIG_DIR", dir.join("cfg")) };
    let root = userprofiles::root();
    for (n, t) in [("trojan", TROJAN), ("ss", KEYED)] {
        let src = dir.join(format!("src-{n}"));
        std::fs::create_dir_all(&src)?;
        for (f, c) in ["meta.yaml", "server.json.tpl", "client.json.tpl"].iter().zip(t) {
            std::fs::write(src.join(f), c)?;
        }
        userprofiles::commit_in(&root, &userprofiles::plan_install_in(&root, &src)?)?;
    }
    println!("✓ профили установлены и прошли проверку");

    let cert = tlscert::generate("www.bing.com")?;
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem)?;
    std::fs::write(dir.join("key.pem"), &cert.key_pem)?;
    let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"E2E","private_key":"UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef","sni":"www.microsoft.com","port":24546,"users":[]}"#).unwrap();
    st.users = vec![
        User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret-1".into()) },
        User { name: "bob".into(), uuid: "b158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("e2e-secret-2".into()) },
    ];
    st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: cert.spki_sha256_b64.clone(), cert_sha256: cert.cert_sha256_hex.clone() });
    let (tj, ss) = (Proto::new("e2e-trojan").unwrap(), Proto::new("e2e-ss").unwrap());
    st.protocols.enabled.insert(tj.clone(), ProtoState { transport: Some(profiles::Transport::Tcp), ..ProtoState::new(24543) });
    st.protocols.enabled.insert(ss.clone(), ProtoState { server_key: Some("AAAAAAAAAAAAAAAAAAAAAA==".into()), transport: Some(profiles::Transport::Both), ..ProtoState::new(24544) });

    let mut scfg = server_config_in(&st, dir.to_str().unwrap())?;
    scfg["log"]["level"] = "info".into();
    std::fs::write(dir.join("server.json"), serde_json::to_vec_pretty(&scfg)?)?;
    let chk = Command::new(&bin).args(["check", "-c"]).arg(dir.join("server.json")).output()?;
    anyhow::ensure!(chk.status.success(), "sing-box check сервера: {}", String::from_utf8_lossy(&chk.stderr));
    println!("✓ sing-box check серверного конфига ({} inbound'а)", scfg["inbounds"].as_array().unwrap().len());

    std::fs::write(dir.join("index.html"), "e2e-ok")?;
    let _http = Proc(Command::new("python3").args(["-m", "http.server", "28081", "--bind", "127.0.0.1"]).current_dir(&dir).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
    let _srv = spawn(&bin, &dir.join("server.json"), &dir.join("server.log"));
    std::thread::sleep(Duration::from_millis(1500));

    let mut failed = 0u32;
    let mut i = 0u16;
    for u in &st.users {
        let all: Vec<Server> = servers_from_state("127.0.0.1", &st, u)?.into_iter().filter(|s| s.kind == Kind::Custom).collect();
        // тот же путь, что у клиента и helper'а: файлы установленных профилей -> проверка -> набор
        let set = userprofiles::profile_set(&userprofiles::files_for_servers(&root, &all)?)?;
        for s in &all {
            i += 1;
            let got = run_client(&bin, &dir, &format!("{}-{}", s.kind_label(), u.name), std::slice::from_ref(s), &set, i)?;
            let ok = got.as_deref() == Some("e2e-ok");
            println!("{} {} / {}: {}", if ok { "✓" } else { "✗" }, s.kind_label(), u.name, got.as_deref().unwrap_or("нет ответа"));
            failed += (!ok) as u32;
        }
    }

    // оба профиля в одном конфиге (urltest/selector)
    let all: Vec<Server> = servers_from_state("127.0.0.1", &st, &st.users[0])?.into_iter().filter(|s| s.kind == Kind::Custom).collect();
    let set = userprofiles::profile_set(&userprofiles::files_for_servers(&root, &all)?)?;
    let got = run_client(&bin, &dir, "auto", &all, &set, 80)?;
    let ok = got.as_deref() == Some("e2e-ok");
    println!("{} urltest по двум сторонним профилям: {}", if ok { "✓" } else { "✗" }, got.as_deref().unwrap_or("нет ответа"));
    failed += (!ok) as u32;

    // негативные
    let by = |id: &str| all.iter().find(|s| s.profile.as_deref() == Some(id)).expect("сервер профиля").clone();
    let mut wrong_pw = by("e2e-trojan");
    wrong_pw.password = Some("0".repeat(32));
    let mut wrong_pin = by("e2e-trojan");
    wrong_pin.pin = Some(tlscert::generate("www.bing.com")?.spki_sha256_b64);
    let mut wrong_key = by("e2e-ss");
    wrong_key.password = Some("BBBBBBBBBBBBBBBBBBBBBB==:CCCCCCCCCCCCCCCCCCCCCC==".into());
    let mut other_user = by("e2e-ss");
    other_user.password = Some(format!("AAAAAAAAAAAAAAAAAAAAAA==:{}", profiles::derive_password("чужой-секрет", "e2e-ss", profiles::PasswordFormat::Base64_16)));
    for (n, s, k) in [("wrong-password", wrong_pw, 91), ("wrong-pin", wrong_pin, 92), ("wrong-server-key", wrong_key, 93), ("unknown-user", other_user, 94)] {
        let got = run_client(&bin, &dir, n, &[s], &set, k)?;
        let ok = got.is_none();
        println!("{} {n}: {}", if ok { "✓ отклонено" } else { "✗ ПРОПУЩЕНО" }, got.as_deref().unwrap_or("нет ответа"));
        failed += (!ok) as u32;
    }

    // сервер видел соединения по каждому профилю от каждого пользователя
    let log: String = {
        let raw = std::fs::read_to_string(dir.join("server.log"))?;
        let (mut out, mut it) = (String::new(), raw.chars());
        while let Some(c) = it.next() {
            if c == '\u{1b}' {
                for d in it.by_ref() { if d == 'm' { break; } }
            } else {
                out.push(c);
            }
        }
        out
    };
    for (kind, tag) in [("trojan", "e2e-trojan"), ("shadowsocks", "e2e-ss")] {
        for u in &st.users {
            let seen = log.lines().any(|l| l.contains(&format!("inbound/{kind}[{tag}]: [{}] inbound connection to target.test", u.name)));
            println!("{} сервер принял трафик через {tag} от пользователя {}", if seen { "✓" } else { "✗" }, u.name);
            failed += (!seen) as u32;
        }
    }
    println!("\nлоги и конфиги: {}", dir.display());
    anyhow::ensure!(failed == 0, "провалено проверок: {failed}");
    println!("всё хорошо");
    Ok(())
}
