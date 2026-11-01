//! M6.2: сторонний профиль проходит весь путь: установка → включение на сервере (конфиг, порты) → запись клиента →
//! клиентский конфиг и проверка в helper'е. Один тест: он задаёт ELEUTHERIA_CONFIG_DIR для всего процесса.

use std::fs;

use eleutheria_core::client::config::{build, build_with_profiles, ClientOpts, RuDirect};
use eleutheria_core::client::profile::{servers_from_state, Kind, Server};
use eleutheria_core::state::{Proto, ProtoState, State, TlsInfo, User};
use eleutheria_core::{config, profiles, provision, userprofiles};
use serde_json::json;

const META: &str = "schema: 1\nid: demo-trojan\nname: Demo Trojan\ntransport: tcp\ndefault_port: 9443\nneeds_cert: true\npassword: hex32\n";
const SERVER: &str = r#"{"type":"trojan","tag":"demo-trojan","listen":"::","listen_port":"{{port}}",
    "users":{"$each":"users","as":"u","do":{"name":"{{u.name}}","password":"{{u.password}}"}},
    "tls":{"enabled":true,"server_name":"{{sni}}","certificate_path":"{{cert_path}}","key_path":"{{key_path}}"}}"#;
const CLIENT: &str = r#"{"type":"trojan","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","password":"{{password}}",
    "tls":{"enabled":true,"server_name":"{{sni}}","certificate_public_key_sha256":"{{?pin_list}}"}}"#;

// профиль с ключом сервера (как SS-2022) и без сертификата
const META_KEYED: &str = "schema: 1\nid: demo-ss\nname: Demo SS\ntransport: both\ndefault_port: 9388\npassword: base64-16\nserver_key: base64-16\nparams:\n  method: 2022-blake3-aes-128-gcm\n";
const SERVER_KEYED: &str = r#"{"type":"shadowsocks","tag":"demo-ss","listen":"::","listen_port":"{{port}}","method":"{{param.method}}","password":"{{server_key}}",
    "users":{"$each":"users","as":"u","do":{"name":"{{u.name}}","password":"{{u.password}}"}}}"#;
const CLIENT_KEYED: &str = r#"{"type":"shadowsocks","tag":"{{tag}}","server":"{{host}}","server_port":"{{port}}","method":"{{method}}","password":"{{password}}"}"#;

fn install(root: &std::path::Path, src: &std::path::Path, m: &str, s: &str, c: &str) {
    fs::create_dir_all(src).unwrap();
    fs::write(src.join("meta.yaml"), m).unwrap();
    fs::write(src.join("server.json.tpl"), s).unwrap();
    fs::write(src.join("client.json.tpl"), c).unwrap();
    let plan = userprofiles::plan_install_in(root, src).unwrap();
    userprofiles::commit_in(root, &plan).unwrap();
}

fn opts() -> ClientOpts {
    ClientOpts {
        listen_port: 2080, clash_port: 9090, secret: "s".into(), test_url: "https://t.example/".into(), ru_direct: RuDirect::Off,
        selected: None, tun: false, ipv6: false, strict_route: false, categories: vec![], probe_ports: vec![],
    }
}

#[test]
fn custom_profile_end_to_end() {
    let base = std::env::temp_dir().join(format!("elt-m62-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    // SAFETY: единственный тест в этом файле, других потоков, читающих окружение, нет
    unsafe { std::env::set_var("ELEUTHERIA_CONFIG_DIR", &base) };
    let root = userprofiles::root();
    assert_eq!(root, base.join("profiles"));

    let demo = Proto::new("demo-trojan").unwrap();
    let keyed = Proto::new("demo-ss").unwrap();

    // 1. профиля нет: ни одна операция не принимает его молча
    let mut st = State::parse(r#"{"version":2,"singbox":"1.14.3","profile":"p","private_key":"a","public_key":"b","short_id":"c","sni":"x.com","port":443,"users":[]}"#).unwrap();
    st.users = vec![
        User { name: "default".into(), uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("s1".into()) },
        User { name: "bob".into(), uuid: "b158cda3-0b3d-424b-a8f8-26a6462c8349".into(), secret: Some("s2".into()) },
    ];
    st.protocols.tls = Some(TlsInfo { sni: "www.bing.com".into(), spki_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(), cert_sha256: "ab".into() });
    st.protocols.enabled.insert(Proto::Hysteria2, ProtoState::new(443));
    st.protocols.enabled.insert(demo.clone(), ProtoState { transport: Some(profiles::Transport::Tcp), ..ProtoState::new(9443) });
    let e = config::server_config(&st).unwrap_err();
    assert!(format!("{e:#}").contains("demo-trojan"), "{e:#}");
    assert!(profiles::parse_protocols(&["demo-trojan".into()]).is_err(), "неустановленный профиль не включается");
    assert!(profiles::parse_protocols(&["hysteira2".into()]).is_err(), "опечатка во встроенном не становится сторонним");

    // 2. установка и включение
    install(&root, &base.join("src1"), META, SERVER, CLIENT);
    install(&root, &base.join("src2"), META_KEYED, SERVER_KEYED, CLIENT_KEYED);
    assert_eq!(profiles::parse_protocols(&["demo-trojan".into(), "all".into()]).unwrap().len(), 4);

    // 3. серверный конфиг: inbound'ы по порядку (встроенный, затем сторонний), у каждого пользователя свой пароль
    let cfg = config::server_config(&st).unwrap();
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.iter().map(|i| i["tag"].as_str().unwrap()).collect::<Vec<_>>(), ["vless-reality", "hysteria2", "demo-trojan"]);
    let tr = &inbounds[2];
    assert_eq!((tr["type"].clone(), tr["listen_port"].clone()), (json!("trojan"), json!(9443)));
    let users = tr["users"].as_array().unwrap();
    assert_eq!(users[1]["name"], "bob");
    assert_eq!(users[0]["password"], profiles::derive_password("s1", "demo-trojan", profiles::PasswordFormat::Hex32));
    assert_ne!(users[0]["password"], users[1]["password"]);
    assert_eq!(tr["tls"]["certificate_path"], "/etc/eleutheria/cert.pem");

    // 4. порты: транспорт сохранён в состоянии, поэтому не зависит от наличия профиля
    let ports = provision::listen_ports(&st);
    assert!(ports.contains(&(9443, "tcp")) && !ports.contains(&(9443, "udp")), "{ports:?}");
    let raw = serde_json::to_string(&st).unwrap();
    assert_eq!(State::parse(&raw).unwrap(), st);
    assert!(raw.contains(r#""transport":"tcp""#) && raw.matches("transport").count() == 1, "только у стороннего: {raw}");

    // 5. запись клиента
    let all = servers_from_state("203.0.113.5", &st, &st.users[0]).unwrap();
    assert_eq!(all.iter().map(|s| s.kind_label()).collect::<Vec<_>>(), ["vless", "hysteria2", "demo-trojan"]);
    let s = all.iter().find(|s| s.kind == Kind::Custom).unwrap().clone();
    s.validate().unwrap();
    assert_eq!((s.profile.as_deref(), s.proto(), s.port), (Some("demo-trojan"), Some(demo.clone()), 9443));
    assert_eq!(s.password.as_deref(), Some(users[0]["password"].as_str().unwrap()), "клиент и сервер выводят один пароль");
    assert!(s.pin.is_some() && s.sni == "www.bing.com");
    let back: Server = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(back, s);
    // запись встроенного вида (как сохраняли до M6.2) читается без поля profile
    let old = serde_json::to_value(&all[1]).unwrap();
    assert!(old.get("profile").is_none());
    let _: Server = serde_json::from_value(old).unwrap();

    // 6. ссылки: у стороннего профиля их нет, остальные не страдают
    let links = config::all_links("203.0.113.5", &st, &st.users[0]).unwrap();
    assert_eq!(links.iter().map(|l| l.proto.as_str()).collect::<Vec<_>>(), ["vless", "hysteria2"]);
    assert!(config::proto_link(&demo, "203.0.113.5", &st, &st.users[0]).is_err());

    // 7. клиентский конфиг: шаблон из набора, без набора честная ошибка
    let files = userprofiles::files_for_servers(&root, &all).unwrap();
    assert_eq!(files.len(), 1);
    let set = userprofiles::profile_set(&files).unwrap();
    let c = build_with_profiles(&all, &opts(), &set).unwrap();
    let out = c["outbounds"].as_array().unwrap().iter().find(|o| o["type"] == "trojan").expect("trojan outbound");
    assert_eq!((out["server"].clone(), out["server_port"].clone(), out["password"].clone()), (json!("203.0.113.5"), json!(9443), json!(s.password)));
    assert_eq!(out["tls"]["certificate_public_key_sha256"], json!([st.protocols.tls.as_ref().unwrap().spki_sha256]));
    let e = build(&all, &opts()).unwrap_err();
    assert!(format!("{e:#}").contains("demo-trojan"), "{e:#}");

    // 8. профиль с ключом сервера: ключ создаёт provisioner, клиент шлёт `ключ:пароль`, шифр из params
    st.protocols.enabled.insert(keyed.clone(), ProtoState { server_key: Some("QUJDREVGR0hJSktMTU5PUA==".into()), transport: Some(profiles::Transport::Both), ..ProtoState::new(9388) });
    let cfg = config::server_config(&st).unwrap();
    let ss = cfg["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "demo-ss").unwrap();
    assert_eq!(ss["password"], "QUJDREVGR0hJSktMTU5PUA==");
    let ks = Server::for_proto(&keyed, "203.0.113.5", &st, &st.users[1]).unwrap();
    ks.validate().unwrap();
    let want = format!("QUJDREVGR0hJSktMTU5PUA==:{}", profiles::derive_password("s2", "demo-ss", profiles::PasswordFormat::Base64_16));
    assert_eq!((ks.password.as_deref(), ks.method.as_deref(), ks.security.as_str(), ks.pin.as_ref()), (Some(want.as_str()), Some("2022-blake3-aes-128-gcm"), "none", None));
    let ports = provision::listen_ports(&st);
    assert!(ports.contains(&(9388, "tcp")) && ports.contains(&(9388, "udp")));
    st.protocols.enabled.get_mut(&keyed).unwrap().server_key = None;
    assert!(config::server_config(&st).is_err(), "без ключа сервера конфиг не собирается");

    // 9. helper получает файлы по IPC и не доверяет им
    let good = files[0].clone();
    assert!(userprofiles::profile_set(&[good.clone(), good.clone()]).is_err(), "дубль");
    let mut evil = good.clone();
    evil.server = evil.server.replace("{{cert_path}}", "/etc/shadow");
    assert!(userprofiles::profile_set(&[evil]).is_err(), "чтение чужих файлов");
    let mut evil = good.clone();
    evil.meta = evil.meta.replace("demo-trojan", "hysteria2");
    assert!(userprofiles::profile_set(&[evil]).is_err(), "подмена встроенного id");
    let mut evil = good.clone();
    evil.client = evil.client.replace("{{password}}", "{{ws_path}}");
    assert!(userprofiles::profile_set(&[evil]).is_err(), "ws_path сторонним не выдаётся");
    let mut big = good.clone();
    big.client.push_str(&" ".repeat(17 * 1024));
    assert!(userprofiles::profile_set(&[big]).is_err(), "размер");
    let wrapped: userprofiles::Files = serde_json::from_str(&serde_json::to_string(&good).unwrap()).unwrap();
    assert!(userprofiles::profile_set(&[wrapped]).is_ok(), "после JSON-передачи профиль тот же");

    // 10. запись Custom без профиля или с чужими полями не проходит проверку helper'а
    for (name, mutate) in [
        ("нет profile", Box::new(|s: &mut Server| s.profile = None) as Box<dyn Fn(&mut Server)>),
        ("плохой id", Box::new(|s: &mut Server| s.profile = Some("../x".into()))),
        ("via", Box::new(|s: &mut Server| s.via = Some("a".into()))),
        ("ws_path", Box::new(|s: &mut Server| s.ws_path = Some("/x".into()))),
        ("пароль с пробелом", Box::new(|s: &mut Server| s.password = Some("a b".into()))),
        ("method с инъекцией", Box::new(|s: &mut Server| s.method = Some("x\",\"detour\":\"y".into()))),
        ("security", Box::new(|s: &mut Server| s.security = "reality".into())),
    ] {
        let mut bad = s.clone();
        mutate(&mut bad);
        assert!(bad.validate().is_err(), "{name}");
    }
    // Custom без набора профилей в конфиг не попадает ни при каком виде
    let mut orphan = s.clone();
    orphan.profile = Some("not-there".into());
    assert!(build_with_profiles(&[orphan], &opts(), &set).is_err());

    // 11. удалили профиль: клиент и сервер объясняют, чего не хватает
    userprofiles::remove_in(&root, "demo-trojan").unwrap();
    assert!(userprofiles::files_for_servers(&root, &all).is_err());
    assert!(servers_from_state("203.0.113.5", &st, &st.users[0]).is_err());
    let _ = fs::remove_dir_all(&base);
}
