//! e2e серверного слоя GUI на локальном стенде (см. scripts/e2e-local.sh: sshd на :2222, заглушки systemctl/ufw).
//! Только для разработки: меняет систему. Запуск: ELEUTHERIA_CONFIG_DIR=/tmp/elcfg-app ELEUTHERIA_PW=... \
//!   cargo run -p eleutheria-app --example e2e_server

use eleutheria_app::server::{self, HostKeyStatus, ProvisionRequest, SshConn};
use eleutheria_core::store;

static mut PASS: u32 = 0;
static mut FAIL: u32 = 0;

fn check(name: &str, ok: bool) {
    unsafe {
        if ok {
            PASS += 1;
            println!("  PASS: {name}");
        } else {
            FAIL += 1;
            println!("  FAIL: {name}");
        }
    }
}

fn conn(pw: Option<&str>, trusted: Option<&str>) -> SshConn {
    SshConn { host: "127.0.0.1".into(), user: "root".into(), ssh_port: 2222, password: pw.map(String::from), key_path: None, trusted_fingerprint: trusted.map(String::from) }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let pw = std::env::var("ELEUTHERIA_PW").expect("ELEUTHERIA_PW");
    let say = |m: &str| println!("    · {m}");
    let id = store::host_id("127.0.0.1", 2222);

    println!("== T1: проверка ключа хоста");
    let p = server::probe_host_key("127.0.0.1", 2222).await.expect("probe");
    check("новый сервер: статус unknown, fingerprint SHA256:…", p.status == HostKeyStatus::Unknown && p.fingerprint.starts_with("SHA256:"));
    check("probe ничего не сохраняет", matches!(store::check_host(&id, &p.fingerprint), store::HostCheck::Unknown));
    check("некорректный адрес отклоняется без сети", server::probe_host_key("a b", 22).await.is_err());

    println!("== T2: установка (server::provision)");
    // стенд: имя stand.test указывает на loopback, где слушает локальный «маскировочный сайт» (см. e2e-local.sh)
    let req = ProvisionRequest { port: Some(4443), sni: Some("stand.test".into()), profile: "t".into(), user_name: "default".into(), harden_ssh: true, bbr: true, firewall: true, protocols: vec![], cdn_host: None };
    let bad_sni = ProvisionRequest { sni: Some("localhost".into()), ..req.clone() };
    check("sni без точки отклоняется валидацией", server::provision(&conn(Some(&pw), Some(&p.fingerprint)), &bad_sni, &say).await.is_err());
    check("установка без подтверждения ключа хоста отклоняется", server::provision(&conn(Some(&pw), None), &req, &say).await.is_err());
    check("и ничего не запоминает", matches!(store::check_host(&id, &p.fingerprint), store::HostCheck::Unknown));
    let r = server::provision(&conn(Some(&pw), Some(&p.fingerprint)), &req, &say).await;
    if let Err(e) = &r {
        println!("    ошибка: {e:#}");
    }
    check("provision выполнен", r.is_ok());
    let Ok(r) = r else { std::process::exit(1) };
    check("сервер сохранён в списке клиента", r.saved_as.is_some() && eleutheria_core::client::profile::load().iter().any(|s| s.host == "127.0.0.1" && s.port == 4443));
    check("одна ссылка vless:// для default", r.links.len() == 1 && r.links[0].name == "default" && r.links[0].link.starts_with("vless://"));
    check("заметки укрепления получены", !r.notes.is_empty());
    for n in &r.notes {
        println!("    {} {}", if n.ok { "✓" } else { "⚠" }, n.text);
    }

    println!("== T3: ключ хоста и вход (после установки пароль отключён, вход по сохранённому ключу)");
    check("после установки ключ хоста известен", server::probe_host_key("127.0.0.1", 2222).await.map(|p| p.status == HostKeyStatus::Known).unwrap_or(false));
    check("вход по сохранённому ключу работает без пароля", server::list_users(&conn(None, None)).await.is_ok());
    check("вход по паролю после укрепления невозможен", server::list_users(&conn(Some(&pw), None)).await.is_err());
    store::forget_host("127.0.0.1").expect("forget");
    let p = server::probe_host_key("127.0.0.1", 2222).await.expect("probe");
    check("после forget сервер снова unknown", p.status == HostKeyStatus::Unknown);
    check("незнакомый ключ без подтверждения отклоняется", server::list_users(&conn(None, None)).await.is_err());
    check("и не запоминается", matches!(store::check_host(&id, &p.fingerprint), store::HostCheck::Unknown));
    check("чужой fingerprint в «подтверждении» отклоняется", server::list_users(&conn(None, Some("SHA256:подделка"))).await.is_err());
    let v = server::list_users(&conn(None, Some(&p.fingerprint))).await;
    check("с подтверждённым fingerprint вход работает", v.is_ok());
    check("после подтверждения ключ сохранён (Known)", server::probe_host_key("127.0.0.1", 2222).await.map(|p| p.status == HostKeyStatus::Known).unwrap_or(false));
    let v = v.unwrap();
    check("один пользователь default", v.users == ["default"] && v.links.len() == 1 && v.links[0].link.starts_with("vless://"));

    println!("== T4: пользователи");
    let v = server::add_user(&conn(None, None), "anna", &say).await;
    check("добавлен anna", v.as_ref().map(|v| v.users == ["default", "anna"] && v.links.len() == 2).unwrap_or(false));
    check("ссылки пользователей различаются", v.as_ref().map(|v| v.links[0].link != v.links[1].link).unwrap_or(false));
    check("дубликат отклонён", server::add_user(&conn(None, None), "anna", &say).await.is_err());
    check("недопустимое имя отклонено", server::add_user(&conn(None, None), "bad name", &say).await.is_err());
    let v = server::remove_user(&conn(None, None), "anna", &say).await;
    check("anna удалена", v.as_ref().map(|v| v.users == ["default"]).unwrap_or(false));
    check("последнего пользователя удалить нельзя", server::remove_user(&conn(None, None), "default", &say).await.is_err());
    check("несуществующего удалить нельзя", server::remove_user(&conn(None, None), "ghost", &say).await.is_err());

    println!("== T5: смена ключа хоста");
    store::remember_host(&id, "SHA256:старый").expect("remember");
    let p2 = server::probe_host_key("127.0.0.1", 2222).await.expect("probe");
    check("probe видит смену ключа", matches!(&p2.status, HostKeyStatus::Changed { previous } if previous == "SHA256:старый"));
    check("вход блокируется даже с «подтверждённым» fingerprint", server::list_users(&conn(None, Some(&p2.fingerprint))).await.is_err());
    store::remember_host(&id, &p2.fingerprint).expect("restore");

    let (pass, fail) = unsafe { (PASS, FAIL) };
    println!("\n== итог: PASS={pass} FAIL={fail}");
    std::process::exit(if fail > 0 { 1 } else { 0 });
}
