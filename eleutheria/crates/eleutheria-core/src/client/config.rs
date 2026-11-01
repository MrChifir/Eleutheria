//! Генерация клиентского конфига sing-box по списку серверов.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::categories::Category;
use super::profile::{Kind, Server};
use super::prober::{selector_tag, ProbePort, DIRECT};
use crate::profiles;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuDirect {
    /// всё через VPN
    Off,
    /// домены .ru/.su/.рф и приватные адреса напрямую (работает без загрузок)
    Minimal,
    /// + наборы правил geoip-ru и geosite-category-ru (скачиваются через прокси при запуске)
    RuleSets,
}

#[derive(Clone, Debug)]
pub struct ClientOpts {
    pub listen_port: u16,
    pub clash_port: u16,
    pub secret: String,
    pub test_url: String,
    pub ru_direct: RuDirect,
    /// имя сервера, который выбрать по умолчанию; None = автовыбор по задержке
    pub selected: Option<String>,
    /// системный VPN через TUN (нужны права: запускает helper) вместо локального прокси
    pub tun: bool,
    /// IPv6 включён в системе (иначе sing-box не сможет назначить v6-адрес на TUN)
    pub ipv6: bool,
    /// строгая маршрутизация (защита от утечек мимо TUN). Нужно выключать, только если в ядре вообще нет IPv6:
    /// строгий режим добавляет v6-правила, а они невозможны, зато и v6-утечек быть не может
    pub strict_route: bool,
    /// категории с отдельными переключателями (учитываются только при двух и более серверах и `enabled`)
    pub categories: Vec<Category>,
    /// локальные пробные входы по одному на outbound (+ `direct`); пусто = без проб
    pub probe_ports: Vec<ProbePort>,
}

/// В ядре есть поддержка IPv6 (пусть и отключённая настройкой).
pub fn ipv6_supported() -> bool {
    // macOS и Windows всегда имеют стек IPv6 (/proc там нет); отдельно выключить его на уровне ядра нельзя
    cfg!(any(target_os = "macos", windows)) || std::path::Path::new("/proc/net/if_inet6").exists()
}

/// IPv6 включён и поддерживается ядром (проверяется в сетевом пространстве текущего процесса).
pub fn ipv6_available() -> bool {
    // Без IPv6 в TUN нативный IPv6 системы шёл бы мимо туннеля, поэтому на macOS/Windows TUN всегда с IPv6
    if cfg!(any(target_os = "macos", windows)) {
        return true;
    }
    ipv6_supported()
        && std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|v| v.trim() == "0")
            .unwrap_or(false)
}

pub const PROBE_USER: &str = "probe";

pub fn probe_tag(outbound: &str) -> String {
    format!("probe-{outbound}")
}

pub const RU_SUFFIXES: [&str; 3] = [".ru", ".su", ".xn--p1ai"];

pub fn server_tag(index: usize) -> String {
    format!("srv-{}", index + 1)
}

/// Внешний exit: SOCKS5 через `detour` на свой сервер-вход. Имя прокси не разрешается (адрес только IP).
fn socks_outbound(tag: &str, s: &Server, via_tag: &str) -> Value {
    let mut o = json!({ "type": "socks", "tag": tag, "server": s.host, "server_port": s.port, "version": "5", "detour": via_tag });
    if let (Some(u), Some(p)) = (&s.username, &s.password) {
        o["username"] = json!(u);
        o["password"] = json!(p);
    }
    o
}

/// Проверенные сторонние профили по идентификатору (нужны серверам с `kind = custom`).
pub type ProfileSet = std::collections::BTreeMap<String, crate::profiles::Profile>;

fn outbound(tag: &str, s: &Server, via_tag: Option<&str>, set: &ProfileSet) -> Result<Value> {
    if s.kind == Kind::Socks5 {
        return Ok(socks_outbound(tag, s, via_tag.context("у внешнего exit нет сервера-входа")?));
    }
    let mut o = match s.proto() {
        None if s.kind == Kind::Custom => bail!("у сервера `{}` не задан сторонний профиль", s.name.chars().take(32).collect::<String>()),
        None => vless_outbound(tag, s),
        Some(p) => {
            let vars = json!({
                "tag": tag, "host": s.host, "port": s.port, "uuid": s.uuid, "sni": s.sni,
                "password": s.password.clone().unwrap_or_default(),
                "method": s.method.clone().unwrap_or_default(),
                "ws_path": s.ws_path.clone().unwrap_or_default(),
                "pin_list": s.pin.iter().collect::<Vec<_>>(),
            });
            match profiles::builtin(&p) {
                Some(b) => b.render_client(&vars)?,
                None => set
                    .get(p.id())
                    .with_context(|| format!("профиль `{}` не установлен или не передан", p.id()))?
                    .render_client(&vars)?,
            }
        }
    };
    if s.host.parse::<std::net::IpAddr>().is_err() {
        o["domain_resolver"] = json!("local");
    }
    Ok(o)
}

fn vless_outbound(tag: &str, s: &Server) -> Value {
    let mut tls = json!({
        "enabled": true,
        "server_name": s.sni,
        "utls": { "enabled": true, "fingerprint": s.fingerprint },
    });
    if s.security == "reality" {
        tls["reality"] = json!({
            "enabled": true,
            "public_key": s.public_key.clone().unwrap_or_default(),
            "short_id": s.short_id.clone().unwrap_or_default(),
        });
    }
    let mut o = json!({
        "type": "vless",
        "tag": tag,
        "server": s.host,
        "server_port": s.port,
        "uuid": s.uuid,
        "tls": tls,
    });
    if let Some(f) = &s.flow {
        o["flow"] = json!(f);
    }
    o
}

pub fn build(servers: &[Server], o: &ClientOpts) -> Result<Value> {
    build_with_profiles(servers, o, &ProfileSet::new())
}

/// То же, но серверы со сторонними профилями собираются по шаблонам из `set` (они должны быть уже проверены).
pub fn build_with_profiles(servers: &[Server], o: &ClientOpts, set: &ProfileSet) -> Result<Value> {
    if servers.is_empty() {
        bail!("нет серверов: добавь командой `eleutheria import <ссылка или подписка>`");
    }
    super::profile::check_chains(servers)?;
    let tags: Vec<String> = (0..servers.len()).map(server_tag).collect();
    let via_tag = |s: &Server| s.via.as_deref().and_then(|v| servers.iter().position(|x| x.name == v)).map(server_tag);
    let mut outbounds: Vec<Value> = servers.iter().zip(&tags).map(|(s, t)| outbound(t, s, via_tag(s).as_deref(), set)).collect::<Result<_>>()?;
    // Внешние exit не участвуют в автовыборе и общем переключателе: весь трафик через них не идёт никогда,
    // только точечно по категориям, когда роутер решил (и пользователь разрешил) это
    let normal_tags: Vec<String> = servers.iter().zip(&tags).filter(|(s, _)| !s.is_external_exit()).map(|(_, t)| t.clone()).collect();

    let multi = servers.len() > 1;
    let default = match &o.selected {
        Some(name) => {
            let i = servers
                .iter()
                .position(|s| &s.name == name)
                .ok_or_else(|| anyhow::anyhow!("сервера `{name}` нет в списке"))?;
            if servers[i].is_external_exit() {
                bail!("`{name}` внешний exit: он не может быть основным сервером");
            }
            tags[i].clone()
        }
        None if multi => "auto".to_string(),
        None => normal_tags[0].clone(),
    };
    let mut choices: Vec<String> = Vec::new();
    if multi {
        outbounds.push(json!({
            "type": "urltest", "tag": "auto", "outbounds": normal_tags,
            "url": o.test_url, "interval": "3m", "tolerance": 50,
        }));
        choices.push("auto".into());
    }
    choices.extend(normal_tags.iter().cloned());
    outbounds.push(json!({ "type": "selector", "tag": "proxy", "outbounds": choices, "default": default }));
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    // Переключатели категорий: по умолчанию следуют за общим `proxy`; роутер переводит их на другой путь точечно
    let active_cats: Vec<&Category> = if multi { o.categories.iter().filter(|c| c.enabled && !c.domains.is_empty()).collect() } else { Vec::new() };
    for c in &active_cats {
        let mut opts: Vec<String> = vec!["proxy".into()];
        opts.extend(tags.iter().cloned());
        opts.push(DIRECT.into());
        outbounds.push(json!({ "type": "selector", "tag": selector_tag(&c.id), "outbounds": opts, "default": "proxy" }));
    }

    // DNS: RU-домены через системный резолвер, остальное через DoH за прокси
    let mut dns_rules: Vec<Value> = Vec::new();
    let mut route_rules: Vec<Value> = vec![json!({ "action": "sniff" })];
    if o.tun {
        // весь DNS-трафик системы перехватывается и обслуживается встроенным DNS sing-box (без утечек)
        route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    route_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    let mut rule_sets: Vec<Value> = Vec::new();
    // Пробные входы привязаны к своему outbound раньше любых других правил: проба должна идти именно туда
    let mut probe_rules: Vec<Value> = Vec::new();
    for p in &o.probe_ports {
        let target = if p.tag == DIRECT || tags.contains(&p.tag) { p.tag.clone() } else { bail!("пробный порт для неизвестного outbound `{}`", p.tag) };
        probe_rules.push(json!({ "inbound": [probe_tag(&p.tag)], "outbound": target }));
    }
    if o.ru_direct != RuDirect::Off {
        dns_rules.push(json!({ "domain_suffix": RU_SUFFIXES, "server": "local" }));
        route_rules.push(json!({ "domain_suffix": RU_SUFFIXES, "outbound": "direct" }));
    }
    if o.ru_direct == RuDirect::RuleSets {
        let rs = |tag: &str, url: &str| {
            json!({ "type": "remote", "tag": tag, "format": "binary", "url": url, "download_detour": "proxy" })
        };
        rule_sets.push(rs("geoip-ru", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"));
        rule_sets.push(rs("geosite-category-ru", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs"));
        dns_rules.push(json!({ "rule_set": ["geosite-category-ru"], "server": "local" }));
        route_rules.push(json!({ "rule_set": ["geoip-ru", "geosite-category-ru"], "outbound": "direct" }));
    }

    // Категории идут после «прямых» правил (приватные адреса, RU), чтобы не перехватывать их трафик
    for c in &active_cats {
        route_rules.push(json!({ "domain_suffix": c.domains, "outbound": selector_tag(&c.id) }));
    }
    for (i, r) in probe_rules.into_iter().enumerate() {
        route_rules.insert(i, r);
    }

    let mut dns_servers = vec![
        json!({ "type": "local", "tag": "local" }),
        json!({ "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" }),
    ];
    if o.tun {
        // остальные A/AAAA-запросы получают фиктивные адреса: настоящее имя уходит на сервер через туннель
        let mut fake = json!({ "type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15" });
        if o.ipv6 {
            fake["inet6_range"] = json!("fc00::/18");
        }
        dns_servers.push(fake);
        dns_rules.push(json!({ "query_type": ["A", "AAAA"], "server": "fakeip" }));
    }

    let mut route = json!({
        "rules": route_rules,
        "final": "proxy",
        "default_domain_resolver": "local",
    });
    if o.tun {
        route["auto_detect_interface"] = json!(true); // исходящие к VPN-серверу идут мимо TUN, без петли
    }
    if !rule_sets.is_empty() {
        route["rule_set"] = json!(rule_sets);
    }

    let inbound = if o.tun {
        let mut addr = vec!["172.19.0.1/30"];
        if o.ipv6 {
            addr.push("fdfe:dcba:9876::1/126");
        }
        json!({
            "type": "tun", "tag": "tun-in",
            "address": addr,
            "auto_route": true, "strict_route": o.strict_route, "stack": "mixed",
        })
    } else {
        json!({
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": o.listen_port,
        })
    };

    let mut inbounds = vec![inbound];
    for p in &o.probe_ports {
        inbounds.push(json!({
            "type": "mixed", "tag": probe_tag(&p.tag),
            "listen": "127.0.0.1", "listen_port": p.port,
            // порт доступен любому локальному процессу, поэтому вход закрыт паролем (секрет Clash API)
            "users": [{ "username": PROBE_USER, "password": o.secret }],
        }));
    }

    Ok(json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "remote",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", o.clash_port),
                "secret": o.secret,
            }
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::profile::Kind;

    fn srv(name: &str, host: &str) -> Server {
        Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name: name.into(), host: host.into(), port: 443,
            uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(),
            kind: Kind::Vless, password: None, method: None, pin: None,
            flow: Some("xtls-rprx-vision".into()), security: "reality".into(),
            sni: "www.microsoft.com".into(), fingerprint: "chrome".into(),
            public_key: Some("PUB".into()), short_id: Some("abcd".into()),
        }
    }

    fn opts() -> ClientOpts {
        ClientOpts {
            listen_port: 7890, clash_port: 9090, secret: "s3".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            ru_direct: RuDirect::Minimal, selected: None, tun: false, ipv6: true, strict_route: true,
            categories: vec![], probe_ports: vec![],
        }
    }

    fn tag<'a>(c: &'a Value, t: &str) -> &'a Value {
        c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == t).unwrap()
    }

    #[test]
    fn single_server_has_no_urltest() {
        let c = build(&[srv("a", "203.0.113.5")], &opts()).unwrap();
        assert!(c["outbounds"].as_array().unwrap().iter().all(|o| o["type"] != "urltest"));
        assert_eq!(tag(&c, "proxy")["default"], "srv-1");
        assert_eq!(c["route"]["final"], "proxy");
    }

    #[test]
    fn multiple_servers_get_auto_group_by_default() {
        let c = build(&[srv("a", "203.0.113.5"), srv("b", "198.51.100.7")], &opts()).unwrap();
        assert_eq!(tag(&c, "proxy")["default"], "auto");
        assert_eq!(tag(&c, "auto")["outbounds"], json!(["srv-1", "srv-2"]));
        assert_eq!(tag(&c, "proxy")["outbounds"], json!(["auto", "srv-1", "srv-2"]));
    }

    #[test]
    fn selected_server_overrides_auto_and_unknown_fails() {
        let mut o = opts();
        o.selected = Some("b".into());
        let c = build(&[srv("a", "203.0.113.5"), srv("b", "198.51.100.7")], &o).unwrap();
        assert_eq!(tag(&c, "proxy")["default"], "srv-2");
        o.selected = Some("zzz".into());
        assert!(build(&[srv("a", "203.0.113.5")], &o).is_err());
    }

    #[test]
    fn reality_and_domain_resolver() {
        let c = build(&[srv("a", "vpn.example.com")], &opts()).unwrap();
        let o = tag(&c, "srv-1");
        assert_eq!(o["tls"]["reality"]["public_key"], "PUB");
        assert_eq!(o["flow"], "xtls-rprx-vision");
        assert_eq!(o["domain_resolver"], "local");
        let c = build(&[srv("a", "203.0.113.5")], &opts()).unwrap();
        assert!(tag(&c, "srv-1").get("domain_resolver").is_none());
    }

    #[test]
    fn ru_direct_modes() {
        let s = [srv("a", "203.0.113.5")];
        let has_ru = |c: &Value| c["route"]["rules"].as_array().unwrap().iter().any(|r| r["domain_suffix"] == json!(RU_SUFFIXES));
        let mut o = opts();
        o.ru_direct = RuDirect::Off;
        let c = build(&s, &o).unwrap();
        assert!(!has_ru(&c) && c["route"].get("rule_set").is_none());
        o.ru_direct = RuDirect::Minimal;
        let c = build(&s, &o).unwrap();
        assert!(has_ru(&c) && c["route"].get("rule_set").is_none());
        o.ru_direct = RuDirect::RuleSets;
        let c = build(&s, &o).unwrap();
        assert!(has_ru(&c));
        assert_eq!(c["route"]["rule_set"].as_array().unwrap().len(), 2);
        assert_eq!(c["route"]["rule_set"][0]["download_detour"], "proxy");
    }

    #[test]
    fn clash_api_and_inbound_are_local_only() {
        let c = build(&[srv("a", "203.0.113.5")], &opts()).unwrap();
        assert_eq!(c["experimental"]["clash_api"]["external_controller"], "127.0.0.1:9090");
        assert_eq!(c["experimental"]["clash_api"]["secret"], "s3");
        assert_eq!(c["inbounds"][0]["listen"], "127.0.0.1");
        assert!(build(&[], &opts()).is_err());
    }

    #[test]
    fn tun_mode_has_tun_inbound_dns_hijack_and_fakeip() {
        let mut o = opts();
        o.tun = true;
        let c = build(&[srv("a", "203.0.113.5")], &o).unwrap();
        assert_eq!(c["inbounds"][0]["type"], "tun");
        assert_eq!(c["inbounds"][0]["address"].as_array().unwrap().len(), 2);
        assert_eq!(c["inbounds"][0]["strict_route"], true);
        assert_eq!(c["route"]["auto_detect_interface"], true);
        let rules = c["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["protocol"] == "dns" && r["action"] == "hijack-dns"));
        let servers = c["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().any(|s| s["type"] == "fakeip"));
        let dns_rules = c["dns"]["rules"].as_array().unwrap();
        // RU-правило обязано стоять раньше fakeip, иначе RU-домены получат фиктивный адрес
        let ru = dns_rules.iter().position(|r| r.get("domain_suffix").is_some()).unwrap();
        let fk = dns_rules.iter().position(|r| r["server"] == "fakeip").unwrap();
        assert!(ru < fk);
    }

    #[test]
    fn proxy_mode_has_no_tun_artifacts() {
        let c = build(&[srv("a", "203.0.113.5")], &opts()).unwrap();
        assert_eq!(c["inbounds"][0]["type"], "mixed");
        assert!(c["route"].get("auto_detect_interface").is_none());
        assert!(c["dns"]["servers"].as_array().unwrap().iter().all(|s| s["type"] != "fakeip"));
        assert!(c["route"]["rules"].as_array().unwrap().iter().all(|r| r["protocol"] != "dns"));
    }

    #[test]
    fn tun_without_ipv6_has_only_v4_address_and_range() {
        let mut o = opts();
        o.tun = true;
        o.ipv6 = false;
        let c = build(&[srv("a", "203.0.113.5")], &o).unwrap();
        assert_eq!(c["inbounds"][0]["address"], json!(["172.19.0.1/30"]));
        let fake = c["dns"]["servers"].as_array().unwrap().iter().find(|s| s["type"] == "fakeip").unwrap();
        assert!(fake.get("inet6_range").is_none());
    }

    #[test]
    fn strict_route_follows_option() {
        let mut o = opts();
        o.tun = true;
        o.strict_route = false;
        let c = build(&[srv("a", "203.0.113.5")], &o).unwrap();
        assert_eq!(c["inbounds"][0]["strict_route"], false);
        o.strict_route = true;
        let c = build(&[srv("a", "203.0.113.5")], &o).unwrap();
        assert_eq!(c["inbounds"][0]["strict_route"], true);
    }

    fn cats() -> Vec<Category> {
        crate::client::categories::builtin()
    }
    fn probes(n: usize) -> Vec<ProbePort> {
        let mut v: Vec<ProbePort> = (0..n).map(|i| ProbePort { tag: server_tag(i), port: 30001 + i as u16 }).collect();
        v.push(ProbePort { tag: "direct".into(), port: 30000 });
        v
    }
    fn two() -> [Server; 2] {
        [srv("a", "203.0.113.5"), srv("b", "198.51.100.7")]
    }

    #[test]
    fn categories_get_selectors_and_rules_only_with_multiple_servers() {
        let mut o = opts();
        o.categories = cats();
        let c = build(&two(), &o).unwrap();
        let sel = tag(&c, "cat-video");
        assert_eq!(sel["type"], "selector");
        assert_eq!(sel["default"], "proxy");
        assert_eq!(sel["outbounds"], json!(["proxy", "srv-1", "srv-2", "direct"]));
        let rules = c["route"]["rules"].as_array().unwrap();
        let r = rules.iter().find(|r| r["outbound"] == "cat-video").unwrap();
        assert!(r["domain_suffix"].as_array().unwrap().contains(&json!("youtube.com")));
        // единственный сервер: переключать некуда, переключателей нет
        let c = build(&[srv("a", "203.0.113.5")], &o).unwrap();
        assert!(c["outbounds"].as_array().unwrap().iter().all(|x| !x["tag"].as_str().unwrap().starts_with("cat-")));
    }

    #[test]
    fn disabled_category_has_no_selector_or_rule() {
        let mut o = opts();
        o.categories = cats();
        o.categories[0].enabled = false;
        let id = o.categories[0].id.clone();
        let c = build(&two(), &o).unwrap();
        assert!(c["outbounds"].as_array().unwrap().iter().all(|x| x["tag"] != format!("cat-{id}")));
        assert!(c["route"]["rules"].as_array().unwrap().iter().all(|r| r["outbound"] != format!("cat-{id}")));
    }

    #[test]
    fn category_rules_come_after_direct_rules_so_ru_traffic_stays_direct() {
        let mut o = opts();
        o.categories = cats();
        let c = build(&two(), &o).unwrap();
        let rules = c["route"]["rules"].as_array().unwrap();
        let ru = rules.iter().position(|r| r["outbound"] == "direct" && r.get("domain_suffix").is_some()).unwrap();
        let cat = rules.iter().position(|r| r["outbound"] == "cat-video").unwrap();
        assert!(ru < cat);
    }

    #[test]
    fn probe_inbounds_are_local_password_protected_and_pinned_to_their_outbound_first() {
        let mut o = opts();
        o.probe_ports = probes(2);
        let c = build(&two(), &o).unwrap();
        let ins = c["inbounds"].as_array().unwrap();
        assert_eq!(ins.len(), 4, "основной вход, два сервера и direct");
        for i in &ins[1..] {
            assert_eq!(i["listen"], "127.0.0.1");
            assert_eq!(i["users"][0]["username"], PROBE_USER);
            assert_eq!(i["users"][0]["password"], "s3", "пароль = секрет Clash API");
        }
        let rules = c["route"]["rules"].as_array().unwrap();
        // правила проб идут самыми первыми, раньше sniff и всех остальных
        assert_eq!(rules[0], json!({ "inbound": ["probe-srv-1"], "outbound": "srv-1" }));
        assert_eq!(rules[1], json!({ "inbound": ["probe-srv-2"], "outbound": "srv-2" }));
        assert_eq!(rules[2], json!({ "inbound": ["probe-direct"], "outbound": "direct" }));
        assert_eq!(rules[3], json!({ "action": "sniff" }));
    }

    #[test]
    fn probe_port_for_unknown_outbound_is_rejected() {
        let mut o = opts();
        o.probe_ports = vec![ProbePort { tag: "srv-9".into(), port: 30009 }];
        assert!(build(&two(), &o).is_err());
        o.probe_ports = vec![ProbePort { tag: "x\"y".into(), port: 30009 }];
        assert!(build(&two(), &o).is_err());
    }

    #[test]
    fn without_probes_config_is_unchanged_in_shape() {
        let c = build(&two(), &opts()).unwrap();
        assert_eq!(c["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(c["route"]["rules"][0], json!({ "action": "sniff" }));
    }

    /// Настоящая проверка ядром: SING_BOX=/путь/к/sing-box cargo test singbox_accepts
    #[test]
    fn singbox_accepts_generated_configs() {
        let Ok(bin) = std::env::var("SING_BOX") else { return };
        let dir = std::env::temp_dir().join(format!("el-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, tun, ru) in [("proxy", false, RuDirect::Minimal), ("tun", true, RuDirect::Minimal), ("rulesets", false, RuDirect::RuleSets)] {
            let mut o = opts();
            o.categories = cats();
            o.probe_ports = probes(2);
            o.tun = tun;
            o.ru_direct = ru;
            let valid = |mut s: Server| {
                s.public_key = Some("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into());
                s.short_id = Some("abcd1234".into());
                s
            };
            let [a, b] = two();
            let c = build(&[valid(a), valid(b)], &o).unwrap();
            let path = dir.join(format!("{name}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
            let out = std::process::Command::new(&bin).args(["check", "-c"]).arg(&path).output().unwrap();
            assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
        }
    }

    fn hy2() -> Server {
        Server {
            ws_path: None, origin: None, via: None, username: None, profile: None,
            name: "h".into(), host: "203.0.113.5".into(), port: 443, uuid: String::new(), kind: Kind::Hysteria2,
            password: Some("pw".into()), method: None, pin: Some("13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo=".into()),
            flow: None, security: "tls".into(), sni: "www.bing.com".into(), fingerprint: "chrome".into(), public_key: None, short_id: None,
        }
    }

    #[test]
    fn quic_and_ss_outbounds_come_from_profile_templates() {
        let tuic = Server { kind: Kind::Tuic, uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(), ..hy2() };
        let ss = Server { kind: Kind::Ss2022, method: Some("2022-blake3-aes-128-gcm".into()), pin: None, password: Some("K:U".into()), ..hy2() };
        let c = build(&[hy2(), tuic, ss], &opts()).unwrap();
        let h = tag(&c, "srv-1");
        assert_eq!((h["type"].clone(), h["server_port"].clone(), h["password"].clone()), (json!("hysteria2"), json!(443), json!("pw")));
        assert_eq!(h["tls"]["certificate_public_key_sha256"], json!(["13ULBbir1nqlPWjgHnT6DCikyTLepLk031sjzQ7GiGo="]));
        assert_eq!(h["tls"]["server_name"], "www.bing.com");
        let t = tag(&c, "srv-2");
        assert_eq!((t["type"].clone(), t["uuid"].clone(), t["congestion_control"].clone()), (json!("tuic"), json!("a158cda3-0b3d-424b-a8f8-26a6462c8349"), json!("bbr")));
        let s = tag(&c, "srv-3");
        assert_eq!((s["type"].clone(), s["method"].clone(), s["password"].clone()), (json!("shadowsocks"), json!("2022-blake3-aes-128-gcm"), json!("K:U")));
        assert!(s.get("tls").is_none());
        assert_eq!(tag(&c, "auto")["outbounds"], json!(["srv-1", "srv-2", "srv-3"]));
    }

    #[test]
    fn unpinned_quic_server_has_no_pin_field_and_domain_gets_resolver() {
        let s = Server { pin: None, host: "vpn.example.com".into(), ..hy2() };
        let c = build(&[s], &opts()).unwrap();
        let o = tag(&c, "srv-1");
        assert!(o["tls"].get("certificate_public_key_sha256").is_none());
        assert_eq!(o["domain_resolver"], "local");
    }

    #[test]
    fn cdn_outbound_is_vless_over_ws_tls_with_domain_resolver() {
        let st = {
            let mut s = hy2();
            s.kind = Kind::VlessWs;
            s.host = "cdn.example.com".into();
            s.sni = "cdn.example.com".into();
            s.port = 443;
            s.uuid = "a158cda3-0b3d-424b-a8f8-26a6462c8349".into();
            s.password = None;
            s.pin = None;
            s.ws_path = Some("/a1b2".into());
            s.origin = Some("203.0.113.5".into());
            s
        };
        let c = build(&[st], &opts()).unwrap();
        let o = tag(&c, "srv-1");
        assert_eq!((o["type"].clone(), o["server"].clone(), o["server_port"].clone()), (json!("vless"), json!("cdn.example.com"), json!(443)));
        assert_eq!(o["transport"]["path"], "/a1b2");
        assert_eq!(o["transport"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(o["domain_resolver"], "local");
    }

    fn exit(via: &str) -> Server {
        Server {
            ws_path: None, origin: None, via: Some(via.into()), username: Some("u1".into()), profile: None,
            name: "exit".into(), host: "198.51.100.7".into(), port: 1080, uuid: String::new(), kind: Kind::Socks5,
            password: Some("p1".into()), method: None, pin: None, flow: None, security: "none".into(),
            sni: String::new(), fingerprint: "chrome".into(), public_key: None, short_id: None,
        }
    }

    #[test]
    fn external_exit_is_chained_through_its_entry_server_and_never_default() {
        let c = build(&[hy2(), exit("h")], &opts()).unwrap();
        let x = tag(&c, "srv-2");
        assert_eq!((x["type"].clone(), x["server"].clone(), x["server_port"].clone(), x["version"].clone()), (json!("socks"), json!("198.51.100.7"), json!(1080), json!("5")));
        assert_eq!((x["username"].clone(), x["password"].clone(), x["detour"].clone()), (json!("u1"), json!("p1"), json!("srv-1")), "цепочка идёт через свой сервер");
        assert!(x.get("domain_resolver").is_none(), "имя не разрешается: адрес только IP");
        let proxy = tag(&c, "proxy");
        assert!(!proxy["outbounds"].as_array().unwrap().iter().any(|t| t == "srv-2"), "общий переключатель внешний exit не содержит");
        assert_eq!(proxy["default"], "auto");
        assert_eq!(tag(&c, "auto")["outbounds"], json!(["srv-1"]), "автовыбор тоже");
    }

    #[test]
    fn external_exit_is_available_to_category_selectors_only() {
        let mut o = opts();
        o.categories = vec![Category { id: "video".into(), title: "v".into(), domains: vec!["video.example".into()], probe_url: "https://video.example/".into(), enabled: true }];
        let c = build(&[hy2(), exit("h")], &o).unwrap();
        let sel = tag(&c, "cat-video");
        assert!(sel["outbounds"].as_array().unwrap().iter().any(|t| t == "srv-2"));
        assert_eq!(sel["default"], "proxy", "по умолчанию категория идёт как весь трафик, не через внешний exit");
    }

    #[test]
    fn broken_chains_are_refused() {
        // нет входного сервера
        assert!(build(&[hy2(), exit("nope")], &opts()).is_err());
        // цепочка из двух внешних exit
        let mut second = exit("exit");
        second.name = "exit2".into();
        assert!(build(&[hy2(), exit("h"), second], &opts()).is_err());
        // только внешние exit
        let mut lone = exit("exit");
        lone.name = "h".into();
        assert!(build(&[lone], &opts()).is_err());
        // внешний exit как основной сервер
        let mut o = opts();
        o.selected = Some("exit".into());
        assert!(build(&[hy2(), exit("h")], &o).is_err());
    }
}
