//! Генерация клиентского конфига sing-box по списку серверов.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::profile::Server;

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

pub const RU_SUFFIXES: [&str; 3] = [".ru", ".su", ".xn--p1ai"];

pub fn server_tag(index: usize) -> String {
    format!("srv-{}", index + 1)
}

fn outbound(tag: &str, s: &Server) -> Value {
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
    if s.host.parse::<std::net::IpAddr>().is_err() {
        o["domain_resolver"] = json!("local");
    }
    o
}

pub fn build(servers: &[Server], o: &ClientOpts) -> Result<Value> {
    if servers.is_empty() {
        bail!("нет серверов: добавь командой `eleutheria import <ссылка или подписка>`");
    }
    let tags: Vec<String> = (0..servers.len()).map(server_tag).collect();
    let mut outbounds: Vec<Value> = servers.iter().zip(&tags).map(|(s, t)| outbound(t, s)).collect();

    let multi = servers.len() > 1;
    let default = match &o.selected {
        Some(name) => {
            let i = servers
                .iter()
                .position(|s| &s.name == name)
                .ok_or_else(|| anyhow::anyhow!("сервера `{name}` нет в списке"))?;
            tags[i].clone()
        }
        None if multi => "auto".to_string(),
        None => tags[0].clone(),
    };
    let mut choices: Vec<String> = Vec::new();
    if multi {
        outbounds.push(json!({
            "type": "urltest", "tag": "auto", "outbounds": tags,
            "url": o.test_url, "interval": "3m", "tolerance": 50,
        }));
        choices.push("auto".into());
    }
    choices.extend(tags.iter().cloned());
    outbounds.push(json!({ "type": "selector", "tag": "proxy", "outbounds": choices, "default": default }));
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    // DNS: RU-домены через системный резолвер, остальное через DoH за прокси
    let mut dns_rules: Vec<Value> = Vec::new();
    let mut route_rules: Vec<Value> = vec![json!({ "action": "sniff" })];
    if o.tun {
        // весь DNS-трафик системы перехватывается и обслуживается встроенным DNS sing-box (без утечек)
        route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    route_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    let mut rule_sets: Vec<Value> = Vec::new();
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

    Ok(json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "remote",
        },
        "inbounds": [inbound],
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

    fn srv(name: &str, host: &str) -> Server {
        Server {
            name: name.into(), host: host.into(), port: 443,
            uuid: "a158cda3-0b3d-424b-a8f8-26a6462c8349".into(),
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
}
