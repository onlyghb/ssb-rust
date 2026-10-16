//! sing-box 1.14 configuration. Keep API services and explicit HTTP clients;
//! clash_api and implicit download clients are deliberately not used.
use crate::{
    platform,
    profile::{split_listen, Dirs, Settings, State},
};
use anyhow::Result;
use serde_json::{json, Value};

pub const DASHBOARD_URL: &str =
    "https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/gh-pages.zip";
pub const RULESET_CDN: &str =
    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/";
pub const RULESET_GITHUB: &str =
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/";

pub fn ruleset_source(s: &Settings) -> String {
    if s.route_mode == "global" {
        return "global 模式不使用规则集".into();
    }
    let mut text = if s.ruleset_source == "github" {
        "GitHub（raw.githubusercontent.com）"
    } else {
        "jsdelivr（testingcf.jsdelivr.net）"
    }
    .to_owned();
    if s.ruleset_source == "github" && !s.mirror_prefix.is_empty() {
        text.push_str(&format!("，镜像 {}", s.mirror_prefix));
    }
    text.push_str(if s.download_detour == "PROXY" {
        "，PROXY 出站"
    } else {
        "，直连"
    });
    text
}
fn custom_rule(domains: &[String], key: &str, value: &str) -> Value {
    let exact: Vec<&String> = domains.iter().filter(|d| !d.starts_with('.')).collect();
    let suffix: Vec<String> = domains
        .iter()
        .map(|d| {
            if d.starts_with('.') {
                d.clone()
            } else {
                format!(".{d}")
            }
        })
        .collect();
    let mut r = json!({key:value});
    if !exact.is_empty() {
        r["domain"] = json!(exact);
    }
    if !suffix.is_empty() {
        r["domain_suffix"] = json!(suffix);
    }
    r
}

pub fn build(st: &State, d: &Dirs) -> Result<Value> {
    build_for(st, d, platform::host_has_ipv6(), cfg!(target_os = "linux"))
}
// Explicit capabilities make config tests independent of the host and permit
// checking Windows output from Linux without changing process-global state.
pub fn build_for(st: &State, d: &Dirs, host_ipv6: bool, linux: bool) -> Result<Value> {
    let s = &st.settings;
    s.validate()?;
    let v6 = match s.ipv6.as_str() {
        "on" => true,
        "off" => false,
        _ => host_ipv6,
    };
    let nodes = st.all_nodes();
    let tags: Vec<&str> = nodes.iter().map(|n| n.tag.as_str()).collect();
    let mut members = vec![];
    if !nodes.is_empty() {
        members.push("auto");
    }
    members.extend(&tags);
    members.push("direct");
    let mut selector = json!({"type":"selector","tag":"PROXY","outbounds":members,"interrupt_exist_connections":true});
    if !nodes.is_empty() {
        selector["default"] = "auto".into();
    }
    let mut outbounds = vec![selector];
    if !nodes.is_empty() {
        outbounds.push(json!({"type":"urltest","tag":"auto","outbounds":tags,"url":"https://www.gstatic.com/generate_204","interval":"3m","tolerance":50}));
    }
    outbounds.push(json!({"type":"direct","tag":"direct"}));
    outbounds.extend(nodes.into_iter().map(|n| n.outbound));

    let mut dns_servers = vec![
        json!({"type":"udp","tag":"dns-cn","server":s.dns_cn}),
        proxy_dns(&s.dns_proxy)?,
    ];
    let mut dns_rules = vec![];
    if !v6 {
        dns_rules.push(json!({"query_type":["AAAA"],"action":"predefined","rcode":"NOERROR"}));
    }
    if !s.custom_proxy.is_empty() {
        let mut rule = custom_rule(
            &s.custom_proxy,
            "server",
            if s.fakeip { "dns-fakeip" } else { "dns-proxy" },
        );
        if s.fakeip {
            // FakeIP only answers address queries. Let TXT/MX/HTTPS use real DoH.
            rule["query_type"] = if v6 {
                json!(["A", "AAAA"])
            } else {
                json!(["A"])
            };
        }
        dns_rules.push(rule);
        if s.fakeip {
            dns_rules.push(custom_rule(&s.custom_proxy, "server", "dns-proxy"));
        }
    }
    if !s.custom_direct.is_empty() {
        dns_rules.push(custom_rule(&s.custom_direct, "server", "dns-cn"));
    }
    if s.route_mode != "global" {
        dns_rules.push(json!({"rule_set":"geosite-cn","server":"dns-cn"}));
    }
    if s.fakeip {
        let mut fake = json!({"type":"fakeip","tag":"dns-fakeip","inet4_range":"198.18.0.0/15"});
        let mut types = vec!["A"];
        if v6 {
            fake["inet6_range"] = "fc00::/18".into();
            types.push("AAAA");
        }
        dns_servers.push(fake);
        dns_rules.push(json!({"query_type":types,"server":"dns-fakeip"}));
    }
    let mut inbounds = vec![];
    if s.tun_enabled {
        let mut addresses = vec![s.tun_address.as_str()];
        if v6 {
            addresses.push("fdfe:dcba:9876::1/126");
        }
        let mut tun = json!({"type":"tun","tag":"tun-in","address":addresses,"mtu":9000,"auto_route":true,"strict_route":v6,"stack":"mixed"});
        if !v6 {
            tun["route_address"] = json!(["0.0.0.0/0"]);
        }
        if linux && s.auto_redirect {
            tun["auto_redirect"] = true.into();
        }
        inbounds.push(tun);
    }
    if s.mixed_enabled || !s.tun_enabled {
        inbounds.push(json!({"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":s.mixed_port}));
    }
    let mut rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
        json!({"ip_is_private":true,"outbound":"direct"}),
    ];
    if !s.custom_proxy.is_empty() {
        rules.push(custom_rule(&s.custom_proxy, "outbound", "PROXY"));
    }
    if !s.custom_direct.is_empty() {
        rules.push(custom_rule(&s.custom_direct, "outbound", "direct"));
    }
    let mut route = json!({"final":"PROXY","auto_detect_interface":true,"default_domain_resolver":{"server":"dns-cn"}});
    if s.route_mode != "global" {
        rules.push(json!({"rule_set":["geosite-cn"],"outbound":"direct"}));
        rules.push(json!({"rule_set":["geoip-cn"],"outbound":"direct"}));
        let base = if s.ruleset_source == "github" {
            format!("{}{RULESET_GITHUB}", s.mirror_prefix)
        } else {
            RULESET_CDN.into()
        };
        route["rule_set"] = json!([
            {"type":"remote","tag":"geosite-cn","format":"binary","url":format!("{base}geosite/cn.srs"),"http_client":"http-download","update_interval":"1d"},
            {"type":"remote","tag":"geoip-cn","format":"binary","url":format!("{base}geoip/cn.srs"),"http_client":"http-download","update_interval":"1d"}
        ]);
    }
    route["rules"] = json!(rules);
    let addr = split_listen(&s.api_listen)?;
    let mut api = json!({"type":"api","tag":"api","listen":addr.ip().to_string(),"listen_port":addr.port(),"secret":s.api_secret});
    if !s.dashboard_off {
        api["dashboard"] = json!({"enabled":true,"path":d.dashboard(),"download_url":format!("{}{DASHBOARD_URL}",s.mirror_prefix),"http_client":"http-download","update_interval":"1d"});
    }
    let mut config = json!({
        "log":{"level":s.log_level,"timestamp":true},
        "dns":{"servers":dns_servers,"final":"dns-proxy"},
        "inbounds":inbounds,"outbounds":outbounds,"route":route,"services":[api],
        "experimental":{"cache_file":{"enabled":true,"path":d.cache(),"store_fakeip":true,"store_dns":true}}
    });
    if !dns_rules.is_empty() {
        config["dns"]["rules"] = json!(dns_rules);
    }
    if !s.fakeip {
        config["dns"]["reverse_mapping"] = true.into();
    }
    if s.route_mode != "global" || !s.dashboard_off {
        let mut client = json!({"tag":"http-download"});
        if s.download_detour == "PROXY" {
            client["detour"] = "PROXY".into();
        }
        config["http_clients"] = json!([client]);
    }
    Ok(config)
}

fn proxy_dns(server: &str) -> Result<Value> {
    let u = crate::profile::proxy_dns_url(server)?;
    let host = match u.host().expect("validated DNS host") {
        url::Host::Ipv6(ip) => ip.to_string(),
        host => host.to_string(),
    };
    let mut v = json!({"type":"https","tag":"dns-proxy","server":host,"detour":"PROXY"});
    if let Some(port) = u.port() {
        v["server_port"] = port.into();
    }
    if u.path() != "/" || u.query().is_some() {
        v["path"] = if let Some(query) = u.query() {
            format!("{}?{query}", u.path())
        } else {
            u.path().into()
        }
        .into();
    }
    Ok(v)
}
