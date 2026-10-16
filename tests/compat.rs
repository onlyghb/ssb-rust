use base64::{engine::general_purpose as b64, Engine};
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use ssb::platform;
use ssb::{
    link,
    profile::{self, Dirs, State},
    render, subscription,
};

fn node(raw: &str) -> Value {
    link::parse(raw).unwrap().outbound
}

#[test]
fn vless_reality_and_websocket_match_upstream_examples() {
    let n = link::parse("vless://5e3da52a-2d69-4e5e-b7ef-1e0e7a2e8b9c@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179&type=tcp#我的VLESS").unwrap();
    assert_eq!(n.tag, "我的VLESS");
    assert_eq!(
        n.outbound,
        json!({"type":"vless","tag":"我的VLESS","server":"1.2.3.4","server_port":443,"uuid":"5e3da52a-2d69-4e5e-b7ef-1e0e7a2e8b9c","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"www.apple.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","short_id":"6ba85179"}}})
    );
    let ws = node("vless://uuid-1@example.com:8443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&alpn=h2,http/1.1#ws节点");
    assert_eq!(
        ws["transport"],
        json!({"type":"ws","path":"/ws","max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol","headers":{"Host":"cdn.example.com"}})
    );
    assert_eq!(ws["tls"]["alpn"], json!(["h2", "http/1.1"]));
}
#[test]
fn anytls_trojan_hysteria_and_tuic() {
    let a = node("anytls://p%40ss@5.6.7.8:8443/?sni=example.org&insecure=1&fp=chrome#AnyTLS-1");
    assert_eq!(a["password"], "p@ss");
    assert_eq!(a["tls"]["insecure"], true);
    assert_eq!(a["tls"]["server_name"], "example.org");
    let t = node("trojan://pw123@7.7.7.7:443?security=tls&sni=t.example.com&type=grpc&serviceName=grpcSvc&fp=safari#tj");
    assert_eq!(
        t["transport"],
        json!({"type":"grpc","service_name":"grpcSvc"})
    );
    assert_eq!(t["password"], "pw123");
    let h = node("hy2://letmein@8.8.4.4:36712/?insecure=1&obfs=salamander&obfs-password=obfspw&sni=hy.example.com&mport=443,2000-3000&hop-interval=10#hy2节点");
    assert_eq!(h["type"], "hysteria2");
    assert_eq!(h["server_ports"], json!(["443:443", "2000:3000"]));
    assert_eq!(h["hop_interval"], "10s");
    assert_eq!(h["tls"]["alpn"], json!(["h3"]));
    assert_eq!(h["obfs"]["password"], "obfspw");
    let u = node("tuic://uuid-x:pass-y@6.6.6.6:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tu.example.com#tuic1");
    assert_eq!(u["uuid"], "uuid-x");
    assert_eq!(u["password"], "pass-y");
    assert_eq!(u["congestion_control"], "bbr");
}
#[test]
fn shadowsocks_all_three_encodings() {
    let ui = b64::URL_SAFE_NO_PAD.encode("aes-256-gcm:test1234");
    let sip = node(&format!("ss://{ui}@9.9.9.9:8388#ss1"));
    assert_eq!(sip["method"], "aes-256-gcm");
    assert_eq!(sip["password"], "test1234");
    let modern = node("ss://2022-blake3-aes-256-gcm:aGVsbG8lMjB3b3JsZA%3D%3D@9.9.9.9:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ss2022");
    assert_eq!(modern["password"], "aGVsbG8lMjB3b3JsZA==");
    assert_eq!(modern["plugin_opts"], "obfs=http;obfs-host=example.com");
    let legacy = node(&format!(
        "ss://{}#legacy%20node",
        b64::STANDARD.encode("rc4-md5:passwd@3.3.3.3:1234")
    ));
    assert_eq!(legacy["tag"], "legacy node");
    assert_eq!(legacy["server_port"], 1234);
}
#[test]
fn vmess_string_and_numeric_fields() {
    for port in [json!(443), json!("443")] {
        let v = json!({"ps":"vm节点","add":"vm.example.com","port":port,"id":"uuid","aid":"0","scy":"auto","net":"ws","path":"/vmws","tls":"tls","sni":"vm.example.com"});
        let n = node(&format!("vmess://{}", b64::STANDARD.encode(v.to_string())));
        assert_eq!(n["server_port"], 443);
        assert_eq!(n["alter_id"], 0);
        assert_eq!(n["transport"]["path"], "/vmws");
    }
}
#[test]
fn malformed_links_are_errors_and_mixed_lists_keep_valid_nodes() {
    for raw in [
        "wireguard://x@1.2.3.4:51820",
        "vless://u@example.com",
        "vless://u@example.com:0",
        "trojan://pw@example.com:70000",
        "vmess://garbage",
        "ss://garbage",
        "vless://example.com:443",
    ] {
        assert!(link::parse(raw).is_err(), "{raw}");
    }
    let (nodes, errors) =
        link::parse_mixed("# comment\nssh://root@1.2.3.4:22\ntrojan://pw@1.1.1.1:443#ok");
    assert_eq!(nodes.len(), 1);
    assert_eq!(errors.len(), 1);
    let (nodes, errors) = link::parse_mixed(
        &b64::STANDARD.encode("trojan://pw@1.1.1.1:443#t1\nvless://u@2.2.2.2:443#t2"),
    );
    assert_eq!(nodes.len(), 2);
    assert!(errors.is_empty());
}
#[test]
fn repeated_parameters_and_clash_numeric_ports_match_go() {
    let n = node("trojan://p@example.com:443?sni=first.test&sni=second.test&insecure=0&insecure=1");
    assert_eq!(n["tls"]["server_name"], "first.test");
    assert!(n["tls"].get("insecure").is_none());
    let n = subscription::convert_clash(&json!({"name":"numeric","type":"vmess","server":"example.com","port":443.0,"uuid":"u","alterId":0.0})).unwrap();
    assert_eq!(n.outbound["server_port"], 443);
    assert_eq!(n.outbound["alter_id"], 0);
}
#[test]
fn percent_escaped_credentials_fragments_and_ipv6_hosts() {
    let n = node("trojan://p%3Ass%40word@[2001:db8::1]:443#%E9%A6%99%E6%B8%AF%201");
    assert_eq!(n["server"], "2001:db8::1");
    assert_eq!(n["password"], "p:ss@word");
    assert_eq!(n["tag"], "香港 1");
}
#[test]
fn singbox_subscription_keeps_unknown_fields_and_filters_groups() {
    let r = subscription::parse_body(r#"{"outbounds":[{"type":"selector","tag":"PROXY"},{"type":"direct","tag":"direct"},{"type":"vless","tag":"sg-01","server":"sg.example.com","server_port":443,"uuid":"9999","custom":{"future":42}}]}"#).unwrap();
    assert_eq!(r.format, "sing-box");
    assert_eq!(r.nodes.len(), 1);
    assert_eq!(r.nodes[0].outbound["custom"]["future"], 42);
}
#[test]
fn clash_subscription_supports_all_protocols_and_skips_unknown() {
    let proxies = json!({"proxies":[
        {"name":"v","type":"vless","server":"a.test","port":443,"uuid":"u","tls":true,"flow":"xtls-rprx-vision","reality-opts":{"public-key":"pbk","short-id":"abcd"},"network":"ws","ws-opts":{"path":"/ws","headers":{"Host":"cdn.test"}}},
        {"name":"vm","type":"vmess","server":"a.test","port":"443","uuid":"u","alterId":0,"network":"grpc","grpc-opts":{"grpc-service-name":"service"}},
        {"name":"t","type":"trojan","server":"a.test","port":443,"password":"p"},
        {"name":"a","type":"anytls","server":"a.test","port":443,"password":"p","skip-cert-verify":true},
        {"name":"s","type":"ss","server":"a.test","port":443,"cipher":"aes-256-gcm","password":"p","plugin":"obfs","plugin-opts":{"mode":"http","host":"obfs.test"}},
        {"name":"h","type":"hysteria2","server":"a.test","port":443,"password":"p","obfs":"salamander","obfs-password":"ob","ports":"1000-2000"},
        {"name":"u","type":"tuic","server":"a.test","port":443,"uuid":"u","password":"p","congestion-controller":"bbr"},
        {"name":"bad","type":"unsupported","server":"a.test","port":443}
    ]});
    let r = subscription::parse_body(&serde_yaml::to_string(&proxies).unwrap()).unwrap();
    assert_eq!(r.format, "clash");
    assert_eq!(r.nodes.len(), 7);
    assert_eq!(r.warnings.len(), 1);
    assert_eq!(r.nodes[0].outbound["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(
        r.nodes[0].outbound["transport"]["headers"]["Host"],
        "cdn.test"
    );
    assert_eq!(r.nodes[1].outbound["transport"]["service_name"], "service");
    assert_eq!(
        r.nodes[4].outbound["plugin_opts"],
        "obfs=http;obfs-host=obfs.test"
    );
    assert_eq!(r.nodes[5].outbound["server_ports"], json!(["1000:2000"]));
}
#[test]
fn go_state_null_arrays_empty_defaults_and_false_booleans_migrate() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Dirs::new(tmp.path()).unwrap();
    d.ensure().unwrap();
    std::fs::write(d.state(),r#"{"subscriptions":null,"manual_nodes":null,"settings":{"route_mode":"","mixed_port":0,"api_secret":"","tun_enabled":false,"fakeip":false,"dashboard_off":false,"custom_proxy":null}}"#).unwrap();
    let st = State::load(&d).unwrap();
    assert!(st.subscriptions.is_empty());
    assert_eq!(st.settings.route_mode, "rule");
    assert_eq!(st.settings.mixed_port, 2080);
    assert!(!st.settings.tun_enabled);
    assert!(!st.settings.fakeip);
    assert!(!st.settings.dashboard_off);
    assert_eq!(st.settings.api_secret.len(), 24);
    st.save(&d).unwrap();
    let restored = State::load(&d).unwrap();
    assert_eq!(restored.settings.api_secret, st.settings.api_secret);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(d.state()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn duplicate_tags_and_reserved_tags_never_collide_or_mutate_state() {
    let mut st = State::default();
    for tag in ["x", "x #2", "x", "PROXY", "auto", "direct"] {
        st.manual_nodes
            .push(link::parse(&format!("trojan://p@a.test:443#{tag}")).unwrap());
    }
    let original = serde_json::to_value(&st).unwrap();
    let nodes = st.all_nodes();
    let tags: std::collections::HashSet<_> = nodes.iter().map(|n| n.tag.as_str()).collect();
    assert_eq!(tags.len(), nodes.len());
    assert!(!tags.contains("PROXY"));
    assert_eq!(serde_json::to_value(&st).unwrap(), original);
}
#[test]
fn config_capabilities_matrix_covers_ipv6_modes_dashboard_and_routes() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Dirs::new(tmp.path()).unwrap();
    for host in [false, true] {
        for ipv6 in ["auto", "on", "off"] {
            for mode in ["rule", "global"] {
                for dashboard in [false, true] {
                    let mut st = State::default();
                    let s = &mut st.settings;
                    s.ipv6 = ipv6.into();
                    s.route_mode = mode.into();
                    s.dashboard_off = !dashboard;
                    s.auto_redirect = true;
                    let cfg = render::build_for(&st, &d, host, false).unwrap();
                    let v6 = ipv6 == "on" || (ipv6 == "auto" && host);
                    assert_eq!(
                        cfg["inbounds"][0]["address"].as_array().unwrap().len(),
                        if v6 { 2 } else { 1 }
                    );
                    assert_eq!(cfg["inbounds"][0]["strict_route"], v6);
                    assert!(cfg["inbounds"][0].get("auto_redirect").is_none());
                    assert_eq!(
                        cfg.get("http_clients").is_some(),
                        mode == "rule" || dashboard
                    );
                    assert_eq!(cfg["route"].get("rule_set").is_some(), mode == "rule");
                    assert!(cfg["experimental"].get("clash_api").is_none());
                    assert_eq!(cfg["services"][0]["type"], "api");
                    assert_eq!(cfg["services"][0].get("dashboard").is_some(), dashboard);
                    if !v6 {
                        assert_eq!(cfg["inbounds"][0]["route_address"], json!(["0.0.0.0/0"]));
                        assert_eq!(cfg["dns"]["rules"][0]["action"], "predefined");
                    }
                }
            }
        }
    }
}
#[test]
fn custom_routing_dns_priority_mirrors_and_explicit_download_detour() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Dirs::new(tmp.path()).unwrap();
    let mut st = State::default();
    let s = &mut st.settings;
    s.custom_proxy = vec!["a.com".into(), ".cn".into()];
    s.custom_direct = vec!["b.com".into()];
    s.ruleset_source = "github".into();
    s.mirror_prefix = "https://mirror.test/".into();
    s.download_detour = "PROXY".into();
    s.dashboard_off = false;
    let c = render::build_for(&st, &d, true, true).unwrap();
    assert_eq!(c["route"]["rules"][3]["domain"], json!(["a.com"]));
    assert_eq!(
        c["route"]["rules"][3]["domain_suffix"],
        json!([".a.com", ".cn"])
    );
    assert_eq!(c["dns"]["rules"][0]["server"], "dns-fakeip");
    assert_eq!(c["dns"]["rules"][0]["query_type"], json!(["A", "AAAA"]));
    assert_eq!(c["dns"]["rules"][1]["server"], "dns-proxy");
    assert!(c["dns"]["rules"][1].get("query_type").is_none());
    assert_eq!(c["dns"]["rules"][2]["server"], "dns-cn");
    assert!(c["route"]["rule_set"][0]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://mirror.test/https://raw.githubusercontent.com/"));
    assert_eq!(c["http_clients"][0]["detour"], "PROXY");
    st.settings.download_detour = "direct".into();
    st.settings.ruleset_source = "jsdelivr".into();
    let c = render::build_for(&st, &d, true, true).unwrap();
    assert!(c["http_clients"][0].get("detour").is_none());
    assert!(c["route"]["rule_set"][0]["url"]
        .as_str()
        .unwrap()
        .starts_with(render::RULESET_CDN));
}
#[test]
fn no_nodes_and_disabled_inbounds_still_have_working_direct_and_mixed() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Dirs::new(tmp.path()).unwrap();
    let mut st = State::default();
    st.settings.tun_enabled = false;
    st.settings.mixed_enabled = false;
    st.settings.fakeip = false;
    st.settings.route_mode = "global".into();
    st.settings.dns_proxy = "https://1.1.1.1:8443/custom-dns".into();
    let c = render::build_for(&st, &d, true, true).unwrap();
    assert_eq!(c["outbounds"][0]["outbounds"], json!(["direct"]));
    assert_eq!(c["inbounds"][0]["type"], "mixed");
    assert_eq!(c["dns"]["servers"][1]["server"], "1.1.1.1");
    assert_eq!(c["dns"]["servers"][1]["server_port"], 8443);
    assert_eq!(c["dns"]["servers"][1]["path"], "/custom-dns");
    assert!(c["dns"].get("rules").is_none());
    assert_eq!(c["dns"]["reverse_mapping"], true);
}
#[test]
fn settings_validation_is_transactional() {
    let mut s = profile::Settings::default();
    let original = serde_json::to_value(&s).unwrap();
    for (key, value) in [
        ("mixed_port", "0"),
        ("api_listen", "localhost:9090"),
        ("tun_address", "bad"),
        ("ipv6", "other"),
        ("custom_proxy", "https://example.com"),
        ("dns_cn", "https://223.5.5.5"),
        ("dns_proxy", "http://dns.example.com/dns-query"),
        ("dns_proxy", "https://user:pass@dns.example.com"),
        ("dns_proxy", "https://dns.example.com:0/dns-query"),
        ("dns_proxy", "https://dns.example.com/#fragment"),
    ] {
        assert!(profile::set_setting(&mut s, key, value).is_err());
        assert_eq!(serde_json::to_value(&s).unwrap(), original);
    }
    profile::set_setting(&mut s, "custom_proxy", "Example.COM，.cn; foo.test").unwrap();
    assert_eq!(s.custom_proxy, vec!["example.com", ".cn", "foo.test"]);
}
#[test]
fn doh_urls_keep_queries_normalize_ipv6_and_preserve_fakeip_types() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Dirs::new(tmp.path()).unwrap();
    let mut st = State::default();
    for (input, host, path) in [
        (
            "https://dns.example.com/?token=abc",
            "dns.example.com",
            Some("/?token=abc"),
        ),
        (
            "https://[2606:4700:4700::1111]:8443/dns-query",
            "2606:4700:4700::1111",
            Some("/dns-query"),
        ),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", None),
        ("dns.example.com", "dns.example.com", None),
    ] {
        profile::set_setting(&mut st.settings, "dns_proxy", input).unwrap();
        let config = render::build_for(&st, &d, false, true).unwrap();
        let dns = &config["dns"]["servers"][1];
        assert_eq!(dns["server"], host);
        assert_eq!(dns["path"].as_str(), path);
    }
    st.settings.custom_proxy = vec!["example.cn".into()];
    let config = render::build_for(&st, &d, false, true).unwrap();
    let rules = config["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["action"], "predefined"); // IPv6-off policy still wins.
    assert_eq!(rules[1]["server"], "dns-fakeip");
    assert_eq!(rules[1]["query_type"], json!(["A"]));
    assert_eq!(rules[2]["server"], "dns-proxy"); // TXT/MX/HTTPS keep forced-proxy DNS.
    assert_eq!(rules[2]["domain"], json!(["example.cn"]));
    assert!(config["dns"].get("reverse_mapping").is_none());
}
#[cfg(target_os = "linux")]
#[test]
fn ipv6_probe_handles_kernel_done_errors() {
    assert_eq!(
        platform::probe_result(3, &(-libc::EAFNOSUPPORT).to_ne_bytes()),
        0
    );
    assert_eq!(platform::probe_result(3, &0i32.to_ne_bytes()), 1);
    assert_eq!(platform::probe_result(3, &[]), 1);
    assert_eq!(platform::probe_result(2, &(-libc::EPERM).to_ne_bytes()), -1);
    assert_eq!(platform::probe_result(2, &[]), -1);
    assert_ne!(platform::ipv6_rule_supported(), -1, "本地 netlink 探测失败");
}
