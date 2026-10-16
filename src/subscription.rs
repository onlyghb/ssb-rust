use crate::{
    link::{self, base, csv, nonempty, number, put, string, transport, Node, Tls},
    profile::Userinfo,
};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};

#[derive(Debug)]
pub struct SubscriptionResult {
    pub nodes: Vec<Node>,
    pub format: String,
    pub userinfo: Option<Userinfo>,
    pub warnings: Vec<String>,
}

pub fn fetch(url: &str) -> Result<SubscriptionResult> {
    let parsed = url::Url::parse(url).context("订阅 URL 无效")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("订阅仅支持 HTTP/HTTPS");
    }
    let client = Client::builder().timeout(Duration::from_secs(20)).build()?;
    let mut last = anyhow::anyhow!("订阅内容为空");
    let mut userinfo = None;
    for ua in [
        "sing-box/1.14.0 (ssb; SFA compatible)",
        "clash.meta/1.19.0 mihomo (ssb)",
        "v2rayN/7.0 (ssb)",
    ] {
        let attempt = (|| -> Result<SubscriptionResult> {
            let resp = client
                .get(url)
                .header("User-Agent", ua)
                .send()?
                .error_for_status()?;
            if let Some(h) = resp
                .headers()
                .get("subscription-userinfo")
                .and_then(|h| h.to_str().ok())
            {
                userinfo = parse_userinfo(h);
            }
            let mut bytes = Vec::new();
            resp.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                bail!("订阅超过 16 MiB 限制");
            }
            let mut result =
                parse_body(std::str::from_utf8(&bytes).context("订阅不是 UTF-8 文本")?)?;
            result.userinfo = userinfo.clone();
            Ok(result)
        })();
        match attempt {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(last.context("订阅获取失败"))
}

pub fn parse_body(body: &str) -> Result<SubscriptionResult> {
    let text = body.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        bail!("内容为空");
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some(outbounds) = v["outbounds"].as_array() {
            let nodes: Vec<Node> = outbounds
                .iter()
                .filter(|o| {
                    let typ = string(o, "type");
                    !typ.is_empty()
                        && !string(o, "tag").is_empty()
                        && !["selector", "urltest", "direct", "block", "dns"]
                            .contains(&typ.as_str())
                })
                .map(|o| Node {
                    tag: string(o, "tag"),
                    raw: String::new(),
                    outbound: o.clone(),
                })
                .collect();
            if !nodes.is_empty() {
                return Ok(SubscriptionResult {
                    nodes,
                    format: "sing-box".into(),
                    userinfo: None,
                    warnings: vec![],
                });
            }
        }
    }
    if text.contains("proxies:") || text.contains("\"proxies\"") {
        if let Ok(v) = serde_yaml::from_str::<Value>(text) {
            if let Some(proxies) = v["proxies"].as_array() {
                let mut nodes = vec![];
                let mut warnings = vec![];
                for p in proxies {
                    match convert_clash(p) {
                        Ok(n) => nodes.push(n),
                        Err(e) => warnings.push(format!("{}: {e}", string(p, "name"))),
                    }
                }
                if !nodes.is_empty() {
                    return Ok(SubscriptionResult {
                        nodes,
                        format: "clash".into(),
                        userinfo: None,
                        warnings,
                    });
                }
            }
        }
    }
    let (nodes, warnings) = link::parse_mixed(text);
    if nodes.is_empty() {
        bail!("无法识别订阅格式（sing-box JSON / Clash YAML / base64 或明文链接列表）");
    }
    Ok(SubscriptionResult {
        nodes,
        format: "base64/uri".into(),
        userinfo: None,
        warnings,
    })
}

fn boolean(p: &Value, k: &str) -> bool {
    p[k] == true || matches!(string(p, k).as_str(), "true" | "1")
}
fn strings(p: &Value, k: &str) -> Vec<String> {
    p[k].as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_else(|| csv(&string(p, k)))
}
fn clash_tls(p: &Value, server: &str) -> Tls {
    Tls {
        sni: nonempty(string(p, "servername"), &nonempty(string(p, "sni"), server)),
        insecure: boolean(p, "skip-cert-verify"),
        alpn: strings(p, "alpn"),
        fp: string(p, "client-fingerprint"),
        ..Tls::default()
    }
}
fn clash_number(p: &Value, key: &str) -> i64 {
    p[key]
        .as_f64()
        .map(|v| v as i64)
        .unwrap_or_else(|| number(p, key))
}
pub fn convert_clash(p: &Value) -> Result<Node> {
    let typ = string(p, "type");
    let tag = string(p, "name");
    let server = string(p, "server");
    let port = u16::try_from(clash_number(p, "port"))
        .ok()
        .filter(|p| *p > 0)
        .context("缺少 server/port 或端口无效")?;
    if server.is_empty() {
        bail!("缺少 server");
    }
    let mut o = base(
        if typ == "ss" { "shadowsocks" } else { &typ },
        &tag,
        &server,
        port,
    );
    match typ.as_str() {
        "ss" => {
            o["method"] = string(p, "cipher").into();
            o["password"] = string(p, "password").into();
            let opts = &p["plugin-opts"];
            let plugin = string(p, "plugin");
            let mut parts = vec![];
            match plugin.as_str() {
                "obfs" => {
                    o["plugin"] = "obfs-local".into();
                    parts.push(format!("obfs={}", string(opts, "mode")));
                    if !string(opts, "host").is_empty() {
                        parts.push(format!("obfs-host={}", string(opts, "host")));
                    }
                }
                "v2ray-plugin" => {
                    o["plugin"] = plugin.into();
                    if boolean(opts, "tls") {
                        parts.push("tls".into());
                    }
                    for k in ["host", "path"] {
                        if !string(opts, k).is_empty() {
                            parts.push(format!("{k}={}", string(opts, k)));
                        }
                    }
                }
                _ => {}
            }
            put(&mut o, "plugin_opts", parts.join(";"));
        }
        "vmess" | "vless" => {
            o["uuid"] = string(p, "uuid").into();
            if typ == "vmess" {
                o["security"] = nonempty(string(p, "cipher"), "auto").into();
                o["alter_id"] = clash_number(p, "alterId").into();
            } else {
                put(&mut o, "flow", string(p, "flow"));
            }
            let reality = &p["reality-opts"];
            if boolean(p, "tls") || (typ == "vless" && reality.is_object()) {
                let mut tls = clash_tls(p, &server);
                if typ == "vless" && reality.is_object() {
                    tls.public_key = string(reality, "public-key");
                    tls.short_id = string(reality, "short-id");
                    tls.fp = nonempty(tls.fp, "chrome");
                }
                o["tls"] = tls.build();
            }
        }
        "trojan" | "anytls" => {
            o["password"] = string(p, "password").into();
            o["tls"] = clash_tls(p, &server).build();
        }
        "hysteria2" | "tuic" => {
            if typ == "hysteria2" {
                o["password"] = nonempty(string(p, "password"), &string(p, "auth")).into();
                let obfs = string(p, "obfs");
                if !obfs.is_empty() && obfs != "none" {
                    o["obfs"] = json!({"type":obfs,"password":string(p,"obfs-password")});
                }
                let ports = string(p, "ports");
                if !ports.is_empty() {
                    o["server_ports"] = json!(link::port_ranges(&ports));
                }
            } else {
                o["uuid"] = string(p, "uuid").into();
                put(&mut o, "password", string(p, "password"));
                put(
                    &mut o,
                    "congestion_control",
                    nonempty(
                        string(p, "congestion-controller"),
                        &string(p, "congestion-control"),
                    ),
                );
                put(&mut o, "udp_relay_mode", string(p, "udp-relay-mode"));
            }
            let mut tls = clash_tls(p, &server);
            if tls.alpn.is_empty() {
                tls.alpn = vec!["h3".into()];
            }
            o["tls"] = tls.build();
        }
        _ => bail!("暂不支持的 Clash 代理类型 {typ}"),
    }
    if matches!(typ.as_str(), "vmess" | "vless" | "trojan") {
        let net = string(p, "network");
        let opts = &p[format!("{net}-opts")];
        let host = if net == "h2" {
            strings(opts, "host").first().cloned().unwrap_or_default()
        } else {
            nonempty(
                string(&opts["headers"], "Host"),
                &string(&opts["headers"], "host"),
            )
        };
        put(
            &mut o,
            "transport",
            transport(
                &net,
                &string(opts, "path"),
                &host,
                &string(opts, "grpc-service-name"),
            ),
        );
    }
    Ok(Node {
        tag,
        raw: String::new(),
        outbound: o,
    })
}

pub fn parse_userinfo(header: &str) -> Option<Userinfo> {
    if header.trim().is_empty() {
        return None;
    }
    let mut u = Userinfo::default();
    for part in header.split(';') {
        if let Some((key, value)) = part.trim().split_once('=') {
            if let Ok(n) = value.trim().parse::<i64>() {
                match key.trim().to_lowercase().as_str() {
                    "upload" => u.upload = n,
                    "download" => u.download = n,
                    "total" => u.total = n,
                    "expire" => u.expire = n,
                    _ => {}
                }
            }
        }
    }
    Some(u)
}
pub fn human_bytes(n: i64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let mut n = n as f64;
    let mut unit = "B";
    for u in ["KB", "MB", "GB", "TB", "PB", "EB"] {
        n /= 1024.;
        unit = u;
        if n < 1024. {
            break;
        }
    }
    format!("{n:.1} {unit}")
}
