//! Share links to sing-box outbound objects. Unknown outbound fields from JSON
//! subscriptions are kept verbatim by the subscription module.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose as b64, Engine};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    pub tag: String,
    pub raw: String,
    pub outbound: Value,
}

pub fn decode64(s: &str) -> Option<String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    [
        &b64::STANDARD,
        &b64::STANDARD_NO_PAD,
        &b64::URL_SAFE,
        &b64::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|engine| {
        engine
            .decode(&s)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    })
}
fn unescape(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}
pub fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}
pub fn string(v: &Value, k: &str) -> String {
    match &v[k] {
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) => v[k].to_string(),
        _ => String::new(),
    }
}
pub fn number(v: &Value, k: &str) -> i64 {
    v[k].as_i64()
        .unwrap_or_else(|| string(v, k).parse().unwrap_or_default())
}
pub fn put(o: &mut Value, k: &str, v: impl Into<Value>) {
    let v = v.into();
    if !v.is_null() && v != "" && v.as_array().is_none_or(|a| !a.is_empty()) {
        o[k] = v;
    }
}
pub fn base(typ: &str, tag: &str, server: &str, port: u16) -> Value {
    json!({"type":typ,"tag":tag,"server":server,"server_port":port})
}

#[derive(Default)]
pub struct Tls {
    pub sni: String,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub fp: String,
    pub public_key: String,
    pub short_id: String,
}
impl Tls {
    pub fn build(&self) -> Value {
        let mut t = json!({"enabled":true});
        put(&mut t, "server_name", self.sni.clone());
        if self.insecure {
            t["insecure"] = true.into();
        }
        put(&mut t, "alpn", json!(self.alpn));
        if !self.fp.is_empty() {
            t["utls"] = json!({"enabled":true,"fingerprint":self.fp});
        }
        if !self.public_key.is_empty() {
            t["reality"] =
                json!({"enabled":true,"public_key":self.public_key,"short_id":self.short_id});
        }
        t
    }
}

pub fn transport(net: &str, path: &str, host: &str, service: &str) -> Value {
    let mut t = json!({});
    match net {
        "ws" | "websocket" => {
            t["type"] = "ws".into();
            let (path, ed) = path
                .split_once("?ed=")
                .map(|(p, n)| {
                    (
                        p,
                        n.chars()
                            .take_while(char::is_ascii_digit)
                            .collect::<String>()
                            .parse::<u64>()
                            .unwrap_or_default(),
                    )
                })
                .unwrap_or((path, 0));
            put(&mut t, "path", path);
            if !host.is_empty() {
                t["headers"] = json!({"Host":host});
            }
            if ed > 0 {
                t["max_early_data"] = ed.into();
                t["early_data_header_name"] = "Sec-WebSocket-Protocol".into();
            }
        }
        "grpc" | "gun" => {
            t["type"] = "grpc".into();
            put(&mut t, "service_name", service);
        }
        "httpupgrade" => {
            t["type"] = "httpupgrade".into();
            put(&mut t, "path", path);
            put(&mut t, "host", host);
        }
        "http" | "h2" | "tcp-http" => {
            t["type"] = "http".into();
            put(&mut t, "path", path);
            if !host.is_empty() {
                t["host"] = json!([host]);
            }
        }
        _ => return Value::Null,
    }
    t
}

pub fn port_ranges(s: &str) -> Vec<String> {
    csv(s)
        .iter()
        .map(|p| {
            p.split_once('-')
                .map(|(a, b)| format!("{a}:{b}"))
                .unwrap_or_else(|| format!("{p}:{p}"))
        })
        .collect()
}

fn host_port(u: &Url) -> Result<(String, u16)> {
    let host = u
        .host_str()
        .context("缺少服务器地址")?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = u
        .port()
        .filter(|p| *p > 0)
        .context("缺少端口或端口无效（1–65535）")?;
    Ok((host, port))
}

pub fn parse(raw: &str) -> Result<Node> {
    let raw = raw.trim();
    let (scheme, body) = raw.split_once("://").context("不是分享链接")?;
    let scheme = scheme.to_ascii_lowercase();
    let mut node = match scheme.as_str() {
        "ss" => parse_ss(body)?,
        "vmess" => parse_vmess(body)?,
        "vless" | "anytls" | "trojan" | "hysteria2" | "hy2" | "tuic" => {
            let u = Url::parse(raw).context("链接格式错误")?;
            let (host, port) = host_port(&u)?;
            let tag = unescape(u.fragment().unwrap_or_default()).trim().to_owned();
            let typ = if scheme == "hy2" {
                "hysteria2"
            } else {
                &scheme
            };
            let mut o = base(typ, &tag, &host, port);
            let mut q: HashMap<String, String> = HashMap::new();
            for (key, value) in u.query_pairs().into_owned() {
                // Match Go url.Values.Get: the first repeated parameter wins.
                q.entry(key).or_insert(value);
            }
            let get = |keys: &[&str]| {
                keys.iter()
                    .find_map(|k| q.get(*k).filter(|v| !v.is_empty()))
                    .cloned()
                    .unwrap_or_default()
            };
            let flag = |keys: &[&str]| {
                keys.iter().any(|k| {
                    q.get(*k)
                        .is_some_and(|s| matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"))
                })
            };
            let user = unescape(u.username());
            let pass = u.password().map(unescape).unwrap_or_default();
            let auth = if pass.is_empty() {
                user.clone()
            } else {
                format!("{user}:{pass}")
            };
            let mut tls = Tls {
                sni: get(&["sni", "peer"]),
                insecure: flag(&["insecure", "allowInsecure", "allow_insecure"]),
                alpn: csv(&get(&["alpn"])),
                fp: get(&["fp"]),
                ..Tls::default()
            };
            if tls.sni.is_empty() {
                tls.sni = host;
            }
            match typ {
                "vless" => {
                    if user.is_empty() {
                        bail!("vless: 缺少 UUID");
                    }
                    o["uuid"] = user.into();
                    put(&mut o, "flow", get(&["flow"]));
                    let sec = get(&["security"]);
                    if sec == "reality" {
                        tls.public_key = get(&["pbk"]);
                        tls.short_id = get(&["sid"]);
                        if tls.fp.is_empty() {
                            tls.fp = "chrome".into();
                        }
                    }
                    if matches!(sec.as_str(), "tls" | "xtls" | "reality") {
                        o["tls"] = tls.build();
                    }
                }
                "anytls" | "trojan" => {
                    if auth.is_empty() {
                        bail!("{typ}: 缺少 password");
                    }
                    o["password"] = auth.into();
                    if typ != "trojan" || get(&["security"]) != "none" {
                        o["tls"] = tls.build();
                    }
                }
                "hysteria2" => {
                    put(&mut o, "password", auth);
                    let obfs = get(&["obfs"]);
                    if !obfs.is_empty() && obfs != "none" {
                        o["obfs"] = json!({"type":obfs,"password":get(&["obfs-password"])});
                    }
                    let ports = get(&["mport", "ports"]);
                    if !ports.is_empty() {
                        o["server_ports"] = json!(port_ranges(&ports));
                        let mut interval = get(&["hop-interval"]);
                        if interval.parse::<u64>().is_ok() {
                            interval.push('s');
                        }
                        put(&mut o, "hop_interval", interval);
                    }
                    tls.alpn = vec!["h3".into()];
                    tls.fp.clear();
                    o["tls"] = tls.build();
                }
                "tuic" => {
                    if user.is_empty() {
                        bail!("tuic: 缺少 UUID");
                    }
                    o["uuid"] = user.into();
                    put(&mut o, "password", pass);
                    put(
                        &mut o,
                        "congestion_control",
                        get(&["congestion_control", "congestion_controller"]),
                    );
                    put(&mut o, "udp_relay_mode", get(&["udp_relay_mode"]));
                    if tls.alpn.is_empty() {
                        tls.alpn = vec!["h3".into()];
                    }
                    tls.fp.clear();
                    o["tls"] = tls.build();
                }
                _ => unreachable!(),
            }
            if matches!(typ, "vless" | "trojan") {
                put(
                    &mut o,
                    "transport",
                    transport(
                        &get(&["type"]),
                        &get(&["path"]),
                        &get(&["host"]),
                        &get(&["serviceName", "path"]),
                    ),
                );
            }
            Node {
                tag,
                outbound: o,
                raw: String::new(),
            }
        }
        _ => bail!("暂不支持的协议 {scheme}://"),
    };
    if node.tag.is_empty() {
        node.tag = format!(
            "{}:{}",
            string(&node.outbound, "server"),
            node.outbound["server_port"]
        );
    }
    node.outbound["tag"] = node.tag.clone().into();
    node.raw = raw.into();
    Ok(node)
}

fn parse_ss(body: &str) -> Result<Node> {
    let (body, tag) = body
        .rsplit_once('#')
        .map(|(b, t)| (b, unescape(t)))
        .unwrap_or((body, String::new()));
    let body = if body.contains('@') {
        body.to_string()
    } else {
        decode64(body).context("无法解码 legacy base64")?
    };
    let u = Url::parse(&format!("ss://{body}"))?;
    let (host, port) = host_port(&u)?;
    let user = unescape(u.username());
    let (method, password) = if let Some(p) = u.password() {
        (user, unescape(p))
    } else {
        let decoded = decode64(&user).unwrap_or(user);
        let (m, p) = decoded
            .split_once(':')
            .context("无法解析 method:password")?;
        (m.to_owned(), p.to_owned())
    };
    if method.is_empty() || password.is_empty() {
        bail!("method/password 为空");
    }
    let mut o = base("shadowsocks", &tag, &host, port);
    o["method"] = method.into();
    o["password"] = password.into();
    if let Some((_, plugin)) = u.query_pairs().find(|(k, _)| k == "plugin") {
        let (name, opts) = plugin.split_once(';').unwrap_or((&plugin, ""));
        o["plugin"] = if name == "simple-obfs" {
            "obfs-local"
        } else {
            name
        }
        .into();
        put(&mut o, "plugin_opts", opts);
    }
    Ok(Node {
        tag,
        outbound: o,
        raw: String::new(),
    })
}

fn parse_vmess(body: &str) -> Result<Node> {
    let decoded = decode64(body).context("vmess: 无法解码 base64")?;
    let v: Value = serde_json::from_str(&decoded).context("vmess: JSON 无效")?;
    let host = string(&v, "add");
    let tag = string(&v, "ps");
    let uuid = string(&v, "id");
    let port = u16::try_from(number(&v, "port"))
        .ok()
        .filter(|p| *p > 0)
        .context("vmess: 端口无效")?;
    if host.is_empty() || uuid.is_empty() {
        bail!("vmess: 缺少 add/id");
    }
    let mut o = base("vmess", &tag, &host, port);
    o["uuid"] = uuid.into();
    o["security"] = nonempty(string(&v, "scy"), "auto").into();
    o["alter_id"] = number(&v, "aid").into();
    if matches!(string(&v, "tls").as_str(), "tls" | "reality") {
        o["tls"] = Tls {
            sni: nonempty(string(&v, "sni"), &nonempty(string(&v, "host"), &host)),
            alpn: csv(&string(&v, "alpn")),
            fp: string(&v, "fp"),
            ..Tls::default()
        }
        .build();
    }
    let mut net = string(&v, "net");
    if net == "tcp" && v["type"] == "http" {
        net = "http".into();
    }
    put(
        &mut o,
        "transport",
        transport(
            &net,
            &string(&v, "path"),
            &string(&v, "host"),
            &string(&v, "path"),
        ),
    );
    Ok(Node {
        tag,
        outbound: o,
        raw: String::new(),
    })
}
pub fn nonempty(s: String, default: &str) -> String {
    if s.is_empty() {
        default.into()
    } else {
        s
    }
}

pub fn parse_mixed(text: &str) -> (Vec<Node>, Vec<String>) {
    let decoded;
    let text = if !text.contains("://") {
        decoded = decode64(text).unwrap_or_else(|| text.into());
        &decoded
    } else {
        text
    };
    let mut nodes = vec![];
    let mut errors = vec![];
    for line in text.lines().filter(|l| !l.trim().starts_with(['#'])) {
        for raw in line
            .split_whitespace()
            .filter(|s| s.contains("://") && !s.starts_with("//"))
        {
            match parse(raw) {
                Ok(n) => nodes.push(n),
                Err(e) => errors.push(e.to_string()),
            }
        }
    }
    (nodes, errors)
}
