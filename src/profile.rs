use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::link::Node;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub route_mode: String,
    pub tun_enabled: bool,
    pub tun_address: String,
    pub ipv6: String,
    pub auto_redirect: bool,
    pub mixed_enabled: bool,
    pub mixed_port: u16,
    pub api_listen: String,
    pub api_secret: String,
    pub dashboard_off: bool,
    pub mirror_prefix: String,
    pub fakeip: bool,
    pub download_detour: String,
    pub ruleset_source: String,
    pub dns_cn: String,
    pub dns_proxy: String,
    pub singbox_path: String,
    pub log_level: String,
    pub advanced_routing: bool,
    #[serde(deserialize_with = "null_vec")]
    pub custom_proxy: Vec<String>,
    #[serde(deserialize_with = "null_vec")]
    pub custom_direct: Vec<String>,
}

pub fn random_secret() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            route_mode: "rule".into(),
            tun_enabled: true,
            tun_address: "10.255.0.1/30".into(),
            ipv6: "auto".into(),
            auto_redirect: false,
            mixed_enabled: true,
            mixed_port: 2080,
            api_listen: "127.0.0.1:9090".into(),
            api_secret: random_secret(),
            dashboard_off: true,
            mirror_prefix: String::new(),
            fakeip: true,
            download_detour: "direct".into(),
            ruleset_source: "jsdelivr".into(),
            dns_cn: "223.5.5.5".into(),
            dns_proxy: "8.8.8.8".into(),
            singbox_path: String::new(),
            log_level: "warn".into(),
            advanced_routing: false,
            custom_proxy: vec![],
            custom_direct: vec![],
        }
    }
}

pub fn null_vec<'de, D, T>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Go encodes nil slices as null, including slices containing nil pointers.
    Ok(Option::<Vec<Option<T>>>::deserialize(d)?
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Userinfo {
    pub upload: i64,
    pub download: i64,
    pub total: i64,
    pub expire: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub name: String,
    pub url: String,
    pub updated_at: String,
    pub format: String,
    pub userinfo: Option<Userinfo>,
    #[serde(deserialize_with = "null_vec")]
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    #[serde(deserialize_with = "null_vec")]
    pub subscriptions: Vec<Subscription>,
    #[serde(deserialize_with = "null_vec")]
    pub manual_nodes: Vec<Node>,
    pub settings: Settings,
}

#[derive(Debug, Clone)]
pub struct Dirs {
    pub base: PathBuf,
}
impl Dirs {
    pub fn new(base: impl AsRef<Path>) -> Result<Self> {
        let base = base.as_ref();
        Ok(Self {
            base: if base.is_absolute() {
                base.into()
            } else {
                std::env::current_dir()?.join(base)
            },
        })
    }
    pub fn data(&self) -> PathBuf {
        self.base.join("data")
    }
    pub fn state(&self) -> PathBuf {
        self.data().join("state.json")
    }
    pub fn config(&self) -> PathBuf {
        self.data().join("config.json")
    }
    pub fn backup(&self) -> PathBuf {
        self.data().join("config.json.bak")
    }
    pub fn binary(&self) -> PathBuf {
        self.data().join(if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        })
    }
    pub fn dashboard(&self) -> PathBuf {
        self.data().join("dashboard")
    }
    pub fn cache(&self) -> PathBuf {
        self.data().join("cache.db")
    }
    pub fn log(&self) -> PathBuf {
        self.base.join("logs/sing-box.log")
    }
    pub fn pid(&self) -> PathBuf {
        self.base.join("run/sing-box.pid")
    }
    pub fn ensure(&self) -> Result<()> {
        for p in [
            self.data(),
            self.dashboard(),
            self.base.join("logs"),
            self.base.join("run"),
        ] {
            fs::create_dir_all(p)?;
        }
        Ok(())
    }
}

impl State {
    pub fn load(d: &Dirs) -> Result<Self> {
        let bytes = match fs::read(d.state()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let mut st: Self = serde_json::from_slice(&bytes).context("state.json 损坏，请恢复备份")?;
        // Older Go state files explicitly stored empty strings and zero ports.
        let defaults = serde_json::to_value(Settings::default())?;
        let mut settings = serde_json::to_value(&st.settings)?;
        for (key, value) in defaults.as_object().unwrap() {
            if settings[key] == "" || (key == "mixed_port" && settings[key] == 0) {
                settings[key] = value.clone();
            }
        }
        st.settings = serde_json::from_value(settings)?;
        Ok(st)
    }
    pub fn save(&self, d: &Dirs) -> Result<()> {
        d.ensure()?;
        atomic_write(&d.state(), &serde_json::to_vec_pretty(self)?, false)
    }
    pub fn all_nodes(&self) -> Vec<Node> {
        // Reserve built-ins, and check suffixed names too ("x", "x #2", "x").
        let mut seen: HashSet<String> = ["PROXY", "auto", "direct"]
            .into_iter()
            .map(String::from)
            .collect();
        self.manual_nodes
            .iter()
            .chain(self.subscriptions.iter().flat_map(|s| &s.nodes))
            .filter(|n| n.outbound.is_object())
            .map(|n| {
                let base = if n.tag.is_empty() { "node" } else { &n.tag };
                let mut tag = base.to_string();
                let mut i = 2;
                while !seen.insert(tag.clone()) {
                    tag = format!("{base} #{i}");
                    i += 1;
                }
                let mut n = n.clone();
                n.tag = tag.clone();
                n.outbound["tag"] = tag.into();
                n
            })
            .collect()
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let parent = path.parent().context("文件缺少父目录")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o600
            }))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("写入 {} 失败", path.display()))?;
    Ok(())
}

pub fn set_setting(s: &mut Settings, key: &str, text: &str) -> Result<()> {
    let mut value = serde_json::to_value(&*s)?;
    let current = value.get(key).context("未知设置")?;
    value[key] = match current {
        Value::Bool(_) => match text {
            "true" | "on" | "开" => true.into(),
            "false" | "off" | "关" => false.into(),
            _ => bail!("请输入 true/false"),
        },
        Value::Number(_) => Value::from(text.parse::<u16>().context("端口应为 1–65535")?),
        Value::Array(_) => {
            let domains: Vec<String> = text
                .split(|c: char| c.is_whitespace() || ",，;；".contains(c))
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
                .collect();
            if domains.iter().any(|d| d.contains(['/', ':']) || d == ".") {
                bail!("请输入裸域名（不带协议、端口或路径）");
            }
            serde_json::to_value(domains)?
        }
        _ => Value::from(text.trim()),
    };
    let mut next: Settings = serde_json::from_value(value)?;
    if next.api_secret.is_empty() {
        next.api_secret = random_secret();
    }
    next.validate()?;
    *s = next;
    Ok(())
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        for (name, value, opts) in [
            (
                "路由模式",
                self.route_mode.as_str(),
                &["rule", "global"][..],
            ),
            ("IPv6", &self.ipv6, &["auto", "on", "off"][..]),
            ("下载出站", &self.download_detour, &["direct", "PROXY"][..]),
            (
                "规则集源",
                &self.ruleset_source,
                &["jsdelivr", "github"][..],
            ),
            (
                "日志级别",
                &self.log_level,
                &["trace", "debug", "info", "warn", "error", "fatal", "panic"][..],
            ),
        ] {
            if !opts.contains(&value) {
                bail!("{name} 无效: {value}");
            }
        }
        if self.mixed_port == 0 {
            bail!("mixed 端口应为 1–65535");
        }
        self.dns_cn
            .parse::<std::net::IpAddr>()
            .context("国内 DNS 应为 UDP DNS 的 IP 地址，例如 223.5.5.5")?;
        proxy_dns_url(&self.dns_proxy)?;
        split_listen(&self.api_listen)?;
        let (ip, prefix) = self
            .tun_address
            .split_once('/')
            .context("TUN 地址应为 IPv4 CIDR")?;
        ip.parse::<std::net::Ipv4Addr>()
            .context("TUN 地址应为 IPv4 CIDR")?;
        if prefix.parse::<u8>().context("TUN 前缀无效")? > 32 {
            bail!("TUN 前缀应为 0–32");
        }
        Ok(())
    }
}

/// Normalize the supported DoH shorthand without accepting other URL schemes.
pub fn proxy_dns_url(text: &str) -> Result<url::Url> {
    let url = if text.starts_with("https://") {
        url::Url::parse(text)
    } else if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        let host = match ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        };
        url::Url::parse(&format!("https://{host}"))
    } else {
        if text.is_empty()
            || text.contains(['/', ':', '?', '#', '@'])
            || text.chars().any(char::is_whitespace)
        {
            bail!("代理 DNS 应为 IP、域名或完整 HTTPS URL");
        }
        url::Url::parse(&format!("https://{text}"))
    }
    .context("代理 DNS 地址无效")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        bail!("代理 DNS 应包含有效主机和端口，不支持用户名、密码或片段");
    }
    Ok(url)
}

pub fn split_listen(addr: &str) -> Result<std::net::SocketAddr> {
    let normalized = if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.into()
    };
    let addr: std::net::SocketAddr = normalized
        .parse()
        .context("API 监听应为 IP:端口（IPv6 用 [::1]:9090）")?;
    if addr.port() == 0 {
        bail!("API 端口应为 1–65535");
    }
    Ok(addr)
}
