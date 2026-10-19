use crate::{
    platform,
    profile::{self, Dirs, Settings, State},
};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const SELF: &str = if cfg!(windows) { ".\\ssb" } else { "./ssb" };

pub fn locate(d: &Dirs, s: &Settings) -> Result<PathBuf> {
    if !s.singbox_path.is_empty() {
        let p = PathBuf::from(&s.singbox_path);
        let p = if p.is_absolute() { p } else { d.base.join(p) };
        if !p.is_file() {
            bail!("设置里的 sing-box 路径不存在: {}", p.display());
        }
        return Ok(p);
    }
    if d.binary().is_file() {
        return Ok(d.binary());
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(if cfg!(windows) {
                "sing-box.exe"
            } else {
                "sing-box"
            });
            if p.is_file() {
                return Ok(fs::canonicalize(p)?);
            }
        }
    }
    bail!(
        "未找到 sing-box，请运行 {SELF} install，或把内核放入 {}",
        d.binary().display()
    )
}

/// Capture through temporary files so a verbose child cannot block on a full
/// pipe while its parent waits for the deadline.
pub fn command_output(mut cmd: Command, timeout: Duration) -> Result<String> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    cmd.stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    let mut child = cmd.spawn().context("无法执行 sing-box")?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("sing-box 命令超时（{} 秒）", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(30));
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = String::new();
    let mut err = String::new();
    stdout.take(4 << 20).read_to_string(&mut out)?;
    stderr.take(4 << 20).read_to_string(&mut err)?;
    if !status.success() {
        bail!(
            "{}",
            if err.trim().is_empty() {
                format!("{status}: {}", out.trim())
            } else {
                strip_ansi(&err).trim().into()
            }
        );
    }
    if !err.trim().is_empty() {
        out.push('\n');
        out.push_str(&err);
    }
    Ok(out)
}
pub fn version(bin: &Path) -> Result<String> {
    let mut cmd = Command::new(bin);
    cmd.arg("version");
    Ok(command_output(cmd, Duration::from_secs(8))?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .into())
}
pub fn check(bin: &Path, config: &Path) -> Result<String> {
    let mut cmd = Command::new(bin);
    cmd.args(["check", "-c"]).arg(config);
    let out = command_output(cmd, Duration::from_secs(30)).context("sing-box check 未通过")?;
    Ok(strip_ansi(&out)
        .lines()
        .filter(|ln| ln.trim_start().starts_with("WARN"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n"))
}
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.next() == Some('[') {
                for ch in chars.by_ref() {
                    if ('@'..='~').contains(&ch) {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn asset_suffix(os: &str, arch: &str) -> String {
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        v => v,
    };
    format!(
        "-{os}-{arch}{}",
        if os == "windows" { ".zip" } else { ".tar.gz" }
    )
}
pub fn download(d: &Dirs, mirror: &str) -> Result<String> {
    d.ensure()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(600))
        .user_agent("ssb-rust")
        .build()?;
    let release: Value = client
        .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()?
        .error_for_status()?
        .json()?;
    let tag = release["tag_name"]
        .as_str()
        .context("GitHub release 缺少版本号")?;
    let suffix = asset_suffix(std::env::consts::OS, std::env::consts::ARCH);
    let url = release["assets"]
        .as_array()
        .context("GitHub release 缺少资产列表")?
        .iter()
        .find(|a| a["name"].as_str().is_some_and(|n| n.ends_with(&suffix)))
        .and_then(|a| a["browser_download_url"].as_str())
        .with_context(|| format!("release {tag} 中未找到 *{suffix} 资产"))?;
    let resp = client
        .get(format!("{mirror}{url}"))
        .send()?
        .error_for_status()?;
    let mut bytes = vec![];
    resp.take((256 << 20) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 256 << 20 {
        bail!("内核压缩包超过 256 MiB 限制");
    }
    extract_archive(d, &bytes, suffix.ends_with(".zip"))?;
    Ok(tag.into())
}
pub fn extract_archive(d: &Dirs, bytes: &[u8], zip: bool) -> Result<()> {
    d.ensure()?;
    if zip {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let mut files = vec![];
        let mut found = false;
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            if !entry.is_file() {
                continue;
            }
            let name = entry
                .name()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned();
            if name != "sing-box.exe" && !name.to_lowercase().ends_with(".dll") {
                continue;
            }
            if name.contains(['\\', ':']) || name == ".." {
                bail!("压缩包文件名无效");
            }
            if entry.size() > 256 << 20 {
                bail!("解压文件过大");
            }
            let mut content = vec![];
            entry.take((256 << 20) + 1).read_to_end(&mut content)?;
            if content.len() > 256 << 20 {
                bail!("解压文件过大");
            }
            found |= name == "sing-box.exe";
            files.push((name, content));
        }
        if !found {
            bail!("压缩包里没有 sing-box.exe");
        }
        for (name, content) in files {
            profile::atomic_write(&d.data().join(name), &content, true)?;
        }
    } else {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
        for entry in archive.entries()? {
            let entry = entry?;
            if !entry.header().entry_type().is_file()
                || entry.path()?.file_name().is_none_or(|n| n != "sing-box")
            {
                continue;
            }
            let mut content = vec![];
            entry.take((256 << 20) + 1).read_to_end(&mut content)?;
            if content.len() > 256 << 20 {
                bail!("解压文件过大");
            }
            profile::atomic_write(&d.binary(), &content, true)?;
            return Ok(());
        }
        bail!("压缩包里没有 sing-box");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct ProcessRecord {
    pid: u32,
    identity: String,
    image: PathBuf,
}
fn record_path(d: &Dirs) -> PathBuf {
    d.base.join("run/sing-box.process.json")
}
pub fn running(d: &Dirs) -> Option<u32> {
    let pid: u32 = fs::read_to_string(d.pid()).ok()?.trim().parse().ok()?;
    if pid <= 1 {
        return None;
    }
    let info = platform::process_info(pid)?;
    if let Ok(bytes) = fs::read(record_path(d)) {
        let record: ProcessRecord = serde_json::from_slice(&bytes).ok()?;
        if record.pid != pid || record.identity != info.identity || record.image != info.image {
            return None;
        }
    } else {
        // Accept the old Go pidfile when migrating an already running core.
        if !info
            .image
            .file_name()?
            .to_string_lossy()
            .to_lowercase()
            .starts_with("sing-box")
        {
            return None;
        }
        #[cfg(target_os = "linux")]
        if !info.args.iter().any(|a| Path::new(a) == d.config()) {
            return None;
        }
    }
    Some(pid)
}
fn remove_pid(d: &Dirs) {
    let _ = fs::remove_file(d.pid());
    let _ = fs::remove_file(record_path(d));
}
pub fn start(bin: &Path, d: &Dirs) -> Result<()> {
    if let Some(pid) = running(d) {
        bail!("sing-box 已在运行 (pid {pid})");
    }
    d.ensure()?;
    if fs::metadata(d.log()).is_ok_and(|m| m.len() > 8 << 20) {
        fs::rename(d.log(), d.base.join("logs/sing-box.log.1"))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.log())?;
    let mut cmd = Command::new(bin);
    cmd.args(["run", "-c"])
        .arg(d.config())
        .current_dir(&d.base)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    platform::detach(&mut cmd);
    let mut child = cmd.spawn().context("sing-box 启动失败")?;
    let pid = child.id();
    let record = (|| -> Result<()> {
        let info = platform::process_info(pid).context("sing-box 启动即退出")?;
        profile::atomic_write(
            &record_path(d),
            &serde_json::to_vec(&ProcessRecord {
                pid,
                identity: info.identity,
                image: info.image,
            })?,
            false,
        )?;
        profile::atomic_write(&d.pid(), pid.to_string().as_bytes(), false)
    })();
    if let Err(err) = record {
        let _ = child.kill();
        let _ = child.wait();
        remove_pid(d);
        return Err(err);
    }
    thread::sleep(Duration::from_millis(1200));
    if let Some(status) = child.try_wait()? {
        remove_pid(d);
        let logs = tail(d, 15);
        bail!(
            "sing-box 启动即退出 ({status})：\n{logs}{}",
            start_hint(&logs, bin)
        );
    }
    // A live TUI must reap children too; dropping a Child alone does not do so.
    thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
pub fn stop(d: &Dirs) -> Result<()> {
    let Some(pid) = running(d) else {
        remove_pid(d);
        bail!("sing-box 未在运行");
    };
    platform::terminate(pid, false)?;
    for _ in 0..50 {
        if running(d) != Some(pid) {
            remove_pid(d);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    if running(d) == Some(pid) {
        platform::terminate(pid, true)?;
    }
    remove_pid(d);
    Ok(())
}
fn start_hint(log: &str, bin: &Path) -> String {
    let l = log.to_lowercase();
    if l.contains("address family not supported") {
        "\n提示：系统无法安装所需的 IPv6 路由或阻断规则。请检查 IPv6/策略路由支持；为避免绕过代理，不会自动关闭严格路由。也可关闭 TUN，仅使用显式应用代理。".into()
    } else if l.contains("address already in use") || l.contains("only one usage of each socket") {
        format!("\n提示：端口被占用，运行 {SELF} doctor 检查，或更改 mixed/API 端口。")
    } else if l.contains("operation not permitted")
        || l.contains("permission denied")
        || l.contains("access is denied")
        || log.contains("拒绝访问")
    {
        format!("\n提示：{}", platform::privilege_hint(bin))
    } else {
        String::new()
    }
}

pub fn api_address(listen: &str) -> String {
    match profile::split_listen(listen) {
        Ok(mut addr) => {
            if addr.ip().is_unspecified() {
                addr.set_ip(if addr.is_ipv4() {
                    std::net::Ipv4Addr::LOCALHOST.into()
                } else {
                    std::net::Ipv6Addr::LOCALHOST.into()
                });
            }
            addr.to_string()
        }
        Err(_) => listen.into(),
    }
}
pub fn api_alive(listen: &str) -> bool {
    Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .is_ok_and(|c| {
            c.get(format!("http://{}/", api_address(listen)))
                .send()
                .is_ok()
        })
}
pub fn api_output(bin: &Path, s: &Settings, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(bin);
    cmd.args([
        "api",
        "--url",
        &format!("http://{}", api_address(&s.api_listen)),
        "--secret",
        &s.api_secret,
    ])
    .args(args);
    command_output(cmd, Duration::from_secs(8)).context("sing-box API 调用失败")
}
pub fn parse_selected(out: &str) -> String {
    strip_ansi(out)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("Selected:")
                .map(str::trim)
                .filter(|s| *s != "-")
                .map(String::from)
        })
        .unwrap_or_default()
}
pub fn selected(bin: &Path, s: &Settings) -> Result<String> {
    Ok(parse_selected(&api_output(
        bin,
        s,
        &["group", "show", "PROXY"],
    )?))
}
pub fn select(bin: &Path, s: &Settings, tag: &str) -> Result<()> {
    api_output(bin, s, &["group", "select", "PROXY", tag])?;
    Ok(())
}
pub fn tail(d: &Dirs, n: usize) -> String {
    let Ok(mut file) = fs::File::open(d.log()) else {
        return "（暂无日志）".into();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or_default();
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(128 << 10)));
    let mut bytes = vec![];
    let _ = file.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<_> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}
pub fn doctor(d: &Dirs, st: &State) -> Vec<CheckResult> {
    let mut result = vec![];
    let mut add = |name: &str, ok: bool, detail: String| {
        result.push(CheckResult {
            name: name.into(),
            ok,
            detail,
        })
    };
    let bin = locate(d, &st.settings);
    match &bin {
        Ok(bin) => match version(bin) {
            Ok(v) => add("sing-box 二进制", true, format!("{} ({v})", bin.display())),
            Err(e) => add("sing-box 二进制", false, e.to_string()),
        },
        Err(e) => add("sing-box 二进制", false, e.to_string()),
    }
    if st.settings.tun_enabled {
        #[cfg(target_os = "linux")]
        add(
            "/dev/net/tun",
            Path::new("/dev/net/tun").exists(),
            "TUN 设备（容器需映射 /dev/net/tun）".into(),
        );
        let path = bin.as_deref().unwrap_or(Path::new("sing-box"));
        let privileged = platform::has_tun_privilege(path);
        add(
            "TUN 权限",
            privileged,
            if privileged {
                "权限可用".into()
            } else {
                platform::privilege_hint(path)
            },
        );
        let mode = st.settings.ipv6.as_str();
        let supported = platform::host_has_ipv6();
        add(
            "IPv6",
            mode != "on" || supported,
            if mode == "off" {
                "off：使用 IPv4，拒绝 IPv6 连接".into()
            } else if supported {
                format!("IPv6 可用（{mode}）")
            } else if mode == "on" {
                "IPv6 不可用；使用 auto/off 时，TUN 仍要求系统支持 IPv6 阻断规则".into()
            } else {
                "IPv6 不可用，auto 使用 IPv4；TUN 严格路由仍阻断 IPv6".into()
            },
        );
    }
    #[cfg(target_os = "linux")]
    if fs::read_to_string("/etc/resolv.conf").is_ok_and(|s| s.contains("127.0.0.53")) {
        add(
            "systemd-resolved",
            true,
            "127.0.0.53 存根；若解析异常可手动设置 DNSStubListener=no".into(),
        );
    }
    let mut ports = vec![("API 端口", st.settings.api_listen.clone())];
    if st.settings.mixed_enabled || !st.settings.tun_enabled {
        ports.push((
            "mixed 端口",
            format!("127.0.0.1:{}", st.settings.mixed_port),
        ));
    }
    for (name, addr) in ports {
        let address = profile::split_listen(&api_address(&addr));
        let occupied = address.as_ref().is_ok_and(|a| {
            std::net::TcpStream::connect_timeout(a, Duration::from_millis(500)).is_ok()
        });
        let managed = running(d).is_some();
        add(
            name,
            address.is_ok() && (!occupied || managed),
            format!(
                "{addr} {}",
                if occupied {
                    if managed {
                        "被托管内核占用"
                    } else {
                        "已被其他进程占用，请换端口"
                    }
                } else {
                    "空闲"
                }
            ),
        );
    }
    if let Ok(bin) = bin {
        if d.config().is_file() {
            match check(&bin, &d.config()) {
                Ok(w) => add(
                    "config.json",
                    w.is_empty(),
                    if w.is_empty() {
                        "check 通过".into()
                    } else {
                        w
                    },
                ),
                Err(e) => add("config.json", false, format!("{e:#}")),
            }
        } else {
            add("config.json", false, format!("尚未生成，运行 {SELF} gen"));
        }
    }
    result
}
