use crate::{
    core, link, platform,
    profile::{Dirs, State, Subscription},
    render, subscription,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use fs2::FileExt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone)]
pub struct App {
    pub dirs: Dirs,
    pub state: State,
}
pub struct DirectoryLock(fs::File);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // Closing alone can leave flock held by a concurrently forked child
        // until it execs. Release ownership explicitly before closing the file.
        let _ = FileExt::unlock(&self.0);
    }
}
pub fn resolve_base(flag: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = flag {
        return Ok(dir.into());
    }
    if let Some(dir) = std::env::var_os("SSB_DIR").filter(|s| !s.is_empty()) {
        return Ok(dir.into());
    }
    Ok(std::env::current_exe()?
        .parent()
        .context("无法确定可执行文件目录")?
        .into())
}
impl App {
    pub fn open(base: impl AsRef<Path>) -> Result<Self> {
        let dirs = Dirs::new(base)?;
        let state = State::load(&dirs)?;
        Ok(Self { dirs, state })
    }
    /// Each mutating CLI command or TUI worker holds this guard. Read-only
    /// status commands remain available while downloads are in progress.
    pub fn lock(&mut self) -> Result<DirectoryLock> {
        self.dirs.ensure()?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dirs.base.join("run/ssb.lock"))?;
        lock.try_lock_exclusive()
            .context("另一个 ssb 正在修改此目录，请稍后再试")?;
        let guard = DirectoryLock(lock);
        self.state = State::load(&self.dirs)?;
        Ok(guard)
    }
    pub fn save(&self) -> Result<()> {
        self.state.save(&self.dirs)
    }
    pub fn generate(&self) -> Result<String> {
        let config = render::build(&self.state, &self.dirs)?;
        self.dirs.ensure()?;
        let mut tmp = tempfile::Builder::new()
            .prefix("config-")
            .suffix(".json")
            .tempfile_in(self.dirs.data())?;
        let mut bytes = serde_json::to_vec_pretty(&config)?;
        bytes.push(b'\n');
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        let warning = match core::locate(&self.dirs, &self.state.settings) {
            Ok(bin) => core::check(&bin, tmp.path())?,
            Err(e) => format!("未找到 sing-box，本次跳过配置校验（{e}）"),
        };
        if self.dirs.config().exists() {
            let old = fs::read(self.dirs.config())?;
            crate::profile::atomic_write(&self.dirs.backup(), &old, false)?;
        }
        self.save()?; // persist the API secret even on a first `gen`
        tmp.persist(self.dirs.config())
            .map_err(|e| e.error)
            .context("替换 config.json 失败，旧配置仍保留在 .bak")?;
        if self.state.all_nodes().is_empty() {
            Ok(format!(
                "没有可用代理节点：已生成阻断配置，请先添加节点或订阅后启动{}",
                if warning.is_empty() {
                    String::new()
                } else {
                    format!("；{warning}")
                }
            ))
        } else {
            Ok(warning)
        }
    }
    pub fn add_nodes(&mut self, text: &str) -> Result<(usize, Vec<String>)> {
        let (nodes, errors) = link::parse_mixed(text);
        if nodes.is_empty() {
            bail!(
                "没有发现可解析的节点链接{}",
                if errors.is_empty() {
                    String::new()
                } else {
                    format!("：{}", errors.join("；"))
                }
            );
        }
        let count = nodes.len();
        self.state.manual_nodes.extend(nodes);
        self.save()?;
        Ok((count, errors))
    }
    pub fn remove_manual(&mut self, tag: &str) -> Result<()> {
        // TUI displays the disambiguated tag; map it back to the stored node.
        let all = self.state.all_nodes();
        let eligible: Vec<usize> = self
            .state
            .manual_nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.outbound.is_object())
            .map(|(i, _)| i)
            .collect();
        let index = all
            .iter()
            .take(eligible.len())
            .position(|n| n.tag == tag)
            .map(|i| eligible[i])
            .or_else(|| self.state.manual_nodes.iter().position(|n| n.tag == tag))
            .with_context(|| format!("手动节点 {tag:?} 不存在；订阅节点需删除或更新订阅"))?;
        self.state.manual_nodes.remove(index);
        self.save()
    }
    pub fn sub_add(&mut self, name: &str, url: &str) -> Result<Subscription> {
        let name = if name.is_empty() {
            let mut index = self.state.subscriptions.len() + 1;
            while self
                .state
                .subscriptions
                .iter()
                .any(|s| s.name == format!("sub-{index}"))
            {
                index += 1;
            }
            format!("sub-{index}")
        } else {
            name.into()
        };
        if self.state.subscriptions.iter().any(|s| s.name == name) {
            bail!("订阅 {name:?} 已存在");
        }
        self.state.subscriptions.push(Subscription {
            name,
            url: url.into(),
            ..Subscription::default()
        });
        let i = self.state.subscriptions.len() - 1;
        let result = self.refresh_sub(i);
        self.save()?;
        result?;
        Ok(self.state.subscriptions[i].clone())
    }
    fn refresh_sub(&mut self, i: usize) -> Result<()> {
        let result = subscription::fetch(&self.state.subscriptions[i].url)?;
        let s = &mut self.state.subscriptions[i];
        s.nodes = result.nodes;
        s.format = result.format;
        s.userinfo = result.userinfo;
        s.updated_at = Utc::now().to_rfc3339();
        Ok(())
    }
    pub fn sub_update(&mut self, name: &str) -> Result<(Vec<String>, bool)> {
        let targets: Vec<usize> = self
            .state
            .subscriptions
            .iter()
            .enumerate()
            .filter(|(_, s)| name.is_empty() || s.name == name)
            .map(|(i, _)| i)
            .collect();
        if targets.is_empty() {
            bail!(
                "没有可更新的订阅{}",
                if name.is_empty() {
                    String::new()
                } else {
                    format!("：{name}")
                }
            );
        }
        let mut report = vec![];
        let mut failed = false;
        for i in targets {
            match self.refresh_sub(i) {
                Ok(()) => {
                    let s = &self.state.subscriptions[i];
                    report.push(format!(
                        "✓ {}: {} 个节点 ({})",
                        s.name,
                        s.nodes.len(),
                        s.format
                    ));
                }
                Err(e) => {
                    failed = true;
                    report.push(format!("✗ {}: {e:#}", self.state.subscriptions[i].name));
                }
            }
        }
        self.save()?;
        Ok((report, failed))
    }
    pub fn sub_remove(&mut self, name: &str) -> Result<()> {
        let index = self
            .state
            .subscriptions
            .iter()
            .position(|s| s.name == name)
            .with_context(|| format!("订阅 {name:?} 不存在"))?;
        self.state.subscriptions.remove(index);
        self.save()
    }
    pub fn install(&self) -> Result<String> {
        if self.dirs.binary().exists() {
            return Ok(format!(
                "{} 已存在（如需更新请删除后重新下载）",
                self.dirs.binary().display()
            ));
        }
        let version = core::download(&self.dirs, &self.state.settings.mirror_prefix)
            .context("下载 sing-box 失败；可自行把内核复制到 data/ 或配置镜像前缀")?;
        Ok(format!(
            "已下载 sing-box {version} → {}",
            self.dirs.binary().display()
        ))
    }
    pub fn ensure_binary(&self) -> Result<PathBuf> {
        match core::locate(&self.dirs, &self.state.settings) {
            Ok(bin) => Ok(bin),
            Err(e) if !self.state.settings.singbox_path.is_empty() => Err(e),
            Err(_) => {
                self.install()?;
                Ok(self.dirs.binary())
            }
        }
    }
    fn require_nodes(&self) -> Result<()> {
        if self.state.all_nodes().is_empty() {
            bail!("没有可用代理节点，已拒绝启动或切换出口以避免直连；请先添加节点或订阅");
        }
        Ok(())
    }
    pub fn start(&self) -> Result<()> {
        self.require_nodes()?;
        if let Some(pid) = core::running(&self.dirs) {
            bail!("sing-box 已在运行 (pid {pid})");
        }
        let bin = self.ensure_binary()?;
        if self.state.settings.tun_enabled && !platform::has_tun_privilege(&bin) {
            bail!("{}", platform::privilege_hint(&bin));
        }
        let warning = self.generate()?;
        if !warning.is_empty() {
            eprintln!("警告: {warning}");
        }
        core::start(&bin, &self.dirs)
    }
    pub fn stop(&self) -> Result<()> {
        core::stop(&self.dirs)
    }
    pub fn restart(&self) -> Result<()> {
        // Check before stopping a running core that still has its previous nodes.
        self.require_nodes()?;
        if core::running(&self.dirs).is_some() {
            self.stop()?;
        }
        self.start()
    }
    pub fn run_core(&self) -> Result<()> {
        self.require_nodes()?;
        let bin = self.ensure_binary()?;
        if self.state.settings.tun_enabled && !platform::has_tun_privilege(&bin) {
            bail!("{}", platform::privilege_hint(&bin));
        }
        let warning = self.generate()?;
        if !warning.is_empty() {
            eprintln!("警告: {warning}");
        }
        let mut cmd = Command::new(bin);
        cmd.args(["run", "-c"])
            .arg(self.dirs.config())
            .current_dir(&self.dirs.base);
        platform::foreground(&mut cmd)
    }
    pub fn select_node(&self, tag: &str) -> Result<()> {
        self.require_nodes()?;
        if core::running(&self.dirs).is_none() {
            bail!("sing-box 未运行，请先启动");
        }
        let bin = core::locate(&self.dirs, &self.state.settings)?;
        core::select(&bin, &self.state.settings, tag).context("切换失败；如刚增删节点，请重启内核")
    }
    pub fn selected_node(&self) -> String {
        if core::running(&self.dirs).is_none() {
            return String::new();
        }
        core::locate(&self.dirs, &self.state.settings)
            .and_then(|bin| core::selected(&bin, &self.state.settings))
            .unwrap_or_default()
    }
    pub fn dashboard_url(&self) -> String {
        format!(
            "http://{}/dashboard/",
            core::api_address(&self.state.settings.api_listen)
        )
    }
    pub fn status_text(&self) -> String {
        let mut out = match core::running(&self.dirs) {
            Some(pid) => format!("sing-box: 运行中 (pid {pid})\n"),
            None => "sing-box: 未运行\n".into(),
        };
        match core::locate(&self.dirs, &self.state.settings) {
            Ok(bin) => out.push_str(&format!(
                "二进制: {} ({})\n",
                bin.display(),
                core::version(&bin).unwrap_or_else(|e| e.to_string())
            )),
            Err(_) => out.push_str("二进制: 未找到\n"),
        }
        let s = &self.state.settings;
        let alive = core::api_alive(&s.api_listen);
        out.push_str(&format!(
            "API 服务: {}（{}，secret {}）\n",
            if alive { "可达" } else { "不可达" },
            s.api_listen,
            s.api_secret
        ));
        if alive {
            let selected = self.selected_node();
            if !selected.is_empty() {
                out.push_str(&format!("当前出口: {selected}\n"));
            }
        }
        out.push_str(&format!(
            "节点数: {}（手动 {} + 订阅 {} 个源）\n",
            self.state.all_nodes().len(),
            self.state.manual_nodes.len(),
            self.state.subscriptions.len()
        ));
        out.push_str(&format!(
            "路由模式: {}，TUN: {}，FakeIP: {}\n规则集: {}\n工作目录: {}\n",
            s.route_mode,
            s.tun_enabled,
            s.fakeip,
            render::ruleset_source(s),
            self.dirs.base.display()
        ));
        if !s.dashboard_off {
            out.push_str(&format!("Dashboard: {}\n", self.dashboard_url()));
        }
        out
    }
}
