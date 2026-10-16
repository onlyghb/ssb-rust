use crate::{app::App, core, link, profile, subscription};
use anyhow::{bail, Result};
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use serde_json::Value;
use std::{
    io,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

const ACCENT: Color = Color::Cyan;
const HELP: &str = "全局\n  1–4 / Tab / h l     切换状态、订阅、节点、设置\n  j k / ↑ ↓          移动光标；状态页翻日志\n  PgUp PgDn / Home End   翻页 / 首尾\n  /                  搜索当前列表；Enter 保留；Esc 清除筛选\n  s                  启动或停止 sing-box\n  r                  校验配置并重启应用\n  g                  生成并校验配置\n  q / Ctrl-C         退出，sing-box 继续在后台运行\n\n状态页：i 下载内核\n订阅页：a 添加 URL [名称]；Enter/u 更新；U 全部更新；x/Delete 删除\n节点页：a 添加链接；Enter/空格 立即切换出口；x/Delete 删除手动节点\n设置页：Enter/空格 轮转；e 编辑原始值；Backspace 反向轮转\n\n文本编辑：支持粘贴、方向键、Home/End；Ctrl-U 清空；Esc 取消\n设置或节点变更会自动保存和校验配置；运行中按 r 使改动生效\n宽屏右侧显示详情；窄屏在列表下方显示\n\n按 ? / Esc / Enter 返回";

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}

#[derive(Clone)]
enum Operation {
    Toggle,
    Restart,
    Generate,
    Install,
    AddNodes(String),
    AddSub(String, String),
    UpdateSub(String),
    RemoveSub(String),
    RemoveNode(String),
    Select(String),
    Setting(String, String),
}
impl Operation {
    fn changes_config(&self) -> bool {
        matches!(
            self,
            Self::Generate
                | Self::AddNodes(_)
                | Self::AddSub(..)
                | Self::UpdateSub(_)
                | Self::RemoveSub(_)
                | Self::RemoveNode(_)
                | Self::Setting(..)
        )
    }
    fn label(&self) -> &'static str {
        match self {
            Self::Toggle => "启停内核",
            Self::Restart => "应用配置并重启",
            Self::Generate => "生成配置",
            Self::Install => "下载内核",
            Self::AddNodes(_) => "添加节点",
            Self::AddSub(..) => "添加订阅",
            Self::UpdateSub(_) => "更新订阅",
            Self::RemoveSub(_) => "删除订阅",
            Self::RemoveNode(_) => "删除节点",
            Self::Select(_) => "切换出口",
            Self::Setting(..) => "保存设置",
        }
    }
    fn apply(&self, a: &mut App) -> Result<String> {
        let _guard = a.lock()?;
        let message = match self {
            Self::Toggle => if core::running(&a.dirs).is_some() {
                a.stop()?;
                "已停止"
            } else {
                a.start()?;
                "已启动"
            }
            .into(),
            Self::Restart => {
                a.restart()?;
                "已重启".into()
            }
            Self::Install => a.install()?,
            Self::Select(tag) => {
                a.select_node(tag)?;
                format!("出口 → {tag}")
            }
            Self::Generate => "配置已生成".into(),
            Self::AddNodes(text) => {
                let (n, errors) = a.add_nodes(text)?;
                format!(
                    "已添加 {n} 个节点{}",
                    if errors.is_empty() {
                        String::new()
                    } else {
                        format!("；跳过：{}", errors.join("；"))
                    }
                )
            }
            Self::AddSub(url, name) => {
                let s = a.sub_add(name, url)?;
                format!("{}: {} 个节点 ({})", s.name, s.nodes.len(), s.format)
            }
            Self::UpdateSub(name) => {
                let (report, failed) = a.sub_update(name)?;
                let warning = a.generate()?;
                if failed {
                    bail!(
                        "{}{}",
                        report.join("；"),
                        if warning.is_empty() {
                            String::new()
                        } else {
                            format!("；{warning}")
                        }
                    );
                }
                return Ok(format!(
                    "{}{}",
                    report.join("；"),
                    if warning.is_empty() {
                        String::new()
                    } else {
                        format!("；{warning}")
                    }
                ));
            }
            Self::RemoveSub(name) => {
                a.sub_remove(name)?;
                format!("已删除 {name}")
            }
            Self::RemoveNode(tag) => {
                a.remove_manual(tag)?;
                format!("已删除 {tag}")
            }
            Self::Setting(key, text) => {
                let previous = a.state.settings.clone();
                profile::set_setting(&mut a.state.settings, key, text)?;
                return match a.generate() {
                    Ok(warning) => Ok(if warning.is_empty() {
                        "设置已保存，配置校验通过".into()
                    } else {
                        format!("设置已保存；{warning}")
                    }),
                    Err(error) => {
                        a.state.settings = previous;
                        Err(error)
                    }
                };
            }
        };
        if self.changes_config() {
            let warning = a.generate()?;
            return Ok(format!(
                "{message}{}",
                if warning.is_empty() {
                    String::new()
                } else {
                    format!("；警告: {warning}")
                }
            ));
        }
        Ok(message)
    }
}
struct Finished {
    app: App,
    result: Result<String>,
    changed: bool,
    restart: bool,
}
struct Snapshot {
    app: App,
    status: String,
    selected: String,
}
#[derive(Clone)]
enum InputKind {
    Nodes,
    Subscription,
    Setting(String),
    Search,
}
#[derive(Clone)]
struct Editor {
    kind: InputKind,
    label: String,
    text: String,
    cursor: usize,
}
impl Editor {
    fn new(kind: InputKind, label: String, text: String) -> Self {
        let cursor = text.len();
        Self {
            kind,
            label,
            text,
            cursor,
        }
    }
    fn insert(&mut self, s: &str) {
        self.text.insert_str(self.cursor, s);
        self.cursor += s.len();
    }
    fn viewport(&self, width: usize) -> String {
        let mut used = 0;
        let mut start = self.cursor;
        for (index, c) in self.text[..self.cursor].char_indices().rev() {
            let cell_width = Span::raw(c.to_string().replace(['\n', '\r'], " ")).width();
            if used + cell_width > width.saturating_sub(1) {
                break;
            }
            used += cell_width;
            start = index;
        }
        format!(
            "{}▏{}",
            &self.text[start..self.cursor],
            &self.text[self.cursor..]
        )
        .replace(['\n', '\r'], " ")
    }
    fn prev(&self) -> usize {
        self.text[..self.cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
    fn next(&self) -> usize {
        self.text[self.cursor..]
            .chars()
            .next()
            .map(|c| self.cursor + c.len_utf8())
            .unwrap_or(self.cursor)
    }
    fn key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Left => self.cursor = self.prev(),
            KeyCode::Right => self.cursor = self.next(),
            KeyCode::Backspace => {
                let prev = self.prev();
                self.text.replace_range(prev..self.cursor, "");
                self.cursor = prev;
            }
            KeyCode::Delete => {
                let next = self.next();
                self.text.replace_range(self.cursor..next, "");
            }
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                self.text.clear();
                self.cursor = 0;
            }
            KeyCode::Char('a') if k.modifiers.contains(KeyModifiers::CONTROL) => self.cursor = 0,
            KeyCode::Char('e') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cursor = self.text.len()
            }
            KeyCode::Char(c)
                if !k
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert(&c.to_string())
            }
            _ => {}
        }
    }
}
struct Row {
    key: &'static str,
    label: &'static str,
    description: &'static str,
    options: &'static [&'static str],
}
fn setting_rows(a: &App) -> Vec<Row> {
    let mut rows = vec![
        Row {
            key: "route_mode",
            label: "代理 / 路由模式",
            description:
                "rule：国内直连、其余代理；global：默认代理；两种模式均保留私网直连及自定义分流",
            options: &["rule", "global"],
        },
        Row {
            key: "tun_enabled",
            label: "代理 / TUN 透明代理",
            description: "接管系统流量，需要 root/CAP_NET_ADMIN 或管理员权限",
            options: &["true", "false"],
        },
        Row {
            key: "tun_address",
            label: "代理 / TUN IP",
            description: "IPv4 CIDR，默认 10.255.0.1/30",
            options: &[],
        },
        Row {
            key: "ipv6",
            label: "代理 / IPv6",
            description: "auto 按系统 IPv6/策略路由能力探测；on 强制开启；off 纯 IPv4",
            options: &["auto", "on", "off"],
        },
        Row {
            key: "auto_redirect",
            label: "代理 / auto_redirect",
            description: "Linux nftables 加速；官方推荐用于 TUN，需系统内核支持；仅 TUN 开启时生效",
            options: &["true", "false"],
        },
        Row {
            key: "fakeip",
            label: "代理 / FakeIP",
            description:
                "开启：代理域名的 A/AAAA 查询返回假 IP；关闭：使用真实 IP 并保留域名反向映射",
            options: &["true", "false"],
        },
        Row {
            key: "mixed_enabled",
            label: "本地入站 / mixed 开关",
            description: "127.0.0.1 上的 SOCKS5/HTTP 入站；关闭 TUN 时始终保留",
            options: &["true", "false"],
        },
        Row {
            key: "mixed_port",
            label: "本地入站 / mixed 端口",
            description: "端口范围 1–65535，默认 2080",
            options: &[],
        },
        Row {
            key: "api_listen",
            label: "本地入站 / API 监听",
            description: "IP:端口；0.0.0.0:9090 可供局域网访问面板",
            options: &[],
        },
        Row {
            key: "api_secret",
            label: "本地入站 / API 密钥",
            description: "API/面板 secret；留空确认后重新随机生成",
            options: &[],
        },
        Row {
            key: "dashboard_off",
            label: "面板 / Dashboard",
            description: "开启后由 API 服务自动下载并托管官方网页面板",
            options: &["false", "true"],
        },
        Row {
            key: "dns_cn",
            label: "DNS / 国内 DNS",
            description: "直连 UDP DNS 的 IP，例如 223.5.5.5",
            options: &[],
        },
        Row {
            key: "dns_proxy",
            label: "DNS / 代理 DNS",
            description: "DoH 的 IP、域名或 HTTPS URL，例如 https://1.1.1.1/dns-query",
            options: &[],
        },
        Row {
            key: "ruleset_source",
            label: "下载 / 规则集源",
            description: "jsdelivr 默认直连 CDN；github 可配置镜像或 PROXY 下载",
            options: &["jsdelivr", "github"],
        },
        Row {
            key: "mirror_prefix",
            label: "下载 / GitHub 镜像前缀",
            description: "内核、面板和 GitHub 规则集下载加速，例如 https://ghproxy.net/",
            options: &[],
        },
        Row {
            key: "download_detour",
            label: "下载 / 下载出站",
            description: "sing-box 下载规则集和面板的出站，不影响 ssb 下载内核",
            options: &["direct", "PROXY"],
        },
        Row {
            key: "singbox_path",
            label: "内核 / sing-box 路径",
            description: "留空自动查找 data/sing-box 和 PATH；相对路径基于工作目录",
            options: &[],
        },
        Row {
            key: "log_level",
            label: "内核 / 日志级别",
            description: "warn 适合日常使用；排查时选择 info/debug",
            options: &["trace", "debug", "info", "warn", "error", "fatal", "panic"],
        },
        Row {
            key: "advanced_routing",
            label: "高级 / 自定义分流",
            description: "显示强制代理/直连域名设置，优先级高于内置中国规则",
            options: &["true", "false"],
        },
    ];
    if !cfg!(target_os = "linux") {
        rows.retain(|r| r.key != "auto_redirect");
    }
    if a.state.settings.advanced_routing {
        rows.extend([
            Row {
                key: "custom_proxy",
                label: "高级 / 强制代理域名",
                description: "逗号/空格分隔；example.com 包含子域名；.cn 只匹配后缀",
                options: &[],
            },
            Row {
                key: "custom_direct",
                label: "高级 / 强制直连域名",
                description: "逗号/空格分隔；example.com 包含子域名；.cn 只匹配后缀",
                options: &[],
            },
        ]);
    }
    rows
}
fn setting_value(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

fn setting_display(value: &Value, key: &str) -> String {
    let raw = setting_value(value, key);
    match (key, raw.as_str()) {
        ("route_mode", "rule") => "规则分流 · rule".into(),
        ("route_mode", "global") => "全局代理 · global".into(),
        ("ipv6", "auto") => "自动探测 · auto".into(),
        ("ipv6", "on") => "强制开启 · on".into(),
        ("ipv6", "off") => "仅 IPv4 · off".into(),
        ("download_detour", "direct") => "直连 · direct".into(),
        ("download_detour", "PROXY") => "当前代理 · PROXY".into(),
        (_, _) if value[key].is_boolean() => if (raw == "true") ^ (key == "dashboard_off") {
            "开"
        } else {
            "关"
        }
        .into(),
        (_, "") => "（空）".into(),
        _ => raw,
    }
}

// Indices refer to the unfiltered list, so actions always target the displayed row.
fn node_tags(nodes: &[link::Node]) -> Vec<String> {
    let mut tags = Vec::new();
    if !nodes.is_empty() {
        tags.push("auto".into());
    }
    tags.extend(nodes.iter().map(|n| n.tag.clone()));
    tags.push("direct".into());
    tags
}

struct Ui {
    app: App,
    tab: usize,
    cursor: [usize; 4],
    scroll: [usize; 4],
    query: [String; 4],
    log_scroll: usize,
    status: String,
    selected: String,
    message: String,
    error: bool,
    dirty: bool,
    help: bool,
    editor: Option<Editor>,
    submitted_editor: Option<Editor>,
    confirm: Option<(String, Operation)>,
    job: Option<Receiver<Finished>>,
    snapshot: Option<Receiver<Snapshot>>,
    last_snapshot: Instant,
    quit_pending: bool,
}
impl Ui {
    fn new(app: App) -> Self {
        Self {
            app,
            tab: 0,
            cursor: [0; 4],
            scroll: [0; 4],
            query: Default::default(),
            log_scroll: 0,
            status: "正在读取状态…".into(),
            selected: String::new(),
            message: String::new(),
            error: false,
            dirty: false,
            help: false,
            editor: None,
            submitted_editor: None,
            confirm: None,
            job: None,
            snapshot: None,
            last_snapshot: Instant::now() - Duration::from_secs(10),
            quit_pending: false,
        }
    }
    fn launch(&mut self, op: Operation) {
        if self.job.is_some() {
            return;
        }
        self.message = format!("{}…", op.label());
        self.error = false;
        let mut app = self.app.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let before = std::fs::read(app.dirs.config()).ok();
            let result = op.apply(&mut app);
            let changed = op.changes_config() && before != std::fs::read(app.dirs.config()).ok();
            let finished = Finished {
                app,
                result,
                changed,
                restart: matches!(op, Operation::Restart | Operation::Toggle),
            };
            let _ = tx.send(finished);
        });
        self.job = Some(rx);
    }
    fn tick(&mut self) {
        if let Some(rx) = &self.job {
            match rx.try_recv() {
                Ok(done) => {
                    self.app = done.app;
                    let success = done.result.is_ok();
                    match done.result {
                        Ok(m) => {
                            self.message = m;
                            self.error = false;
                        }
                        Err(e) => {
                            self.message = format!("{e:#}");
                            self.error = true;
                            self.editor = self.submitted_editor.take();
                        }
                    }
                    self.submitted_editor = None;
                    if done.changed && core::running(&self.app.dirs).is_some() {
                        self.dirty = true;
                    }
                    if done.restart && success {
                        self.dirty = false;
                    }
                    self.job = None;
                    // Any older snapshot is discarded before refreshing after a mutation.
                    self.snapshot = None;
                    self.last_snapshot = Instant::now() - Duration::from_secs(10);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.job = None;
                    self.error = true;
                    self.message = "后台操作意外退出".into();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.snapshot {
            match rx.try_recv() {
                Ok(snapshot) => {
                    if self.job.is_none() {
                        self.app = snapshot.app;
                        self.status = snapshot.status;
                        self.selected = snapshot.selected;
                    }
                    self.snapshot = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.snapshot = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.snapshot.is_none()
            && self.job.is_none()
            && self.last_snapshot.elapsed() >= Duration::from_secs(2)
        {
            let app = self.app.clone();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let app = App::open(&app.dirs.base).unwrap_or(app);
                let status = app.status_text();
                let selected = status
                    .lines()
                    .find_map(|l| l.strip_prefix("当前出口: "))
                    .unwrap_or_default()
                    .into();
                let _ = tx.send(Snapshot {
                    app,
                    status,
                    selected,
                });
            });
            self.snapshot = Some(rx);
            self.last_snapshot = Instant::now();
        }
        for tab in 1..4 {
            self.cursor[tab] = self.cursor[tab].min(self.len(tab).saturating_sub(1));
        }
    }
    fn len(&self, tab: usize) -> usize {
        self.visible_indices(tab).len()
    }
    fn query(&self, tab: usize) -> &str {
        if tab == self.tab {
            if let Some(editor) = &self.editor {
                if matches!(editor.kind, InputKind::Search) {
                    return &editor.text;
                }
            }
        }
        &self.query[tab]
    }
    fn visible_indices(&self, tab: usize) -> Vec<usize> {
        let query = self.query(tab).trim().to_lowercase();
        let matches = |text: String| text.to_lowercase().contains(&query);
        match tab {
            1 => self
                .app
                .state
                .subscriptions
                .iter()
                .enumerate()
                .filter(|(_, s)| matches(format!("{} {} {}", s.name, s.url, s.format)))
                .map(|(i, _)| i)
                .collect(),
            2 => {
                let nodes = self.app.state.all_nodes();
                let mut texts = vec![];
                if !nodes.is_empty() {
                    texts.push("auto 自动测速".into());
                }
                texts.extend(nodes.iter().map(|n| {
                    format!(
                        "{} {} {}",
                        n.tag,
                        link::string(&n.outbound, "type"),
                        link::string(&n.outbound, "server")
                    )
                }));
                texts.push("direct 直连".into());
                texts
                    .into_iter()
                    .enumerate()
                    .filter(|(_, text)| matches(text.clone()))
                    .map(|(i, _)| i)
                    .collect()
            }
            3 => setting_rows(&self.app)
                .iter()
                .enumerate()
                .filter(|(_, r)| matches(format!("{} {} {}", r.key, r.label, r.description)))
                .map(|(i, _)| i)
                .collect(),
            _ => vec![],
        }
    }
    fn selected_index(&self) -> Option<usize> {
        self.visible_indices(self.tab)
            .get(self.cursor[self.tab])
            .copied()
    }
    fn move_by(&mut self, n: isize) {
        if self.tab == 0 {
            self.log_scroll = self.log_scroll.saturating_add_signed(-n).min(300);
        } else {
            self.cursor[self.tab] = self.cursor[self.tab]
                .saturating_add_signed(n)
                .min(self.len(self.tab).saturating_sub(1));
        }
    }
    fn prompt(&mut self, kind: InputKind, label: &str, text: String) {
        self.editor = Some(Editor::new(kind, label.into(), text));
    }
    fn key(&mut self, k: KeyEvent) -> bool {
        let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
        if let Some(editor) = &mut self.editor {
            if k.code == KeyCode::Esc || ctrl_c {
                self.editor = None;
                return false;
            }
            if k.code == KeyCode::Enter {
                let editor = self.editor.as_ref().unwrap();
                // Validate before closing the editor, so corrections retain pasted input.
                let validation = match &editor.kind {
                    InputKind::Setting(key) => profile::set_setting(
                        &mut self.app.state.settings.clone(),
                        key,
                        &editor.text,
                    ),
                    InputKind::Nodes if link::parse_mixed(&editor.text).0.is_empty() => {
                        Err(anyhow::anyhow!("没有可解析的节点链接，请检查后重试"))
                    }
                    InputKind::Subscription => {
                        let url = editor.text.split_whitespace().next().unwrap_or_default();
                        url::Url::parse(url)
                            .map_err(anyhow::Error::from)
                            .and_then(|u| {
                                if matches!(u.scheme(), "http" | "https") && u.host_str().is_some()
                                {
                                    Ok(())
                                } else {
                                    bail!("订阅地址应为 HTTP/HTTPS URL")
                                }
                            })
                    }
                    _ => Ok(()),
                };
                if let Err(error) = validation {
                    self.message = format!("{error:#}");
                    self.error = true;
                    return false;
                }
                let editor = self.editor.take().unwrap();
                if matches!(editor.kind, InputKind::Setting(_)) {
                    self.submitted_editor = Some(editor.clone());
                }
                let op = match editor.kind {
                    InputKind::Search => {
                        self.query[self.tab] = editor.text;
                        return false;
                    }
                    InputKind::Nodes => Operation::AddNodes(editor.text),
                    InputKind::Subscription => {
                        let text = editor.text.trim();
                        let (url, name) = text
                            .split_once(char::is_whitespace)
                            .map(|(u, n)| (u, n.trim()))
                            .unwrap_or((text, ""));
                        Operation::AddSub(url.into(), name.into())
                    }
                    InputKind::Setting(key) => Operation::Setting(key, editor.text),
                };
                self.launch(op);
            } else {
                editor.key(k);
                if matches!(editor.kind, InputKind::Search) {
                    self.cursor[self.tab] = 0;
                    self.scroll[self.tab] = 0;
                }
            }
            return false;
        }
        if self.confirm.is_some() {
            let (_, op) = self.confirm.take().unwrap();
            if matches!(
                k.code,
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter
            ) {
                self.launch(op);
            }
            return false;
        }
        if ctrl_c || k.code == KeyCode::Char('q') {
            if self.job.is_some() {
                self.quit_pending = true;
                self.message = "操作完成后退出，sing-box 继续后台运行".into();
                return false;
            }
            return true;
        }
        if self.help {
            if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?')) {
                self.help = false;
            }
            return false;
        }
        match k.code {
            KeyCode::Char('?') => self.help = true,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.tab = (self.tab + 1) % 4,
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.tab = (self.tab + 3) % 4,
            KeyCode::Char(c @ '1'..='4') => self.tab = c as usize - '1' as usize,
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::PageDown => self.move_by(8),
            KeyCode::PageUp => self.move_by(-8),
            KeyCode::Char('d') if k.modifiers.contains(KeyModifiers::CONTROL) => self.move_by(8),
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => self.move_by(-8),
            KeyCode::Home => {
                self.cursor[self.tab] = 0;
                if self.tab == 0 {
                    self.log_scroll = 300;
                }
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.cursor[self.tab] = self.len(self.tab).saturating_sub(1);
                self.log_scroll = 0;
            }
            KeyCode::Esc => {
                self.query[self.tab].clear();
                self.cursor[self.tab] = 0;
                self.scroll[self.tab] = 0;
            }
            KeyCode::Char('/') if self.tab != 0 => self.prompt(
                InputKind::Search,
                "搜索 · Enter 保留 · Esc 取消",
                self.query[self.tab].clone(),
            ),
            _ if self.job.is_some() => {}
            KeyCode::Char('s') => self.launch(Operation::Toggle),
            KeyCode::Char('r') => self.launch(Operation::Restart),
            KeyCode::Char('g') => self.launch(Operation::Generate),
            KeyCode::Char('i') if self.tab == 0 => self.launch(Operation::Install),
            _ => self.tab_key(k),
        }
        false
    }
    fn tab_key(&mut self, k: KeyEvent) {
        let index = self.selected_index();
        if self.tab == 1 {
            let sub = index
                .and_then(|i| self.app.state.subscriptions.get(i))
                .cloned();
            match k.code {
                KeyCode::Char('a') => self.prompt(
                    InputKind::Subscription,
                    "订阅 URL，后面可空格加名称",
                    String::new(),
                ),
                KeyCode::Char('U') => self.launch(Operation::UpdateSub(String::new())),
                KeyCode::Enter | KeyCode::Char('u') => {
                    if let Some(s) = sub {
                        self.launch(Operation::UpdateSub(s.name));
                    }
                }
                KeyCode::Delete | KeyCode::Char('x') => {
                    if let Some(s) = sub {
                        self.confirm = Some((
                            format!("删除订阅 {} 和其 {} 个节点？", s.name, s.nodes.len()),
                            Operation::RemoveSub(s.name),
                        ));
                    }
                }
                _ => {}
            }
        } else if self.tab == 2 {
            let nodes = self.app.state.all_nodes();
            let tag = index.and_then(|i| node_tags(&nodes).get(i).cloned());
            match k.code {
                KeyCode::Char('a') => self.prompt(
                    InputKind::Nodes,
                    "分享链接 / 多条链接 / base64",
                    String::new(),
                ),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if let Some(tag) = tag {
                        if self.dirty {
                            self.message = "配置尚未应用，请按 r 重启后切换出口".into();
                            self.error = true;
                        } else {
                            self.launch(Operation::Select(tag));
                        }
                    }
                }
                KeyCode::Delete | KeyCode::Char('x') => {
                    let Some(tag) = tag else {
                        return;
                    };
                    let Some(index) = nodes.iter().position(|n| n.tag == tag) else {
                        return;
                    };
                    let manual = self
                        .app
                        .state
                        .manual_nodes
                        .iter()
                        .filter(|n| n.outbound.is_object())
                        .count();
                    if index < manual {
                        self.confirm =
                            Some((format!("删除节点 {tag}？"), Operation::RemoveNode(tag)));
                    } else {
                        self.message = "这是订阅节点，请到订阅页更新或删除整个订阅".into();
                        self.error = true;
                    }
                }
                _ => {}
            }
        } else if self.tab == 3 {
            let rows = setting_rows(&self.app);
            let Some(row) = index.and_then(|i| rows.get(i)) else {
                return;
            };
            if matches!(
                k.code,
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('e') | KeyCode::Backspace
            ) {
                let settings = serde_json::to_value(&self.app.state.settings).unwrap();
                let value = setting_value(&settings, row.key);
                if row.options.is_empty() || k.code == KeyCode::Char('e') {
                    if k.code != KeyCode::Backspace {
                        self.prompt(
                            InputKind::Setting(row.key.into()),
                            &format!("{} · {}", row.label, row.key),
                            value,
                        );
                    }
                } else {
                    let position = row.options.iter().position(|v| *v == value).unwrap_or(0);
                    let next = if k.code == KeyCode::Backspace {
                        (position + row.options.len() - 1) % row.options.len()
                    } else {
                        (position + 1) % row.options.len()
                    };
                    self.launch(Operation::Setting(row.key.into(), row.options[next].into()));
                }
            }
        }
    }
    fn details(&self, compact: bool) -> String {
        let Some(index) = self.selected_index() else {
            return "没有匹配项\n\n按 / 修改搜索，Esc 清除筛选".into();
        };
        match self.tab {
            1 => {
                let s = &self.app.state.subscriptions[index];
                if compact {
                    return format!(
                        "{} · {} 节点 · {}\n更新：{}\n{}",
                        s.name,
                        s.nodes.len(),
                        s.format,
                        if s.updated_at.is_empty() {
                            "从未更新"
                        } else {
                            &s.updated_at
                        },
                        s.url
                    );
                }
                format!("{}\n\n格式：{}\n节点：{}\n更新：{}\n\n{}\n\nEnter 更新此订阅 · U 更新全部\nx 删除订阅及其节点", s.name,
                    if s.format.is_empty() { "尚未识别" } else { &s.format }, s.nodes.len(),
                    if s.updated_at.is_empty() { "从未更新" } else { &s.updated_at }, s.url)
            }
            2 => {
                let nodes = self.app.state.all_nodes();
                let tags = node_tags(&nodes);
                let tag = &tags[index];
                if let Some(n) = nodes.iter().find(|n| n.tag == *tag) {
                    let manual = self
                        .app
                        .state
                        .manual_nodes
                        .iter()
                        .filter(|n| n.outbound.is_object())
                        .count();
                    let position = nodes.iter().position(|n| n.tag == *tag).unwrap();
                    let source = if position < manual {
                        "手动添加".into()
                    } else {
                        let mut offset = position - manual;
                        self.app
                            .state
                            .subscriptions
                            .iter()
                            .find_map(|s| {
                                let count =
                                    s.nodes.iter().filter(|n| n.outbound.is_object()).count();
                                if offset < count {
                                    Some(format!("订阅 · {}", s.name))
                                } else {
                                    offset -= count;
                                    None
                                }
                            })
                            .unwrap_or_else(|| "订阅".into())
                    };
                    if compact {
                        format!(
                            "{tag} · {}\n服务器：{} · 端口：{}\n来源：{source}",
                            link::string(&n.outbound, "type"),
                            link::string(&n.outbound, "server"),
                            n.outbound["server_port"]
                        )
                    } else {
                        format!("{tag}\n\n协议：{}\n服务器：{}\n端口：{}\n来源：{source}\n\nEnter / 空格 立即切换\n切换结果由运行中内核保存", link::string(&n.outbound, "type"), link::string(&n.outbound, "server"), n.outbound["server_port"])
                    }
                } else if tag == "auto" {
                    "自动测速 · auto\n\n由 urltest 每 3 分钟检测节点，容差 50ms，自动选择低延迟出口。\n\nEnter / 空格 切换到自动选择".into()
                } else {
                    "直连 · direct\n\nPROXY 分组直接连接目标，不经过代理节点。\n\nEnter / 空格 切换到直连".into()
                }
            }
            3 => {
                let rows = setting_rows(&self.app);
                let r = &rows[index];
                let settings = serde_json::to_value(&self.app.state.settings).unwrap();
                let schema = match r.key {
                    "route_mode" | "custom_proxy" | "custom_direct" => {
                        "route.rules / route.final + dns.rules"
                    }
                    "tun_enabled" => "inbounds[].type = tun",
                    "tun_address" => "inbounds[tun].address",
                    "auto_redirect" => "inbounds[tun].auto_redirect",
                    "ipv6" => "TUN address / DNS AAAA 查询策略",
                    "fakeip" => "dns.servers[].type = fakeip",
                    "mixed_enabled" => "inbounds[].type = mixed",
                    "mixed_port" => "inbounds[mixed].listen_port",
                    "api_listen" => "services[api].listen / listen_port",
                    "api_secret" => "services[api].secret",
                    "dashboard_off" => "services[api].dashboard.enabled（取反）",
                    "dns_cn" => "dns.servers[dns-cn] · UDP",
                    "dns_proxy" => "dns.servers[dns-proxy] · HTTPS",
                    "download_detour" => "http_clients[http-download].detour",
                    "ruleset_source" => "route.rule_set[].url",
                    "log_level" => "log.level",
                    _ => "ssb 管理设置",
                };
                let note = match r.key {
                    "auto_redirect" | "tun_address" if !self.app.state.settings.tun_enabled => {
                        "\n\n当前 TUN 已关闭，此项暂不生效。"
                    }
                    "mixed_enabled" if !self.app.state.settings.tun_enabled => {
                        "\n\n当前 TUN 已关闭，mixed 入站仍会保留。"
                    }
                    "ruleset_source" if self.app.state.settings.route_mode == "global" => {
                        "\n\n当前为 global 模式，不下载中国规则集。"
                    }
                    _ => "",
                };
                if compact {
                    format!(
                        "{} · {}\n{}{}",
                        r.key,
                        setting_display(&settings, r.key),
                        r.description,
                        note
                    )
                } else {
                    format!("{}\n{}\n\n当前：{}\n\n{}{}\n\n配置：{}\n\nEnter / 空格 轮转 · e 编辑\nBackspace 反向 · 保存后按 r 应用", r.label, r.key, setting_display(&settings, r.key), r.description, note, schema)
                }
            }
            _ => String::new(),
        }
    }
    fn draw(&mut self, f: &mut Frame) {
        let regions = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .split(f.area());
        let mut title = format!("ssb {}", crate::VERSION);
        if core::running(&self.app.dirs).is_some() {
            title.push_str("  ● 运行中");
            if !self.selected.is_empty() {
                title.push_str(&format!(" · {}", self.selected));
            }
        } else {
            title.push_str("  ○ 未运行");
        }
        if self.dirty {
            title.push_str("  配置有改动，按 r 重启生效");
        }
        f.render_widget(
            Tabs::new(["1 状态", "2 订阅", "3 节点", "4 设置"])
                .select(self.tab)
                .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .block(Block::default().title(title).borders(Borders::ALL)),
            regions[0],
        );
        if self.help {
            f.render_widget(
                Paragraph::new(HELP)
                    .wrap(Wrap { trim: false })
                    .block(Block::default().title("全部按键").borders(Borders::ALL)),
                regions[1],
            );
        } else if self.tab == 0 {
            let status_lines = self.status.lines().count() as u16;
            let areas = Layout::vertical([
                Constraint::Length(status_lines.min(regions[1].height.saturating_sub(4))),
                Constraint::Min(1),
            ])
            .split(regions[1]);
            f.render_widget(
                Paragraph::new(self.status.as_str()).wrap(Wrap { trim: false }),
                areas[0],
            );
            let logs = core::tail(&self.app.dirs, 500);
            let lines: Vec<_> = logs.lines().collect();
            let visible = areas[1].height.saturating_sub(2) as usize;
            let end = lines
                .len()
                .saturating_sub(self.log_scroll.min(lines.len().saturating_sub(visible)));
            let start = end.saturating_sub(visible);
            let text: Vec<Line> = lines[start..end]
                .iter()
                .map(|line| {
                    Line::styled(
                        core::strip_ansi(line),
                        Style::default().fg(if line.contains("ERROR") || line.contains("FATAL") {
                            Color::Red
                        } else if line.contains("WARN") {
                            Color::Yellow
                        } else {
                            Color::Gray
                        }),
                    )
                })
                .collect();
            f.render_widget(
                Paragraph::new(text).block(
                    Block::default()
                        .title("日志 · i 下载内核 · j/k 翻日志")
                        .borders(Borders::ALL),
                ),
                areas[1],
            );
        } else {
            let body = regions[1];
            let (list_area, detail_area) = if body.width >= 110 {
                let parts =
                    Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                        .split(body);
                (parts[0], Some(parts[1]))
            } else if body.height >= 16 {
                let parts =
                    Layout::vertical([Constraint::Min(6), Constraint::Length(7)]).split(body);
                (parts[0], Some(parts[1]))
            } else {
                (body, None)
            };
            if let Some(area) = detail_area {
                f.render_widget(
                    Paragraph::new(self.details(body.width < 110))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .title("详情 · sing-box 1.14+")
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(Color::DarkGray)),
                        ),
                    area,
                );
            }
            let mut items = vec![];
            match self.tab {
                1 => {
                    for s in &self.app.state.subscriptions {
                        let traffic = s
                            .userinfo
                            .as_ref()
                            .filter(|u| u.total > 0)
                            .map(|u| {
                                let mut t = format!(
                                    " · 流量 {}/{}",
                                    subscription::human_bytes(u.upload + u.download),
                                    subscription::human_bytes(u.total)
                                );
                                if let Some(expiry) = chrono::DateTime::from_timestamp(u.expire, 0)
                                    .filter(|_| u.expire > 0)
                                {
                                    t.push_str(&format!(" · 到期 {}", expiry.format("%Y-%m-%d")));
                                }
                                t
                            })
                            .unwrap_or_default();
                        items.push(ListItem::new(vec![
                            Line::from(format!(
                                "{}  {} 节点 · {}{}",
                                s.name,
                                s.nodes.len(),
                                if s.updated_at.is_empty() {
                                    "从未更新"
                                } else {
                                    &s.updated_at
                                },
                                traffic
                            )),
                            Line::styled(
                                format!("  {}", s.url),
                                Style::default().fg(Color::DarkGray),
                            ),
                        ]));
                    }
                }
                2 => {
                    let nodes = self.app.state.all_nodes();
                    let marker = |tag: &str| if self.selected == tag { "●" } else { " " };
                    if !nodes.is_empty() {
                        items.push(ListItem::new(format!(
                            "{} auto  自动测速，选择低延迟节点",
                            marker("auto")
                        )));
                    }
                    let manual = self
                        .app
                        .state
                        .manual_nodes
                        .iter()
                        .filter(|n| n.outbound.is_object())
                        .count();
                    for (i, n) in nodes.iter().enumerate() {
                        items.push(ListItem::new(format!(
                            "{} {}  [{}] {}  {}",
                            marker(&n.tag),
                            n.tag,
                            if i < manual { "手动" } else { "订阅" },
                            link::string(&n.outbound, "type"),
                            link::string(&n.outbound, "server")
                        )));
                    }
                    items.push(ListItem::new(format!(
                        "{} direct  直接连接",
                        marker("direct")
                    )));
                }
                3 => {
                    let settings = serde_json::to_value(&self.app.state.settings).unwrap();
                    for row in setting_rows(&self.app) {
                        let display = setting_display(&settings, row.key);
                        items.push(ListItem::new(Line::from(vec![
                            Span::raw(format!("{}  ", row.label)),
                            Span::styled(display, Style::default().fg(Color::Yellow)),
                        ])));
                    }
                }
                _ => {}
            }
            let visible = self.visible_indices(self.tab);
            let total = items.len();
            let items: Vec<_> = items
                .into_iter()
                .enumerate()
                .filter(|(i, _)| visible.binary_search(i).is_ok())
                .map(|(_, item)| item)
                .collect();
            let query = self.query(self.tab);
            let title = if query.is_empty() {
                format!(
                    " {} · {} 项 · / 搜索 ",
                    ["状态", "订阅", "节点", "设置"][self.tab],
                    total
                )
            } else {
                format!(" 搜索：{} · {}/{} · Esc 清除 ", query, items.len(), total)
            };
            if items.is_empty() {
                f.render_widget(
                    Paragraph::new(if query.is_empty() {
                        "还没有订阅，按 a 添加订阅 URL"
                    } else {
                        "没有匹配项，按 / 修改搜索或 Esc 清除筛选"
                    })
                    .block(Block::default().title(title).borders(Borders::ALL)),
                    list_area,
                );
            } else {
                self.cursor[self.tab] = self.cursor[self.tab].min(items.len() - 1);
                let mut list_state = ListState::default()
                    .with_offset(self.scroll[self.tab])
                    .with_selected(Some(self.cursor[self.tab]));
                f.render_stateful_widget(
                    List::new(items)
                        .highlight_symbol("▸ ")
                        .highlight_style(
                            Style::default()
                                .bg(Color::DarkGray)
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        )
                        .block(Block::default().title(title).borders(Borders::ALL)),
                    list_area,
                    &mut list_state,
                );
                self.scroll[self.tab] = list_state.offset();
            }
        }
        let hint = match self.tab {
            1 => "a 添加 · Enter/u 更新 · U 全部更新 · x 删除 · / 搜索 · ? 帮助 · q 退出",
            2 => "a 添加 · Enter 切换出口 · x 删除 · / 搜索 · r 应用配置 · ? 帮助 · q 退出",
            3 => "Enter/空格 轮转 · e 编辑 · / 搜索 · r 应用配置 · ? 帮助 · q 退出",
            _ => "1–4/Tab 页签 · s 启停 · r 应用配置 · g 校验配置 · ? 帮助 · q 退出",
        };
        let message = if self.message.is_empty()
            && self.tab == 3
            && regions[1].height < 16
            && regions[1].width < 110
        {
            self.selected_index()
                .and_then(|i| {
                    setting_rows(&self.app)
                        .get(i)
                        .map(|r| r.description.to_string())
                })
                .unwrap_or_default()
        } else {
            self.message.replace('\n', " ⏎ ")
        };
        let message = if self.job.is_some() {
            format!("◌ {message}")
        } else {
            message
        };
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    message,
                    Style::default().fg(if self.error { Color::Red } else { Color::Green }),
                ),
                Line::styled(hint, Style::default().fg(Color::DarkGray)),
            ])
            .block(Block::default().borders(Borders::TOP)),
            regions[2],
        );
        if let Some(editor) = &self.editor {
            let area = if matches!(editor.kind, InputKind::Search) {
                regions[2]
            } else {
                popup(f.area(), 7)
            };
            f.render_widget(Clear, area);
            let text = editor.viewport(area.width.saturating_sub(3) as usize);
            f.render_widget(
                Paragraph::new(format!("{text}\n\nEnter 确认 · Esc 取消 · Ctrl-U 清空"))
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .title(editor.label.as_str())
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(ACCENT)),
                    ),
                area,
            );
        }
        if let Some((question, _)) = &self.confirm {
            let area = popup(f.area(), 5);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(format!("{question}\n\ny/Enter 确认 · 其他键取消"))
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .title("确认删除")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Yellow)),
                    ),
                area,
            );
        }
    }
}
fn popup(area: Rect, height: u16) -> Rect {
    let width = area.width.saturating_sub(4).max(1).min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

pub fn run(mut app: App) -> Result<()> {
    if !app.dirs.state().exists() {
        let _guard = app.lock()?;
        app.save()?;
    }
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut ui = Ui::new(app);
    loop {
        ui.tick();
        if ui.quit_pending && ui.job.is_none() {
            break;
        }
        terminal.draw(|f| ui.draw(f))?;
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if ui.key(k) {
                        break;
                    }
                }
                Event::Paste(text) => {
                    if let Some(editor) = &mut ui.editor {
                        if editor.text.len() + text.len() <= 16 << 20 {
                            editor.insert(&text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn press(ui: &mut Ui, code: KeyCode) {
        assert!(!ui.key(KeyEvent::new(code, KeyModifiers::NONE)));
    }
    #[test]
    fn search_maps_actions_to_visible_rows_and_ignores_empty_matches() {
        let temp = tempfile::tempdir().unwrap();
        let mut ui = Ui::new(App::open(temp.path()).unwrap());
        ui.app.state.manual_nodes = ["香港一", "Tokyo", "香港二"]
            .iter()
            .map(|tag| link::parse(&format!("trojan://p@a.test:443#{tag}")).unwrap())
            .collect();
        ui.tab = 2;
        press(&mut ui, KeyCode::Char('/'));
        for c in "香港二".chars() {
            press(&mut ui, KeyCode::Char(c));
        }
        assert_eq!(ui.len(2), 1); // Live search before Enter.
        press(&mut ui, KeyCode::Enter);
        press(&mut ui, KeyCode::Char('x'));
        assert!(matches!(&ui.confirm, Some((_, Operation::RemoveNode(tag))) if tag == "香港二"));
        press(&mut ui, KeyCode::Esc);
        ui.query[2] = "no match".into();
        press(&mut ui, KeyCode::Enter);
        assert!(ui.job.is_none());
        press(&mut ui, KeyCode::Esc);
        assert_eq!(ui.len(2), 5);

        ui.tab = 3;
        ui.query[3] = "mixed_port".into();
        press(&mut ui, KeyCode::Char('e'));
        assert!(
            matches!(&ui.editor, Some(e) if matches!(&e.kind, InputKind::Setting(key) if key == "mixed_port"))
        );
        ui.editor.as_mut().unwrap().text = "0".into();
        press(&mut ui, KeyCode::Enter);
        assert!(ui.error);
        assert_eq!(ui.editor.as_ref().unwrap().text, "0");
        assert!(ui.job.is_none());
        assert_eq!(ui.app.state.settings.mixed_port, 2080);

        ui.editor = None;
        ui.tab = 1;
        ui.app.state.subscriptions = ["first", "second"]
            .iter()
            .map(|name| profile::Subscription {
                name: (*name).into(),
                ..Default::default()
            })
            .collect();
        ui.query[1] = "SECOND".into();
        press(&mut ui, KeyCode::Delete);
        assert!(matches!(&ui.confirm, Some((_, Operation::RemoveSub(name))) if name == "second"));
    }
    #[test]
    fn empty_nodes_match_selector_and_dirty_config_blocks_selection() {
        let temp = tempfile::tempdir().unwrap();
        let mut ui = Ui::new(App::open(temp.path()).unwrap());
        assert_eq!(node_tags(&ui.app.state.all_nodes()), vec!["direct"]);
        ui.tab = 2;
        ui.dirty = true;
        press(&mut ui, KeyCode::Enter);
        assert!(ui.job.is_none());
        assert!(ui.message.contains("重启"));
    }
    #[cfg(unix)]
    #[test]
    fn failed_core_check_keeps_previous_settings_and_config() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let mut app = App::open(temp.path()).unwrap();
        app.dirs.ensure().unwrap();
        let checker = temp.path().join("checker");
        std::fs::write(&checker, "#!/bin/sh\necho invalid >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&checker, std::fs::Permissions::from_mode(0o755)).unwrap();
        app.state.settings.singbox_path = checker.to_string_lossy().into();
        app.save().unwrap();
        std::fs::write(app.dirs.config(), "old config").unwrap();
        let before = std::fs::read(app.dirs.state()).unwrap();
        assert!(Operation::Setting("mixed_port".into(), "2081".into())
            .apply(&mut app)
            .is_err());
        assert_eq!(app.state.settings.mixed_port, 2080);
        assert_eq!(std::fs::read(app.dirs.state()).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(app.dirs.config()).unwrap(),
            "old config"
        );
    }
    #[test]
    fn unicode_editor_preserves_character_boundaries() {
        let mut e = Editor::new(InputKind::Nodes, "".into(), "香港😀".into());
        e.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        e.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        e.insert("京");
        assert_eq!(e.text, "香京😀");
        e.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(e.text, "香京");
        assert_eq!(e.viewport(4), "京▏"); // Each Chinese character occupies two cells.
    }
    #[test]
    fn four_tabs_render_in_small_and_normal_terminals() {
        let temp = tempfile::tempdir().unwrap();
        let app = App::open(temp.path()).unwrap();
        for (w, h) in [(140, 35), (100, 30), (20, 8), (1, 1)] {
            let backend = ratatui::backend::TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut ui = Ui::new(app.clone());
            for tab in 0..4 {
                ui.tab = tab;
                terminal.draw(|f| ui.draw(f)).unwrap();
            }
            ui.editor = Some(Editor::new(
                InputKind::Nodes,
                "链接".into(),
                "vless://用户@地址".into(),
            ));
            terminal.draw(|f| ui.draw(f)).unwrap();
            ui.editor = None;
            ui.confirm = Some(("确认？".into(), Operation::Generate));
            terminal.draw(|f| ui.draw(f)).unwrap();
            ui.confirm = None;
            ui.query[3] = "nothing matches".into();
            ui.tab = 3;
            terminal.draw(|f| ui.draw(f)).unwrap();
        }
    }
}
