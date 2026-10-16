use anyhow::{bail, Context, Result};
use ssb::{
    app::{self, App},
    core, profile, subscription, tui,
};
use std::{
    fs,
    io::{self, IsTerminal, Read, Seek, SeekFrom, Write},
    thread,
    time::Duration,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("错误: {e:#}");
        std::process::exit(1);
    }
}
fn usage() {
    println!(
        "ssb {} — sing-box 节点/订阅管理器（Rust）\n\
用法: ssb [--dir 目录] [命令]\n\
  (无命令)              进入 TUI\n\
  add <链接...>         添加节点，也支持 stdin / base64 链接列表\n\
  sub add <URL> [名称]  添加订阅并拉取\n\
  sub update [名称]     更新指定或全部订阅\n\
  sub rm <名称> | ls    删除 / 列出订阅\n\
  nodes [rm <tag>]      列出 / 删除手动节点\n\
  gen                   生成 config.json，并用 sing-box check 校验\n\
  install               下载 sing-box 到 data/\n\
  start|stop|restart    启停后台内核\n\
  run-core              前台运行（Docker / 调试）\n\
  status                运行状态\n\
  logs [-f]             查看 / 跟随日志\n\
  dashboard             打印 Dashboard 地址与 secret\n\
  doctor                环境体检\n\
  settings [set <键> <值>]  查看 / 修改设置（额外 CLI 入口）\n\
  select <tag>          运行时切换节点（额外 CLI 入口）\n\
  version | help        版本 / 帮助\n\
环境变量: SSB_DIR；目录优先级: --dir > SSB_DIR > 可执行文件所在目录",
        ssb::VERSION
    );
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut rest = vec![];
    let mut dir = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" {
            i += 1;
            dir = Some(args.get(i).context("--dir 缺少目录参数")?.clone());
        } else if let Some(value) = args[i].strip_prefix("--dir=") {
            if value.is_empty() {
                bail!("--dir 缺少目录参数");
            }
            dir = Some(value.into());
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    let cmd = rest.first().map(String::as_str).unwrap_or_default();
    if matches!(cmd, "help" | "-h" | "--help") {
        usage();
        return Ok(());
    }
    if matches!(cmd, "version" | "--version" | "-V") {
        println!("ssb {} (Rust)", ssb::VERSION);
        return Ok(());
    }
    let mut a = App::open(app::resolve_base(dir.as_deref())?)?;
    if cmd.is_empty() {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("TUI 需要交互终端；使用 ssb help 查看 CLI 命令");
        }
        return tui::run(a);
    }
    let args = &rest[1..];
    let arg = |n: usize, hint: &str| -> Result<&str> {
        args.get(n)
            .map(String::as_str)
            .with_context(|| format!("用法: {hint}"))
    };
    let mutating = matches!(
        cmd,
        "add" | "gen" | "install" | "start" | "stop" | "restart" | "run-core" | "select"
    ) || (cmd == "sub" && args.first().is_some_and(|x| x != "ls"))
        || (cmd == "nodes" && !args.is_empty())
        || (cmd == "settings" && !args.is_empty());
    let _guard = if mutating { Some(a.lock()?) } else { None };
    match cmd {
        "add" => {
            let text = if args.is_empty() {
                if io::stdin().is_terminal() {
                    bail!("请提供链接参数或从 stdin 输入");
                }
                let mut text = String::new();
                io::stdin().take(16 << 20).read_to_string(&mut text)?;
                text
            } else {
                args.join("\n")
            };
            let (n, errors) = a.add_nodes(&text)?;
            for e in errors {
                eprintln!("跳过: {e}");
            }
            println!("已添加 {n} 个节点");
            regen(&a)?;
        }
        "sub" => match arg(0, "ssb sub add|update|rm|ls")? {
            "add" => {
                let s = a.sub_add(
                    args.get(2).map(String::as_str).unwrap_or_default(),
                    arg(1, "ssb sub add <URL> [名称]")?,
                )?;
                println!("✓ {}: {} 个节点 ({})", s.name, s.nodes.len(), s.format);
                regen(&a)?;
            }
            "update" => {
                let (report, failed) =
                    a.sub_update(args.get(1).map(String::as_str).unwrap_or_default())?;
                for line in report {
                    println!("{line}");
                }
                regen(&a)?;
                if failed {
                    bail!("部分订阅更新失败，已保留其原节点");
                }
            }
            "rm" => {
                a.sub_remove(arg(1, "ssb sub rm <名称>")?)?;
                println!("已删除");
                regen(&a)?;
            }
            "ls" => {
                if a.state.subscriptions.is_empty() {
                    println!("（无订阅）");
                }
                for s in &a.state.subscriptions {
                    let info = s
                        .userinfo
                        .as_ref()
                        .filter(|u| u.total > 0)
                        .map(|u| {
                            format!(
                                " 流量 {}/{}",
                                subscription::human_bytes(u.upload + u.download),
                                subscription::human_bytes(u.total)
                            )
                        })
                        .unwrap_or_default();
                    println!(
                        "{}  {} 节点  更新于 {}{}\n  {}",
                        s.name,
                        s.nodes.len(),
                        if s.updated_at.is_empty() {
                            "从未"
                        } else {
                            &s.updated_at
                        },
                        info,
                        s.url
                    );
                }
            }
            unknown => bail!("未知子命令 sub {unknown}"),
        },
        "nodes" => {
            if !args.is_empty() {
                if args[0] != "rm" {
                    bail!("用法: ssb nodes [rm <tag>]");
                }
                a.remove_manual(arg(1, "ssb nodes rm <tag>")?)?;
                println!("已删除");
                regen(&a)?;
            } else {
                let nodes = a.state.all_nodes();
                if nodes.is_empty() {
                    println!("（无节点，用 ssb add 或 ssb sub add 添加）");
                }
                let manual_count = a
                    .state
                    .manual_nodes
                    .iter()
                    .filter(|n| n.outbound.is_object())
                    .count();
                for (i, n) in nodes.iter().enumerate() {
                    println!(
                        "{} {}  {}  {}",
                        if i < manual_count { "M" } else { " " },
                        n.tag,
                        ssb::link::string(&n.outbound, "type"),
                        ssb::link::string(&n.outbound, "server")
                    );
                }
            }
        }
        "gen" => regen(&a)?,
        "install" => {
            println!("{}", a.install()?);
            println!("版本: {}", core::version(&a.dirs.binary())?);
        }
        "start" => {
            a.start()?;
            println!("已启动");
            dashboard(&a);
        }
        "stop" => {
            a.stop()?;
            println!("已停止");
        }
        "restart" => {
            a.restart()?;
            println!("已重启");
        }
        "run-core" => a.run_core()?,
        "status" => print!("{}", a.status_text()),
        "dashboard" => dashboard(&a),
        "logs" => {
            if args.len() > 1 || args.first().is_some_and(|s| s != "-f") {
                bail!("用法: ssb logs [-f]");
            }
            print_logs(&a, !args.is_empty())?;
        }
        "doctor" => {
            let checks = core::doctor(&a.dirs, &a.state);
            let failed = checks.iter().any(|c| !c.ok);
            for c in checks {
                println!("{} {}: {}", if c.ok { "✓" } else { "✗" }, c.name, c.detail);
            }
            if failed {
                bail!("体检发现上述问题");
            }
        }
        "settings" => {
            if args.is_empty() {
                println!("{}", serde_json::to_string_pretty(&a.state.settings)?);
            } else {
                if args[0] != "set" || args.len() != 3 {
                    bail!("用法: ssb settings set <键> <值>");
                }
                profile::set_setting(&mut a.state.settings, &args[1], &args[2])?;
                a.save()?;
                regen(&a)?;
            }
        }
        "select" => {
            let tag = arg(0, "ssb select <tag>")?;
            a.select_node(tag)?;
            println!("当前出口: {tag}");
        }
        _ => {
            usage();
            bail!("未知命令 {cmd:?}");
        }
    }
    Ok(())
}
fn regen(a: &App) -> Result<()> {
    let warn = a.generate()?;
    if warn.is_empty() {
        println!(
            "config.json 已生成并通过校验: {}",
            a.dirs.config().display()
        );
    } else {
        eprintln!("警告: {warn}");
        println!("config.json 已生成: {}", a.dirs.config().display());
    }
    if core::running(&a.dirs).is_some() {
        println!(
            "提示: sing-box 正在运行，执行 {} restart 使新配置生效",
            core::SELF
        );
    }
    Ok(())
}
fn dashboard(a: &App) {
    if a.state.settings.dashboard_off {
        println!("Dashboard 网页面板已关闭（TUI 节点页可直接切换节点）");
    } else {
        println!(
            "地址: {}\nsecret: {}",
            a.dashboard_url(),
            a.state.settings.api_secret
        );
    }
}
fn print_logs(a: &App, follow: bool) -> Result<()> {
    let mut file = fs::File::open(a.dirs.log()).context("暂无日志")?;
    loop {
        io::copy(&mut file, &mut io::stdout())?;
        io::stdout().flush()?;
        if !follow {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
        // Reopen after start-time rotation; seek back when the file is truncated.
        if file.metadata()?.len() < file.stream_position()? {
            file.seek(SeekFrom::Start(0))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(a.dirs.log())
                .is_ok_and(|m| m.ino() != file.metadata().map(|m| m.ino()).unwrap_or_default())
            {
                file = fs::File::open(a.dirs.log())?;
            }
        }
    }
}
