use ssb::{app::App, core, profile, subscription};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn serve_replies(
    replies: Vec<(&'static str, &'static str)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/sub", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = vec![];
        for (headers, body) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = vec![];
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            requests.push(String::from_utf8(request).unwrap());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        requests
    });
    (url, handle)
}
#[test]
fn subscription_ua_fallback_and_traffic_headers() {
    let headers =
        "subscription-userinfo: upload=100; download=200; total=1073741824; expire=1893456000\r\n";
    let (url,server) = serve_replies(vec![(headers,"invalid content"),(headers,"proxies:\n - {name: test, type: anytls, server: example.com, port: 443, password: pass}\n")]);
    let result = subscription::fetch(&url).unwrap();
    assert_eq!(result.format, "clash");
    assert_eq!(result.nodes.len(), 1);
    let u = result.userinfo.unwrap();
    assert_eq!(u.total, 1073741824);
    assert_eq!(u.upload + u.download, 300);
    let requests = server.join().unwrap();
    assert!(requests[0].contains("sing-box/1.14.0"));
    assert!(requests[1].contains("clash.meta/1.19.0"));
}
#[test]
fn failed_updates_keep_last_successful_nodes_and_timestamp() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    let (url, server) = serve_replies(vec![
        ("", "trojan://pass@example.com:443#cached"),
        ("", "invalid"),
        ("", "invalid"),
        ("", "invalid"),
    ]);
    let s = a.sub_add("airport", &url).unwrap();
    let timestamp = s.updated_at.clone();
    let (report, failed) = a.sub_update("airport").unwrap();
    assert!(failed);
    assert!(report[0].contains("✗"));
    assert_eq!(a.state.subscriptions[0].nodes[0].tag, "cached");
    assert_eq!(a.state.subscriptions[0].updated_at, timestamp);
    server.join().unwrap();
    let restored = App::open(tmp.path()).unwrap();
    assert_eq!(restored.state.subscriptions[0].nodes.len(), 1);
}
#[test]
fn named_subscription_errors_and_failed_add_preserves_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    assert!(a.sub_add("bad", "file:///etc/passwd").is_err());
    assert_eq!(a.state.subscriptions.len(), 1);
    assert!(a.state.subscriptions[0].nodes.is_empty());
    assert!(a.sub_add("bad", "https://example.test/").is_err());
    assert!(a.sub_update("missing").is_err());
    assert!(a.sub_remove("missing").is_err());
}
#[test]
fn operation_lock_reloads_disk_state_and_rejects_concurrent_writers() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    let mut b = a.clone();
    let guard = a.lock().unwrap();
    a.add_nodes("trojan://p@example.test:443#one").unwrap();
    assert!(b.lock().is_err());
    drop(guard);
    let _guard = b.lock().unwrap();
    assert_eq!(b.state.manual_nodes.len(), 1);
    b.add_nodes("trojan://p@example.test:443#two").unwrap();
    assert_eq!(App::open(tmp.path()).unwrap().state.manual_nodes.len(), 2);
}
#[test]
fn removing_disambiguated_manual_nodes_preserves_subscriptions() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    a.add_nodes("trojan://p@a.test:443#same\ntrojan://p@b.test:443#same")
        .unwrap();
    a.state.subscriptions.push(profile::Subscription {
        name: "s".into(),
        nodes: vec![ssb::link::parse("trojan://p@c.test:443#sub-node").unwrap()],
        ..Default::default()
    });
    a.save().unwrap();
    a.remove_manual("same #2").unwrap();
    assert_eq!(a.state.manual_nodes.len(), 1);
    assert_eq!(a.state.manual_nodes[0].outbound["server"], "a.test");
    assert!(a.remove_manual("sub-node").is_err());
    assert_eq!(a.state.subscriptions[0].nodes.len(), 1);
}
#[test]
fn core_api_parser_and_asset_names() {
    assert_eq!(core::asset_suffix("linux", "x86_64"), "-linux-amd64.tar.gz");
    assert_eq!(
        core::asset_suffix("windows", "aarch64"),
        "-windows-arm64.zip"
    );
    assert_eq!(
        core::parse_selected("Name: PROXY\n\x1b[32mSelected: 香港 01\x1b[0m\n"),
        "香港 01"
    );
    assert_eq!(core::parse_selected("Selected: -"), "");
    assert_eq!(core::api_address("0.0.0.0:9090"), "127.0.0.1:9090");
    assert_eq!(core::api_address("[::]:9090"), "[::1]:9090");
}
#[test]
fn zip_extraction_copies_exe_and_dll_without_extracting_other_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let d = profile::Dirs::new(tmp.path()).unwrap();
    let mut data = std::io::Cursor::new(vec![]);
    {
        let mut zip = zip::ZipWriter::new(&mut data);
        for (path, content) in [
            ("bundle/sing-box.exe", "exe"),
            ("bundle/libcronet.dll", "dll"),
            ("../../outside.txt", "ignored"),
        ] {
            zip.start_file(path, zip::write::FileOptions::default())
                .unwrap();
            zip.write_all(content.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }
    core::extract_archive(&d, data.get_ref(), true).unwrap();
    assert_eq!(
        std::fs::read(d.data().join("sing-box.exe")).unwrap(),
        b"exe"
    );
    assert_eq!(
        std::fs::read(d.data().join("libcronet.dll")).unwrap(),
        b"dll"
    );
    assert!(!tmp.path().join("outside.txt").exists());
}
#[cfg(unix)]
fn fake_core(a: &mut App, script: &str) -> std::path::PathBuf {
    a.dirs.ensure().unwrap();
    let bin = a.dirs.data().join("test-core");
    profile::atomic_write(&bin, script.as_bytes(), true).unwrap();
    a.state.settings.singbox_path = bin.to_string_lossy().into();
    bin
}
#[cfg(unix)]
#[test]
fn generation_checks_before_replacing_and_keeps_backup_on_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    a.add_nodes("trojan://p@proxy.test:443#test").unwrap();
    fake_core(
        &mut a,
        "#!/bin/sh\necho 'WARN compatibility warning' >&2\nexit 0\n",
    );
    std::fs::write(a.dirs.config(), b"original config").unwrap();
    assert_eq!(a.generate().unwrap(), "WARN compatibility warning");
    let good = std::fs::read(a.dirs.config()).unwrap();
    assert_eq!(std::fs::read(a.dirs.backup()).unwrap(), b"original config");
    fake_core(
        &mut a,
        "#!/bin/sh\necho 'FATAL rejected config' >&2\nexit 1\n",
    );
    a.state.settings.api_secret = "new-secret".into();
    let error = a.generate().unwrap_err();
    assert!(format!("{error:#}").contains("rejected config"));
    assert_eq!(std::fs::read(a.dirs.config()).unwrap(), good);
    assert_eq!(std::fs::read(a.dirs.backup()).unwrap(), b"original config");
    assert!(!std::fs::read_dir(a.dirs.data()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("config-")));
}
#[test]
fn empty_nodes_cannot_start_restart_run_or_select_direct() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    a.state.settings.singbox_path = tmp.path().join("must-not-execute").to_string_lossy().into();
    // Ignore legacy/null outbound entries when deciding whether a proxy exists.
    a.state.manual_nodes.push(
        serde_json::from_value(serde_json::json!({"tag":"invalid","outbound":null})).unwrap(),
    );
    for result in [
        a.start(),
        a.restart(),
        a.run_core(),
        a.select_node("direct"),
    ] {
        assert!(result.unwrap_err().to_string().contains("没有可用代理节点"));
    }
    assert!(!a.dirs.binary().exists());
    assert!(!a.dirs.config().exists());
    assert!(!a.dirs.pid().exists());
}
#[cfg(target_os = "linux")]
#[test]
fn empty_node_restart_preserves_the_existing_core() {
    let tmp = tempfile::tempdir().unwrap();
    let a = App::open(tmp.path()).unwrap();
    a.dirs.ensure().unwrap();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let info = ssb::platform::process_info(child.id()).unwrap();
    std::fs::write(a.dirs.pid(), child.id().to_string()).unwrap();
    std::fs::write(
        a.dirs.base.join("run/sing-box.process.json"),
        serde_json::to_vec(
            &serde_json::json!({"pid":child.id(),"identity":info.identity,"image":info.image}),
        )
        .unwrap(),
    )
    .unwrap();
    let was_running = core::running(&a.dirs) == Some(child.id());
    let result = a.restart();
    let survived = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(was_running);
    assert!(result.unwrap_err().to_string().contains("没有可用代理节点"));
    assert!(
        survived,
        "empty-node restart stopped the previous core before validation"
    );
}
#[cfg(unix)]
#[test]
fn command_timeout_kills_and_reaps_the_child() {
    let tmp = tempfile::tempdir().unwrap();
    let mut a = App::open(tmp.path()).unwrap();
    let bin = fake_core(&mut a, "#!/bin/sh\nwhile :; do :; done\n");
    let started = std::time::Instant::now();
    let err = core::command_output(std::process::Command::new(bin), Duration::from_millis(100))
        .unwrap_err();
    assert!(err.to_string().contains("超时"));
    assert!(started.elapsed() < Duration::from_secs(2));
}
#[cfg(target_os = "linux")]
#[test]
fn invalid_or_reused_pid_files_never_target_unrelated_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let a = App::open(tmp.path()).unwrap();
    a.dirs.ensure().unwrap();
    for text in ["-1", "0", "1", "garbage"] {
        std::fs::write(a.dirs.pid(), text).unwrap();
        assert_eq!(core::running(&a.dirs), None);
    }
    std::fs::write(a.dirs.pid(), std::process::id().to_string()).unwrap();
    assert_eq!(core::running(&a.dirs), None);
    assert!(a.stop().is_err());
    assert!(ssb::platform::process_info(std::process::id()).is_some());
}
