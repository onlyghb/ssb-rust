#!/usr/bin/env python3
"""Real-core smoke test. Uses loopback only and never enables TUN routing."""
import argparse
import contextlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FixtureServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/sub":
            body = b"trojan://test@127.0.0.1:65530#fixture-node"
            self.send_response(200)
            self.send_header("subscription-userinfo", "upload=100; download=200; total=1073741824")
        else:
            body = b"ssb proxy roundtrip"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssb", default="target/debug/ssb")
    parser.add_argument("--core", default="sing-box")
    parser.add_argument("--downloads", action="store_true", help="also test rule-set and Dashboard downloads")
    args = parser.parse_args()
    import shutil
    ssb = Path(args.ssb).resolve()
    core = Path(shutil.which(args.core) or args.core).resolve()
    if not ssb.is_file() or not core.is_file():
        parser.error("build ssb first and provide an installed sing-box with --core")
    with tempfile.TemporaryDirectory(prefix="ssb-e2e-") as base:
        base = Path(base)

        def run(*command, check=True):
            print("RUN:", " ".join(command), flush=True)
            # A detached Windows core can retain inherited capture pipes. Files
            # let us wait for the CLI itself and decode its UTF-8 output directly.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                result = subprocess.run([str(ssb), "--dir", str(base), *command], stdout=stdout, stderr=stderr, timeout=90)
                stdout.seek(0)
                stderr.seek(0)
                result.stdout = stdout.read().decode("utf-8")
                result.stderr = stderr.read().decode("utf-8")
            if check and result.returncode:
                raise AssertionError(f"{command}:\n{result.stdout}\n{result.stderr}")
            return result

        # Create state directly before the first generation so the first
        # emitted config is already TUN-free and uses isolated local ports.
        settings = json.loads(run("settings").stdout)
        settings.update(tun_enabled=False, route_mode="global", ipv6="off", singbox_path=str(core),
                        mixed_port=free_port(), api_listen=f"127.0.0.1:{free_port()}", api_secret="e2e-secret")
        (base / "data").mkdir()
        (base / "data/state.json").write_text(json.dumps({"settings": settings, "manual_nodes": None, "subscriptions": None}), encoding="utf-8")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureServer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        local_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            result = run("gen")
            assert "WARN" not in result.stderr, result.stderr
            original = (base / "data/config.json").read_bytes()
            assert json.loads(original)["inbounds"][0]["type"] == "mixed"
            assert json.loads(original)["route"]["rules"][0]["action"] == "reject"
            rejected = run("start", check=False)
            assert rejected.returncode and "没有可用代理节点" in rejected.stderr
            bootstrap = "vless://00000000-0000-4000-8000-000000000002@127.0.0.1:65530?security=tls#smoke-bootstrap"
            run("add", bootstrap)
            run("start")
            status = run("status").stdout
            assert "运行中" in status and "API 服务: 可达" in status, status
            run("select", "direct")
            assert "当前出口: direct" in run("status").stdout
            # A real HTTP request through the generated mixed proxy.
            connection = http.client.HTTPConnection("127.0.0.1", settings["mixed_port"], timeout=5)
            connection.request("GET", local_url + "/hello")
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"ssb proxy roundtrip"
            connection.close()
            run("restart")
            assert "API 服务: 可达" in run("status").stdout
            run("doctor")
            run("stop")
            assert "未运行" in run("status").stdout
            assert not (base / "run/sing-box.pid").exists()
            run("nodes", "rm", "smoke-bootstrap")

            run("add", "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:65531?security=tls#manual")
            run("sub", "add", local_url + "/sub", "fixture")
            assert "fixture-node" in run("nodes").stdout
            assert "1.0 GB" in run("sub", "ls").stdout
            run("sub", "update", "fixture")
            run("nodes", "rm", "manual")
            run("sub", "rm", "fixture")
            assert json.loads((base / "data/state.json").read_text())["manual_nodes"] == []
            assert (base / "data/config.json.bak").is_file()
            run("settings", "set", "dns_proxy", "https://1.1.1.1/dns-query")
            run("settings", "set", "custom_proxy", "example.com,.cn")
            run("settings", "set", "custom_direct", "direct.example")
            config = json.loads((base / "data/config.json").read_text())
            assert config["dns"]["servers"][1]["path"] == "/dns-query"
            # A bad user setting must leave both state and config unchanged.
            state_before = (base / "data/state.json").read_bytes()
            config_before = (base / "data/config.json").read_bytes()
            assert run("settings", "set", "mixed_port", "0", check=False).returncode != 0
            assert (base / "data/state.json").read_bytes() == state_before
            assert (base / "data/config.json").read_bytes() == config_before
            log = (base / "logs/sing-box.log").read_text(errors="replace")
            assert "FATAL" not in log and "WARN" not in log, log

            if args.downloads:
                run("add", bootstrap)
                run("settings", "set", "route_mode", "rule")
                run("settings", "set", "dashboard_off", "false")
                run("start")
                api_port = int(settings["api_listen"].rsplit(":", 1)[1])
                connection = http.client.HTTPConnection("127.0.0.1", api_port, timeout=10)
                connection.request("GET", "/dashboard/")
                response = connection.getresponse()
                assert response.status == 200, response.status
                response.read()
                connection.close()
                assert "API 服务: 可达" in run("status").stdout
                run("stop")
                log = (base / "logs/sing-box.log").read_text(errors="replace")
                assert "FATAL" not in log and "WARN" not in log, log
            print("PASS: real sing-box check/start/API/select/proxy/restart/doctor/stop, subscriptions, settings, backups")
        finally:
            with contextlib.suppress(Exception):
                run("stop", check=False)
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
