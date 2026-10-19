#!/usr/bin/env python3
"""Linux TUN regression test. Run with sudo unshare --net; never use the host network."""
import argparse
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, encoding="utf-8", timeout=20).stdout


def peer(ready, hits):
    deadline = time.monotonic() + 10
    while not ready.exists():
        if time.monotonic() > deadline:
            raise RuntimeError("peer setup timed out")
        time.sleep(0.02)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with hits.open("a") as output:
                output.write(self.client_address[0] + "\n")
            body = b"isolated TUN fixture"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    class IPv6Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    for server_class, host in [(http.server.ThreadingHTTPServer, "198.51.100.2"),
                               (IPv6Server, "2001:db8:2::2")]:
        server = server_class((host, 18080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        signal.pause()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssb", default="target/debug/ssb")
    parser.add_argument("--core")
    parser.add_argument("--peer", nargs=2, metavar=("READY", "HITS"))
    args = parser.parse_args()
    if args.peer:
        return peer(*(Path(path) for path in args.peer))
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires Linux root in a fresh network namespace: sudo unshare --net python3 scripts/verify-tun.py --core ...")
    links = json.loads(command("ip", "-j", "link", "show"))
    if [link["ifname"] for link in links] != ["lo"]:
        parser.error("refusing to change a populated network namespace; use sudo unshare --net")
    if not args.core:
        parser.error("--core is required")
    ssb = str(Path(args.ssb).resolve())
    core = str(Path(args.core).resolve())
    with tempfile.TemporaryDirectory(prefix="ssb-tun-test-") as temporary:
        base = Path(temporary)
        # A network namespace does not isolate filesystem-backed system buses.
        # sing-box 1.14 invokes resolvectl by PATH; hide host helper programs so
        # this fixture cannot change the host's systemd-resolved configuration.
        helper_path = base / "empty-path"
        helper_path.mkdir()
        core_environment = dict(os.environ, PATH=str(helper_path))
        ready, hits = base / "ready", base / "hits"
        hits.touch()
        with tempfile.TemporaryFile() as peer_log:
            other = subprocess.Popen(["unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                                      "--peer", str(ready), str(hits)], stdout=peer_log, stderr=peer_log)
            try:
                # Give unshare time to enter the peer namespace before nsenter.
                deadline = time.monotonic() + 5
                while os.readlink(f"/proc/{other.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                    assert time.monotonic() < deadline, "peer did not enter its namespace"
                    time.sleep(0.02)
                command("ip", "link", "set", "lo", "up")
                command("ip", "link", "add", "ssb-out", "type", "veth", "peer", "name", "ssb-peer")
                command("ip", "link", "set", "ssb-peer", "netns", str(other.pid))
                command("ip", "addr", "add", "192.0.2.1/24", "dev", "ssb-out")
                command("ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "ssb-out", "nodad")
                command("ip", "link", "set", "ssb-out", "up")
                for family, address in [("-4", "192.0.2.2/24"), ("-6", "2001:db8:1::2/64")]:
                    prefix = ["nsenter", "-t", str(other.pid), "-n", "--", "ip"]
                    command(*prefix, family, "addr", "add", address, "dev", "ssb-peer", *(["nodad"] if family == "-6" else []))
                command("nsenter", "-t", str(other.pid), "-n", "--", "ip", "link", "set", "lo", "up")
                command("nsenter", "-t", str(other.pid), "-n", "--", "ip", "addr", "add", "198.51.100.2/32", "dev", "lo")
                command("nsenter", "-t", str(other.pid), "-n", "--", "ip", "-6", "addr", "add", "2001:db8:2::2/128", "dev", "lo", "nodad")
                command("nsenter", "-t", str(other.pid), "-n", "--", "ip", "link", "set", "ssb-peer", "up")
                command("ip", "route", "add", "default", "via", "192.0.2.2")
                command("ip", "-6", "route", "add", "default", "via", "2001:db8:1::2")
                ready.touch()
                while True:
                    try:
                        with socket.create_connection(("198.51.100.2", 18080), timeout=0.2):
                            break
                    except OSError:
                        assert other.poll() is None, "peer exited"
                        assert time.monotonic() < deadline, "peer did not listen"
                        time.sleep(0.05)

                def request(host, blocked=False):
                    before = hits.read_text()
                    connection = http.client.HTTPConnection(host, 18080, timeout=3)
                    try:
                        connection.request("GET", "/")
                        response = connection.getresponse()
                        body = response.read()
                        assert not blocked, "request bypassed the blocking policy"
                        assert response.status == 200 and body == b"isolated TUN fixture"
                    except (OSError, http.client.HTTPException):
                        if not blocked:
                            raise
                    finally:
                        connection.close()
                    if blocked:
                        assert hits.read_text() == before, "blocked request reached the peer"

                request("198.51.100.2")
                request("2001:db8:2::2")
                settings = json.loads(command(ssb, "--dir", str(base), "settings"))
                settings.update(tun_enabled=True, mixed_enabled=False, route_mode="global", ipv6="on",
                                api_listen="127.0.0.1:19090", api_secret="isolated-test", singbox_path=core)
                (base / "data").mkdir()

                def generate(ipv6, nodes):
                    settings["ipv6"] = ipv6
                    state = {"settings": settings, "manual_nodes": nodes}
                    (base / "data/state.json").write_text(json.dumps(state))
                    command(ssb, "--dir", str(base), "gen")
                    config_path = base / "data/config.json"
                    config = json.loads(config_path.read_text())
                    config["inbounds"][0]["interface_name"] = "ssb-tun"
                    config_path.write_text(json.dumps(config))
                    return config_path

                @contextlib.contextmanager
                def running(config, select_direct=True):
                    with tempfile.TemporaryFile() as log:
                        process = subprocess.Popen([core, "run", "-c", str(config)],
                                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                   env=core_environment)
                        try:
                            deadline = time.monotonic() + 8
                            while True:
                                if process.poll() is not None:
                                    log.seek(0)
                                    raise AssertionError(log.read().decode())
                                try:
                                    with socket.create_connection(("127.0.0.1", 19090), timeout=0.2):
                                        break
                                except OSError:
                                    assert time.monotonic() < deadline, "TUN core did not start"
                                    time.sleep(0.05)
                            if select_direct:
                                command(core, "api", "--url", "http://127.0.0.1:19090", "--secret", "isolated-test",
                                        "group", "select", "PROXY", "direct")
                            yield
                        finally:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()

                fixture = [{"tag": "fixture", "outbound": {"type": "trojan", "tag": "fixture",
                            "server": "127.0.0.1", "server_port": 65530, "password": "test", "tls": {"enabled": True}}}]
                with running(generate("on", fixture)):
                    route = command("ip", "route", "get", "198.51.100.2")
                    assert "ssb-tun" in route, route
                    request("198.51.100.2")
                    request("2001:db8:2::2")
                print("PASS: IPv4 and IPv6 work through a real TUN in isolated namespaces")
                with running(generate("off", fixture)):
                    request("198.51.100.2")
                    assert "unreachable" in command("ip", "-6", "rule", "show")
                    request("2001:db8:2::2", blocked=True)
                request("2001:db8:2::2")
                print("PASS: ipv6=off installs an IPv6 unreachable rule and prevents a literal-address bypass")
                with running(generate("off", []), select_direct=False):
                    request("198.51.100.2", blocked=True)
                    # Native TUN DNS can bypass ordinary route rules; verify it
                    # refuses a query instead of returning a FakeIP answer.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
                        dns.settimeout(2)
                        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01"
                        dns.connect(("10.255.0.2", 53))
                        dns.send(query)
                        try:
                            response = dns.recv(4096)
                        except OSError:
                            pass  # ICMP rejection or a dropped query is also blocked.
                        else:
                            assert response[:2] == query[:2] and response[3] & 15 == 5, response
                print("PASS: even a manually started empty-node TUN config blocks direct traffic and native DNS")
            finally:
                other.terminate()
                try:
                    other.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    other.kill()
                    other.wait()


if __name__ == "__main__":
    main()
