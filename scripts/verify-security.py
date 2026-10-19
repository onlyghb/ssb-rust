#!/usr/bin/env python3
"""Check leak policies with a real core and loopback targets; TUN stays disabled."""
import argparse
import contextlib
import http.client
import http.server
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

from verify import free_port


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits += 1
        body = b"security fixture"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class IPv6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssb", default="target/debug/ssb")
    parser.add_argument("--core", required=True)
    args = parser.parse_args()
    ssb = str(Path(args.ssb).resolve())
    core = str(Path(shutil.which(args.core) or args.core).resolve())
    with tempfile.TemporaryDirectory(prefix="ssb-security-") as temporary, contextlib.ExitStack() as cleanup:
        base = Path(temporary)

        def run(*command, check=True):
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                result = subprocess.run([ssb, "--dir", str(base), *command], stdout=out, stderr=err, timeout=45)
                out.seek(0)
                err.seek(0)
                result.stdout = out.read().decode("utf-8")
                result.stderr = err.read().decode("utf-8")
            if check and result.returncode:
                raise AssertionError(f"{command}: {result.stdout}\n{result.stderr}")
            return result

        def target(server_class, host):
            server = server_class((host, 0), Target)
            server.hits = 0
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cleanup.callback(server.server_close)
            cleanup.callback(server.shutdown)
            return server

        ipv4 = target(http.server.ThreadingHTTPServer, "127.0.0.1")
        try:
            ipv6 = target(IPv6Server, "::1")
        except OSError:
            ipv6 = None

        settings = json.loads(run("settings").stdout)
        settings.update(tun_enabled=False, route_mode="global", ipv6="off", singbox_path=core,
                        mixed_port=free_port(), api_listen=f"127.0.0.1:{free_port()}")
        (base / "data").mkdir()
        (base / "data/state.json").write_text(json.dumps({"settings": settings}), encoding="utf-8")
        run("gen")
        for command in [("start",), ("restart",), ("run-core",), ("select", "direct")]:
            result = run(*command, check=False)
            assert result.returncode and "没有可用代理节点" in result.stderr, result
        assert not (base / "run/sing-box.pid").exists()

        def request(server, host, blocked):
            before = server.hits
            connection = http.client.HTTPConnection("127.0.0.1", settings["mixed_port"], timeout=3)
            try:
                connection.request("GET", f"http://{host}:{server.server_address[1]}/")
                response = connection.getresponse()
                body = response.read()
                if blocked:
                    assert response.status != 200, "blocked request unexpectedly succeeded"
                else:
                    assert response.status == 200 and body == b"security fixture"
            except (OSError, http.client.HTTPException):
                if not blocked:
                    raise
            finally:
                connection.close()
            assert server.hits == before + (0 if blocked else 1), "request escaped the blocking policy"

        # Even manually running a generated empty-node config must reject traffic.
        with tempfile.TemporaryFile() as log:
            child = subprocess.Popen([core, "run", "-c", str(base / "data/config.json")],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 8
                while True:
                    assert child.poll() is None, "blocked config failed to start"
                    try:
                        with socket.create_connection(("127.0.0.1", settings["mixed_port"]), timeout=0.2):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "core did not listen"
                        time.sleep(0.05)
                request(ipv4, "127.0.0.1", blocked=True)
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        print("PASS: empty-node CLI startup and generated config both refuse direct traffic")

        run("add", "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:65530?security=tls#fixture")
        try:
            run("start")
            run("select", "direct")
            request(ipv4, "127.0.0.1", blocked=False)
            if ipv6:
                request(ipv6, "[::1]", blocked=True)
                run("settings", "set", "ipv6", "on")
                run("restart")
                run("select", "direct")
                request(ipv6, "[::1]", blocked=False)
                print("PASS: IPv6 literal blocked with ipv6=off; IPv4 and enabled IPv6 still work")
            else:
                print("SKIP: IPv6 loopback unavailable; IPv4 positive control passed")
        finally:
            run("stop", check=False)


if __name__ == "__main__":
    main()
