#!/usr/bin/env python3
"""Exercise the TUI in a real Unix pseudo-terminal (no TUN or network routing)."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import tempfile
import termios
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssb", default="target/debug/ssb")
    args = parser.parse_args()
    ssb = str(Path(args.ssb).resolve())
    with tempfile.TemporaryDirectory(prefix="ssb-ui-") as base:
        data = Path(base) / "data"
        data.mkdir()
        # Use a fake checker in this test; the real core is exercised by verify.py.
        core = data / "test-core"
        core.write_text("#!/bin/sh\nexit 0\n")
        core.chmod(0o755)
        (data / "state.json").write_text(json.dumps({"settings": {"tun_enabled": False, "singbox_path": str(core), "api_listen": "127.0.0.1:1"}}))
        pid, master = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execv(ssb, [ssb, "--dir", base])
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        captured = bytearray()

        def drain(seconds=0.3):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                readable, _, _ = select.select([master], [], [], min(0.1, max(0, end-time.monotonic())))
                if readable:
                    with contextlib.suppress(OSError):
                        captured.extend(os.read(master, 65536))

        def send(text):
            os.write(master, text.encode())
            drain()

        def wait_for(predicate, message):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                drain(0.1)
                if predicate():
                    return
            raise AssertionError(message + "\n" + captured.decode(errors="replace")[-3000:])

        def state():
            return json.loads((data / "state.json").read_text())

        try:
            drain(0.5)
            send("3a")
            # Bracketed paste must insert a whole multi-line payload.
            send("\x1b[200~trojan://p@a.test:443#香港一\ntrojan://p@b.test:443#香港二\x1b[201~")
            send("\r")
            wait_for(lambda: len(state().get("manual_nodes", [])) == 2 and (data / "config.json").is_file(), "paste/add did not save both nodes and generate config")
            send("/香港二\r")
            send("x")
            send("y")
            wait_for(lambda: len(state()["manual_nodes"]) == 1, "delete confirmation did not remove a manual node")
            assert state()["manual_nodes"][0]["tag"] == "香港一", "filtered deletion targeted the wrong node"
            send("\x1b")
            send("4/mixed_port\r")
            send("e")
            send("\x150\r")  # Ctrl-U, invalid port: keep editor and state.
            assert state()["settings"]["mixed_port"] == 2080
            send("\x152081\r")
            wait_for(lambda: state()["settings"]["mixed_port"] == 2081, "invalid input was not retained for correction")
            send("\x1b")
            send("4\r")  # route_mode rule -> global
            wait_for(lambda: state()["settings"]["route_mode"] == "global", "setting toggle was not saved")
            send("?")
            send("\x1b")
            send("1")
            # Resize also tests recovery while rendering Unicode labels.
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 8, 20, 0, 0))
            os.kill(pid, signal.SIGWINCH)
            drain()
            send("q")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                got, status = os.waitpid(pid, os.WNOHANG)
                if got:
                    assert os.waitstatus_to_exitcode(status) == 0, captured.decode(errors="replace")[-3000:]
                    assert b"\x1b[?1049l" in captured, "alternate screen was not restored"
                    print("PASS: real PTY tabs, Unicode paste/search, filtered deletion, setting correction, help, resize, exit")
                    return
                drain(0.1)
            raise AssertionError("TUI did not exit")
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
            os.close(master)


if __name__ == "__main__":
    main()
