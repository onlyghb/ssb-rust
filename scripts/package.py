#!/usr/bin/env python3
"""Build portable release archives around an already built native ssb binary."""
import argparse
import hashlib
import io
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile


def archive(stage, target, windows):
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    if windows:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as output:
            for path in files:
                output.write(path, path.relative_to(stage).as_posix())
    else:
        with tarfile.open(target, "w:gz") as output:
            for path in files:
                output.add(path, arcname=path.relative_to(stage).as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--os", required=True, choices=["linux", "windows"])
    parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--core-version", default="1.14.3")
    parser.add_argument("--output", default="dist")
    parser.add_argument("--slim-only", action="store_true")
    args = parser.parse_args()
    if any("/" in v or "\\" in v or v in ("", ".", "..") for v in (args.version, args.core_version)):
        parser.error("invalid version")
    root = Path(__file__).resolve().parent.parent
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    windows = args.os == "windows"
    extension = ".zip" if windows else ".tar.gz"
    prefix = f"ssb-{args.version}-{args.os}-{args.arch}"
    with tempfile.TemporaryDirectory(prefix="ssb-package-") as temporary:
        stage = Path(temporary)
        binary = stage / ("ssb.exe" if windows else "ssb")
        shutil.copy2(args.binary, binary)
        if not windows:
            binary.chmod(0o755)
        for file in ("README.md", "LICENSE"):
            shutil.copy2(root / file, stage / file)
        archive(stage, output / (prefix + extension), windows)
        if not args.slim_only:
            name = f"sing-box-{args.core_version}-{args.os}-{args.arch}"
            url = f"https://github.com/SagerNet/sing-box/releases/download/v{args.core_version}/{name}{extension}"
            request = urllib.request.Request(url, headers={"User-Agent": "ssb-release"})
            with urllib.request.urlopen(request, timeout=600) as response:
                content = response.read(256 * 1024 * 1024 + 1)
            if len(content) > 256 * 1024 * 1024:
                raise RuntimeError("core archive exceeds 256 MiB")
            data = stage / "data"
            data.mkdir()
            if windows:
                with zipfile.ZipFile(io.BytesIO(content)) as source:
                    for entry in source.infolist():
                        basename = entry.filename.rsplit("/", 1)[-1]
                        if basename == "sing-box.exe" or basename.lower().endswith(".dll"):
                            if "/" in basename or "\\" in basename or ":" in basename:
                                raise RuntimeError("invalid archive filename")
                            (data / basename).write_bytes(source.read(entry))
                if not (data / "sing-box.exe").is_file():
                    raise RuntimeError("missing sing-box.exe in official archive")
            else:
                with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as source:
                    entry = next((e for e in source if e.isfile() and Path(e.name).name == "sing-box"), None)
                    if entry is None:
                        raise RuntimeError("missing sing-box in official archive")
                    with source.extractfile(entry) as executable:
                        (data / "sing-box").write_bytes(executable.read())
                (data / "sing-box").chmod(0o755)
            (stage / "SINGBOX-LICENSE.txt").write_text(
                f"This package bundles an unmodified official sing-box v{args.core_version} executable.\n"
                "Copyright SagerNet, licensed under GPL-3.0.\n"
                f"Corresponding source: https://github.com/SagerNet/sing-box/tree/v{args.core_version}\n"
                f"License: https://github.com/SagerNet/sing-box/blob/v{args.core_version}/LICENSE\n", encoding="utf-8")
            archive(stage, output / (prefix + "-with-singbox" + extension), windows)
    for path in sorted(output.glob(prefix + "*" + extension)):
        print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")


if __name__ == "__main__":
    main()
