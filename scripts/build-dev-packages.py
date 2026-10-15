"""Build development installation artifacts. This does not create a GitHub Release."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request


def member(archive, name):
    entry = archive.getmember(name)
    if not entry.isfile() or entry.size > 128 * 1024 * 1024:
        raise ValueError("Unexpected official archive entry")
    return archive.extractfile(entry).read()


def fetch(url, expected):
    if not url.startswith("https://github.com/"):
        raise ValueError("Unexpected upstream artifact host")
    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read(128 * 1024 * 1024 + 1)
    if len(content) > 128 * 1024 * 1024:
        raise ValueError("Official artifact exceeds package size limit")
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Official artifact SHA256 mismatch")
    return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    script_dir = Path(__file__).resolve().parent
    manifest = json.loads((script_dir / "core-artifacts.json").read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    sums = {}
    for arch in ("amd64", "arm64"):
        files = {"relaydeck": (args.binary_dir / ("relaydeck-linux-" + arch)).read_bytes()}
        for kind in ("sing-box", "caddy"):
            record = manifest[kind]["linux-" + arch]
            content = fetch(record["url"], record["sha256"])
            prefix = "sing-box-" + manifest[kind]["version"] + "-linux-" + arch + "/" if kind == "sing-box" else ""
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
                files[kind] = member(archive, prefix + kind)
                files[kind.upper() + "-LICENSE.txt"] = member(archive, prefix + "LICENSE")
        target = args.output / ("relaydeck-linux-" + arch + ".tar.gz")
        with tarfile.open(target, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o644 if name.endswith(".txt") else 0o755
                info.mtime = 0
                archive.addfile(info, io.BytesIO(content))
        sums[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    subprocess.run([sys.executable, str(script_dir / "build-installer.py"), str(args.output / "relaydeck.sh")], check=True)
    sums["relaydeck.sh"] = hashlib.sha256((args.output / "relaydeck.sh").read_bytes()).hexdigest()
    (args.output / "SHA256SUMS").write_text("".join(digest + "  " + name + "\n" for name, digest in sorted(sums.items())))
    (args.output / "BUILD-INFO.json").write_text(json.dumps({"developmentOnly": True, "commit": os.getenv("GITHUB_SHA", "local"), "upstreamVersions": {kind: record["version"] for kind, record in manifest.items()}, "realVpsTested": False}, indent=2) + "\n")
    print("Built Linux amd64/arm64 development packages with upstream licenses")


if __name__ == "__main__":
    main()
