"""Rebuild pinned Caddy source with the patched Go toolchain and explicit dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

MODULE = "github.com/caddyserver/caddy/v2"
VERSION = "v2.11.7"
SUM = "h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4="
MOD_SUM = "h1:Hy0hh5OTFu/INfBPyvkzImXF4wh6O91jyrZLWeB0fx0="

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--targets", default="linux-amd64,linux-arm64")
    parser.add_argument("--vulncheck")
    args = parser.parse_args()
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    record = json.loads(subprocess.check_output([go, "mod", "download", "-json", MODULE + "@" + VERSION]))
    if record.get("Sum") != SUM or record.get("GoModSum") != MOD_SUM:
        raise RuntimeError("Pinned Caddy official source checksum mismatch")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "caddy-build-source"
    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(record["Dir"], source, copy_function=shutil.copyfile)
    for directory, _, names in os.walk(source):
        Path(directory).chmod(0o755)
        for name in names:
            (Path(directory) / name).chmod(0o644)
    overrides = json.loads(Path(__file__).with_name("caddy-security-overrides.json").read_text())
    env = dict(os.environ, GO111MODULE="on", GOFLAGS="")
    subprocess.run([go, "get"] + [name + "@" + version for name, version in sorted(overrides.items())], cwd=source, env=env, check=True)
    for suffix in ("mod", "sum"):
        shutil.copyfile(source / ("go." + suffix), output / ("caddy-security." + suffix))
    binary_version = VERSION + "-relaydeck.1"
    for target in args.targets.split(","):
        if target not in ("linux-amd64", "linux-arm64", "darwin-arm64"):
            raise ValueError("Unsupported build target")
        system, arch = target.split("-")
        target_env = dict(env, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
        if args.vulncheck:
            with (output / ("caddy-vulnerability-" + target + ".txt")).open("w") as handle:
                subprocess.run([str(Path(args.vulncheck).resolve()), "./cmd/caddy"], cwd=source, env=target_env, stdout=handle, stderr=subprocess.STDOUT, check=True)
        subprocess.run([go, "build", "-trimpath", "-ldflags", "-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=" + binary_version, "-o", str(output / ("caddy-" + target)), "./cmd/caddy"], cwd=source, env=target_env, check=True)
    shutil.copyfile(source / "LICENSE", output / "CADDY-LICENSE.txt")
    shutil.copyfile(record["Zip"], output / ("caddy-source-" + VERSION + ".zip"))
    shutil.copyfile(__file__, output / "build-caddy.py")
    shutil.copyfile(Path(__file__).with_name("caddy-security-overrides.json"), output / "caddy-security-overrides.json")
    (output / "CADDY-BUILD.json").write_text(json.dumps({"module": MODULE, "version": VERSION, "binaryVersion": binary_version, "sourceSum": SUM, "goModSum": MOD_SUM, "modifiedUpstreamSource": False, "modifiedDependencyGraph": True, "dependencyOverrides": overrides, "resolvedModSHA256": hashlib.sha256((source / "go.mod").read_bytes()).hexdigest(), "resolvedSumSHA256": hashlib.sha256((source / "go.sum").read_bytes()).hexdigest(), "sourceVulnerabilityCheck": bool(args.vulncheck)}, indent=2) + "\n")
    print("Built pinned Caddy source with documented dependency security overrides")

if __name__ == "__main__":
    main()
