"""Build checksum-pinned upstream source with explicit security dependency overrides."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import hashlib

VERSION = "v1.14.3"
MODULE = "github.com/sagernet/sing-box"
SUM = "h1:cBg8TP5SPWoMAlWqTqbSNdHGKPUciZisjQbLtqFlMZA="
MOD_SUM = "h1:Yei01EtPLnLTpLho05THCbqUwfidsaE/0vm1oSu+XQA="
TAGS = "with_quic,with_utls,with_acme,with_clash_api,with_v2ray_api"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--targets", default="linux-amd64,linux-arm64")
    parser.add_argument("--vulncheck", help="Path to govulncheck; fail on reachable source findings")
    args = parser.parse_args()
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    record = json.loads(subprocess.check_output([go, "mod", "download", "-json", MODULE + "@" + VERSION]))
    if record.get("Sum") != SUM or record.get("GoModSum") != MOD_SUM:
        raise RuntimeError("Pinned official source checksum mismatch")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_dir = output / "sing-box-build-source"
    if source_dir.exists():
        shutil.rmtree(source_dir)
    shutil.copytree(record["Dir"], source_dir, copy_function=shutil.copyfile)
    for directory, _, names in os.walk(source_dir):
        Path(directory).chmod(0o755)
        for name in names:
            (Path(directory) / name).chmod(0o644)
    overrides = json.loads(Path(__file__).with_name("core-security-overrides.json").read_text())
    modfile = output / "sing-box-security.mod"
    sumfile = output / "sing-box-security.sum"
    build_env = dict(os.environ, GO111MODULE="on", GOFLAGS="")
    subprocess.run([go, "get"] + [name + "@" + version for name, version in sorted(overrides.items())], cwd=source_dir, env=build_env, check=True)
    shutil.copyfile(source_dir / "go.mod", modfile)
    shutil.copyfile(source_dir / "go.sum", sumfile)
    binary_version = VERSION[1:] + "-relaydeck.1"
    for target in args.targets.split(","):
        if target not in ("linux-amd64", "linux-arm64", "darwin-arm64"):
            raise ValueError("Unsupported build target")
        system, arch = target.split("-")
        env = dict(build_env, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
        if args.vulncheck:
            report = output / ("sing-box-vulnerability-" + target + ".txt")
            with report.open("w") as handle:
                subprocess.run([str(Path(args.vulncheck).resolve()), "-tags=" + TAGS, "./cmd/sing-box"], cwd=source_dir, env=env, stdout=handle, stderr=subprocess.STDOUT, check=True)
        subprocess.run([go, "build", "-trimpath", "-tags", TAGS, "-ldflags", "-s -w -X github.com/sagernet/sing-box/constant.Version=" + binary_version, "-o", str(output / ("sing-box-" + target)), "./cmd/sing-box"], cwd=source_dir, env=env, check=True)
    shutil.copyfile(Path(record["Dir"]) / "LICENSE", output / "SING-BOX-LICENSE.txt")
    # Ship corresponding upstream source and build instructions beside development binaries.
    shutil.copyfile(record["Zip"], output / ("sing-box-source-" + VERSION + ".zip"))
    shutil.copyfile(__file__, output / "build-stats-core.py")
    shutil.copyfile(Path(__file__).with_name("core-security-overrides.json"), output / "core-security-overrides.json")
    (output / "SING-BOX-BUILD.json").write_text(json.dumps({"module": MODULE, "version": VERSION, "binaryVersion": binary_version, "sourceSum": SUM, "goModSum": MOD_SUM, "tags": TAGS, "modifiedUpstreamSource": False, "modifiedDependencyGraph": True, "dependencyOverrides": overrides, "resolvedModSHA256": hashlib.sha256(modfile.read_bytes()).hexdigest(), "resolvedSumSHA256": hashlib.sha256(sumfile.read_bytes()).hexdigest(), "sourceVulnerabilityCheck": bool(args.vulncheck)}, indent=2) + "\n")
    print("Built pinned upstream source with documented dependency security overrides")

if __name__ == "__main__":
    main()
