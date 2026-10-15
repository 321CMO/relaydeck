"""Build the unmodified, checksum-pinned upstream core with user statistics enabled."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

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
    args = parser.parse_args()
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    record = json.loads(subprocess.check_output([go, "mod", "download", "-json", MODULE + "@" + VERSION]))
    if record.get("Sum") != SUM or record.get("GoModSum") != MOD_SUM:
        raise RuntimeError("Pinned official source checksum mismatch")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for target in args.targets.split(","):
        if target not in ("linux-amd64", "linux-arm64", "darwin-arm64"):
            raise ValueError("Unsupported build target")
        system, arch = target.split("-")
        env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
        subprocess.run([go, "build", "-trimpath", "-tags", TAGS, "-ldflags", "-s -w -X github.com/sagernet/sing-box/constant.Version=" + VERSION[1:], "-o", str(output / ("sing-box-" + target)), "./cmd/sing-box"], cwd=record["Dir"], env=env, check=True)
    shutil.copyfile(Path(record["Dir"]) / "LICENSE", output / "SING-BOX-LICENSE.txt")
    # Ship corresponding upstream source and build instructions beside development binaries.
    shutil.copyfile(record["Zip"], output / ("sing-box-source-" + VERSION + ".zip"))
    shutil.copyfile(__file__, output / "build-stats-core.py")
    (output / "SING-BOX-BUILD.json").write_text(json.dumps({"module": MODULE, "version": VERSION, "sourceSum": SUM, "goModSum": MOD_SUM, "tags": TAGS, "modifiedUpstreamSource": False}, indent=2) + "\n")
    print("Built pinned upstream core with local-only user statistics")

if __name__ == "__main__":
    main()
