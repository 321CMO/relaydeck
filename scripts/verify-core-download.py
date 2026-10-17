import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(__file__).with_name("core-artifacts.json").read_text())
kind = sys.argv[2] if len(sys.argv) > 2 else "sing-box"
arch = sys.argv[3] if len(sys.argv) > 3 else "amd64"
if kind not in manifest or "linux-" + arch not in manifest[kind]:
    raise SystemExit("Unsupported official core")
expected = manifest[kind]["linux-" + arch]["sha256"]
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("Official core archive SHA256 mismatch")
print(f"Official {kind} v{manifest[kind]['version']} Linux {arch} SHA256 verified")
