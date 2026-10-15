import hashlib
import pathlib
import sys

expected = "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("Official sing-box archive SHA256 mismatch")
print("Official sing-box v1.14.3 Linux amd64 SHA256 verified")
