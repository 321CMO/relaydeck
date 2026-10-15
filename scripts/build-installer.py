"""Create the single downloadable installer from reviewed source files."""
from pathlib import Path
import sys

source = Path(__file__).resolve().parent
script = (source / "relaydeck.sh").read_text()
library = (source / "lib/lifecycle.sh").read_text()
marker = 'if ! declare -F upgrade_transaction >/dev/null; then\n source "${BASH_SOURCE[0]%/*}/lib/lifecycle.sh"\nfi'
if script.count(marker) != 1:
    raise SystemExit("Installer library inclusion marker missing or duplicated")
output = Path(sys.argv[1] if len(sys.argv) > 1 else "release/relaydeck.sh")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(script.replace(marker, library))
output.chmod(0o755)
print(output)
