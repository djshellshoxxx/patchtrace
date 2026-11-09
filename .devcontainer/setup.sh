#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v sudo >/dev/null 2>&1; then
  echo "This setup expects the standard non-root Codespaces user with sudo." >&2
  exit 2
fi

sudo apt-get update
sudo apt-get install -y jq libegl1 libopengl0 libgl1

python3 - <<'PY'
import sys
if sys.version_info[:2] != (3, 12):
    raise SystemExit(f"PatchTrace CI uses Python 3.12; found {sys.version.split()[0]}")
PY

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --only-binary=:all: -e '.[dev,search,rules]' pytest-xdist
python -m pip check
python tools/check_protobuf_runtime.py
