#!/bin/sh
# One-line installer for the qBittorrent blocklist sync tool.
#
#   curl -fsSL https://raw.githubusercontent.com/wolffcatskyy/qbittorrent-blocklist/main/install.sh | sh
#
# Downloads the compiler and sync tool into a temporary directory, compiles
# the blocklist, loads it into a running qBittorrent via its Web API, then
# removes the temporary directory. Persistent state (the live filter file
# and the 24-hour download guard cache) is kept.
#
# Prereqs: Linux or macOS, Python 3.10+, and qBittorrent running with its
# WebUI enabled (Tools > Options > Web UI). You will be prompted for the
# WebUI username/password unless QBT_USERNAME/QBT_PASSWORD are set. If the
# WebUI is not on the default http://127.0.0.1:8080, set QBT_URL.
#
# This script never changes qBittorrent's WebUI or password settings and
# never prints or stores your credentials.
set -eu

REPO_RAW="${QBT_BLOCKLIST_RAW:-https://raw.githubusercontent.com/wolffcatskyy/qbittorrent-blocklist/main}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required (3.10+)." >&2
    exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo "ERROR: Python 3.10 or newer is required." >&2
    exit 1
}

TMPDIR_SYNC="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SYNC"' EXIT INT TERM

echo "Downloading the compiler..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO_RAW/main.py" -o "$TMPDIR_SYNC/main.py"
    curl -fsSL "$REPO_RAW/qbt_sync.py" -o "$TMPDIR_SYNC/qbt_sync.py"
else
    python3 - "$REPO_RAW" "$TMPDIR_SYNC" <<'PY'
import sys, urllib.request
raw, dest = sys.argv[1], sys.argv[2]
for name in ("main.py", "qbt_sync.py"):
    urllib.request.urlretrieve(f"{raw}/{name}", f"{dest}/{name}")
PY
fi

python3 "$TMPDIR_SYNC/qbt_sync.py" "$@"
