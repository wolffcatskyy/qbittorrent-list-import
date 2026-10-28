#!/bin/sh
# One-line installer for the qBittorrent blocklist sync tool.
#
#   curl -fsSL https://raw.githubusercontent.com/wolffcatskyy/qbittorrent-blocklist/main/install.sh | sh
#
# Downloads one consistent snapshot of the repository into a temporary
# directory, compiles the blocklist, loads it into a running qBittorrent
# via its Web API, then removes the temporary directory. Persistent state
# (the live filter file and the 24-hour download-guard cache) is kept.
#
# Prereqs: Linux or macOS, Python 3.10+, and qBittorrent running with its
# WebUI enabled (Tools > Options > Web UI). You will be prompted for the
# WebUI username/password on the terminal. If the WebUI is not at
# http://127.0.0.1:8080, set QBT_URL.
#
# This script never changes qBittorrent's WebUI or password settings and
# never prints or stores your credentials.
set -eu

REPO="wolffcatskyy/qbittorrent-blocklist"

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

# Resolve the current main HEAD to a commit SHA, then download THAT
# commit's tarball in one request. Fetching main.py and qbt_sync.py as
# separate raw files could mix versions if a push lands between fetches;
# a single-commit tarball cannot. Fails closed if the SHA cannot be
# resolved rather than falling back to inconsistent files.
SHA="$(python3 - "$REPO" <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen(
            f"https://api.github.com/repos/{sys.argv[1]}/commits/main",
            timeout=15) as r:
        print(json.load(r)["sha"])
except Exception:
    pass
PY
)"

echo "Downloading the compiler..."
if [ -n "$SHA" ]; then
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$SHA" -o "$TMPDIR_SYNC/repo.tar.gz"
    else
        python3 -c "import urllib.request; urllib.request.urlretrieve('https://codeload.github.com/$REPO/tar.gz/$SHA', '$TMPDIR_SYNC/repo.tar.gz')"
    fi
    tar -xzf "$TMPDIR_SYNC/repo.tar.gz" -C "$TMPDIR_SYNC" --strip-components=1
    rm "$TMPDIR_SYNC/repo.tar.gz"
else
    echo "ERROR: could not resolve a consistent snapshot of the tools" >&2
    echo "(GitHub API unreachable or rate-limited). Please retry in a minute." >&2
    exit 1
fi

python3 "$TMPDIR_SYNC/qbt_sync.py" "$@"
