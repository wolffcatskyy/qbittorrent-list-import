#!/usr/bin/env python3
"""Install or update the compiled blocklist inside a running qBittorrent.

Compiles the filter with main.py and loads it into qBittorrent through the
Web API, using path alternation so filtering is never interrupted:

  - qBittorrent re-parses the filter only when ip_filter_path CHANGES to a
    different path (SessionImpl::setIPFilterFile no-ops on the same path).
  - On a path change it parses the new file in a background thread, then
    installs the parsed filter "in one go so there isn't a time window
    where there isn't an ip_filter" (sessionimpl.cpp, enableIPFilter).
    The old rules stay active until the new ones are fully loaded.
  - Toggling ip_filter_enabled off/on is NOT used: disabling installs an
    empty filter immediately, which is exactly the unfiltered window we
    avoid (sessionimpl.cpp, disableIPFilter).

So every run writes the fresh list to the alternate file
(ipfilter-a.dat <-> ipfilter-b.dat next to the configured path) and then
points qBittorrent at the new path. The API is touched only AFTER the new
file is fully compiled and written; any failure before that leaves the
running filter completely untouched.

Credentials come from the user (arguments, environment, or an interactive
prompt). They are never printed, logged, or written to disk by this tool,
and this tool never changes qBittorrent's WebUI or password settings.

Requires Python 3.10+ (standard library only) and a qBittorrent with the
WebUI enabled. Tested on Linux and macOS.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import main as compiler

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_FILTER_DIR = Path.home() / ".qbittorrent-blocklist"
API_TIMEOUT = 15
LOG_POLL_SECONDS = 15

# Marker suffixes of the two files this tool alternates between. Only files
# matching "<stem>-a.dat" / "<stem>-b.dat" in the chosen directory are ever
# created or deleted by this tool; the user's original filter file (if the
# stem was derived from it) is left alone.
SUFFIXES = ("-a", "-b")


class ApiError(RuntimeError):
    pass


def prompt_credential(prompt: str, secret: bool) -> str:
    """Prompt on the controlling terminal, never stdin.

    Under `curl ... | sh` the tool's stdin is the download pipe, so
    input() would raise EOFError; /dev/tty is the user's actual terminal.
    Fails with a clear message (no traceback) when no terminal exists.
    """
    if secret:
        try:
            return getpass.getpass(prompt)
        except (EOFError, OSError):
            pass  # fall through to the clear error below
    else:
        try:
            fd = os.open("/dev/tty", os.O_RDONLY)
            with os.fdopen(fd, "r") as tty_in:
                with open("/dev/tty", "w") as tty_out:
                    tty_out.write(prompt)
                    tty_out.flush()
                line = tty_in.readline()
                if line:
                    return line.rstrip("\n")
        except OSError:
            pass
    sys.exit(
        "ERROR: cannot prompt for the qBittorrent WebUI "
        + ("password" if secret else "username")
        + ": no interactive terminal is available. Re-run from a terminal."
    )


def _request(base: str, path: str, cookie: str | None = None,
             data: dict | None = None) -> bytes:
    url = base.rstrip("/") + path
    body = None
    headers = {}
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            return resp.read(), resp.headers
    except urllib.error.HTTPError as exc:
        raise ApiError(f"qBittorrent API {path}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(
            f"cannot reach qBittorrent Web API at {base} ({exc.reason}); "
            "is qBittorrent running with the WebUI enabled?"
        ) from exc


def api_login(base: str, username: str, password: str) -> str:
    """Log in and return the session cookie pair.

    qBittorrent < 5.x answers 200 with body "Ok." and a SID cookie;
    qBittorrent 5.x answers 204 No Content with a QBT_SID_<port> cookie.
    Bad credentials get 401 (5.x) or 403 (< 5.x). Success is therefore
    detected by the session cookie, not the body.
    """
    try:
        _body, headers = _request(base, "/api/v2/auth/login",
                                  data={"username": username, "password": password})
    except ApiError as exc:
        if "HTTP 401" in str(exc) or "HTTP 403" in str(exc):
            raise ApiError("qBittorrent rejected the supplied credentials") from exc
        raise
    cookie = headers.get("Set-Cookie", "")
    if not cookie:
        raise ApiError("qBittorrent login returned no session cookie")
    return cookie.split(";", 1)[0]


def api_get_preferences(base: str, cookie: str) -> dict:
    body, _ = _request(base, "/api/v2/app/preferences", cookie=cookie)
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ApiError("unexpected response from qBittorrent preferences") from exc


def api_set_preferences(base: str, cookie: str, prefs: dict) -> None:
    _request(base, "/api/v2/app/setPreferences", cookie=cookie,
             data={"json": json.dumps(prefs)})


def api_watch_parse(base: str, cookie: str, since_unix: int) -> str:
    """Watch qBittorrent's log for the parse outcome: 'parsed', 'failed',
    or 'unknown' (timeout / log unreadable).

    This matters because qBittorrent reacts to a parse failure by
    installing an EMPTY filter (sessionimpl.cpp handleIPFilterError), which
    would leave the client unfiltered while reporting enabled=true. The
    caller reverts to the previous filter file on 'failed'.
    """
    deadline = time.monotonic() + LOG_POLL_SECONDS
    while time.monotonic() < deadline:
        try:
            body, _ = _request(base, "/api/v2/log/main?normal=true&last_known_id=-1",
                               cookie=cookie)
            for entry in json.loads(body):
                if entry.get("timestamp", 0) < since_unix:
                    continue  # log timestamps are Unix seconds
                msg = entry.get("message", "")
                if "Failed to parse the IP filter" in msg:
                    return "failed"
                if "Successfully parsed the" in msg and "IP filter" in msg:
                    # 5.x: "... IP filter file. Number of rules applied: N"
                    # 4.x: "... the provided IP filter: N rules were applied"
                    count = None
                    for rx in (r"Number of rules applied: (\d+)",
                               r"IP filter: (\d+) rules were applied"):
                        m = re.search(rx, msg)
                        if m:
                            count = int(m.group(1))
                            break
                    if count is not None:
                        # A file that parses to ZERO rules also leaves an
                        # EMPTY filter installed (verified on qBittorrent
                        # 5.3.0: malformed input logs success with 0 rules),
                        # so zero counts as failure and triggers the revert.
                        return "parsed" if count > 0 else "failed"
        except (ApiError, json.JSONDecodeError):
            pass
        time.sleep(1)
    return "unknown"


def split_stem_suffix(path: Path) -> tuple[str, str | None]:
    """Split 'ipfilter-a.dat' -> ('ipfilter', '-a'); 'ipfilter.dat' -> ('ipfilter', None)."""
    name = path.name
    if name.lower().endswith(".dat"):
        name = name[:-4]
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)], suffix
    return name, None


def choose_paths(current_path: str, filter_dir: Path | None) -> tuple[Path, Path | None]:
    """Pick the path to write next and the stale alternate to clean up.

    If qBittorrent already points at one of our alternates, flip to the
    other. Otherwise adopt the directory/stem of the existing configured
    path (or the default dir/stem) and start with '-a'.
    """
    current = Path(current_path) if current_path else None
    if current is not None:
        stem, suffix = split_stem_suffix(current)
        directory = filter_dir or current.parent
        if suffix is not None and (filter_dir is None or current.parent == filter_dir):
            other = SUFFIXES[1] if suffix == SUFFIXES[0] else SUFFIXES[0]
            new_path = directory / f"{stem}{other}.dat"
            return new_path, current
    else:
        stem = "ipfilter"
        directory = filter_dir or DEFAULT_FILTER_DIR
    return directory / f"{stem}{SUFFIXES[0]}.dat", None


def compile_rules(feeds: str) -> tuple[list, list]:
    """Compile via main.py. Aborts (SystemExit) on any feed failure before
    any qBittorrent setting is touched. Returns (rules, source_urls)."""
    selected = compiler.select_feeds(feeds)
    rules = compiler.collect(selected, allow_partial=False)
    return rules, [f["url"] for f in selected]


def run(argv=None, *, now_unix: int | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile the blocklist and load it into a running qBittorrent."
    )
    parser.add_argument("--url", default=os.environ.get("QBT_URL", DEFAULT_URL),
                        help="qBittorrent Web API base URL "
                             "(default: %(default)s, env QBT_URL)")
    parser.add_argument("--username", default=os.environ.get("QBT_USERNAME"),
                        help="WebUI username (env QBT_USERNAME; prompted if omitted)")
    parser.add_argument("--password", default=os.environ.get("QBT_PASSWORD"),
                        help="WebUI password (env QBT_PASSWORD; prompted if omitted)")
    parser.add_argument("--filter-dir", type=Path, default=None,
                        help="directory for the alternating filter files "
                             "(default: directory of the configured filter path, "
                             "or ~/.qbittorrent-blocklist)")
    parser.add_argument("--feeds", choices=["all", "security"], default="all",
                        help="'all' (default) includes the rate-limited Bluetack "
                             "feed (user-started runs only, 24h cache); "
                             "'security' is FireHOL + Spamhaus only")
    parser.add_argument("--min-rules", type=int, default=compiler.MIN_RULES,
                        help="abort if the merged list has fewer rules than this")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="permit sending WebUI credentials over plaintext "
                             "HTTP to a non-localhost host (NOT recommended)")
    args = parser.parse_args(argv)

    parsed_url = urllib.parse.urlparse(args.url)
    host = (parsed_url.hostname or "").lower()
    if parsed_url.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1") \
            and not args.allow_insecure_http:
        sys.exit(
            f"ERROR: {args.url} would send the WebUI password over plaintext "
            "HTTP to a non-localhost host. Use HTTPS, an SSH tunnel, a "
            "loopback-only setup, or pass --allow-insecure-http if you "
            "accept the risk."
        )

    username = args.username
    password = args.password
    if username is None:
        username = prompt_credential("qBittorrent WebUI username: ", secret=False)
    if password is None:
        password = prompt_credential("qBittorrent WebUI password: ", secret=True)

    # 1. Verify API reachability and credentials BEFORE downloading anything.
    try:
        cookie = api_login(args.url, username, password)
        prefs = api_get_preferences(args.url, cookie)
    except ApiError as exc:
        sys.exit(f"ERROR: {exc}")

    # 2. Pick the alternate path, then compile into it. On any failure the
    #    process exits here and qBittorrent keeps its previous filter.
    new_path, stale_path = choose_paths(prefs.get("ip_filter_path") or "",
                                        args.filter_dir)
    new_path.parent.mkdir(parents=True, exist_ok=True)

    rules, source_urls = compile_rules(args.feeds)
    if len(rules) < args.min_rules:
        sys.exit(
            f"ERROR: merged list has only {len(rules)} rules (< {args.min_rules}); "
            "leaving the existing qBittorrent filter untouched"
        )
    compiler.atomic_write_text(new_path, compiler.render_dat(rules, source_urls))
    # Round-trip validation: strictly re-parse the file as written before
    # qBittorrent ever sees it. Catches corrupt/partial writes and format
    # regressions while qBittorrent's settings are still untouched. Residual
    # it cannot cover: qBittorrent's own parser rejecting a well-formed file.
    try:
        validated = compiler.validate_dat(new_path.read_text(encoding="utf-8"),
                                          min_rules=args.min_rules)
    except (OSError, ValueError) as exc:
        sys.exit(f"ERROR: post-write validation failed: {exc}; "
                 "qBittorrent settings left untouched")
    if validated != len(rules):
        sys.exit(f"ERROR: post-write validation counted {validated} rules, "
                 f"expected {len(rules)}; qBittorrent settings left untouched")
    print(f"Wrote {len(rules)} rules to {new_path} (re-validated on disk)")

    # 3. Point qBittorrent at the NEW path. Visible residual-risk warning
    #    BEFORE any state change: the failure window is real even though
    #    the success path is atomic and the revert is automatic.
    print("About to switch qBittorrent to the new filter. If qBittorrent cannot")
    print("parse it, qBittorrent installs an empty filter; this tool detects that")
    print("within seconds and reverts automatically. To avoid even that brief")
    print("window, pause your torrents before updating.")
    # 4. Point qBittorrent at the NEW path. qBittorrent parses it in the
    #    background and swaps the filter atomically; the previous rules stay
    #    active until the swap (verified in qBittorrent source, see module
    #    docstring). ip_filter_enabled is only ever set to true, never
    #    toggled, so there is no disable/re-enable window.
    started_unix = now_unix if now_unix is not None else int(time.time()) - 2
    api_set_preferences(args.url, cookie, {
        "ip_filter_enabled": True,
        "ip_filter_path": str(new_path),
    })

    # 5. Confirm the preference landed.
    applied = api_get_preferences(args.url, cookie)
    applied_path = os.path.normpath(applied.get("ip_filter_path") or "")
    if applied_path != os.path.normpath(str(new_path)):
        sys.exit(
            f"ERROR: qBittorrent did not adopt the new filter path "
            f"(reports {applied_path!r}); the previous filter is still active "
            f"and {new_path} is unused - investigate before re-running"
        )
    if not applied.get("ip_filter_enabled"):
        sys.exit("ERROR: qBittorrent reports ip_filter_enabled=false after update")

    # 6. Confirm the background parse outcome. qBittorrent installs an
    #    EMPTY filter when parsing fails, so a failure must revert the
    #    path preference to the previous filter file (which qBittorrent
    #    then re-parses, restoring the old rules).
    outcome = api_watch_parse(args.url, cookie, started_unix)
    if outcome == "failed":
        original = {"ip_filter_enabled": prefs.get("ip_filter_enabled", False),
                    "ip_filter_path": prefs.get("ip_filter_path", "")}
        api_set_preferences(args.url, cookie, original)
        restored = api_get_preferences(args.url, cookie)
        if os.path.normpath(restored.get("ip_filter_path") or "") \
                == os.path.normpath(original["ip_filter_path"]):
            sys.exit(
                f"ERROR: qBittorrent failed to parse {new_path}; restored the "
                f"previous filter settings ({original['ip_filter_path'] or 'filtering off'}). "
                f"The new file was left in place for inspection."
            )
        sys.exit(
            f"ERROR: qBittorrent failed to parse {new_path} AND restoring the "
            "previous filter settings failed - open qBittorrent and re-select "
            "your previous filter file manually."
        )
    if outcome == "parsed":
        print("qBittorrent parsed and applied the new filter (confirmed in its log)")
        # 7. Clean up ONLY the stale alternate file this tool manages, and
        #    only after the new filter is confirmed live. The live filter
        #    and the rate-limit cache are persistent and stay.
        if stale_path is not None and stale_path.exists() \
                and os.path.normpath(str(stale_path)) != applied_path:
            stem, suffix = split_stem_suffix(stale_path)
            if suffix is not None:
                stale_path.unlink()
                print(f"Removed stale previous filter {stale_path}")
    else:
        print("note: could not confirm the background parse in qBittorrent's log "
              f"within {LOG_POLL_SECONDS}s; the path preference is set. The "
              "previous filter file was kept - if qBittorrent shows the new "
              "rule count, you can remove it manually.")

    print(f"Done: qBittorrent now filters with {new_path} "
          f"({len(rules)} rules, sources: {', '.join(source_urls)})")
    return 0


if __name__ == "__main__":
    sys.exit(run())
