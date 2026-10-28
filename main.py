#!/usr/bin/env python3
"""Compile public IP blocklists into a qBittorrent ipfilter.dat file.

Fetches raw IP blocklists from public sources, parses CIDR ranges, bare IPs
and PeerGuardian P2P ranges, excludes special-purpose ranges, removes exact
and fully-covered duplicates, sorts, and writes one file in eMule DAT format
(the format qBittorrent parses for .dat):

  IP_Start - IP_End , 000 , Description

Per qBittorrent's filterparserthread.cpp, access level must be 127 or lower,
a range's two ends must share one address family, and lines starting with # or
// are skipped. IPv4 and IPv6 ranges are both accepted; IPv6 rules come from
Spamhaus DROPv6. Arbitrary P2P ranges are emitted as-is (start - end); they
are never expanded into individual addresses.

Sources (all fetched over HTTPS, standard library only):
  - FireHOL Level 1:  https://github.com/firehol/blocklist-ipsets (CIDR)
  - Spamhaus DROP:    https://www.spamhaus.org/drop/drop.txt (CIDR)
  - Spamhaus DROPv6:  https://www.spamhaus.org/drop/dropv6.txt (CIDR)
  - Bluetack Level 1: free anti-P2P list served by I-BlockList (P2P, gzipped)

Spamhaus EDROP was merged into DROP by Spamhaus and is intentionally not
listed separately; its file is now empty. FireHOL Level 1 aggregates
spamhaus_drop among others, so its overlap with the DROP feed is expected;
dedup absorbs it. Bluetack's entries reflect its maintainers' labeling,
which mixes anti-P2P organizations with general threat ranges; inclusion of
an address is not verified attribution of who operates it.

Special-purpose ranges (RFC1918 private, loopback, link-local, multicast,
reserved, unspecified) are excluded: blocking them would break local traffic
and they never belong in a peer blocklist. This classification comes from
Python's ipaddress module and can vary between Python versions, so the
workflow pins the runtime and the test suite pins the expected exclusions.

Overlap handling: rules are address ranges (version, start, end). Exact
duplicates collapse, and a range fully covered by an equal-or-earlier-feed
range is dropped (the earlier feed's label wins; security feeds precede
Bluetack). A later feed's broader range is kept even where it covers an
earlier feed's narrower rule, so no source's label is ever swallowed.
Partially overlapping ranges are all kept - merging them would lose label
provenance. No range is ever expanded into individual addresses.

Behaviour:
  - Rate-limited feeds (Bluetack: one download per 24h by provider policy)
    are served from a local cache inside the interval, so repeat runs do
    not re-download.
  - By default, every feed must download successfully and yield at least one
    valid entry; any failure aborts the run BEFORE the existing ipfilter.dat
    is touched. --allow-partial is an explicit degraded opt-in.
  - A feed that downloads but has zero valid entries (an error page, a
    retired feed's notice) counts as failed.
  - Downloads and decompression are size-capped; a feed larger than the cap
    is refused rather than trusted.
  - A run yielding fewer than --min-rules rules (default 1000) aborts, so a
    gutted list can never replace a good one.
  - The write is atomic: temp file in the same directory, fsync, rename.
  - Output is deterministic: no timestamps, so the workflow only commits
    when the actual rules change.

Requires only the Python standard library (Python 3.10+; CI pins 3.12).

Usage:
    python3 main.py [--output ipfilter.dat] [--min-rules 1000] [--allow-partial]
"""

from __future__ import annotations

import argparse
import fcntl
import zlib
import ipaddress
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "qbittorrent-blocklist-compiler/2.1"
REQUEST_TIMEOUT = 60      # seconds per request
MAX_RETRIES = 3
RETRY_BACKOFF = 5         # seconds, doubled each retry
MIN_RULES = 1000          # sanity floor: refuse to publish a gutted list

# Download safety caps. Bluetack L1 is ~3.7 MB gzipped / ~12.8 MB text; the
# caps leave generous headroom while refusing a decompression bomb or a
# runaway endpoint.
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
GZIP_MAGIC = b"\x1f\x8b"

# I-BlockList's developer policy caps downloads at once per 24 hours.
# Running the compiler by hand does not exempt that cap, so it is enforced
# here with a local cache, not by user habit. The cap is enforced fail-closed:
# if durable state is unavailable, a rate-limited feed is not fetched at all.
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "qbittorrent-blocklist-compiler"
MIN_FETCH_INTERVAL_SECONDS = 24 * 60 * 60
# After a FAILED attempt at a rate-limited feed, wait before trying again so
# a retry loop cannot hammer the provider inside the 24h window either.

# Feeds are processed in order; on exact or covered duplicates the earlier
# feed keeps the label. Security feeds come first so Bluetack labels appear
# only on ranges they do not already cover.
#
# format "cidr": one CIDR network or bare IP per line.
#   Comments (#, ;, //) and trailing metadata after the first token are ignored.
# format "p2p": PeerGuardian "Description:start_ip-end_ip" per line (IPv4;
#   the description may itself contain colons, so the range is split from
#   the LAST colon). May be served gzipped; detected by magic bytes.
FEEDS = [
    {
        # FireHOL level1: basic-protection aggregate (includes dshield, feodo,
        # spamhaus_drop). https://iplists.firehol.org/
        "name": "FireHOL_L1",
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "format": "cidr",
    },
    {
        # Spamhaus DROP (Don't Route Or Peer). Use is subject to the Spamhaus
        # DROP Terms of Use: https://www.spamhaus.org/blocklists/drop-fair-use-policy/
        # (EDROP was merged into DROP by Spamhaus and is no longer a feed.)
        "name": "Spamhaus_DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "format": "cidr",
    },
    {
        # Spamhaus DROPv6: the IPv6 DROP list. qBittorrent's DAT parser
        # accepts IPv6 ranges, so these become real rules, not dead weight.
        "name": "Spamhaus_DROPv6",
        "url": "https://www.spamhaus.org/drop/dropv6.txt",
        "format": "cidr",
    },
    {
        # Bluetack Level 1, the classic anti-P2P list, served free by
        # I-BlockList as gzipped PeerGuardian P2P. Labels are the upstream
        # maintainers' own and are not verified attribution.
        "name": "Bluetack_L1",
        "url": "https://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz",
        "format": "p2p",
        # Provider caps downloads at once per 24h; fetch_feed caches it.
        "rate_limited": True,
    },
]

COMMENT_PREFIXES = ("#", ";", "//")

# One rule is (version, start_int, end_int, label); ints come from
# ipaddress, so family mixing is impossible inside a rule.


def _read_bounded(resp, cap: int) -> bytes:
    data = resp.read(cap + 1)
    if len(data) > cap:
        raise RuntimeError(f"feed larger than {cap} bytes; refusing to use it")
    return data


def _gunzip_bounded(data: bytes) -> bytes:
    """Decompress gzip data, refusing output beyond the decompression cap.

    Output is limited DURING decompression, so a zip bomb cannot make us
    allocate the full payload before we refuse it.
    """
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
    except zlib.error as exc:
        raise RuntimeError(f"corrupt gzip payload: {exc}") from exc
    if d.unconsumed_tail or len(out) > MAX_DECOMPRESSED_BYTES:
        raise RuntimeError(
            f"decompressed feed larger than {MAX_DECOMPRESSED_BYTES} bytes; refusing to use it"
        )
    out += d.flush()
    return out


def fetch(url: str) -> str:
    """Download a feed with retries and a timeout; return decoded text.

    Gzipped responses are detected by magic bytes and decompressed. Both the
    download and the decompressed payload are size-capped.
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                raw = _read_bounded(resp, MAX_COMPRESSED_BYTES)
            if raw[:2] == GZIP_MAGIC:
                raw = _gunzip_bounded(raw)
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            last_error = exc
            print(f"  attempt {attempt}/{MAX_RETRIES} failed: {exc}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * (2 ** (attempt - 1)))
    raise RuntimeError(f"download failed after {MAX_RETRIES} attempts: {last_error}")


def fetch_feed(feed: dict) -> str:
    """Fetch a feed's text, honoring provider download-frequency caps."""
    if not feed.get("rate_limited"):
        return fetch(feed["url"])
    return _fetch_rate_limited(feed)


def _fetch_rate_limited(feed: dict) -> str:
    """Fetch a provider-capped feed with the cap enforced fail-closed.

    A feed marked rate_limited (I-BlockList: one download per 24h) is cached
    locally for MIN_FETCH_INTERVAL_SECONDS; runs inside the interval reuse
    the cached content and do NOT touch the network. Every attempt is stamped
    BEFORE the network is touched, and an attempt that did not complete blocks
    any further attempt for the full interval: the provider counts requests,
    including partial or ambiguous transfers, so no outcome can produce two
    requests inside one 24h window. A successful download clears the stamp.
    A stale cache is never silently substituted for a failed download: past
    the interval the feed is downloaded fresh and the existing failure rules
    apply if that fails.

    Fail-closed: when durable state (cache dir, lock, attempt stamp) is
    unavailable, the feed is NOT fetched - without it the cap cannot be
    proven or enforced. A lock file serializes concurrent runs so two
    processes cannot both download inside the window.
    """
    name = feed["name"].lower()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        lock = open(CACHE_DIR / f"{name}.lock", "a+b")
    except OSError as exc:
        raise RuntimeError(
            f"{feed['name']}: cannot enforce the provider's download cap "
            f"(cache dir unusable: {exc}); refusing to fetch"
        ) from exc
    with lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            cache = CACHE_DIR / f"{name}.txt"
            stamp = CACHE_DIR / f"{name}.attempt"
            now = time.time()

            age = None
            try:
                age = now - cache.stat().st_mtime
            except OSError:
                pass
            if age is not None and age < MIN_FETCH_INTERVAL_SECONDS:
                try:
                    text = cache.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = None
                if text:
                    print(f"  using cached copy ({int(age // 60)} min old; "
                          f"provider caps downloads at one per 24h)")
                    return text

            last_attempt = None
            try:
                last_attempt = float(stamp.read_text().strip())
            except (OSError, ValueError):
                pass
            if last_attempt is not None and now - last_attempt < MIN_FETCH_INTERVAL_SECONDS:
                wait_h = (MIN_FETCH_INTERVAL_SECONDS - (now - last_attempt)) / 3600
                raise RuntimeError(
                    f"{feed['name']}: a download attempt was already made "
                    f"{int((now - last_attempt) // 60)} min ago and did not complete; the "
                    f"provider caps requests at one per 24h, so the next attempt is "
                    f"allowed in ~{wait_h:.1f} h"
                )

            # Prove durable state is writable BEFORE downloading; otherwise a
            # successful fetch with no record would let the next run refetch.
            # Probe with a temp file: opening the cache itself in append mode
            # would create an EMPTY cache file, which a later run would
            # mistake for a fresh download after a failed attempt.
            try:
                if cache.exists():
                    with open(cache, "a", encoding="utf-8"):
                        pass
                fd, probe = tempfile.mkstemp(dir=CACHE_DIR, prefix=".write-probe-")
                os.close(fd)
                os.unlink(probe)
            except OSError as exc:
                raise RuntimeError(
                    f"{feed['name']}: cannot record downloads ({exc}); "
                    "refusing to fetch without cap enforcement"
                ) from exc

            # Record the attempt BEFORE any network access. The provider
            # counts requests, not successful transfers: a partial or
            # ambiguous transfer is still a request. Stamping first means no
            # outcome (failed transfer, crashed process, failed cache write)
            # can lead to a second request inside the provider's window.
            try:
                stamp.write_text(str(now), encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(
                    f"{feed['name']}: cannot record the download attempt "
                    f"({exc}); refusing to fetch without cap enforcement"
                ) from exc
            text = fetch(feed["url"])
            # Atomic cache write: a failure never leaves an empty or partial
            # cache that later runs would treat as a fresh copy. The stamp
            # already stands, so a failed write cannot cause a refetch inside
            # the provider's window either.
            fd, tmp = tempfile.mkstemp(dir=CACHE_DIR, prefix=".cache-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp, cache)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            try:
                stamp.unlink()
            except OSError:
                pass
            return text
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def parse_feed(text: str) -> tuple[list, int]:
    """Extract networks from raw CIDR-format feed text.

    Return (networks, malformed_count).
    """
    networks = []
    malformed = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        # Spamhaus style "1.2.3.0/24 ; SBL123456": keep only the first token.
        token = line.replace(";", " ").split()[0]
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
            continue
        except ValueError:
            pass
        try:
            addr = ipaddress.ip_address(token)
            networks.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"))
        except ValueError:
            malformed += 1
    return networks, malformed


def parse_p2p(text: str) -> tuple[list, int]:
    """Extract ranges from PeerGuardian P2P text: "Description:start-end".

    Returns (rules, malformed_count) with rules as (version, start, end,
    label) tuples. The description may contain colons, so the range is split
    from the last colon. Lines whose range does not parse, mixes address
    families, or is reversed are counted malformed and skipped. Ranges are
    kept as ranges; nothing is expanded to individual addresses.
    """
    rules = []
    malformed = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        label, sep, rng = line.rpartition(":")
        if not sep or "-" not in rng:
            malformed += 1
            continue
        start_s, _, end_s = rng.partition("-")
        try:
            start = ipaddress.ip_address(start_s.strip())
            end = ipaddress.ip_address(end_s.strip())
            if start.version != end.version or end < start:
                raise ValueError("bad range")
        except ValueError:
            malformed += 1
            continue
        rules.append((start.version, int(start), int(end), label.strip() or "unlabeled"))
    return rules, malformed


def is_special_purpose(net) -> bool:
    """True for ranges that must never appear in a peer blocklist.

    Covers RFC1918 private space, loopback, link-local, multicast, reserved
    and unspecified ranges. Blocking these would break local traffic. The
    exact set comes from Python's ipaddress module and the IANA special
    registries it tracks, so it can vary between Python versions; the
    workflow pins the runtime and test_main.py pins the expected exclusions.
    """
    return (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_reserved
        or net.is_unspecified
    )


def range_is_special(version: int, start: int, end: int) -> bool:
    """True when an address range lies entirely inside special-purpose space.

    An arbitrary range is checked via its (few) covering CIDRs - summarized,
    never enumerated address by address. A range that only partly overlaps
    special-purpose space is kept whole; splitting it would mislabel the
    remainder.
    """
    a = ipaddress.ip_address(start)
    b = ipaddress.ip_address(end)
    return all(is_special_purpose(net) for net in ipaddress.summarize_address_range(a, b))


def sanitize_label(label: str) -> str:
    # ',' separates fields in DAT format, so descriptions must not contain
    # one. Upstream P2P labels sometimes do.
    return " ".join(label.replace(",", ";").split())


def dedupe_and_drop_covered(rules: list) -> list:
    """Collapse exact duplicates and drop ranges covered by an earlier feed.

    Input items are (version, start, end, label, priority). Within one
    address family, sorting by start (then longest first) lets a single
    sweep drop any range whose end is already covered by a kept range that
    started at or before it. Coverage only counts from ranges whose feed has
    equal or higher priority (lower number), so a later feed's broad range
    can never swallow an earlier feed's more specific label; such overlaps
    simply coexist. Partial overlaps are likewise kept: merging them would
    lose which source labeled which space. Returns sorted
    (version, start, end, label) rules.
    """
    out = []
    for version in (4, 6):
        group = sorted(
            (r for r in rules if r[0] == version),
            key=lambda r: (r[1], -r[2], r[4]),
        )
        max_end_by_priority: dict[int, int] = {}
        for _v, start, end, label, prio in group:
            covered = any(
                end <= max_end
                for p, max_end in max_end_by_priority.items()
                if p <= prio
            )
            if covered:
                continue  # exact duplicate or covered by an equal/earlier feed
            out.append((version, start, end, label))
            max_end_by_priority[prio] = max(max_end_by_priority.get(prio, -1), end)
    out.sort(key=lambda r: (r[0], r[1], r[2]))
    return out


def collect(feeds: list, allow_partial: bool = False) -> list:
    """Fetch every feed and merge into sorted (version, start, end, label) rules.

    Every configured feed must both download successfully and yield at least
    one valid entry. A feed that fails to download, or that downloads fine
    but contains no valid entries (an error page, a retired feed's notice),
    counts as failed. By default any failed feed aborts the run with a
    non-zero exit BEFORE any output file is touched, so a bad run cannot
    shrink a previously good filter. allow_partial=True is an explicit
    degraded mode: proceed with whichever feeds succeeded. Special-purpose
    ranges are excluded as each feed is merged.
    """
    collected = []  # (version, start, end, label, priority)
    failures = []
    for priority, feed in enumerate(feeds):
        print(f"Fetching {feed['name']}: {feed['url']}")
        try:
            text = fetch_feed(feed)
        except RuntimeError as exc:
            print(f"ERROR: {feed['name']}: {exc}", file=sys.stderr)
            failures.append(feed["name"])
            continue
        if feed.get("format") == "p2p":
            parsed, malformed = parse_p2p(text)
            parsed = [(v, s, e, f"{feed['name']} {lbl}") for v, s, e, lbl in parsed]
        else:
            networks, malformed = parse_feed(text)
            parsed = [
                (n.version, int(n.network_address), int(n.broadcast_address),
                 f"{feed['name']} {n.with_prefixlen}")
                for n in networks
            ]
        if not parsed:
            print(
                f"ERROR: {feed['name']}: downloaded but contained no valid entries",
                file=sys.stderr,
            )
            failures.append(feed["name"])
            continue
        kept = excluded = 0
        for version, start, end, label in parsed:
            if range_is_special(version, start, end):
                excluded += 1
                continue
            collected.append((version, start, end, sanitize_label(label), priority))
            kept += 1
        print(
            f"  {len(parsed)} entries ({kept} kept, {excluded} special-purpose excluded, "
            f"{malformed} malformed lines skipped)"
        )
    if failures:
        msg = "feeds failed: " + ", ".join(failures)
        if not allow_partial:
            sys.exit(
                f"ERROR: {msg}; aborting without touching existing output files. "
                "Re-run with --allow-partial to publish a partial list anyway."
            )
        print(f"WARNING: {msg}; continuing because --allow-partial was passed",
              file=sys.stderr)
    if not collected:
        sys.exit("ERROR: no usable rules from any feed; aborting")
    rules = dedupe_and_drop_covered(collected)
    dropped = len(collected) - len(rules)
    if dropped:
        print(f"  {dropped} duplicate or fully covered ranges dropped across feeds")
    return rules


def atomic_write_text(path: Path, content: str) -> None:
    """Write content to path atomically: temp file in the same dir, fsync, rename.

    A crash or kill mid-write leaves either the old file or the new file in
    place, never a truncated one.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def render_dat(rules: list, source_urls: list) -> str:
    lines = [
        "# qBittorrent IP filter - eMule DAT format",
        "# generated by qbittorrent-blocklist-compiler",
        "# sources: " + ", ".join(source_urls),
        f"# rules: {len(rules)}",
    ]
    for version, start, end, label in rules:
        lines.append(
            f"{ipaddress.ip_address(start)} - {ipaddress.ip_address(end)} , 000 , {label}"
        )
    return "\n".join(lines) + "\n"


def select_feeds(name: str) -> list:
    """Choose the feed set. 'security' excludes the Bluetack feed: its
    provider's developer terms (iblocklist.com/developer) forbid automated
    access at a predefined time, so CI may only fetch the security feeds.
    The combined 'all' build is for a run the user starts themselves."""
    if name == "security":
        return [f for f in FEEDS if f.get("format") == "cidr"]
    return FEEDS


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile public IP blocklists into qBittorrent ipfilter.dat."
    )
    parser.add_argument("--output", default="ipfilter.dat",
                        help="eMule DAT output (start - end , 000 , description)")
    parser.add_argument("--min-rules", type=int, default=MIN_RULES,
                        help="abort if the merged list has fewer rules than this")
    parser.add_argument("--allow-partial", action="store_true",
                        help="publish anyway if some feeds fail (degraded mode, off by default)")
    parser.add_argument("--feeds", choices=["all", "security"], default="all",
                        help="'all' (default) includes Bluetack and is for local, "
                             "user-started runs. 'security' is the CI set.")
    args = parser.parse_args(argv)

    feeds = select_feeds(args.feeds)
    rules = collect(feeds, allow_partial=args.allow_partial)
    if len(rules) < args.min_rules:
        sys.exit(
            f"ERROR: merged list has only {len(rules)} rules (< {args.min_rules}); "
            "aborting without touching existing output files"
        )

    source_urls = [feed["url"] for feed in feeds]
    atomic_write_text(Path(args.output), render_dat(rules, source_urls))
    print(f"Wrote {len(rules)} unique rules to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
