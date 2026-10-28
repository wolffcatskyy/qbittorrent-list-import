# qbittorrent-blocklist-compiler

Build your own qBittorrent IP filter. Know what's in it. Know when it fails.

Have you ever been frustrated wanting to use qBittorrent features like
blocklists, but could never find a list to use? Us too. This project doesn't
make or host the lists. Like CrowdSec's engine, it's the tool: your machine
downloads the lists from their providers, combines them, and installs the
result into qBittorrent. No data is hosted or redistributed by this project.

Multiple sources, one `ipfilter.dat`, generated on your machine. Combine
FireHOL Level 1, Spamhaus DROP and DROPv6, and Bluetack Level 1 in the DAT
format qBittorrent expects. Retained rules carry source labels. Duplicate
and fully covered ranges are removed, while partial overlaps remain labeled.

Built to stop rather than fail quietly. Failed or empty feeds abort the
build by default. A configurable minimum-rule floor helps catch unexpectedly
small results. Failed builds leave your existing output untouched;
successful builds replace it atomically. Special-purpose address ranges are
excluded at build time.

Direct downloads, local output. Bluetack has a persistent 24-hour cache,
recorded fetch attempts, and a concurrency lock. If the guard can't
maintain its state, it refuses to fetch. No scheduled Bluetack pulls. No
compiled lists committed or uploaded by CI. Each source's terms still apply.

Simple to run. Python 3.10+ on Linux or macOS, standard library only:

```
python3 main.py
```

Use `--feeds security` to omit Bluetack or `--output` to choose the
destination. Inspect the generated file, then select it in qBittorrent's
IP filtering settings. Identical inputs and settings produce identical
output, without timestamp churn. Offline tests and CI format validation
check the build.

An IP filter, not invisibility. It doesn't hide your address from trackers
or DHT, guarantee protection from monitoring, or replace a VPN. Feeds can
lag, and blocked ranges can contain legitimate peers. If a torrent stalls,
check the filter first.

## One-line setup: compile and install into qBittorrent

```
curl -fsSL https://raw.githubusercontent.com/wolffcatskyy/qbittorrent-blocklist/main/install.sh | sh
```

The script downloads the compiler and sync tool into a temporary directory,
builds the filter, loads it into a running qBittorrent through its Web API,
then removes the temporary directory. The live filter file and the 24-hour
download-guard cache are kept.

Prereqs: Linux or macOS, Python 3.10+, and qBittorrent running with its
WebUI enabled (Tools > Options > Web UI). You'll be prompted for the WebUI
username and password on the terminal (set `QBT_URL` if it isn't
`http://127.0.0.1:8080`). Credentials are never printed or stored, and the
tool never changes qBittorrent's WebUI or password settings. Both login contracts are handled (qBittorrent 5.x's 204 +
`QBT_SID_<port>` cookie and the older 200 "Ok." + `SID`).

The normal update path never interrupts filtering. Toggling the filter off
and on leaves qBittorrent unfiltered in between, so this tool never does
that. Instead it writes the new list to an alternate file (`ipfilter-a.dat`
/ `ipfilter-b.dat`) and points qBittorrent at the new path; qBittorrent
loads it in a background thread and swaps the filter atomically, with the
old rules active until the new ones are in place. That behavior is verified
in qBittorrent's source (`sessionimpl.cpp`: the path change re-parses and
then sets the filter "in one go so there isn't a time window") and
exercised end-to-end against a live qBittorrent 5.3.0 on Linux: fresh
install, update alternation, restart persistence, and parse confirmation in
qBittorrent's own log.

The failure path is handled, but read this honestly: if qBittorrent cannot
parse the new file after the switch (which qBittorrent answers by
installing an empty filter - including via a "0 rules applied" success
message), the tool detects it from qBittorrent's log within seconds and
automatically reverts to your previous filter file, which qBittorrent then
re-loads (verified live: the full rule set comes back). Between qBittorrent
installing the empty filter and the revert, filtering is briefly open. The
compiler's guards (atomic write, minimum-rule floor, fail-closed feeds)
make a bad file very unlikely, but the window is real, so it is stated
here. If you need even that window closed, pause your torrents before
updating.

Any failure before the install step leaves the running filter untouched.
Cleanup removes only the temporary download directory and, only after a
confirmed successful load, the previous alternate filter file the tool
itself created; a pre-existing filter file of yours is never deleted.

Re-run the command whenever you want a fresh list - daily, monthly, your
choice. The rate-limited Bluetack feed won't download more than once in 24
hours no matter how often you re-run, and it should stay a feed you fetch
by hand: its provider's terms prohibit scheduled access. Pass options
through with `sh -s --`, e.g. `... | sh -s -- --feeds security`.

qBittorrent on another machine (NAS, docker)? The filter file must be on a
filesystem that qBittorrent process can read, so run the command on that
host, or use `--filter-dir` pointed at a shared mount plus `QBT_URL` aimed
at that host.

## Output format: read this before changing it

The file is written in the **eMule DAT format**, which is what qBittorrent
parses for files ending in `.dat` (verified against
`src/base/bittorrent/filterparserthread.cpp`):

```
1.2.3.4 - 1.2.3.255 , 000 , Spamhaus_DROP 1.2.3.0/24
```

That is: start IP, dash, end IP, comma, access level, comma, description.
Access level `000` means blocked; the DAT parser skips any rule whose access
level is above 127. A range's two ends must be the same address family.
Lines starting with `#` are skipped. IPv4 and IPv6 are both accepted.

**Do not** change the output to the PeerGuardian P2P format
(`Description:start_ip-end_ip`) while the file is named `ipfilter.dat`.
qBittorrent only parses P2P lines from files ending in `.p2p`; P2P-style
lines in a `.dat` file are logged as malformed and dropped, so it would
silently produce an empty filter. (P2P is supported as an *input* format,
not an output one.)

## Sources

| Feed | Format | Purpose |
| --- | --- | --- |
| **FireHOL Level 1** | CIDR | Basic-protection aggregate (bogons, dshield, feodo, spamhaus_drop) |
| **Spamhaus DROP** | CIDR | Hijacked / cybercrime-operated netblocks |
| **Spamhaus DROPv6** | CIDR | The IPv6 DROP list |
| **Bluetack Level 1** (via I-BlockList) | P2P, gzipped | The classic anti-P2P organization list |

The first three are general security threat feeds. Bluetack Level 1 is the
anti-P2P feed; its labels are its maintainers' own claims about which
organization controls a range, **not** verified attribution. Treat it as a
community list, not proof of who operates an address.

FireHOL Level 1 already aggregates spamhaus_drop, so overlap between the
first two feeds is expected; dedup absorbs it. Spamhaus **EDROP** was merged
into DROP by Spamhaus and is intentionally not fetched. Use of the Spamhaus
DROP lists is subject to their fair-use policy:
https://www.spamhaus.org/blocklists/drop-fair-use-policy/
Bluetack's free list is served by I-BlockList; check their terms before
redistributing the compiled output.

## What the compiler does

1. Fetches every feed over HTTPS with 3 retries and backoff. Downloads and
   decompression are size-capped (gzip is detected by magic bytes), so a
   runaway endpoint or zip bomb is refused instead of trusted.
2. Parses CIDR ranges, bare IPs, and PeerGuardian `Label:start-end` ranges
   (P2P labels may contain colons; the range splits from the last colon).
3. **Excludes special-purpose ranges** (RFC1918 private, loopback,
   link-local, multicast, reserved, unspecified). Blocking those would break
   local traffic. The classification comes from Python's `ipaddress` module
   and can vary between Python versions, so the workflow pins Python 3.12
   and `test_main.py` pins the expected exclusions.
4. Deduplicates: exact duplicates collapse, and a range fully covered by an
   equal-or-earlier feed's range is dropped (the earlier feed's label wins;
   the security feeds precede Bluetack). A later feed's broader range is
   kept even where it covers an earlier feed's narrower rule, so no
   source's label is ever swallowed. Partial overlaps are all kept.
   Ranges are never expanded into individual addresses.
5. Sorts IPv4 numerically first, then IPv6.
6. Writes `ipfilter.dat` atomically (temp file, fsync, rename). Output is
   deterministic - no timestamps - so the daily workflow only commits when
   the actual rules change.

Current size: 231,521 rules (~18 MB) with all four feeds, built in a few
seconds (live four-feed validation, Oct 27 2026). qBittorrent handles lists
of this size routinely.

## Failure behavior

A bad feed day must never shrink a working filter:

- By default, **every** feed must download successfully and yield at least
  one valid entry. Any failure aborts the run **before** `ipfilter.dat` is
  touched. `--allow-partial` is an explicit degraded opt-in.
- A feed that downloads but parses to zero entries (an error page, a retired
  feed's notice) counts as failed.
- A run that would produce fewer than `--min-rules` rules (default **1000**)
  aborts, so a gutted list can never replace a good one.

## Usage

```
python3 main.py                          # all four feeds, writes ./ipfilter.dat
python3 main.py --feeds security         # omit Bluetack (what CI builds)
python3 main.py --output /path/ipfilter.dat
python3 main.py --min-rules 500          # custom sanity floor
python3 main.py --allow-partial          # proceed if some feeds fail
```

To compile *and* install into a running qBittorrent in one step (see
"One-line setup" above):

```
python3 qbt_sync.py                      # prompts for WebUI credentials
python3 qbt_sync.py --feeds security --filter-dir /path/to/dir
QBT_URL=http://nas:8080 python3 qbt_sync.py   # non-secret setting only
```

## Project history

This project started with a different goal: publish a curated, hosted IP
filter - a single ready-to-use URL that always serves a fresh list. While
building it, we checked the terms of the sources we wanted to include, and
that changed the plan:

- **Spamhaus DROP/DROPv6** grants conditional free use but no license to
  redistribute derived data.
- **I-BlockList's developer policy** bars scheduled fetching and any
  redistribution of its data - explicitly including private redistribution -
  without written permission.
- **FireHOL Level 1** aggregates those and other lists, so its output
  carries the same upstream constraints.

A hosted compiled list would have redistributed exactly that data, so the
published scope became code only: this repository ships the compiler, and
no compiled blocklists are committed, hosted, or uploaded. Separately,
qBittorrent has no native URL import for IP filters
([qbittorrent/qBittorrent#72](https://github.com/qbittorrent/qBittorrent/issues/72),
open since 2012), so even a permitted hosted list would need a client with
remote-list support or a small local updater that fetches the URL and
reloads the filter through qBittorrent's Web API. A hosted edition can
revisit redistribution-permitted sources in the future.

## Distribution model and upstream terms

The compiled lists are **not committed to this repository**. They embed
upstream feed data whose terms grant use, not redistribution:

- **Spamhaus DROP/DROPv6**: content protected by copyright and database
  right; the fair-use policy grants no redistribution license.
- **Bluetack (I-BlockList)**: the developer terms
  (https://www.iblocklist.com/developer) forbid redistribution - explicitly
  including private/internal redistribution - without written permission,
  cap downloads at once per 24 hours, and forbid deploying scripts that
  access the service **at a predefined time**. That is why the combined
  build never runs on a schedule.
- **FireHOL Level 1**: aggregates Spamhaus DROP and other lists, so its
  output carries the same upstream constraints.

What this means in practice:

- `python3 main.py` (all four feeds, combined filter): run it yourself,
  locally, for personal use. Do not schedule it and do not publish the
  output.
- `python3 main.py --feeds security`: the security-only filter. This is
  what CI builds.

### Rate-limited feed guard (fail closed)

I-BlockList caps downloads at one per 24 hours, so the compiler enforces
that cap locally instead of trusting the operator to remember:

- A successful Bluetack download is cached under
  `~/.cache/qbittorrent-blocklist-compiler/`. Any run within 24 hours
  reuses the cache and does not touch the network.
- Every download attempt is recorded BEFORE the network is touched. If an
  attempt does not complete (failed transfer, crash, failed cache write),
  no further attempt is allowed for the full 24-hour window: the provider
  counts requests, including partial or ambiguous transfers, so no outcome
  can produce two requests inside one window. A successful download clears
  the record.
- A lock file serializes concurrent runs: two simultaneous invocations
  result in a single download.
- The cache is written atomically; a failed attempt never leaves an empty
  or partial cache that a later run would mistake for fresh data.
- **Fail closed**: if the cache directory or lock is unavailable (for
  example an unwritable home directory), the feed is NOT fetched at all,
  because the 24h cap cannot be proven or enforced without durable state.
- The security feed set (`--feeds security`) never touches this path.

## Automation (GitHub Actions)

`.github/workflows/update.yml` runs daily at 00:00 UTC and on demand
(`workflow_dispatch`). Each run installs dependencies, runs the unit tests,
compiles the **security-only** filter and validates every output line
against the DAT format. It is build-and-validate only: it never fetches
Bluetack, never commits compiled data, never uploads it as an artifact
(upstream terms grant use, not redistribution - even private artifact
storage is not established as permitted), and needs only the default read
permission. To actually get a filter file, run `main.py` locally.

## Tests

```
python3 -m unittest
```

53 tests cover CIDR and P2P parsing, gzip and size-cap enforcement, the
special-purpose exclusion set (pinned against the ranges actually present
in the live feeds), exact and covered-range dedup with feed priority, DAT
output format for IPv4 and IPv6, ordering, deterministic rendering, atomic
writes, feed-failure handling and the minimum-rule floor, and the
rate-limited feed guard (24h cache reuse, pre-network attempt stamping,
concurrency lock, fail-closed behavior).
