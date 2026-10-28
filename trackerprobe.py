"""Preflight health checks for tracker list entries.

What this does and does not do:
- udp:// trackers: a BEP 15 *connect* handshake only. No announce, no
  scrape, no info_hash, no peer data - it proves the tracker speaks the
  UDP protocol without registering anything.
- http(s):// trackers: TCP connect (plus TLS handshake for https). This
  proves reachability, NOT that the tracker answers the HTTP announce
  protocol - the only protocol-level HTTP probe (scrape) requires an
  info_hash, which this tool deliberately does not invent.
- "no response" is not proof a tracker is dead: UDP loss, rate limiting
  and probe filtering all produce it. Results are reported truthfully.
- Trackers resolving to private/loopback/reserved addresses are refused
  (no probing your LAN).
"""

import concurrent.futures
import ipaddress
import random
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from urllib.parse import urlparse

UDP_PROTOCOL_ID = 0x41727101980
UDP_ACTION_CONNECT = 0
DEFAULT_TIMEOUT = 4.0
MAX_WORKERS = 10

OK = "ok"                    # protocol-verified (UDP connect handshake)
REACHABLE = "reachable"      # TCP/TLS connect only, protocol not verified
NO_RESPONSE = "no response" # timed out; not proof the tracker is dead
REFUSED = "refused"         # private/reserved address, not probed
INVALID = "invalid"         # unparsable URL
UNSUPPORTED = "unsupported" # scheme this tool cannot probe (ws/wss/...)


@dataclass
class ProbeResult:
    url: str
    status: str
    detail: str = ""
    latency_ms: int | None = None


def _resolve_public_only(host: str, port: int,
                         allow_private: bool) -> tuple[list, str]:
    """Resolve host; return (addrinfos, error). Errors when every route is
    non-public unless allow_private."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_UDP)
    except socket.gaierror as e:
        return [], f"DNS resolution failed: {e}"
    addrs = {ipaddress.ip_address(i[4][0]) for i in infos}
    if allow_private:
        return infos, ""
    nonpublic = [a for a in addrs if not a.is_global]
    if nonpublic:
        return [], (f"resolves to non-public address "
                    f"{sorted(str(a) for a in nonpublic)[0]}; not probed")
    return infos, ""


def probe_udp(host: str, port: int, timeout: float,
              allow_private: bool = False) -> tuple[str, str, int | None]:
    infos, err = _resolve_public_only(host, port, allow_private)
    if err:
        return REFUSED, err, None
    family = infos[0][0]
    txn = random.getrandbits(32)
    req = struct.pack("!QII", UDP_PROTOCOL_ID, UDP_ACTION_CONNECT, txn)
    # Connect to the address we already validated, not the hostname,
    # so DNS cannot rebind to a private target after the check.
    sockaddr = infos[0][4]
    start = time.monotonic()
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _attempt in range(2):
            try:
                sock.sendto(req, sockaddr)
                data, _ = sock.recvfrom(2048)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as e:
                return NO_RESPONSE, f"socket error: {e}", None
            if len(data) >= 16:
                action, rtxn = struct.unpack("!II", data[:8])
                if action == UDP_ACTION_CONNECT and rtxn == txn:
                    ms = int((time.monotonic() - start) * 1000)
                    return OK, "UDP connect handshake answered", ms
            return NO_RESPONSE, "answered with a non-connect packet", None
    return NO_RESPONSE, f"no answer within {timeout:.0f}s (2 tries)", None


def probe_tcp(host: str, port: int, use_tls: bool, timeout: float,
              allow_private: bool = False) -> tuple[str, str, int | None]:
    infos, err = _resolve_public_only(host, port, allow_private)
    if err:
        return REFUSED, err, None
    sockaddr = infos[0][4][:2]  # (ip, port); connect to the validated IP
    start = time.monotonic()
    try:
        with socket.create_connection(sockaddr, timeout=timeout) as sock:
            if use_tls:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
                note = ("TLS handshake ok (certificate valid for "
                        f"{host}); tracker protocol not verified")
            else:
                note = ("plaintext TCP connect ok; tracker protocol "
                        "not verified")
    except ssl.SSLError as e:
        return NO_RESPONSE, f"TLS error: {e}", None
    except (socket.timeout, TimeoutError):
        return NO_RESPONSE, f"no connection within {timeout:.0f}s", None
    except OSError as e:
        return NO_RESPONSE, f"connect failed: {e}", None
    ms = int((time.monotonic() - start) * 1000)
    return REACHABLE, note, ms


def probe_tracker(url: str, timeout: float = DEFAULT_TIMEOUT,
                  allow_private: bool = False) -> ProbeResult:
    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return ProbeResult(url, INVALID, "unparsable URL")
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        return ProbeResult(url, INVALID, "no host in URL")
    if scheme == "udp":
        port = parsed.port or 80
        status, detail, ms = probe_udp(host, port, timeout, allow_private)
    elif scheme in ("http", "https"):
        port = parsed.port or (443 if scheme == "https" else 80)
        status, detail, ms = probe_tcp(host, port, scheme == "https",
                                       timeout, allow_private)
    else:
        return ProbeResult(url, UNSUPPORTED,
                           f"scheme {scheme!r} cannot be probed")
    return ProbeResult(url, status, detail, ms)


def preflight(urls: list[str], timeout: float = DEFAULT_TIMEOUT,
              max_workers: int = MAX_WORKERS,
              allow_private: bool = False) -> list[ProbeResult]:
    """Probe every entry concurrently; results keep the input order."""
    results: list[ProbeResult | None] = [None] * len(urls)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers) as pool:
        futures = {pool.submit(probe_tracker, u, timeout, allow_private): i
                   for i, u in enumerate(urls)}
        for fut in concurrent.futures.as_completed(futures):
            results[futures[fut]] = fut.result()
    return [r for r in results if r is not None]


def summarize(results: list[ProbeResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts
