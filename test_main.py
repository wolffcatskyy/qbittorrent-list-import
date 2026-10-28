#!/usr/bin/env python3
"""Automated tests for main.py. Run: python3 test_main.py (or: python3 -m unittest test_main -v)"""

import gzip
import io
import ipaddress
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main as m

SAMPLE = """# hash comment
; semicolon comment
// slash comment
1.2.3.0/24 ; SBL123456
10.0.0.0/8
5.6.7.8
1.2.3.0/24
not-an-ip
"""

DAT_LINE_V4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3} - (\d{1,3}\.){3}\d{1,3} , 000 , .+$")
DAT_LINE_V6 = re.compile(r"^[0-9a-fA-F:]+ - [0-9a-fA-F:]+ , 000 , .+$")


class ParseFeedTests(unittest.TestCase):
    def test_comments_cidr_bare_ip_and_malformed(self):
        nets, malformed = m.parse_feed(SAMPLE)
        self.assertEqual(malformed, 1)
        self.assertEqual(len(nets), 4)  # the duplicate survives parsing; dedupe is the sweep's job
        self.assertIn(ipaddress.ip_network("1.2.3.0/24"), nets)
        self.assertIn(ipaddress.ip_network("5.6.7.8/32"), nets)

    def test_comment_only_response_yields_zero_entries(self):
        # Shape of Spamhaus' retired-EDROP notice: valid HTTP, zero usable rules.
        nets, malformed = m.parse_feed("; This list has been merged elsewhere\n; EOF\n")
        self.assertEqual((nets, malformed), ([], 0))

    def test_ipv6_accepted(self):
        # qBittorrent's filterparserthread.cpp documents IPv6 ranges, so v6
        # feed entries are valid output.
        nets, _ = m.parse_feed("2001:db8::/32\n")
        self.assertEqual(nets, [ipaddress.ip_network("2001:db8::/32")])


class ParseP2PTests(unittest.TestCase):
    def test_basic_range_with_label(self):
        rules, malformed = m.parse_p2p("Some Org:1.2.3.0-1.2.3.255\n")
        self.assertEqual(malformed, 0)
        v, s, e, label = rules[0]
        self.assertEqual((v, label), (4, "Some Org"))
        self.assertEqual((ipaddress.ip_address(s), ipaddress.ip_address(e)),
                         (ipaddress.ip_address("1.2.3.0"), ipaddress.ip_address("1.2.3.255")))

    def test_label_containing_colon_survives(self):
        # Descriptions may contain colons; split from the LAST colon.
        rules, malformed = m.parse_p2p("Org: Division A:9.9.9.0-9.9.9.9\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(rules[0][3], "Org: Division A")

    def test_malformed_lines_counted_not_fatal(self):
        text = ("# comment\n"
                "Good:1.0.0.0-1.0.0.3\n"
                "no colon or dash\n"
                "NoRange:\n"
                "Reversed:2.0.0.9-2.0.0.1\n"
                "BadIP:999.1.1.1-999.1.1.2\n")
        rules, malformed = m.parse_p2p(text)
        self.assertEqual(len(rules), 1)
        self.assertEqual(malformed, 4)

    def test_single_ip_range_ok(self):
        rules, malformed = m.parse_p2p("Solo:5.6.7.8-5.6.7.8\n")
        self.assertEqual(malformed, 0)
        self.assertEqual(rules[0][1], rules[0][2])

    def test_label_comma_sanitized_for_dat(self):
        with mock.patch.object(m, "fetch", return_value="A, Inc:9.0.0.0-9.0.0.1\n"):
            rules = m.collect([{"name": "F", "url": "u://x", "format": "p2p"}])
        self.assertNotIn(",", rules[0][3])
        self.assertIn("A; Inc", rules[0][3])


class FetchTests(unittest.TestCase):
    class FakeResp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _urlopen(self, payload: bytes):
        # Fresh response object per call: retries must re-read the payload.
        return mock.patch.object(m.urllib.request, "urlopen",
                                 side_effect=lambda *a, **k: self.FakeResp(payload))

    def test_plain_text_fetch(self):
        with self._urlopen(b"1.2.3.0/24\n"):
            self.assertEqual(m.fetch("u://x"), "1.2.3.0/24\n")

    def test_gzip_detected_by_magic_and_decompressed(self):
        payload = gzip.compress(b"Org:1.2.3.0-1.2.3.255\n")
        with self._urlopen(payload):
            self.assertEqual(m.fetch("u://x"), "Org:1.2.3.0-1.2.3.255\n")

    def test_oversize_download_refused(self):
        payload = b"x" * 2048
        with mock.patch.object(m, "MAX_COMPRESSED_BYTES", 1024), \
             self._urlopen(payload), mock.patch.object(m.time, "sleep"):
            with self.assertRaises(RuntimeError):
                m.fetch("u://x")

    def test_decompression_bomb_refused(self):
        payload = gzip.compress(b"x" * 4096)
        with mock.patch.object(m, "MAX_DECOMPRESSED_BYTES", 1024), \
             self._urlopen(payload), mock.patch.object(m.time, "sleep"):
            with self.assertRaises(RuntimeError) as cm:
                m.fetch("u://x")
        self.assertIn("download failed", str(cm.exception))

    def test_corrupt_gzip_refused(self):
        with self._urlopen(b"\x1f\x8b not really gzip"), mock.patch.object(m.time, "sleep"):
            with self.assertRaises(RuntimeError):
                m.fetch("u://x")


class FeedConfigTests(unittest.TestCase):
    def test_dropv6_feed_configured(self):
        urls = [f["url"] for f in m.FEEDS]
        self.assertIn("https://www.spamhaus.org/drop/dropv6.txt", urls)

    def test_bluetack_feed_configured_over_https(self):
        feeds = [f for f in m.FEEDS if f["name"] == "Bluetack_L1"]
        self.assertEqual(len(feeds), 1)
        self.assertTrue(feeds[0]["url"].startswith("https://"))
        self.assertEqual(feeds[0]["format"], "p2p")

    def test_security_feeds_precede_bluetack(self):
        # Earlier feed wins the label on duplicate/covered ranges; the
        # security feeds must keep priority over the anti-P2P list.
        names = [f["name"] for f in m.FEEDS]
        self.assertEqual(names, ["FireHOL_L1", "Spamhaus_DROP", "Spamhaus_DROPv6", "Bluetack_L1"])

    def test_edrop_not_configured(self):
        # EDROP was merged into DROP by Spamhaus; its file is empty.
        for f in m.FEEDS:
            self.assertNotIn("edrop", f["url"].lower())

    def test_security_feed_set_excludes_bluetack(self):
        # I-BlockList's developer terms forbid automated access at a
        # predefined time, so CI must never fetch Bluetack.
        names = [f["name"] for f in m.select_feeds("security")]
        self.assertEqual(names, ["FireHOL_L1", "Spamhaus_DROP", "Spamhaus_DROPv6"])
        self.assertEqual(len(m.select_feeds("all")), 4)


class SpecialPurposeExclusionTests(unittest.TestCase):
    """Pin the exclusion set. Python's ipaddress classification can vary by
    version, so these tests fail loudly if the runtime starts keeping (or
    newly dropping) any of these ranges."""

    def test_ipv4_special_purpose_ranges_excluded(self):
        # The permanent special-purpose ranges currently present in FireHOL L1,
        # plus multicast. All must be excluded.
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
                     "127.0.0.0/8",                                     # loopback
                     "169.254.0.0/16",                                  # link-local
                     "0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24",
                     "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
                     "224.0.0.0/4"):                                    # multicast
            self.assertTrue(m.is_special_purpose(ipaddress.ip_network(cidr)), cidr)

    def test_ipv6_special_purpose_ranges_excluded(self):
        for cidr in ("::1/128", "fe80::/10", "ff00::/8", "fc00::/7"):
            self.assertTrue(m.is_special_purpose(ipaddress.ip_network(cidr)), cidr)

    def test_real_ranges_kept(self):
        # Representative global-unicast ranges from the live feeds must survive.
        for cidr in ("1.2.3.0/24", "5.6.7.8/32", "2a14:8000::/29"):
            self.assertFalse(m.is_special_purpose(ipaddress.ip_network(cidr)), cidr)

    def test_arbitrary_range_inside_special_space_excluded(self):
        # A P2P range that is not CIDR-aligned but sits inside RFC1918.
        self.assertTrue(m.range_is_special(4, int(ipaddress.ip_address("10.1.2.3")),
                                           int(ipaddress.ip_address("10.9.9.9"))))

    def test_partly_overlapping_range_kept(self):
        # 9.0.0.0-11.0.0.0 spans 10.0.0.0/8 but is not itself special-purpose;
        # splitting it would mislabel the rest, so it is kept whole.
        self.assertFalse(m.range_is_special(4, int(ipaddress.ip_address("9.0.0.0")),
                                            int(ipaddress.ip_address("11.0.0.0"))))

    def test_exclusions_applied_in_collect(self):
        payload = ("1.2.3.0/24\n10.0.0.0/8\n127.0.0.0/8\n169.254.0.0/16\n"
                   "192.168.0.0/16\n224.0.0.0/4\n")
        with mock.patch.object(m, "fetch", return_value=payload):
            rules = m.collect([{"name": "F", "url": "u://x"}])
        self.assertEqual(len(rules), 1)
        self.assertEqual(ipaddress.ip_address(rules[0][1]), ipaddress.ip_address("1.2.3.0"))


class DedupeAndCoverageTests(unittest.TestCase):
    def _run(self, rules):
        # rules: (version, start, end, label, priority)
        return m.dedupe_and_drop_covered(rules)

    def v4(self, a, b):
        return (4, int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b)))

    def test_exact_duplicate_first_priority_wins(self):
        r = [self.v4("1.0.0.0", "1.0.0.255") + ("FeedB", 1),
             self.v4("1.0.0.0", "1.0.0.255") + ("FeedA", 0)]
        out = self._run(r)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][3], "FeedA")

    def test_covered_range_dropped(self):
        r = [self.v4("1.0.0.0", "1.0.255.255") + ("Wide", 0),
             self.v4("1.0.1.0", "1.0.1.255") + ("Narrow", 1)]
        out = self._run(r)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][3], "Wide")

    def test_partial_overlap_kept(self):
        r = [self.v4("1.0.0.0", "1.0.0.127") + ("A", 0),
             self.v4("1.0.0.64", "1.0.0.255") + ("B", 1)]
        out = self._run(r)
        self.assertEqual(len(out), 2)

    def test_adjacent_ranges_both_kept(self):
        r = [self.v4("1.0.0.0", "1.0.0.127") + ("A", 0),
             self.v4("1.0.0.128", "1.0.0.255") + ("B", 1)]
        out = self._run(r)
        self.assertEqual(len(out), 2)

    def test_coverage_never_crosses_families(self):
        r = [self.v4("0.1.0.0", "255.0.0.0") + ("V4Wide", 0),
             (6, 0, 2**128 - 1, "V6Wide", 0),
             (6, 5, 6, "V6Tiny", 1)]
        out = self._run(r)
        labels = [x[3] for x in out]
        self.assertIn("V4Wide", labels)
        self.assertIn("V6Wide", labels)
        self.assertNotIn("V6Tiny", labels)

    def test_output_sorted_v4_first(self):
        r = [(6, 5, 50, "V6", 0),
             self.v4("9.0.0.0", "9.0.0.9") + ("V4", 0)]
        out = self._run(r)
        self.assertEqual([x[0] for x in out], [4, 6])


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _rules(self):
        return m.dedupe_and_drop_covered([
            (4, int(ipaddress.ip_address("1.2.3.0")), int(ipaddress.ip_address("1.2.3.255")), "FeedB 1.2.3.0/24", 1),
            (4, int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255")), "FeedB 10.0.0.0/8", 1),
            (4, int(ipaddress.ip_address("1.2.3.0")), int(ipaddress.ip_address("1.2.3.255")), "FeedA 1.2.3.0/24", 0),
            (4, int(ipaddress.ip_address("192.168.0.0")), int(ipaddress.ip_address("192.168.255.255")), "FeedA 192.168.0.0/16", 0),
        ])

    def test_dat_format(self):
        p = self.dir / "out.dat"
        m.atomic_write_text(p, m.render_dat(self._rules(), ["u1"]))
        body = [l for l in p.read_text().splitlines() if not l.startswith("#")]
        self.assertEqual(len(body), 3)  # duplicate 1.2.3.0/24 collapsed
        for line in body:
            self.assertRegex(line, DAT_LINE_V4)
        self.assertTrue(body[0].startswith("1.2.3.0 - 1.2.3.255 , 000 , FeedA 1.2.3.0/24"), body)

    def test_dat_ipv6_line(self):
        rules = [(6, int(ipaddress.ip_address("2001:db8::")),
                  int(ipaddress.ip_address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")), "F 2001:db8::/32")]
        line = m.render_dat(rules, ["u"]).splitlines()[-1]
        self.assertEqual(line, "2001:db8:: - 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff , 000 , F 2001:db8::/32")
        self.assertRegex(line, DAT_LINE_V6)

    def test_sorted_numerically(self):
        body = [l for l in m.render_dat(self._rules(), ["u"]).splitlines() if not l.startswith("#")]
        starts = [int(ipaddress.ip_address(l.split(" - ")[0])) for l in body]
        self.assertEqual(starts, sorted(starts))

    def test_deterministic_render(self):
        a = m.render_dat(self._rules(), ["u1"])
        b = m.render_dat(self._rules(), ["u1"])
        self.assertEqual(a, b)

    def test_no_timestamp_in_header(self):
        # A wall-clock timestamp would force a commit every scheduled run
        # even when no rule changed.
        header = [l for l in m.render_dat(self._rules(), ["u1"]).splitlines()
                  if l.startswith("#")]
        self.assertFalse(any("generated:" in l.lower() and "20" in l for l in header), header)

    def test_no_comma_in_any_description(self):
        # ',' separates fields in DAT format.
        for line in m.render_dat(self._rules(), ["u"]).splitlines():
            if line.startswith("#"):
                continue
            self.assertEqual(line.count(" , "), 2, line)

    def test_atomic_write_replaces_and_leaves_no_tmp(self):
        p = self.dir / "out.dat"
        m.atomic_write_text(p, "old\n")
        m.atomic_write_text(p, "new\n")
        self.assertEqual(p.read_text(), "new\n")
        self.assertEqual(list(self.dir.glob("*.tmp")), [])


class CollectTests(unittest.TestCase):
    def _feeds(self):
        return [{"name": "good", "url": "u://good", "format": "cidr"},
                {"name": "bad", "url": "u://bad", "format": "cidr"}]

    def test_all_feeds_fail_aborts(self):
        with mock.patch.object(m, "fetch", side_effect=RuntimeError("boom")):
            with self.assertRaises(SystemExit) as cm:
                m.collect(self._feeds())
        self.assertNotEqual(cm.exception.code, 0)

    def test_partial_failure_aborts_by_default(self):
        def fake_fetch(url):
            if "good" in url:
                return "1.2.3.0/24\n"
            raise RuntimeError("boom")
        with mock.patch.object(m, "fetch", side_effect=fake_fetch):
            with self.assertRaises(SystemExit):
                m.collect(self._feeds())

    def test_allow_partial_proceeds_with_successful_feeds(self):
        def fake_fetch(url):
            if "good" in url:
                return "1.2.3.0/24\n"
            raise RuntimeError("boom")
        with mock.patch.object(m, "fetch", side_effect=fake_fetch):
            rules = m.collect(self._feeds(), allow_partial=True)
        self.assertEqual(len(rules), 1)
        self.assertEqual(ipaddress.ip_address(rules[0][1]), ipaddress.ip_address("1.2.3.0"))

    def test_zero_entry_feed_counts_as_failure(self):
        # A feed that downloads fine but parses to nothing must not count as success.
        with mock.patch.object(m, "fetch", return_value="; retired list\n; EOF\n"):
            with self.assertRaises(SystemExit):
                m.collect([{"name": "retired", "url": "u://x", "format": "cidr"}])

    def test_no_rules_aborts_even_with_allow_partial(self):
        with mock.patch.object(m, "fetch", side_effect=RuntimeError("boom")):
            with self.assertRaises(SystemExit):
                m.collect(self._feeds(), allow_partial=True)

    def test_p2p_feed_integrates_and_dedupes_against_cidr(self):
        feeds = [{"name": "S", "url": "u://s", "format": "cidr"},
                 {"name": "B", "url": "u://b", "format": "p2p"}]
        def fake_fetch(url):
            if url.endswith("s"):
                return "1.2.3.0/24\n"          # = 1.2.3.0 - 1.2.3.255
            return "Some Org:1.2.3.0-1.2.3.255\nWide:1.0.0.0-1.255.255.255\n"
        with mock.patch.object(m, "fetch", side_effect=fake_fetch):
            rules = m.collect(feeds)
        # The exact duplicate from Bluetack is dropped (the security feed
        # keeps the label). The wide Bluetack range is kept even though it
        # covers the narrower security rule: a later feed never swallows an
        # earlier feed's label.
        self.assertEqual(len(rules), 2)
        self.assertIn("B Wide", rules[0][3])       # 1.0.0.0 sorts first
        self.assertEqual(rules[1][3], "S 1.2.3.0/24")


class RateLimitedCacheTests(unittest.TestCase):
    def _feeds(self):
        return [{"name": "Bluetack_L1", "url": "u://b", "format": "p2p", "rate_limited": True}]

    def _collect(self, cache_dir, fetch_side_effect):
        with mock.patch.object(m, "CACHE_DIR", cache_dir), \
             mock.patch.object(m, "fetch", side_effect=fetch_side_effect) as f:
            m.collect(self._feeds())
        return f

    def test_second_run_within_24h_uses_cache_no_download(self):
        with tempfile.TemporaryDirectory() as d:
            f = self._collect(Path(d), ["Org:9.0.0.0-9.0.0.1\n", "SHOULD NOT BE FETCHED"])
            f2 = self._collect(Path(d), ["SHOULD NOT BE FETCHED"])
            self.assertEqual(f.call_count + f2.call_count, 1)  # second run served from cache

    def test_cache_older_than_24h_refetches(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "bluetack_l1.txt"
            cache.write_text("Old:9.0.0.0-9.0.0.1\n")
            old_time = __import__("time").time() - (m.MIN_FETCH_INTERVAL_SECONDS + 60)
            import os as _os
            _os.utime(cache, (old_time, old_time))
            f = self._collect(Path(d), ["New:9.0.0.0-9.0.0.2\n"])
            self.assertEqual(f.call_count, 1)

    def test_no_cache_and_failure_counts_as_failure(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(m, "CACHE_DIR", Path(d)), \
                 mock.patch.object(m, "fetch", side_effect=RuntimeError("boom")):
                with self.assertRaises(SystemExit):
                    m.collect(self._feeds())

    def test_unwritable_cache_fails_closed_no_download(self):
        # Without durable state the 24h cap cannot be enforced: refuse to
        # fetch at all rather than download-and-bypass.
        with tempfile.TemporaryDirectory() as d:
            blocker = Path(d) / "afile"
            blocker.write_text("not a dir")
            with mock.patch.object(m, "CACHE_DIR", blocker), \
                 mock.patch.object(m, "fetch", return_value="Org:9.0.0.0-9.0.0.1\n") as f:
                with self.assertRaises(SystemExit):
                    m.collect(self._feeds())
            self.assertEqual(f.call_count, 0)

    def test_failed_attempt_blocks_refetch_within_provider_window(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(m, "CACHE_DIR", Path(d)), \
                 mock.patch.object(m, "fetch", side_effect=RuntimeError("boom")) as f:
                with self.assertRaises(SystemExit):
                    m.collect(self._feeds())
                with self.assertRaises(SystemExit):
                    m.collect(self._feeds())  # cooldown: no second network call
            self.assertEqual(f.call_count, 1)
            # A retry one hour later is still refused: the provider counts
            # requests (even failed transfers), not successful downloads.
            stamp = Path(d) / "bluetack_l1.attempt"
            stamp.write_text(str(__import__("time").time() - 3600))
            with mock.patch.object(m, "CACHE_DIR", Path(d)):
                with self.assertRaises(SystemExit):
                    m.collect(self._feeds())

            # Once the provider's 24h window has passed, a retry is allowed.
            stamp.write_text(str(__import__("time").time() - (m.MIN_FETCH_INTERVAL_SECONDS + 60)))
            with mock.patch.object(m, "CACHE_DIR", Path(d)), \
                 mock.patch.object(m, "fetch", return_value="Org:9.0.0.0-9.0.0.1\n") as f:
                rules = m.collect(self._feeds())
            self.assertEqual(f.call_count, 1)
            self.assertEqual(len(rules), 1)

    def test_concurrent_runs_download_once(self):
        import threading, time as _time
        with tempfile.TemporaryDirectory() as d:
            calls = []
            def slow_fetch(url):
                calls.append(url)
                _time.sleep(0.2)
                return "Org:9.0.0.0-9.0.0.1\n"
            results, errors = [], []
            def worker():
                try:
                    results.append(m.collect(self._feeds()))
                except SystemExit as exc:
                    errors.append(exc)
            # Patch globally for the whole threaded section: mock patching
            # is process-wide, not per-thread.
            with mock.patch.object(m, "CACHE_DIR", Path(d)), \
                 mock.patch.object(m, "fetch", side_effect=slow_fetch):
                threads = [threading.Thread(target=worker) for _ in range(3)]
                for t in threads: t.start()
                for t in threads: t.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(calls), 1)  # the lock + cache mean one download
            self.assertEqual(len(results), 3)

    def test_security_feed_set_never_uses_cache(self):
        # Only feeds explicitly marked rate_limited consult the cache.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(m, "CACHE_DIR", Path(d)), \
                 mock.patch.object(m, "fetch", return_value="1.2.3.0/24\n") as f:
                m.collect([{"name": "S", "url": "u://s", "format": "cidr"}])
            self.assertEqual(f.call_count, 1)


class MainTests(unittest.TestCase):
    def test_failed_run_leaves_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            dat = Path(d) / "ipfilter.dat"
            dat.write_text("previous good\n")
            with mock.patch.object(m, "CACHE_DIR", Path(d) / "cache"), \
                 mock.patch.object(m, "fetch", side_effect=RuntimeError("boom")):
                with self.assertRaises(SystemExit):
                    m.main(["--output", str(dat)])
            self.assertEqual(dat.read_text(), "previous good\n")

    def test_successful_run_writes_valid_deterministic_output(self):
        def fake_fetch(url):
            if "iblocklist" in url:
                return "Label, One:9.9.9.0-9.9.9.255\n"
            return "1.10.16.0/20 ; SBL1\n10.0.0.0/8\n5.6.7.8\n2a14:8000::/29\n"
        with tempfile.TemporaryDirectory() as d:
            dat = Path(d) / "a.dat"
            argv = ["--output", str(dat), "--min-rules", "1"]
            with mock.patch.object(m, "CACHE_DIR", Path(d) / "cache"), \
                 mock.patch.object(m, "fetch", side_effect=fake_fetch):
                self.assertEqual(m.main(argv), 0)
            first = dat.read_bytes()
            body = [l for l in dat.read_text().splitlines() if not l.startswith("#")]
            # 10.0.0.0/8 is special-purpose and excluded; 4 rules remain.
            self.assertEqual(len(body), 4)
            for line in body:
                self.assertTrue(DAT_LINE_V4.match(line) or DAT_LINE_V6.match(line), line)
            self.assertTrue(any(line.startswith("2a14:8000:: ") for line in body))
            self.assertTrue(any("Bluetack_L1 Label; One" in line for line in body))
            self.assertFalse(any("10.0.0.0" in line for line in body))
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()),
                             ["a.dat", "cache"])  # only output + cache dir, no tmp
            with mock.patch.object(m, "CACHE_DIR", Path(d) / "cache"), \
                 mock.patch.object(m, "fetch", side_effect=fake_fetch):
                self.assertEqual(m.main(argv), 0)
            self.assertEqual(dat.read_bytes(), first)  # no diff churn for cron

    def test_min_rules_floor_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            dat = Path(d) / "a.dat"
            with mock.patch.object(m, "fetch", return_value="1.2.3.0/24\n"):
                with self.assertRaises(SystemExit):
                    m.main(["--output", str(dat), "--min-rules", "100"])
            self.assertFalse(dat.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
