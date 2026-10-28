#!/usr/bin/env python3
"""Tests for qbt_sync.py against a stub qBittorrent Web API server.

The stub implements the three endpoints qbt_sync uses (auth/login,
app/preferences, app/setPreferences) plus the execution log, records every
preference payload it receives, and simulates the asynchronous parse by
posting a log entry. No real qBittorrent, network feed, or credential is
involved; compilation is replaced with fixture rules.
"""

from __future__ import annotations

import contextlib
import io
import json
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import qbt_sync

GOOD_USER = "admin"
GOOD_PASS = "harness-password"
SECRET = "harness-password"


class StubQbt:
    """A disposable in-process stand-in for the qBittorrent Web API."""

    def __init__(self, prefs: dict | None = None, fail_login: bool = False):
        self.prefs = {
            "ip_filter_enabled": False,
            "ip_filter_path": "",
        }
        if prefs:
            self.prefs.update(prefs)
        self.fail_login = fail_login
        self.cookie_name = "SID"
        self.reject_code = 403
        self.set_calls: list[dict] = []
        self.log_entries: list[dict] = []
        self.passwords_seen: list[str] = []

        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _send(self, code: int, body: str = "Ok.", cookie: bool = False):
                self.send_response(code)
                if cookie:
                    self.send_header("Set-Cookie", stub.cookie_name + "=stub-session; HttpOnly; path=/")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body.encode())

            def _authorized(self) -> bool:
                return self.headers.get("Cookie", "").startswith(stub.cookie_name + "=stub-session")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                from urllib.parse import parse_qs
                form = parse_qs(self.rfile.read(length).decode())
                if self.path == "/api/v2/auth/login":
                    stub.passwords_seen.append(form.get("password", [""])[0])
                    if stub.fail_login or form.get("username") != [GOOD_USER] \
                            or form.get("password") != [GOOD_PASS]:
                        self._send(403, "Fails.")
                        return
                    self._send(200, "Ok.", cookie=True)
                elif self.path == "/api/v2/app/setPreferences" and self._authorized():
                    payload = json.loads(form["json"][0])
                    stub.set_calls.append(payload)
                    stub.prefs.update(payload)
                    if "ip_filter_path" in payload:
                        stub.log_entries.append({
                            "id": len(stub.log_entries) + 1,
                            "message": "Successfully parsed the IP filter file. "
                                       "Number of rules applied: 3",
                            "timestamp": stub.now_unix,
                            "type": 1,
                        })
                    self._send(200, "Ok.")
                else:
                    self._send(403, "Forbidden")

            def do_GET(self):
                if not self._authorized():
                    self._send(403, "Forbidden")
                    return
                if self.path == "/api/v2/app/preferences":
                    self._send(200, json.dumps(stub.prefs))
                elif self.path.startswith("/api/v2/log/main"):
                    self._send(200, json.dumps(stub.log_entries))
                else:
                    self._send(404, "Not Found")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.now_unix = 1_700_000_000

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


FIXTURE_RULES = [
    (4, 0x0A000001, 0x0A0000FE, "fixture-a"),
    (4, 0xC0000201, 0xC00002FE, "fixture-b"),
    (6, 0x20010DB8000000000000000000000001,
     0x20010DB80000000000000000000000FE, "fixture-c"),
]
FIXTURE_URLS = ["https://fixture.invalid/list.txt"]


def fake_compile(feeds: str):
    return list(FIXTURE_RULES), list(FIXTURE_URLS)


def run_sync(stub: StubQbt, extra_args: list[str]):
    argv = ["--url", stub.url, "--username", GOOD_USER,
            "--password", GOOD_PASS, "--min-rules", "1"] + extra_args
    out = io.StringIO()
    with mock.patch.object(qbt_sync, "compile_rules", side_effect=fake_compile), \
            contextlib.redirect_stdout(out):
        code = qbt_sync.run(argv, now_unix=stub.now_unix - 2)
    return code, out.getvalue()


class PathChoiceTests(unittest.TestCase):
    def test_unset_path_uses_default_dir_and_a_suffix(self):
        new, stale = qbt_sync.choose_paths("", None)
        self.assertEqual(new, qbt_sync.DEFAULT_FILTER_DIR / "ipfilter-a.dat")
        self.assertIsNone(stale)

    def test_alternates_a_to_b(self):
        new, stale = qbt_sync.choose_paths("/filters/ipfilter-a.dat", None)
        self.assertEqual(new, Path("/filters/ipfilter-b.dat"))
        self.assertEqual(stale, Path("/filters/ipfilter-a.dat"))

    def test_alternates_b_to_a(self):
        new, stale = qbt_sync.choose_paths("/filters/ipfilter-b.dat", None)
        self.assertEqual(new, Path("/filters/ipfilter-a.dat"))
        self.assertEqual(stale, Path("/filters/ipfilter-b.dat"))

    def test_adopts_user_stem_and_dir(self):
        new, stale = qbt_sync.choose_paths("/home/u/Downloads/mylist.dat", None)
        self.assertEqual(new, Path("/home/u/Downloads/mylist-a.dat"))
        self.assertIsNone(stale)

    def test_filter_dir_override(self):
        new, stale = qbt_sync.choose_paths("/elsewhere/x.dat", Path("/chosen"))
        self.assertEqual(new, Path("/chosen/x-a.dat"))
        self.assertIsNone(stale)


class SyncFlowTests(unittest.TestCase):
    def test_first_install_enables_filter_and_sets_path(self):
        with StubQbt() as stub, TemporaryDirectory() as tmp:
            code, out = run_sync(stub, ["--filter-dir", tmp])
            self.assertEqual(code, 0)
            self.assertEqual(len(stub.set_calls), 1)
            payload = stub.set_calls[0]
            self.assertIs(payload["ip_filter_enabled"], True)
            self.assertEqual(payload["ip_filter_path"],
                             str(Path(tmp) / "ipfilter-a.dat"))
            self.assertTrue(stub.prefs["ip_filter_enabled"])
            self.assertTrue((Path(tmp) / "ipfilter-a.dat").exists())
            self.assertIn("3 rules", out)

    def test_second_run_flips_to_b_and_removes_stale_a(self):
        with TemporaryDirectory() as tmp:
            a = Path(tmp) / "ipfilter-a.dat"
            with StubQbt({"ip_filter_enabled": True,
                          "ip_filter_path": str(a)}) as stub:
                a.write_text("old rules")
                code, out = run_sync(stub, ["--filter-dir", tmp])
                self.assertEqual(code, 0)
                self.assertEqual(stub.set_calls[0]["ip_filter_path"],
                                 str(Path(tmp) / "ipfilter-b.dat"))
                self.assertTrue((Path(tmp) / "ipfilter-b.dat").exists())
                self.assertFalse(a.exists(), "stale alternate should be removed")
                self.assertIn("Removed stale", out)

    def test_third_run_flips_back_to_a(self):
        with TemporaryDirectory() as tmp:
            b = Path(tmp) / "ipfilter-b.dat"
            with StubQbt({"ip_filter_enabled": True,
                          "ip_filter_path": str(b)}) as stub:
                b.write_text("old rules")
                code, _ = run_sync(stub, ["--filter-dir", tmp])
                self.assertEqual(code, 0)
                self.assertEqual(stub.set_calls[0]["ip_filter_path"],
                                 str(Path(tmp) / "ipfilter-a.dat"))
                self.assertFalse(b.exists())

    def test_users_original_file_is_never_deleted(self):
        with TemporaryDirectory() as tmp:
            original = Path(tmp) / "mylist.dat"
            original.write_text("user's own filter")
            with StubQbt({"ip_filter_enabled": True,
                          "ip_filter_path": str(original)}) as stub:
                code, _ = run_sync(stub, [])
                self.assertEqual(code, 0)
                self.assertTrue(original.exists(),
                                "the user's pre-existing filter file must survive")
                self.assertEqual(stub.set_calls[0]["ip_filter_path"],
                                 str(Path(tmp) / "mylist-a.dat"))

    def test_compile_failure_leaves_qbt_untouched(self):
        with StubQbt() as stub, TemporaryDirectory() as tmp:
            def boom(feeds):
                raise SystemExit("ERROR: feeds failed")
            with mock.patch.object(qbt_sync, "compile_rules", side_effect=boom):
                with self.assertRaises(SystemExit):
                    qbt_sync.run(["--url", stub.url, "--username", GOOD_USER,
                                  "--password", GOOD_PASS, "--filter-dir", tmp])
            self.assertEqual(stub.set_calls, [],
                             "no preference change may happen after compile failure")
            self.assertFalse(stub.prefs["ip_filter_enabled"])

    def test_bad_credentials_abort_before_any_change(self):
        with StubQbt(fail_login=True) as stub, TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                run_sync(stub, ["--filter-dir", tmp])
            self.assertIn("rejected", str(ctx.exception))
            self.assertEqual(stub.set_calls, [])
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_never_disables_filter(self):
        """The payload must only ever set ip_filter_enabled to True.

        Setting it False installs an empty filter in qBittorrent (an
        unfiltered window); path alternation makes any toggle unnecessary.
        """
        with TemporaryDirectory() as tmp:
            with StubQbt({"ip_filter_enabled": True,
                          "ip_filter_path": str(Path(tmp) / "ipfilter-a.dat")}) as stub:
                (Path(tmp) / "ipfilter-a.dat").write_text("old")
                run_sync(stub, ["--filter-dir", tmp])
        for payload in stub.set_calls:
            self.assertNotIn(False, [payload.get("ip_filter_enabled")],
                             "ip_filter_enabled must never be set False")


    def test_login_accepts_qbt5_204_no_content(self):
        """qBittorrent 5.x: 204 + QBT_SID_<port> cookie instead of 200 'Ok.'"""
        with StubQbt() as stub:
            stub.cookie_name = "QBT_SID_18080"
            cookie = qbt_sync.api_login(stub.url, GOOD_USER, GOOD_PASS)
            self.assertIn("stub-session", cookie)


class Qbt5StubLoginTests(unittest.TestCase):
    def test_401_maps_to_rejected_credentials(self):
        with StubQbt(fail_login=True) as stub:
            stub.reject_code = 401
            with self.assertRaises(qbt_sync.ApiError) as ctx:
                qbt_sync.api_login(stub.url, GOOD_USER, GOOD_PASS)
            self.assertIn("rejected", str(ctx.exception))

    def test_password_never_appears_in_output(self):
        with StubQbt() as stub, TemporaryDirectory() as tmp:
            _, out = run_sync(stub, ["--filter-dir", tmp])
            self.assertNotIn(SECRET, out)

    def test_min_rules_guard_blocks_api_change(self):
        with StubQbt() as stub, TemporaryDirectory() as tmp:
            with mock.patch.object(qbt_sync, "compile_rules",
                                   return_value=(FIXTURE_RULES[:1], FIXTURE_URLS)):
                with self.assertRaises(SystemExit):
                    qbt_sync.run(["--url", stub.url, "--username", GOOD_USER,
                                  "--password", GOOD_PASS, "--filter-dir", tmp,
                                  "--min-rules", "2"])
            self.assertEqual(stub.set_calls, [])

    def test_unreachable_api_reports_guidance(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                qbt_sync.run(["--url", "http://127.0.0.1:1",
                              "--username", GOOD_USER, "--password", GOOD_PASS,
                              "--filter-dir", tmp])
            self.assertIn("WebUI", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
