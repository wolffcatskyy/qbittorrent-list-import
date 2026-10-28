"""Offline fixture tests for tracker preflight probes."""
import http.server
import socket
import struct
import threading
import unittest

import trackerprobe as tp


class FakeUdpTracker(threading.Thread):
    def __init__(self, answer=True):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        self.start()

    def run(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(2048)
                if not self.answer or len(data) < 16:
                    continue
                _pid, action, txn = struct.unpack("!QII", data[:16])
                if action == tp.UDP_ACTION_CONNECT:
                    resp = struct.pack("!IIQ", 0, txn, 0xBADC0FFEE)
                    self.sock.sendto(resp, addr)
        except (socket.timeout, OSError):
            pass

    def stop(self):
        self.sock.close()


class TrackerProbeTests(unittest.TestCase):
    def test_udp_connect_handshake_ok(self):
        srv = FakeUdpTracker(answer=True)
        try:
            status, detail, ms = tp.probe_udp("127.0.0.1", srv.port, 2.0,
                                              allow_private=True)
        finally:
            srv.stop()
        self.assertEqual(status, tp.OK)
        self.assertIsNotNone(ms)

    def test_udp_no_response_is_not_called_dead(self):
        srv = FakeUdpTracker(answer=False)
        try:
            status, detail, _ = tp.probe_udp("127.0.0.1", srv.port, 0.5,
                                             allow_private=True)
        finally:
            srv.stop()
        self.assertEqual(status, tp.NO_RESPONSE)
        self.assertIn("no answer", detail)

    def test_tcp_reachable_labeled_protocol_unverified(self):
        httpd = http.server.HTTPServer(("127.0.0.1", 0),
                                       http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            status, detail, _ = tp.probe_tcp("127.0.0.1", httpd.server_port,
                                             False, 2.0, allow_private=True)
        finally:
            httpd.shutdown()
        self.assertEqual(status, tp.REACHABLE)
        self.assertIn("not verified", detail)
        self.assertNotIn("TLS", detail, "plaintext HTTP must not claim TLS")

    def test_private_addresses_refused_by_default(self):
        for url in ("udp://127.0.0.1:6969", "udp://192.168.1.1:6969",
                    "http://10.0.0.5:8080/announce", "udp://[::1]:6969"):
            r = tp.probe_tracker(url, timeout=0.5)
            self.assertEqual(r.status, tp.REFUSED, url)
            self.assertIn("non-public", r.detail)

    def test_invalid_and_unsupported(self):
        self.assertEqual(tp.probe_tracker("not a url").status, tp.INVALID)
        r = tp.probe_tracker("wss://tracker.example:443/announce")
        self.assertEqual(r.status, tp.UNSUPPORTED)

    def test_preflight_preserves_order_and_counts(self):
        srv = FakeUdpTracker(answer=True)
        try:
            urls = [f"udp://127.0.0.1:{srv.port}",
                    "udp://127.0.0.2:1",          # refused unless allowed
                    "wss://tracker.example/x"]
            results = tp.preflight(urls, timeout=0.5, allow_private=True)
        finally:
            srv.stop()
        self.assertEqual([r.url for r in results], urls)
        self.assertEqual(results[0].status, tp.OK)
        self.assertEqual(results[2].status, tp.UNSUPPORTED)
        counts = tp.summarize(results)
        self.assertEqual(sum(counts.values()), 3)


if __name__ == "__main__":
    unittest.main()
