"""Hosted demo flow over real loopback HTTP with the suite network guard preserved."""
import http.client
import socket
import threading
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

import tests  # Installs the repository-wide outbound-network guard.
import demo


class HostedDemoTests(unittest.TestCase):
    def setUp(self):
        # tests.__init__ blocks socket.socket globally. Restore the built-in socket
        # type only for this test, and connect exclusively to the loopback server.
        self.socket_patch = patch.object(socket, "socket", socket.SocketType)
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.server = demo.create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.port = self.server.server_address[1]

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_health_and_complete_sample_flow(self):
        status, _, body = self.request("GET", "/healthz")
        self.assertEqual((status, body), (200, b"ok"))

        status, _, landing = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(demo.BANNER.encode(), landing)
        self.assertIn(b"Build my demo report", landing)
        self.assertIn(b"GPTBot", landing)
        self.assertNotIn(b"sign up", landing.lower())

        body = urlencode({"format": "combined", "log": demo.SAMPLE_LOG}).encode()
        status, headers, response = self.request(
            "POST",
            "/analyze",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303, response)
        self.assertTrue(headers["Location"].startswith("/report/"))

        status, _, report = self.request("GET", headers["Location"])
        self.assertEqual(status, 200)
        self.assertIn(demo.BANNER.encode(), report)
        self.assertIn(b"verified", report)
        self.assertIn(b"spoofed", report)
        self.assertIn(b"unverifiable", report)
        self.assertIn(b"/llms.txt", report)
        self.assertIn(b"/docs/missing.md", report)
        self.assertIn(b"User-agent: GPTBot", report)
        self.assertIn(b"192.0.2.0/24", report)

    def test_user_input_is_escaped_in_report(self):
        log = (
            '192.0.2.10 - - [24/Oct/2026:12:00:00 +0000] '
            '"GET /docs/<script>alert(1)</script>.md HTTP/1.1" '
            '404 10 "-" "GPTBot"\n'
        )
        body = urlencode({"format": "combined", "log": log}).encode()
        status, headers, _ = self.request(
            "POST",
            "/analyze",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        status, _, report = self.request("GET", headers["Location"])
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>alert(1)</script>", report)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", report)

    def test_request_bodies_over_64_kb_are_rejected(self):
        body = b"x" * (demo.MAX_BODY + 1)
        status, _, response = self.request(
            "POST",
            "/analyze",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 413)
        self.assertIn(demo.BANNER.encode(), response)
        self.assertIn(b"64 KB", response)

    def test_unknown_pages_keep_the_banner_and_emit_no_request_log(self):
        status, _, body = self.request("GET", "/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn(demo.BANNER.encode(), body)


if __name__ == "__main__":
    unittest.main()
