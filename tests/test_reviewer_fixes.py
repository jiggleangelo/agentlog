"""Regressions for the outside review's public-demo findings."""
import http.client
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

import tests
import demo
from agentlog.cli import trusted_proxies
from agentlog.funnel import rung0_status
from agentlog.server import AgentLogServer
from agentlog.store import Store
from agentlog.vault import FakeVault
from agentlog.verify import FakeResolver
from agentlog.catalog import load_catalog
from tests.test_findings import MemoryConnection, snapshot

ROOT = Path(__file__).resolve().parent.parent


class DemoReviewTests(unittest.TestCase):
    def setUp(self):
        self.socket_patch = patch.object(socket, "socket", socket.SocketType)
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.server = demo.create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = self.server.server_address[1]

    def _stop(self):
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

    def analyze(self, format_name="combined", log=demo.SAMPLE_LOG):
        body = urlencode({"format": format_name, "log": log}).encode()
        return self.request("POST", "/analyze", body, {"Content-Type": "application/x-www-form-urlencoded"})

    def test_report_cache_is_lru_bounded_and_expiring(self):
        self.server.report_limit = 2
        locations = []
        for _ in range(3):
            status, headers, _ = self.analyze()
            self.assertEqual(status, 303)
            locations.append(headers["Location"])
        self.assertEqual(len(self.server.reports), 2)
        self.assertEqual(self.request("GET", locations[0])[0], 404)
        self.assertEqual(self.request("GET", locations[-1])[0], 200)

        token = locations[-1].removeprefix("/report/")
        with self.server.state_lock:
            _, report = self.server.reports[token]
            self.server.reports[token] = (time.monotonic() - 2, report)
        self.server.report_ttl = 1
        self.assertEqual(self.request("GET", locations[-1])[0], 404)

    def test_analyze_is_rate_limited_per_ip(self):
        self.server.rate_limiter = demo.DemoRateLimiter(limit=1, window=60)
        self.assertEqual(self.analyze()[0], 303)
        status, headers, body = self.analyze()
        self.assertEqual(status, 429)
        self.assertEqual(headers["Retry-After"], "60")
        self.assertIn(demo.BANNER.encode(), body)

    def test_handler_timeout_and_connection_cap(self):
        self.assertEqual(demo.DemoHandler.timeout, 10)

        class Request:
            closed = False
            def close(self):
                self.closed = True

        request = Request()
        self.assertTrue(self.server.connection_gate.acquire(False))
        try:
            self.server.process_request(request, ("127.0.0.1", 1))
            self.assertTrue(request.closed)
        finally:
            self.server.connection_gate.release()

    def test_vercel_report_explains_and_hides_unavailable_bytes(self):
        log = json.dumps({"proxy": {
            "clientIp": "192.0.2.1", "method": "GET", "path": "/docs/api.md",
            "statusCode": 200, "userAgent": "GPTBot",
        }})
        status, headers, _ = self.analyze("vercel", log)
        self.assertEqual(status, 303)
        status, _, body = self.request("GET", headers["Location"])
        self.assertEqual(status, 200)
        self.assertIn(b"Bytes unavailable for this format", body)
        self.assertNotIn(b"<th>Bytes</th>", body)


class TrustedProxyReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name) / "db.sqlite")
        self.addCleanup(self.store.db.close)
        with patch("socketserver.socket.socket"), patch.object(AgentLogServer, "server_bind"), patch.object(AgentLogServer, "server_activate"):
            self.server = AgentLogServer(
                ("127.0.0.1", 0), self.store, load_catalog(), snapshot(),
                FakeResolver(), ROOT / "static", 1024 * 1024, "/", FakeVault(),
                "test-secret", trusted_proxies=["127.0.0.0/8"],
            )
        self.addCleanup(self.server.server_close)

    def post_survey(self, forwarded):
        body = json.dumps({"q1": "verify", "q2": "none", "q3": "would_pay"}).encode()
        fields = {
            "Host": "localhost", "Content-Length": str(len(body)),
            "Content-Type": "application/json", "Connection": "close",
            "X-Forwarded-For": forwarded,
        }
        head = "POST /api/survey HTTP/1.1\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields.items())
        connection = MemoryConnection(head.encode() + b"\r\n" + body)
        self.server.finish_request(connection, ("127.0.0.1", 12345))
        raw_headers, response = bytes(connection.output).split(b"\r\n\r\n", 1)
        return int(raw_headers.split(b" ", 2)[1]), json.loads(response)

    def test_forwarded_clients_are_distinct_behind_trusted_proxy(self):
        self.assertEqual(self.post_survey("198.51.100.10")[0], 201)
        self.assertEqual(self.post_survey("198.51.100.11")[0], 201)
        self.assertEqual(rung0_status(self.store)["survey_responses"], 2)

    def test_cli_and_environment_trusted_proxy_configuration(self):
        values = trusted_proxies(
            ["10.0.0.0/8"],
            {"AGENTLOG_TRUSTED_PROXIES": "192.0.2.10, 2001:db8::/32"},
        )
        self.assertEqual(values, ["10.0.0.0/8", "192.0.2.10/32", "2001:db8::/32"])


if __name__ == "__main__":
    unittest.main()
