"""Regression coverage for F1 and F2 without opening network sockets."""

import gzip
import importlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.parsers import parse_lines
from agentlog.server import AgentLogServer
from agentlog.store import Store
from agentlog.vault import FakeVault
from agentlog.verify import FakeResolver, Verifier


COMBINED = '192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET /docs/api.md HTTP/1.1" 200 37 "-" "GPTBot"'


def snapshot():
    return {'agents': {'openai-gptbot': {
        'fetched_at': datetime.now(timezone.utc).isoformat(),
        'ranges': ['192.0.2.0/24'],
    }}}


class MemoryConnection:
    """Socket-shaped HTTP transport; never creates a real socket."""

    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, mode, buffering=-1):
        if mode != 'rb':
            raise AssertionError('unexpected socket file mode')
        return self.input

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.output.extend(data)


class UploadRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.store = Store(root / 'db.sqlite')
        # Only socket construction and binding are replaced. The real server,
        # HTTP handler, parsers, verifier, aggregation and store are exercised.
        # The existing tests package's network prohibition remains intact.
        with patch('socketserver.socket.socket'), \
                patch.object(AgentLogServer, 'server_bind'), \
                patch.object(AgentLogServer, 'server_activate'):
            self.server = AgentLogServer(
                ('127.0.0.1', 0), self.store, load_catalog(), snapshot(),
                FakeResolver({}, {}), root / 'static', 1024 * 1024,
                '/preorder', FakeVault(), 'test-secret',
            )
        self.addCleanup(self.server.server_close)

    def request(self, method, path, body=b'', headers=None):
        fields = {
            'Host': 'localhost',
            'Content-Length': str(len(body)),
            'Connection': 'close',
        }
        fields.update(headers or {})
        head = f'{method} {path} HTTP/1.1\r\n'
        head += ''.join(f'{key}: {value}\r\n' for key, value in fields.items())
        connection = MemoryConnection(head.encode('ascii') + b'\r\n' + body)
        self.server.finish_request(connection, ('127.0.0.1', 12345))
        raw_headers, response = bytes(connection.output).split(b'\r\n\r\n', 1)
        status = int(raw_headers.split(b' ', 2)[1])
        return status, json.loads(response)

    def test_f1_server_and_cli_import(self):
        self.assertIsNotNone(importlib.import_module('agentlog.server').AgentLogServer)
        self.assertIsNotNone(importlib.import_module('agentlog.cli'))

    def test_f1_post_log_and_fetch_persisted_report(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                body = (COMBINED + '\n').encode('utf-8')
                headers = {'X-AgentLog-Share-Consent': 'true'}
                if compressed:
                    body = gzip.compress(body)
                    headers['Content-Encoding'] = 'gzip'
                status, uploaded = self.request(
                    'POST', '/upload?format=combined', body, headers,
                )
                self.assertEqual(status, 201, uploaded)
                self.assertTrue(uploaded['delete_token'])
                status, report = self.request('GET', uploaded['json_url'])
                self.assertEqual(status, 200, report)
                self.assertEqual(report['format'], 'combined')
                self.assertEqual(report['lines_read'], 1)
                self.assertEqual(report['lines_skipped'], 0)
                self.assertEqual(report['agent_hits'], 1)
                self.assertEqual(report['agents'][0]['status'], 'verified')
                self.assertEqual(report['agents'][0]['bytes'], 37)
                self.assertEqual(report['urls'][0]['path'], '/docs/api.md')
                self.assertEqual(report['urls'][0]['bytes'], 37)
                token = uploaded['report_url'].removeprefix('/r/')
                self.assertEqual(self.store.get_report(token), report)

    def test_f1_invalid_upload_is_client_error(self):
        status, response = self.request(
            'POST', '/upload', b'not a log\nstill not a log\n',
            {'X-AgentLog-Share-Consent': 'true'},
        )
        self.assertEqual(status, 400, response)
        self.assertIn('error', response)

    def test_f1_format_and_ip_overrides_are_not_silently_ignored(self):
        for query in ('format=cloudflare', 'client_ip_field=forwarded'):
            with self.subTest(query=query):
                status, response = self.request(
                    'POST', '/upload?' + query,
                    (COMBINED + '\n').encode('utf-8'),
                    {'X-AgentLog-Share-Consent': 'true'},
                )
                self.assertEqual(status, 400, response)
                self.assertIn('error', response)
        self.assertTrue(self.server.upload_gate.acquire(False))
        self.server.upload_gate.release()


class ParsedBytesRegressionTests(unittest.TestCase):
    def test_f2_real_parser_hits_aggregate_bytes_for_every_format(self):
        cases = [
            ('combined', COMBINED, 37),
            ('caddy', json.dumps({
                'request': {
                    'client_ip': '192.0.2.1', 'method': 'GET',
                    'uri': '/docs/api.md',
                    'headers': {'User-Agent': ['GPTBot']},
                },
                'status': 200, 'size': 37, 'ts': 1,
            }), 37),
            ('cloudflare', json.dumps({
                'ClientIP': '192.0.2.1', 'ClientRequestMethod': 'GET',
                'ClientRequestURI': '/docs/api.md',
                'EdgeResponseStatus': 200, 'EdgeResponseBytes': 37,
                'ClientRequestUserAgent': 'GPTBot',
            }), 37),
            ('vercel', json.dumps({
                'proxy': {
                    'clientIp': '192.0.2.1', 'method': 'GET',
                    'path': '/docs/api.md', 'statusCode': 200,
                    'userAgent': 'GPTBot',
                },
            }), 0),
        ]
        catalog = load_catalog()
        for expected_format, line, expected_bytes in cases:
            with self.subTest(format=expected_format):
                name, hits, read, skipped = parse_lines([line, line])
                self.assertEqual(name, expected_format)
                report = aggregate(
                    hits, catalog, Verifier(snapshot(), FakeResolver({}, {})),
                    name, read, skipped,
                )
                self.assertEqual(report['agent_hits'], 2)
                self.assertEqual(report['lines_read'], 2)
                self.assertEqual(report['lines_skipped'], 0)
                self.assertEqual(report['bytes_available'], name != 'vercel')
                self.assertEqual(report['format_beta'], name == 'vercel')
                for section in ('agents', 'purposes', 'urls'):
                    self.assertEqual(len(report[section]), 1)
                    self.assertEqual(report[section][0]['requests'], 2)
                    self.assertEqual(report[section][0]['bytes'], expected_bytes * 2)


if __name__ == '__main__':
    unittest.main()
