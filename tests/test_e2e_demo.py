"""Full HTTP flow over a socket-shaped memory transport; no network."""
import gzip
import io
import json
import logging
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import tests  # Install the suite's network guard even with unittest discover -s tests.
from agentlog import parsers
from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.funnel import rung0_status
from agentlog.server import AgentLogServer
from agentlog.store import Store
from agentlog.vault import FakeVault
from agentlog.verify import FakeResolver, Verifier
from tests.test_findings import MemoryConnection, snapshot, COMBINED

ROOT = Path(__file__).resolve().parent.parent


class EndToEndDemoTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name) / 'db.sqlite')
        self.addCleanup(self.store.db.close)
        self.vault = FakeVault()
        self.resolver = FakeResolver(
            {'192.0.2.3': 'crawl.googlebot.com'},
            {'crawl.googlebot.com': ['192.0.2.3']},
        )
        with patch('socketserver.socket.socket'), \
                patch.object(AgentLogServer, 'server_bind'), \
                patch.object(AgentLogServer, 'server_activate'):
            self.server = AgentLogServer(
                ('127.0.0.1', 0), self.store, load_catalog(), snapshot(),
                self.resolver, ROOT / 'static', 50 * 1024 * 1024,
                'https://checkout.example/preorder', self.vault, 'test-secret',
            )
        self.addCleanup(self.server.server_close)

    def request(self, method, path, body=b'', headers=None):
        fields = {'Host': 'localhost', 'Content-Length': str(len(body)), 'Connection': 'close'}
        fields.update(headers or {})
        head = f'{method} {path} HTTP/1.1\r\n'
        head += ''.join(f'{key}: {value}\r\n' for key, value in fields.items())
        connection = MemoryConnection(head.encode() + b'\r\n' + body)
        self.server.finish_request(connection, ('127.0.0.1', 12345))
        head, response = bytes(connection.output).split(b'\r\n\r\n', 1)
        lines = head.decode().split('\r\n')
        headers = dict(line.split(': ', 1) for line in lines[1:])
        return int(lines[0].split()[1]), headers, response

    def post_json(self, path, body):
        status, _, raw = self.request('POST', path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
        return status, json.loads(raw)

    def test_full_core_flow_with_fakes(self):
        logs = io.StringIO()
        handler = logging.StreamHandler(logs)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            status, _, landing = self.request('GET', '/')
            self.assertEqual(status, 200)
            for marker in (b'/sample', b'/go/preorder', b'name="consent"', b'id="after-report" hidden'):
                self.assertIn(marker, landing)
            status, _, script = self.request('GET', '/static/app.js')
            self.assertEqual(status, 200)
            for marker in (b'/api/upload?', b'X-AgentLog-Share-Consent', b'result.report_url', b'/api/rules'):
                self.assertIn(marker, script)
            self.assertNotIn(b'result.share_url', script)
            status, _, sample = self.request('GET', '/sample')
            self.assertEqual(status, 200)
            self.assertIn(b'AgentLog report', sample)
            self.assertEqual(rung0_status(self.store)['uploads'], 0)

            def line(ip, path, code, amount, ua):
                return f'{ip} - - [24/Oct/2026:12:00:00 +0000] "GET {path} HTTP/1.1" {code} {amount} "-" "{ua}"'

            rows = [
                line('192.0.2.1', '/docs/api.md?email=secret@example.com', 200, 900, 'GPTBot/private-marker'),
                line('198.51.100.1', '/llms.txt', 404, 30, 'GPTBot'),
                line('192.0.2.2', '/docs/missing.md', 500, 20, 'ClaudeBot'),
                line('192.0.2.4', '/docs/search.md', 200, 100, 'OAI-SearchBot'),
                line('192.0.2.3', '/docs/google.md', 200, 80, 'Googlebot'),
                line('192.0.2.5', '/', 200, 10, 'Mozilla/5.0'),
                'malformed',
            ]
            body = gzip.compress(('\n'.join(rows) + '\n').encode())
            status, _, raw = self.request('POST', '/api/upload?format=combined', body)
            self.assertEqual(status, 428)
            status, _, raw = self.request('POST', '/api/upload?format=combined', body, {'X-AgentLog-Share-Consent': 'true'})
            self.assertEqual(status, 201, raw)
            uploaded = json.loads(raw)
            self.assertTrue(uploaded['delete_token'])
            status, headers, raw = self.request('GET', uploaded['json_url'])
            self.assertEqual(status, 200)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            report = json.loads(raw)
            self.assertEqual(report['lines_read'], 7)
            self.assertEqual(report['lines_skipped'], 1)
            self.assertEqual(report['agent_hits'], 5)
            self.assertEqual(report['non_agent_lines'], 1)
            self.assertEqual({r['status'] for r in report['agents']}, {'verified', 'spoofed', 'unchecked', 'unverifiable'})
            self.assertEqual(report['urls'][0]['path'], '/docs/api.md')
            self.assertEqual(report['urls'][0]['bytes'], 900)
            self.assertEqual({r['status'] for r in report['errors']}, {404, 500})
            self.assertEqual({r['kind'] for r in report['docs']}, {'llms', 'markdown'})
            status, _, html = self.request('GET', uploaded['report_url'])
            self.assertEqual(status, 200)
            self.assertIn(b'Costliest URLs', html)
            self.assertIn(b'/llms.txt', html)

            status, rules = self.post_json('/api/rules', {'selected': ['openai-gptbot', 'google-extended'], 'paths': ['/docs/']})
            self.assertEqual(status, 200)
            self.assertIn('User-agent: GPTBot', rules['robots'])
            self.assertIn('User-agent: Google-Extended', rules['robots'])
            self.assertIn('Disallow: /docs/', rules['robots'])
            self.assertIn('192.0.2.0/24', rules['waf'])
            self.assertNotIn('Google-Extended', rules['waf'])
            self.assertIn('~*GPTBot 1;', rules['nginx'])
            self.assertEqual(self.post_json('/api/rules', {'selected': ['openai-gptbot'], 'paths': ['/\nAllow: /']})[0], 400)

            answers = {'q1': 'docs', 'q2': 'other', 'q3': 'would_pay', 'other': 'private-survey-marker'}
            self.assertEqual(self.post_json('/api/survey', answers)[0], 201)
            self.assertEqual(self.post_json('/api/survey', answers)[0], 200)
            email = {'email': 'reviewer@example.com'}
            self.assertEqual(self.post_json('/api/waitlist', email)[0], 201)
            self.assertEqual(self.post_json('/api/waitlist', email)[0], 200)
            status, headers, _ = self.request('GET', '/go/preorder')
            self.assertEqual(status, 302)
            self.assertEqual(headers['Location'], 'https://checkout.example/preorder')
            self.request('GET', '/go/preorder')
            self.store.event('payment', dedupe_key='fake-payment:0')
            self.store.event('payment', dedupe_key='fake-payment:0')
            funnel = rung0_status(self.store)
            for key in ('uploads', 'waitlist', 'pay_clicks', 'payments', 'survey_responses'):
                self.assertEqual(funnel[key], 1, key)
            self.assertEqual(self.vault.calls, [('survey_other', 'private-survey-marker'), ('waitlist_email', 'reviewer@example.com')])
            persisted = '\n'.join(self.store.db.iterdump()) + logs.getvalue()
            for private in ('192.0.2.1', '198.51.100.1', 'secret@example.com', 'reviewer@example.com', 'private-marker', 'private-survey-marker'):
                self.assertNotIn(private, persisted)

    def test_realistic_upload_exceeds_old_line_and_hit_buffer_limits(self):
        count = 210_000
        body = gzip.compress(((COMBINED + '\n') * count).encode())
        status, _, raw = self.request('POST', '/api/upload?format=combined', body, {'X-AgentLog-Share-Consent': 'true'})
        self.assertEqual(status, 201, raw)
        uploaded = json.loads(raw)
        status, _, raw = self.request('GET', uploaded['json_url'])
        self.assertEqual(status, 200)
        report = json.loads(raw)
        self.assertEqual(report['lines_read'], count)
        self.assertEqual(report['agent_hits'], count)
        self.assertEqual(report['urls'][0]['bytes'], 37 * count)

    def test_stream_consumes_only_detection_sample_before_aggregation(self):
        consumed = 0
        def source():
            nonlocal consumed
            for _ in range(2000):
                consumed += 1
                yield COMBINED
        name, hits, stats = parsers.stream_lines(source())
        self.addCleanup(hits.close)
        self.assertEqual(consumed, parsers.DETECTION_LINES)
        report = aggregate(hits, load_catalog(), Verifier(snapshot(), FakeResolver()), name, stats=stats)
        self.assertEqual(consumed, 2000)
        self.assertEqual(report['lines_read'], 2000)
        self.assertEqual(report['urls'][0]['bytes'], 74000)
        self.assertEqual(parsers.MAX_LINES, 5_000_000)


if __name__ == '__main__':
    unittest.main()
