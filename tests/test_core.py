import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agentlog.aggregate import aggregate
from agentlog.catalog import classify, load_catalog
from agentlog.funnel import rung0_status, save_survey
from agentlog.parsers import ParseError, clean_path, detect, parse_combined, parse_lines
from agentlog.report import as_json, render
from agentlog.rules import robots, waf
from agentlog.store import Store
from agentlog.vault import FakeVault
from agentlog.verify import FakeResolver, Verifier, proxy_suspected


class CoreTests(unittest.TestCase):
    def setUp(self): self.catalog = load_catalog()

    def test_combined_and_redaction(self):
        line = '192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET /docs/a@example.com?q=x HTTP/1.1" 404 12 "-" "GPTBot"'
        hit = parse_combined(line); self.assertEqual(hit.path, '/docs/{redacted}'); self.assertEqual(hit.status, 404); self.assertEqual(detect([line]), 'combined')
        with self.assertRaises(ParseError): detect(['garbage', 'still garbage'])

    def test_deep_markdown_and_ordinary_version_slugs(self):
        self.assertEqual(clean_path('/docs/guides/api/auth.md'), '/docs/guides/api/auth.md')
        self.assertEqual(clean_path('/docs/oauth2-guide/python3-setup.md'), '/docs/oauth2-guide/python3-setup.md')

    def test_json_formats(self):
        rows = [json.dumps({'request':{'client_ip':'192.0.2.1','method':'GET','uri':'/x','headers':{'User-Agent':['GPTBot']}},'status':200,'size':3,'ts':1}), json.dumps({'ClientIP':'192.0.2.1','ClientRequestMethod':'GET','ClientRequestURI':'/x','EdgeResponseStatus':200,'EdgeResponseBytes':3,'ClientRequestUserAgent':'GPTBot'}), json.dumps({'proxy':{'clientIp':'192.0.2.1','method':'GET','path':'/x','statusCode':200,'userAgent':'GPTBot'}})]
        self.assertEqual([detect([row]) for row in rows], ['caddy', 'cloudflare', 'vercel'])

    def test_catalog_and_robots_only(self):
        self.assertTrue(all(row['source_url'] and row['checked_at'] for row in self.catalog)); self.assertEqual(classify('FooBot/1.0', self.catalog)[1], 'bot'); self.assertEqual(classify('Bytespider', self.catalog)[1], 'spider')

    def test_verification(self):
        snap = {'agents':{'openai-gptbot':{'fetched_at':datetime.now(timezone.utc).isoformat(),'ranges':['192.0.2.0/24']}}}; entry = next(row for row in self.catalog if row['id'] == 'openai-gptbot')
        inside = parse_combined('192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "GPTBot"'); outside = parse_combined('198.51.100.1 - - [24/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "GPTBot"')
        verifier = Verifier(snap); self.assertEqual(verifier.verify(entry, inside.ip), 'verified'); self.assertEqual(verifier.verify(entry, outside.ip), 'spoofed'); self.assertTrue(proxy_suspected([(outside.ip, 'spoofed')] * 20))

    def test_rdns(self):
        entry = next(row for row in self.catalog if row['id'] == 'googlebot'); resolver = FakeResolver({'192.0.2.3':'crawl.googlebot.com'}, {'crawl.googlebot.com':['192.0.2.3']}); hit = parse_combined('192.0.2.3 - - [24/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Googlebot"'); self.assertEqual(Verifier({}, resolver).verify(entry, hit.ip), 'verified')

    def test_aggregate_and_xss(self):
        snap = {'agents':{'openai-gptbot':{'fetched_at':datetime.now(timezone.utc).isoformat(),'ranges':['192.0.2.0/24']}}}; lines = ['192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET /<script>alert(1)</script>.md HTTP/1.1" 404 12 "-" "GPTBot"']; name, hits, read, skipped = parse_lines(lines); report = aggregate(hits, self.catalog, Verifier(snap), name, read, skipped); self.assertEqual(report['agent_hits'], 1); self.assertEqual(report['docs'][0]['kind'], 'markdown'); self.assertNotIn('<script>alert(1)</script>', render(report)); self.assertEqual(json.loads(as_json(report))['agent_hits'], 1)

    def test_save_survey_and_rung0_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite'); vault = FakeVault()
            for index in range(10): save_survey(store, vault, {'q1':'verify', 'q2':'other', 'q3':'would_pay', 'other':'custom tool'}, dedupe_key=f'client-{index}')
            status = rung0_status(store); self.assertEqual(status['survey_responses'], 10); self.assertTrue(status['conditions'][2]); self.assertTrue(status['conditions'][3])
            with self.assertRaises(ValueError): save_survey(store, vault, {'q1':'verify', 'q2':'other', 'q3':'would_pay'})

    def test_store_tokens_and_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite'); report = {'format':'combined'}; _, share, delete = store.save_report(report); self.assertEqual(store.get_report(share), report); self.assertFalse(store.delete_report(share, 'wrong')); self.assertTrue(store.delete_report(share, delete))
        text = robots(self.catalog, {'openai-gptbot'}); self.assertIn('User-agent: GPTBot', text); expression = waf(self.catalog, {'agents':{'openai-gptbot':{'ranges':['192.0.2.0/24']}}}, {'openai-gptbot'}); self.assertIn('GPTBot', expression); self.assertIn('192.0.2.0/24', expression)


if __name__ == '__main__': unittest.main()
