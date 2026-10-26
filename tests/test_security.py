import ipaddress
import unittest
from datetime import datetime, timezone

from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.parsers import MAX_PATH, Hit, clean_path
from agentlog.report import as_json
from agentlog.verify import FakeResolver, Verifier


class SecurityTests(unittest.TestCase):
    def setUp(self): self.catalog = load_catalog()

    def test_private_paths_are_shape_redacted_bounded_and_decoded_suffix_removed(self):
        cases = {
            '/users/john-smith': '/{redacted}/{redacted}',
            '/profile/jane.doe': '/{redacted}/{redacted}',
            '/docs/bob-jones-42': '/docs/{redacted}',
            '/docs/jane-doe-1990.md': '/docs/{redacted}.md',
            '/u/alice42': '/{redacted}/{redacted}',
        }
        for supplied, expected in cases.items(): self.assertEqual(clean_path(supplied), expected)
        self.assertEqual(clean_path('/docs%3Femail=jane.doe@example.com'), '/docs')
        path = clean_path('/' + '/'.join(['john-smith'] * 100))
        self.assertLessEqual(len(path), MAX_PATH); self.assertIn('{truncated}', path)
        self.assertNotIn('john-smith', as_json({'urls': [{'path': path}]}))

    def test_real_world_docs_slugs_survive(self):
        self.assertEqual(clean_path('/docs/getting-started'), '/docs/getting-started')
        self.assertEqual(clean_path('/docs/oauth2-guide/python3-setup.md'), '/docs/oauth2-guide/python3-setup.md')
        self.assertEqual(clean_path('/docs/v2/api-reference.md'), '/docs/v2/api-reference.md')

    def test_aggregate_heavy_hitter_and_caps(self):
        now = datetime.now(timezone.utc); entry = next(row for row in self.catalog if row['id'] == 'openai-gptbot')
        snapshot = {'agents': {entry['id']: {'fetched_at': now.isoformat(), 'ranges': ['192.0.2.0/24']}}}
        def hits():
            for index in range(1200): yield Hit(now, ipaddress.ip_address('192.0.2.1'), 'GET', f'/docs/page-{index}.md', 404, 1, 'GPTBot')
            yield Hit(now, ipaddress.ip_address('192.0.2.1'), 'GET', '/docs/costly-late-page.md', 500, 10_000_000, 'GPTBot')
        report = aggregate(hits(), self.catalog, Verifier(snapshot), 'combined')
        self.assertLessEqual(len(report['urls']), 200); self.assertLessEqual(len(report['errors']), 100); self.assertLessEqual(len(report['docs']), 100)
        self.assertEqual(report['urls'][0]['path'], '/docs/costly-late-page.md')

    def test_proxy_masking_requires_aggregate_sample(self):
        now = datetime.now(timezone.utc); entry = next(row for row in self.catalog if row['id'] == 'openai-gptbot')
        snapshot = {'agents': {entry['id']: {'fetched_at': now.isoformat(), 'ranges': ['203.0.113.0/24']}}}
        def make(count):
            return [Hit(now, ipaddress.ip_address('192.0.2.1'), 'GET', '/docs/page.md', 200, 1, 'GPTBot') for _ in range(count)]
        self.assertFalse(aggregate(make(1), self.catalog, Verifier(snapshot), 'combined')['proxy_suspected'])
        self.assertTrue(aggregate(make(50), self.catalog, Verifier(snapshot), 'combined')['proxy_suspected'])

    def test_rdns_budget_prioritizes_high_volume_identity(self):
        entry = next(row for row in self.catalog if row['id'] == 'googlebot')
        resolver = FakeResolver({'192.0.2.9': 'crawl.googlebot.com'}, {'crawl.googlebot.com': ['192.0.2.9']})
        verifier = Verifier({}, resolver, rdns_budget=1)
        pairs = [(entry, '198.51.100.1')] + [(entry, '192.0.2.9')] * 5
        results = list(verifier.verify_many(pairs))
        self.assertEqual(results[0], 'unchecked'); self.assertEqual(results[1:], ['verified'] * 5)


if __name__ == '__main__': unittest.main()
