"""F5: personal request data must never spill into temporary files."""

import io
import re
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from agentlog import parsers
from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.verify import FakeResolver, Verifier
from tests.test_findings import UploadRegressionTests


ADDRESS = '192.0.2.123'
USER_AGENT = 'GPTBot/private-user-agent-marker'
COMBINED = (
    f'{ADDRESS} - - [24/Oct/2026:12:00:00 +0000] '
    f'"GET /docs/api.md HTTP/1.1" 200 37 "-" "{USER_AGENT}"'
)


class PrivacyRegressionTests(unittest.TestCase):
    def test_f5_no_personal_data_in_temp_files_during_processing(self):
        catalog = load_catalog()
        verifier = Verifier({}, FakeResolver({}, {}))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checks = 0

            def inspect_directory():
                nonlocal checks
                checks += 1
                for path in root.rglob('*'):
                    if path.is_file():
                        data = path.read_bytes()
                        self.assertIsNone(re.search(
                            rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', data
                        ))
                        self.assertNotIn(USER_AGENT.encode(), data)
                        self.assertNotIn(COMBINED.encode(), data)

            def source():
                for _ in range(parsers.DETECTION_LINES + 25):
                    inspect_directory()
                    yield COMBINED
                inspect_directory()

            # Directory inspection alone cannot see unlinked TemporaryFiles.
            # Forbid all standard tempfile creation paths as well.
            with ExitStack() as stack:
                stack.enter_context(patch.object(tempfile, 'tempdir', directory))
                for name in (
                    'TemporaryFile', 'NamedTemporaryFile',
                    'SpooledTemporaryFile', 'mkstemp',
                ):
                    stack.enter_context(patch.object(
                        tempfile, name,
                        side_effect=AssertionError('disk buffering is forbidden'),
                    ))
                name, hits, read, skipped = parsers.parse_lines(source())
                self.addCleanup(hits.close)
                self.assertIsInstance(hits._spool, io.BytesIO)
                with self.assertRaises(io.UnsupportedOperation):
                    hits._spool.fileno()

                def checked_hits():
                    for hit in hits:
                        inspect_directory()
                        self.assertEqual(str(hit.ip), ADDRESS)
                        self.assertEqual(hit.ua, USER_AGENT)
                        yield hit

                report = aggregate(
                    checked_hits(), catalog, verifier, name, read, skipped,
                )
                inspect_directory()
                self.assertEqual(report['agent_hits'], parsers.DETECTION_LINES + 25)
                self.assertEqual(report['lines_read'], parsers.DETECTION_LINES + 25)
                self.assertEqual(report['lines_skipped'], 0)
                self.assertTrue(hits._spool.closed)
                self.assertGreater(checks, 2 * parsers.DETECTION_LINES)
                self.assertEqual(list(root.iterdir()), [])

    def test_f5_exact_memory_budget_and_overflow_cleanup(self):
        _, hits, _, _ = parsers.parse_lines([COMBINED])
        self.addCleanup(hits.close)
        size = hits._spool.getbuffer().nbytes
        hits.close()
        original_spool = parsers._MemorySpool

        for limit, succeeds in ((size, True), (size - 1, False)):
            with self.subTest(limit=limit):
                opened = []

                def memory_spool():
                    spool = original_spool()
                    opened.append(spool)
                    return spool

                with patch.object(parsers, 'MAX_BUFFER_BYTES', limit), \
                        patch.object(parsers, '_MemorySpool', memory_spool):
                    if succeeds:
                        name, hits, read, skipped = parsers.parse_lines([COMBINED])
                        self.addCleanup(hits.close)
                        self.assertEqual((name, read, skipped), ('combined', 1, 0))
                        self.assertEqual(len(list(hits)), 1)
                    else:
                        with self.assertRaisesRegex(parsers.ParseError, 'memory limit'):
                            parsers.parse_lines([COMBINED])
                self.assertEqual(len(opened), 1)
                self.assertTrue(opened[0].closed)

    def test_f5_buffer_rejects_overflow_before_writing(self):
        with patch.object(parsers, 'MAX_BUFFER_BYTES', 4):
            with parsers._MemorySpool() as spool:
                self.assertEqual(spool.write(b'abcd'), 4)
                with self.assertRaisesRegex(parsers.ParseError, 'memory limit'):
                    spool.write(b'e')
                self.assertEqual(spool.getvalue(), b'abcd')


class PrivacyUploadRegressionTests(unittest.TestCase):
    setUp = UploadRegressionTests.setUp
    request = UploadRegressionTests.request

    def test_f5_memory_limit_rejects_upload_and_releases_gate(self):
        with patch.object(parsers, 'MAX_BUFFER_BYTES', 1):
            status, response = self.request(
                'POST', '/upload', (COMBINED + '\n').encode(),
                {'X-AgentLog-Share-Consent': 'true'},
            )
        self.assertEqual(status, 400, response)
        self.assertIn('memory limit', response['error'])
        self.assertTrue(self.server.upload_gate.acquire(False))
        self.server.upload_gate.release()
        status, response = self.request(
            'POST', '/upload', (COMBINED + '\n').encode(),
            {'X-AgentLog-Share-Consent': 'true'},
        )
        self.assertEqual(status, 201, response)


if __name__ == '__main__':
    unittest.main()
