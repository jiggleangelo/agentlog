"""F4 regressions using real gzip decoding and an in-memory HTTP transport."""

import gzip
import io
import unittest
from unittest.mock import patch

from agentlog import parsers, server
from tests import test_findings


class GzipUploadRegressionTests(unittest.TestCase):
    setUp = test_findings.UploadRegressionTests.setUp
    request = test_findings.UploadRegressionTests.request

    def test_f4_post_compressible_body_bounds_chunks_and_stops_at_line_limit(self):
        payload = (test_findings.COMBINED + '\n').encode() + b'\n' * (2 * 1024 * 1024)
        body = gzip.compress(payload)
        sizes = []
        consumed_lines = 0
        original_decode = server.Handler._decoded_chunks
        original_lines = server.Handler._lines

        def decoded(handler, length):
            for chunk in original_decode(handler, length):
                sizes.append(len(chunk))
                self.assertLessEqual(len(chunk), 65536)
                yield chunk

        def lines(handler, chunks):
            nonlocal consumed_lines
            for line in original_lines(handler, chunks):
                consumed_lines += 1
                yield line

        with patch.object(server.Handler, '_decoded_chunks', decoded), \
                patch.object(server.Handler, '_lines', lines), \
                patch.object(parsers, 'MAX_LINES', 5):
            status, response = self.request(
                'POST', '/upload', body,
                {'X-AgentLog-Share-Consent': 'true', 'Content-Encoding': 'gzip'},
            )
        self.assertEqual(status, 400, response)
        self.assertIn('exceeds 5 lines', response['error'])
        self.assertEqual(consumed_lines, 6)
        self.assertTrue(sizes)
        self.assertLessEqual(sum(sizes), 65536)
        self.assertTrue(self.server.upload_gate.acquire(False))
        self.server.upload_gate.release()

    def test_f4_valid_gzip_spanning_windows_preserves_all_records(self):
        count = 1500
        body = gzip.compress(((test_findings.COMBINED + '\n') * count).encode())
        status, response = self.request(
            'POST', '/upload', body,
            {'X-AgentLog-Share-Consent': 'true', 'Content-Encoding': 'gzip'},
        )
        self.assertEqual(status, 201, response)
        status, report = self.request('GET', response['json_url'])
        self.assertEqual(status, 200, report)
        self.assertEqual(report['lines_read'], count)
        self.assertEqual(report['agent_hits'], count)
        self.assertEqual(report['urls'][0]['bytes'], 37 * count)


class GzipDecoderRegressionTests(unittest.TestCase):
    def handler(self, body, encoding='gzip'):
        handler = object.__new__(server.Handler)
        handler.headers = {'Content-Encoding': encoding}
        handler.rfile = io.BytesIO(body)
        return handler

    def test_f4_compressible_payloads_are_drained_in_small_windows(self):
        for value in (b'\x00', b'\n'):
            for encoding in ('gzip', ''):
                with self.subTest(value=value, encoding=encoding):
                    payload = value * (2 * 1024 * 1024 + 17)
                    body = gzip.compress(payload)
                    handler = self.handler(body, encoding)
                    total = 0
                    chunks = 0
                    for chunk in handler._decoded_chunks(len(body)):
                        self.assertGreater(len(chunk), 0)
                        self.assertLessEqual(len(chunk), 65536)
                        self.assertEqual(chunk, value * len(chunk))
                        total += len(chunk)
                        chunks += 1
                    self.assertEqual(total, len(payload))
                    self.assertGreater(chunks, 1)

    def test_f4_total_decompressed_limit_and_exact_boundary(self):
        limit = 2 * 65536 + 17
        for extra in (0, 1):
            with self.subTest(extra=extra):
                body = gzip.compress(b'x' * (limit + extra))
                handler = self.handler(body)
                total = 0

                def consume():
                    nonlocal total
                    for chunk in handler._decoded_chunks(len(body)):
                        self.assertLessEqual(len(chunk), 65536)
                        total += len(chunk)

                with patch.object(server, 'MAX_DECOMPRESSED', limit):
                    if extra:
                        with self.assertRaisesRegex(parsers.ParseError, 'decompressed upload too large'):
                            consume()
                    else:
                        consume()
                        self.assertEqual(total, limit)
                self.assertLessEqual(total, limit)
        self.assertLessEqual(server.MAX_DECOMPRESSED, 200 * 1024 * 1024)

    def test_f4_truncated_corrupt_and_trailing_gzip_are_rejected(self):
        valid = gzip.compress(b'x' * (3 * 65536))
        corrupt = bytearray(valid)
        corrupt[-8] ^= 1
        for body in (valid[:-1], bytes(corrupt), valid + b'junk', valid + valid):
            with self.subTest(body_length=len(body)):
                handler = self.handler(body)
                with self.assertRaises(parsers.ParseError):
                    for chunk in handler._decoded_chunks(len(body)):
                        self.assertLessEqual(len(chunk), 65536)

    def test_f4_body_reader_is_lazy(self):
        handler = self.handler(b'x' * (3 * 65536), 'identity')
        chunks = handler._body_chunks(3 * 65536)
        self.assertEqual(handler.rfile.tell(), 0)
        self.assertEqual(len(next(chunks)), 65536)
        self.assertEqual(handler.rfile.tell(), 65536)
        chunks.close()


if __name__ == '__main__':
    unittest.main()
