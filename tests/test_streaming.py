"""F3 regressions, including cleanup of the F5 memory-only buffer."""

import gc
import unittest
import weakref
from unittest.mock import patch

from agentlog import parsers
from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.verify import FakeResolver, Verifier


COMBINED = '192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET /docs/api.md HTTP/1.1" 200 37 "-" "GPTBot"'


class StreamingRegressionTests(unittest.TestCase):
    def test_f3_input_and_hits_are_not_retained_in_memory(self):
        references = []
        original_parser = parsers.parse_combined
        maximum_live = 0
        consumed = 0

        class TrackedLine(str):
            pass

        def source():
            nonlocal consumed
            for index in range(2000):
                consumed += 1
                line = TrackedLine(COMBINED + ' ' + str(index))
                references.append(weakref.ref(line))
                yield line

        hit_references = []

        def tracking_parser(line):
            nonlocal maximum_live
            hit = original_parser(line)
            hit_references.append(weakref.ref(hit))
            # Check occasionally to avoid quadratic bookkeeping.
            if len(hit_references) % 100 == 0:
                gc.collect()
                live_lines = sum(ref() is not None for ref in references)
                live_hits = sum(ref() is not None for ref in hit_references)
                self.assertLessEqual(live_lines, parsers.DETECTION_LINES + 2)
                maximum_live = max(maximum_live, live_hits)
            return hit

        with patch.object(parsers, 'parse_combined', tracking_parser):
            name, hits, read, skipped = parsers.parse_lines(source())
        self.addCleanup(hits.close)
        self.assertEqual((name, read, skipped), ('combined', 2000, 0))
        self.assertEqual(consumed, 2000)
        self.assertLessEqual(maximum_live, 3)
        self.assertIs(iter(hits), hits)
        self.assertEqual(sum(1 for _ in hits), 2000)
        self.assertTrue(hits._spool.closed)

    def test_f3_detection_sample_is_replayed_and_counters_reach_aggregate(self):
        def source():
            for _ in range(125):
                yield COMBINED
            yield '\n'
            yield 'invalid log line'
            yield COMBINED

        name, hits, read, skipped = parsers.parse_lines(source())
        self.addCleanup(hits.close)
        report = aggregate(
            hits, load_catalog(), Verifier({}, FakeResolver({}, {})),
            name, read, skipped,
        )
        self.assertEqual(report['lines_read'], 127)
        self.assertEqual(report['lines_skipped'], 1)
        self.assertEqual(report['agent_hits'], 126)
        self.assertEqual(report['urls'][0]['bytes'], 126 * 37)

    def test_f3_line_limit_counts_blank_and_invalid_lines(self):
        for extra in ('', 'invalid', COMBINED):
            with self.subTest(extra=extra):
                consumed = 0

                def source():
                    nonlocal consumed
                    for line in [COMBINED] + [extra] * 20:
                        consumed += 1
                        yield line

                with patch.object(parsers, 'MAX_LINES', 5):
                    with self.assertRaisesRegex(parsers.ParseError, 'exceeds 5 lines'):
                        parsers.parse_lines(source())
                self.assertEqual(consumed, 6)

    def test_f3_exact_line_limit_is_accepted(self):
        with patch.object(parsers, 'MAX_LINES', 5):
            name, hits, read, skipped = parsers.parse_lines(
                COMBINED for _ in range(5)
            )
        self.addCleanup(hits.close)
        self.assertEqual((read, skipped), (5, 0))
        self.assertEqual(len(list(hits)), 5)

    def test_f3_oversized_lines_rejected_before_and_after_detection(self):
        for prefix in ([], [COMBINED] * parsers.DETECTION_LINES):
            with self.subTest(prefix_length=len(prefix)):
                with self.assertRaisesRegex(parsers.ParseError, 'characters'):
                    parsers.parse_lines(iter(
                        prefix + ['x' * (parsers.MAX_LINE_LENGTH + 1)]
                    ))

    def test_f3_spool_closes_on_input_failure(self):
        original_memory_spool = parsers._MemorySpool
        opened = []

        def memory_spool():
            spool = original_memory_spool()
            opened.append(spool)
            return spool

        def source():
            for _ in range(parsers.DETECTION_LINES + 1):
                yield COMBINED
            raise OSError('input failed')

        with patch.object(parsers, '_MemorySpool', memory_spool):
            with self.assertRaisesRegex(OSError, 'input failed'):
                parsers.parse_lines(source())
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].closed)

    def test_f3_spool_can_close_before_iteration(self):
        _, hits, _, _ = parsers.parse_lines([COMBINED])
        hits.close()
        self.assertTrue(hits._spool.closed)
        self.assertEqual(list(hits), [])


if __name__ == '__main__':
    unittest.main()
