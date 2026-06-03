import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from libmagenta.engine import (
    KNOWN_IGNORED_UNDERSCORE_FIELDS,
    RECOGNIZED_UNDERSCORE_FIELDS,
    MagentaReporter,
    _sha1_file,
)


class TestSha1File(unittest.TestCase):
    def test_known_input(self):
        # Known SHA-1 of the bytes b"hello" is "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d".
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            path = f.name
        try:
            self.assertEqual(
                _sha1_file(path),
                "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            )
        finally:
            os.unlink(path)

    def test_streaming_matches_oneshot_on_large_file(self):
        # Build a file larger than the chunk size to exercise the streaming loop.
        payload = (b"abcdef0123456789" * 16) * 4096  # 1 MiB
        expected = hashlib.sha1(payload).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(payload)
            path = f.name
        try:
            self.assertEqual(_sha1_file(path), expected)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        # SHA-1 of empty bytes is "da39a3ee5e6b4b0d3255bfef95601890afd80709".
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            self.assertEqual(
                _sha1_file(path),
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            )
        finally:
            os.unlink(path)


class TestUnderscoreVocabulary(unittest.TestCase):
    def test_recognized_set(self):
        self.assertEqual(
            RECOGNIZED_UNDERSCORE_FIELDS,
            frozenset({"_type", "_tool", "_fp", "_cmd", "_start", "_end"}),
        )

    def test_known_ignored_set(self):
        self.assertEqual(
            KNOWN_IGNORED_UNDERSCORE_FIELDS,
            frozenset({"_scanid", "_taskid", "_id"}),
        )

    def test_sets_are_disjoint(self):
        self.assertEqual(
            RECOGNIZED_UNDERSCORE_FIELDS & KNOWN_IGNORED_UNDERSCORE_FIELDS,
            frozenset(),
        )


def _make_engine():
    # MagentaReporter.__init__ requires a config path; bypass it for unit tests by
    # constructing without __init__ and only setting what the wrap helper needs.
    # _g3_wrap_issue depends on no instance state — it's effectively a pure method.
    return MagentaReporter.__new__(MagentaReporter)


def _write_tmp(content_bytes):
    import tempfile

    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(content_bytes)
    f.close()
    return f.name


class TestG3WrapIssue(unittest.TestCase):
    def setUp(self):
        self.engine = _make_engine()
        self.path = _write_tmp(
            b"hello"
        )  # sha1 = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        self.expected_fp = "magenta aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def tearDown(self):
        os.unlink(self.path)

    def test_injects_constants_and_fp_when_absent(self):
        issue = {"template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_type"], "issue")
        self.assertEqual(issue["_tool"], "magenta")
        self.assertEqual(issue["_fp"], [self.expected_fp])

    def test_validates_existing_type_constant(self):
        issue = {
            "_type": "issue",
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_type"], "issue")

    def test_rejects_wrong_type(self):
        issue = {
            "_type": "host",
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        with self.assertRaises(ValueError):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)

    def test_rejects_wrong_tool(self):
        issue = {
            "_tool": "nmap",
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        with self.assertRaises(ValueError):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)

    def test_fp_set_union_with_parser_supplied(self):
        issue = {
            "_fp": ["nmap 10.0.0.1"],
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(
            sorted(issue["_fp"]), sorted([self.expected_fp, "nmap 10.0.0.1"])
        )

    def test_fp_set_union_with_duplicate_engine_fp(self):
        # Parser already supplied the engine-style fingerprint; should not duplicate.
        issue = {
            "_fp": [self.expected_fp],
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_fp"], [self.expected_fp])

    def test_strips_known_ignored_silently(self):
        issue = {
            "_scanid": "abc",
            "_taskid": "def",
            "_id": "ghi",
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        buf = io.StringIO()
        with redirect_stderr(buf):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertNotIn("_scanid", issue)
        self.assertNotIn("_taskid", issue)
        self.assertNotIn("_id", issue)
        self.assertEqual(buf.getvalue(), "")  # no warning emitted

    def test_warns_and_strips_unknown(self):
        issue = {
            "_foobar": "x",
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        buf = io.StringIO()
        with redirect_stderr(buf):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertNotIn("_foobar", issue)
        self.assertIn("_foobar", buf.getvalue())
        self.assertIn("nmap", buf.getvalue())

    def test_preserves_cmd_start_end(self):
        issue = {
            "_cmd": "nmap -A 10.0.0.1",
            "_start": 1700000000,
            "_end": 1700000060,
            "template": "x",
            "tools": ["nmap"],
            "severity": "low",
            "affects": [],
        }
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_cmd"], "nmap -A 10.0.0.1")
        self.assertEqual(issue["_start"], 1700000000)
        self.assertEqual(issue["_end"], 1700000060)


class TestSingleIssueSkip(unittest.TestCase):
    """Verifies that merge_duplicated_issues passes single-issue templates
    through unchanged instead of invoking the merger (which would rewrite
    _cmd to 'magenta merge'). See spec §5.5."""

    def setUp(self):
        self.engine = _make_engine()
        # merge_duplicated_issues only needs self.mergers populated; for the
        # skip path it isn't even consulted, but populating it as an empty dict
        # keeps the method's other branches unsurprised.
        self.engine.mergers = {}

    def test_single_issue_per_template_is_returned_unchanged(self):
        issue = {
            "template": "cleartext_open_ports",
            "tools": ["nmap"],
            "severity": "low",
            "affects": ["10.0.0.1"],
            "_type": "issue",
            "_tool": "magenta",
            "_fp": ["magenta abc"],
            "_cmd": "nmap -A 10.0.0.1",
        }
        merged = self.engine.merge_duplicated_issues([issue])
        self.assertEqual(len(merged), 1)
        # Identity-preserving: the same dict object should come back.
        self.assertIs(merged[0], issue)
        # And specifically _cmd was NOT rewritten to "magenta merge".
        self.assertEqual(merged[0]["_cmd"], "nmap -A 10.0.0.1")


if __name__ == "__main__":
    unittest.main()
