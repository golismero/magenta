import io
import json
import unittest
from contextlib import redirect_stdout

from libmagenta.merger import Merger


def _run_merger_with_input(template_name, issues):
    """Drive the base Merger.run() machinery against an in-memory issues list."""
    import sys

    merger = Merger(template_name=template_name)
    captured = io.StringIO()
    original_stdin = sys.stdin
    sys.stdin = io.StringIO(json.dumps(issues))
    try:
        with redirect_stdout(captured):
            merger.run()
    finally:
        sys.stdin = original_stdin
    return json.loads(captured.getvalue())


class TestMergerUnderscoreFields(unittest.TestCase):
    def _issue(self, **overrides):
        base = {
            "template": "cleartext_open_ports",
            "tools": ["nmap"],
            "severity": "low",
            "affects": ["10.0.0.1"],
            "taxonomy": ["CWE-319"],
            "references": ["https://example.invalid/"],
            "_type": "issue",
            "_tool": "magenta",
            "_fp": ["magenta deadbeef"],
        }
        base.update(overrides)
        return base

    def test_type_and_tool_constants_preserved(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [self._issue(), self._issue(affects=["10.0.0.2"])],
        )
        self.assertEqual(merged["_type"], "issue")
        self.assertEqual(merged["_tool"], "magenta")

    def test_fp_set_union(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [
                self._issue(_fp=["magenta aaa"]),
                self._issue(_fp=["magenta bbb", "magenta aaa"], affects=["10.0.0.2"]),
            ],
        )
        self.assertEqual(merged["_fp"], ["magenta aaa", "magenta bbb"])

    def test_cmd_becomes_synthetic_label_on_merge(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [
                self._issue(_cmd="nmap -A 10.0.0.1"),
                self._issue(_cmd="nmap -A 10.0.0.2", affects=["10.0.0.2"]),
            ],
        )
        self.assertEqual(merged["_cmd"], "magenta merge")

    def test_cmd_absent_when_no_input_had_it(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [self._issue(), self._issue(affects=["10.0.0.2"])],
        )
        self.assertNotIn("_cmd", merged)

    def test_start_is_min_end_is_max(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [
                self._issue(_start=1700000050, _end=1700000100),
                self._issue(_start=1700000000, _end=1700000080, affects=["10.0.0.2"]),
            ],
        )
        self.assertEqual(merged["_start"], 1700000000)
        self.assertEqual(merged["_end"], 1700000100)

    def test_start_end_absent_when_no_input_had_them(self):
        merged = _run_merger_with_input(
            "cleartext_open_ports",
            [self._issue(), self._issue(affects=["10.0.0.2"])],
        )
        self.assertNotIn("_start", merged)
        self.assertNotIn("_end", merged)


if __name__ == "__main__":
    unittest.main()
