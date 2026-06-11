import os
import tempfile
import unittest

MAGENTA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("MAGENTA_HOME", MAGENTA_ROOT)

from libmagenta.engine import MagentaReporter, ParseHaltError


def _make_reporter(tmpdir, good_names, bad_names):
    """Build a real reporter but stub parsing/rendering so only the
    on_error policy in process_files is exercised. The files are empty;
    routing is by filename prefix + extension, and run_parser is stubbed."""
    for name in list(good_names) + list(bad_names):
        with open(os.path.join(tmpdir, name), "w") as fd:
            fd.write("")
    reporter = MagentaReporter(None)
    reporter.set_language("en")

    def fake_run_parser(tool, filename):
        if os.path.basename(filename) in bad_names:
            raise RuntimeError("simulated parser failure")
        return [{"_type": "issue", "template": "stub"}]

    reporter.run_parser = fake_run_parser
    reporter.merge_duplicated_issues = lambda issues: issues
    reporter.render_report = lambda metadata, issues: (metadata, {}, "REPORT")
    return reporter


class TestOnErrorPolicy(unittest.TestCase):
    def test_ignore_keeps_good_issues_and_counts_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _make_reporter(tmp, ["nmap.good.xml"], ["nmap.bad.xml"])
            result = r.process_files(tmp, None, on_error="ignore")
            self.assertEqual(result["skipped"], 1)
            self.assertEqual(len(result["issues"]), 1)

    def test_skip_counts_skips_and_keeps_good_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _make_reporter(tmp, ["nmap.good.xml"], ["nmap.bad.xml"])
            result = r.process_files(tmp, None, on_error="skip")
            self.assertEqual(result["skipped"], 1)
            self.assertEqual(len(result["issues"]), 1)

    def test_halt_raises_on_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _make_reporter(tmp, ["nmap.good.xml"], ["nmap.bad.xml"])
            with self.assertRaises(ParseHaltError):
                r.process_files(tmp, None, on_error="halt")

    def test_no_errors_zero_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _make_reporter(tmp, ["nmap.good.xml"], [])
            result = r.process_files(tmp, None, on_error="skip")
            self.assertEqual(result["skipped"], 0)
            self.assertEqual(len(result["issues"]), 1)

    def test_invalid_mode_rejected(self):
        reporter = MagentaReporter(None)
        reporter.set_language("en")
        with self.assertRaises(ValueError):
            reporter.process_files("/nonexistent", None, on_error="bogus")


if __name__ == "__main__":
    unittest.main()
