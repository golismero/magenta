import os
import subprocess
import sys
import tempfile
import unittest

MAGENTA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAGENTA_PY = os.path.join(MAGENTA_ROOT, "magenta.py")


def _dir_with_bad_nmap(tmp):
    """Only artifact is an unparseable nmap.xml. nmap declares
    formats=['xml'], so it passes the extension filter and reaches the
    parser, which fails -> a file-level parser error."""
    with open(os.path.join(tmp, "nmap.xml"), "w") as fd:
        fd.write("this is not valid xml at all\n")


def _run(tmp, out_name, *extra):
    out = os.path.join(tmp, out_name)
    proc = subprocess.run(
        [sys.executable, MAGENTA_PY, "report", tmp, "-o", out, *extra],
        cwd=MAGENTA_ROOT,
        capture_output=True,
        text=True,
    )
    return proc, out


class TestOnErrorCli(unittest.TestCase):
    def test_default_is_ignore_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.exists(out))

    def test_ignore_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md", "--on-error", "ignore")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.exists(out))

    def test_skip_no_errors_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            # No recognizable tool files -> nothing to parse, nothing to fail.
            proc, out = _run(tmp, "report.md", "--on-error", "skip")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.exists(out))

    def test_skip_exit_two_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md", "--on-error", "skip")
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertTrue(os.path.exists(out))
            self.assertIn("file(s) skipped", proc.stderr)

    def test_halt_exit_three_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md", "--on-error", "halt")
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
