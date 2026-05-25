import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from xml.etree import ElementTree as ET

try:
    import pypandoc

    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False


MAGENTA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAGENTA_PY = os.path.join(MAGENTA_ROOT, "magenta.py")
SAMPLES_DIR = os.path.join(MAGENTA_ROOT, "tmp", "samples")

# Samples we cannot use in tests because the corresponding parser+template
# combination has known bugs. Tracked outside this test file — these should
# be re-added as the underlying issues are fixed.
EXCLUDED_SAMPLE_DIRS = ()


def _make_filtered_samples_dir(dest_parent):
    """Copy SAMPLES_DIR to a temp location, omitting EXCLUDED_SAMPLE_DIRS.

    Returns the path to the filtered samples dir. Caller is responsible
    for cleanup (typically via tempfile.TemporaryDirectory)."""
    filtered = os.path.join(dest_parent, "samples")
    os.makedirs(filtered)
    for entry in os.listdir(SAMPLES_DIR):
        if entry in EXCLUDED_SAMPLE_DIRS:
            continue
        src = os.path.join(SAMPLES_DIR, entry)
        dst = os.path.join(filtered, entry)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    return filtered


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestTextileFormat(unittest.TestCase):
    def test_textile_extension_autodetects(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "report.textile")
            subprocess.run(
                [sys.executable, MAGENTA_PY, "report", samples, "-o", out],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))
            with open(out, "r", encoding="utf-8") as fd:
                content = fd.read()
            self.assertGreater(len(content), 0)

    def test_textile_explicit_format_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "report.out")
            subprocess.run(
                [
                    sys.executable,
                    MAGENTA_PY,
                    "report",
                    samples,
                    "-o",
                    out,
                    "-f",
                    "textile",
                ],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestDradisFormat(unittest.TestCase):
    def test_dradis_explicit_flag_produces_valid_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "out.zip")
            subprocess.run(
                [
                    sys.executable,
                    MAGENTA_PY,
                    "report",
                    samples,
                    "-o",
                    out,
                    "-f",
                    "dradis",
                ],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))
            with zipfile.ZipFile(out) as zf:
                self.assertIn("dradis-repository.xml", zf.namelist())
                with zf.open("dradis-repository.xml") as fd:
                    root = ET.fromstring(fd.read())
            self.assertEqual(root.tag, "dradis-template")
            self.assertEqual(root.attrib["version"], "4")

    def test_dradis_export_zip_filename_autodetects(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "dradis-export.zip")
            subprocess.run(
                [sys.executable, MAGENTA_PY, "report", samples, "-o", out],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))

    def test_other_zip_filename_errors(self):
        # Any .zip filename OTHER than dradis-export.zip should NOT autodetect.
        # User must pass -f explicitly. Magenta exits with a non-zero code OR
        # prints an error and exits 0 (per existing convention).
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "random.zip")
            result = subprocess.run(
                [sys.executable, MAGENTA_PY, "report", samples, "-o", out],
                cwd=MAGENTA_ROOT,
                capture_output=True,
                text=True,
            )
            combined = result.stdout + result.stderr
            self.assertIn(
                "ambiguous",
                combined.lower(),
                "expected an 'ambiguous .zip' error message; got: " + combined,
            )
            self.assertFalse(
                os.path.isfile(out),
                "no zip should be produced when format is ambiguous",
            )

    def test_custom_dradis_templates_dir(self):
        # Drop a mapping.json5 with only a Title section into a temp dir;
        # verify the output reflects the override.
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            templates_dir = os.path.join(tmp, "my-dradis")
            os.makedirs(templates_dir)
            with open(os.path.join(templates_dir, "mapping.json5"), "w") as fd:
                fd.write("""
{
  evidence_nodes: false,
  issue_sections: [{ name: "Title", value: "{{ title }}" }],
  evidence_sections: [],
  project_properties: {},
}
""")
            out = os.path.join(tmp, "out.zip")
            subprocess.run(
                [
                    sys.executable,
                    MAGENTA_PY,
                    "report",
                    samples,
                    "-o",
                    out,
                    "-f",
                    "dradis",
                    "--dradis-templates",
                    templates_dir,
                ],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            with zipfile.ZipFile(out) as zf:
                with zf.open("dradis-repository.xml") as fd:
                    xml = fd.read().decode("utf-8")
            # Only #[Title]# markers should be present, no #[Description]# etc.
            self.assertIn("#[Title]#", xml)
            self.assertNotIn("#[Description]#", xml)
            self.assertNotIn("#[Solution]#", xml)


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestAutodetectionDeprecation(unittest.TestCase):
    def test_trailing_slash_obsidian_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "vault")  # no extension → obsidian
            result = subprocess.run(
                [sys.executable, MAGENTA_PY, "report", samples, "-o", out],
                cwd=MAGENTA_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("deprecated", combined.lower())
            self.assertIn("obsidian", combined.lower())

    def test_explicit_obsidian_flag_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "vault")
            result = subprocess.run(
                [
                    sys.executable,
                    MAGENTA_PY,
                    "report",
                    samples,
                    "-o",
                    out,
                    "-f",
                    "obsidian",
                ],
                cwd=MAGENTA_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertNotIn("deprecated", combined.lower())
