import json
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


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
class TestG3UnderscoreFieldsE2E(unittest.TestCase):
    """End-to-end verification that Magenta-emitted issues carry the
    G3-aligned underscore fields. See docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md."""

    def _emit_json(self, input_dir, out_json):
        subprocess.run(
            [
                sys.executable,
                MAGENTA_PY,
                "report",
                input_dir,
                "-o",
                out_json,
                "-f",
                "json",
            ],
            check=True,
            cwd=MAGENTA_ROOT,
        )

    def test_emitted_issues_have_underscore_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "out.json")
            self._emit_json(samples, out)
            with open(out) as f:
                report = json.load(f)
            self.assertTrue(report["issues"], "expected at least one issue")
            for issue in report["issues"]:
                self.assertEqual(issue["_type"], "issue")
                self.assertEqual(issue["_tool"], "magenta")
                self.assertTrue(issue["_fp"], "_fp must be non-empty")
                for fp in issue["_fp"]:
                    self.assertTrue(
                        fp.startswith("magenta "),
                        "fingerprint should be 'magenta <hash>': %r" % fp,
                    )

    def test_round_trip_accumulates_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out1 = os.path.join(tmp, "first.json")
            self._emit_json(samples, out1)

            # Stage out1 as a magenta-named input for re-ingestion.
            second_input_dir = os.path.join(tmp, "round2")
            os.makedirs(second_input_dir)
            shutil.copy2(out1, os.path.join(second_input_dir, "magenta.json"))

            out2 = os.path.join(tmp, "second.json")
            self._emit_json(second_input_dir, out2)

            with open(out1) as f:
                first = json.load(f)
            with open(out2) as f:
                second = json.load(f)

            self.assertEqual(len(first["issues"]), len(second["issues"]))

            def key(issue):
                return (issue["template"], tuple(sorted(issue.get("affects", []))))

            first_by_key = {key(i): i for i in first["issues"]}
            matched_at_least_one = False
            for issue in second["issues"]:
                k = key(issue)
                if k not in first_by_key:
                    continue
                matched_at_least_one = True
                first_fps = set(first_by_key[k]["_fp"])
                second_fps = set(issue["_fp"])
                self.assertTrue(
                    first_fps.issubset(second_fps),
                    "round-trip should preserve original _fp entries: "
                    "first=%r second=%r" % (first_fps, second_fps),
                )
                self.assertTrue(
                    len(second_fps) > len(first_fps),
                    "round-trip should add at least one new _fp entry",
                )
            self.assertTrue(
                matched_at_least_one,
                "no issues matched between first and second pass - check key() function",
            )

    def test_single_issue_template_preserves_cmd(self):
        """If a sample produces exactly one issue for some template, its _cmd
        (if any) must NOT be rewritten to 'magenta merge'. Currently no parser
        extracts _cmd, so the field will be absent for most/all issues - which
        is the correct outcome too. The negative assertion is what matters."""
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "out.json")
            self._emit_json(samples, out)
            with open(out) as f:
                report = json.load(f)

            by_template = {}
            for issue in report["issues"]:
                by_template.setdefault(issue["template"], []).append(issue)

            singleton_templates = [
                t for t, group in by_template.items() if len(group) == 1
            ]
            self.assertTrue(
                singleton_templates,
                "samples should produce at least one single-issue template "
                "for this assertion to be meaningful",
            )
            for template in singleton_templates:
                issue = by_template[template][0]
                self.assertNotEqual(
                    issue.get("_cmd"),
                    "magenta merge",
                    "single-issue template %s should not have synthetic merge "
                    "label as _cmd" % template,
                )
