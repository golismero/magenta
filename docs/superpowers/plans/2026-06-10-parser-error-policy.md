# Parser-error policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **GIT POLICY FOR THIS REPO:** The user manages git exclusively. Do **not** run `git add`, `git commit`, `git branch`, `git stash`, or any other git mutation at any point. Each task ends with a test-verification checkpoint instead of a commit.

**Goal:** Add an `--on-error {ignore,skip,halt}` option to Magenta's `report` command that governs how a file-level parser failure affects the run and the process exit code.

**Architecture:** `MagentaReporter.process_files` gains an `on_error` parameter and a skipped-file counter; on `halt` it raises a new `ParseHaltError` to unwind before rendering. The `report` CLI command exposes the option, maps the outcome to exit codes (0 / 2 / 3), and prints a one-line stderr summary when files were skipped. The directory walk, extension filter, and per-issue validation are untouched.

**Tech Stack:** Python 3, `click` (CLI), `unittest` (tests), `subprocess` (CLI integration tests).

**Spec:** [docs/superpowers/specs/2026-06-10-parser-error-policy-design.md](../specs/2026-06-10-parser-error-policy-design.md)

---

## Pre-flight note (already done, not a task)

A pre-existing syntax error in [`parsers/bandit/bandit.json5:9`](../../../parsers/bandit/bandit.json5#L9) (malformed `formats` list, missing two closing quotes) was blocking **every** Magenta run in `_find_parsers`. It has been corrected to `formats: ["csv", "html", "json", "txt", "xml", "yaml"]`. If for any reason that fix is absent, restore it before running anything below — otherwise all tests fail at startup.

## Reference: current code being changed

- `libmagenta/engine.py:1177-1227` — `process_files(self, pathname, metadata=DEFAULT_METADATA)`. Contains the `os.walk` + extension-filter task collection (`1186-1201`), the per-file `try/except` that logs and `continue`s (`1205-1213`), and the result dict (`1222-1227`).
- `libmagenta/engine.py:1083-1112` — `run_parser`; raises on subprocess non-zero / JSON-decode / timeout (the file-level errors), and already drops invalid issues per-issue (`1100-1111`). **Not modified by this plan** — per-issue validation stays lenient in all modes.
- `libmagenta/engine.py:3-33` — module imports; **not** modified, but `ParseHaltError` is added just after this block.
- `magenta.py:34-42` — two `from libmagenta.engine import MagentaReporter` sites (a try/except import shim); **both** need `ParseHaltError` added.
- `magenta.py:67-204` — the `report` command; options end at `111` (`@click.pass_context`), function signature at `112`, `process_files` call at `181`, format dispatch + output at `182-204`.
- `magenta.py:7` — `sys` already imported.
- Verified current behavior (smoke test): a directory whose only file is an unparseable `nmap.xml` exits **0**, logs a `CalledProcessError` traceback to stderr, and still writes an ~85-byte report. nmap declares `formats: ["xml"]`, so a `nmap.xml` passes the extension filter and reaches the parser.
- Test patterns: `tests/test_cli.py:56-60` runs the CLI via `subprocess.run([sys.executable, MAGENTA_PY, "report", ...], cwd=MAGENTA_ROOT)`.

---

## Task 1: `process_files` gains the `on_error` policy

Add `ParseHaltError` and the three-mode logic to the engine. Pure unit test — `run_parser`, `merge_duplicated_issues`, and `render_report` are stubbed so only the new policy logic runs.

**Files:**
- Modify: `libmagenta/engine.py` (add `ParseHaltError` after imports ~`33`; change `process_files` ~`1177-1227`)
- Test: `tests/test_on_error_policy.py` (new)

- [ ] **Step 1: Write the failing test**

Create `tests/test_on_error_policy.py`:

```python
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

    def test_halt_raises_on_first_error(self):
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
        with tempfile.TemporaryDirectory() as tmp:
            r = _make_reporter(tmp, ["nmap.good.xml"], [])
            with self.assertRaises(ValueError):
                r.process_files(tmp, None, on_error="bogus")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m unittest tests.test_on_error_policy -v`
Expected: FAIL — `ImportError: cannot import name 'ParseHaltError'` (and `process_files` rejects the `on_error` keyword).

- [ ] **Step 3: Add the `ParseHaltError` class**

In `libmagenta/engine.py`, immediately after the import block (after the `from .taxonomy import ...` line, before `class FileCache:`), add:

```python
class ParseHaltError(Exception):
    """Raised by MagentaReporter.process_files when on_error='halt' and a
    file-level parser error occurs, to unwind without rendering a report."""
```

- [ ] **Step 4: Add the `on_error` parameter and validation**

Change the `process_files` signature line:

```python
    def process_files(self, pathname, metadata=DEFAULT_METADATA):
```

to:

```python
    def process_files(self, pathname, metadata=DEFAULT_METADATA, on_error="ignore"):
        if on_error not in ("ignore", "skip", "halt"):
            raise ValueError("invalid on_error mode: %r" % (on_error,))
```

- [ ] **Step 5: Track skips and honor `halt` in the parse loop**

Replace the parse loop:

```python
        # Parse the input files.
        issues = []
        for tool, filename in tasks:
            try:
                results = self.run_parser(tool, filename)
            except Exception:
                sys.stderr.write("Error processing file '%s':\n" % filename)
                traceback.print_exc()
                sys.stderr.write("\n")
                continue
            issues.extend(results)
```

with:

```python
        # Parse the input files.
        issues = []
        skipped = 0
        for tool, filename in tasks:
            try:
                results = self.run_parser(tool, filename)
            except Exception:
                sys.stderr.write("Error processing file '%s':\n" % filename)
                traceback.print_exc()
                sys.stderr.write("\n")
                if on_error == "halt":
                    raise ParseHaltError(filename) from None
                skipped += 1
                continue
            issues.extend(results)
```

- [ ] **Step 6: Add `skipped` to the result dict**

Replace the return value:

```python
        # Return the report and several intermediate stages.
        return {
            "metadata": metadata,
            "issues": issues,
            "sections": sections,
            "report": report,
        }
```

with:

```python
        # Return the report and several intermediate stages.
        return {
            "metadata": metadata,
            "issues": issues,
            "sections": sections,
            "report": report,
            "skipped": skipped,
        }
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `python -m unittest tests.test_on_error_policy -v`
Expected: PASS (5 tests).

- [ ] **Step 8: Verification checkpoint**

Run the existing suite to confirm no regression:
Run: `python -m unittest discover -s tests -v`
Expected: existing tests still pass (some may `skip` if `tmp/samples` or pandoc is absent — that is fine). Do **not** commit (user manages git).

---

## Task 2: `--on-error` CLI option, exit codes, and summary

Expose the policy on the `report` command, map outcomes to exit codes 0/2/3, and print the skip summary.

**Files:**
- Modify: `magenta.py` (imports `34-42`; option block + signature `67-119`; call + dispatch `181-204`)
- Test: `tests/test_on_error_cli.py` (new)

- [ ] **Step 1: Write the failing test**

Create `tests/test_on_error_cli.py`:

```python
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

    def test_skip_exit_two_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md", "--on-error", "skip")
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertTrue(os.path.exists(out))
            self.assertIn("skipped", proc.stderr.lower())

    def test_halt_exit_three_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            _dir_with_bad_nmap(tmp)
            proc, out = _run(tmp, "report.md", "--on-error", "halt")
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m unittest tests.test_on_error_cli -v`
Expected: FAIL — `--on-error` is an unknown option (click usage error, exit 2 with a "no such option" message), so the skip/halt assertions don't hold.

- [ ] **Step 3: Add `ParseHaltError` to both imports**

In `magenta.py`, change **both** import sites (lines 36 and 42):

```python
    from libmagenta.engine import MagentaReporter
```

to:

```python
    from libmagenta.engine import MagentaReporter, ParseHaltError
```

- [ ] **Step 4: Add the `--on-error` option and parameter**

In `magenta.py`, insert this option decorator immediately before `@click.pass_context` (line 111, just above the `def report(...)`):

```python
@click.option(
    "--on-error",
    type=click.Choice(("ignore", "skip", "halt"), case_sensitive=False),
    default="ignore",
    show_default=True,
    help="How to react to a file-level parser error: 'ignore' logs and "
    "continues (exit 0); 'skip' logs and continues but exits 2 if any file "
    "failed; 'halt' logs and stops without writing a report (exit 3).",
)
```

Then change the function signature:

```python
def report(ctx, pathname, output, format, language, metadata, dradis_templates):
```

to:

```python
def report(ctx, pathname, output, format, language, metadata, dradis_templates, on_error):
```

- [ ] **Step 5: Pass `on_error` to `process_files` and map exit codes**

Replace lines `181-204` (from `result = magenta.process_files(...)` through the final `assert False`):

```python
    result = magenta.process_files(pathname, metadata)
    if format == "dradis":
        if dradis_templates is None:
            dradis_templates = os.path.join(MAGENTA_HOME, "formats", "dradis")
        magenta.export_as_dradis(result, output, dradis_templates)
        return
    if format == "obsidian":
        magenta.export_as_obsidian(result, output)
    else:
        if output == "-":
            fd = sys.stdout
        else:
            fd = open(output, "w", encoding="utf-8")
        with fd:
            if format == "markdown":
                fd.write(result["report"])
            elif format == "json":
                click.echo(color_json(result), file=fd)
            elif format == "textile":
                from libmagenta.pandoc import convert_from_markdown

                fd.write(convert_from_markdown(result["report"], "textile"))
            else:
                assert False
```

with:

```python
    try:
        result = magenta.process_files(pathname, metadata, on_error)
    except ParseHaltError:
        sys.exit(3)
    if format == "dradis":
        if dradis_templates is None:
            dradis_templates = os.path.join(MAGENTA_HOME, "formats", "dradis")
        magenta.export_as_dradis(result, output, dradis_templates)
    elif format == "obsidian":
        magenta.export_as_obsidian(result, output)
    else:
        if output == "-":
            fd = sys.stdout
        else:
            fd = open(output, "w", encoding="utf-8")
        with fd:
            if format == "markdown":
                fd.write(result["report"])
            elif format == "json":
                click.echo(color_json(result), file=fd)
            elif format == "textile":
                from libmagenta.pandoc import convert_from_markdown

                fd.write(convert_from_markdown(result["report"], "textile"))
            else:
                assert False
    if on_error == "skip" and result.get("skipped"):
        sys.stderr.write(
            "%d file(s) skipped due to parse errors.\n" % result["skipped"]
        )
        sys.exit(2)
```

Notes for the implementer:
- The dradis branch's early `return` is intentionally removed (changed to `elif`) so the skip-summary/exit logic also applies after a dradis export.
- `sys.exit(2)`/`sys.exit(3)` raise `SystemExit` (a `BaseException`), so they pass cleanly through the top-level `except Exception` in `magenta.py:329` and set the real process exit code. Verified: `ParseHaltError` is caught here in `report`, so it never reaches that top-level handler (which would otherwise force exit 1).
- The `json` output format now includes a `"skipped"` key (additive). This is intended and harmless for consumers that read the `issues` array.

- [ ] **Step 6: Run the test to verify it passes**

Run: `python -m unittest tests.test_on_error_cli -v`
Expected: PASS (4 tests).

- [ ] **Step 7: Verification checkpoint**

Run the full suite:
Run: `python -m unittest discover -s tests -v`
Expected: all tests pass (sample/pandoc-gated tests may `skip`). Sanity-check the help text:
Run: `python magenta.py report --help`
Expected: shows `--on-error [ignore|skip|halt]` with `[default: ignore]`. Do **not** commit (user manages git).

---

## Self-Review

**Spec coverage:**
- `--on-error {ignore,skip,halt}`, default `ignore` → Task 2 Step 4; engine behavior Task 1 Steps 4-6. ✓
- File-level-only semantics; per-issue validation unchanged → `run_parser` untouched; Task 1 test asserts good issues survive alongside a skipped file. ✓
- Exit codes 0 / 1 (unchanged) / 2 (skip) / 3 (halt) → Task 2 Step 5; integration tests assert 0/2/3. ✓ (Exit 1 fatal path is the pre-existing top-level handler, unchanged.)
- End-of-run summary line when files skipped → Task 2 Step 5; asserted in `test_skip_exit_two_and_summary`. ✓ (Gated on `on_error == "skip"` so `ignore` stays byte-for-byte the current behavior — exit 0, no summary.)
- `halt` writes no report → Task 2 Step 5 catches `ParseHaltError` before any output; `test_halt_exit_three_no_report` asserts the file is absent. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type/name consistency:** `ParseHaltError` defined in Task 1 Step 3, imported in Task 2 Step 3, raised in Task 1 Step 5, caught in Task 2 Step 5. `on_error` param name consistent across engine and CLI. `result["skipped"]` produced in Task 1 Step 6, read in Task 2 Step 5. ✓
