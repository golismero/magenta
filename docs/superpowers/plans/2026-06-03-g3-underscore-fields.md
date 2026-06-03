# G3-aligned underscore fields on Magenta issues — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Magenta's issue records with the G3-aligned underscore fields (`_type`, `_tool`, `_fp`, `_cmd`, `_start`, `_end`) so that Magenta output is recognizable as G3Data, while keeping Magenta's issue format, 5-level severity, and `tools[]` plural semantics unchanged.

**Architecture:** Engine-injection model. The 11+ existing tool parsers stay untouched; a new method `MagentaReporter._g3_wrap_issue(self, issue, tool, filename)` runs in `run_parser` between parser-subprocess output and schema validation, injecting/validating the underscore fields. The merger framework gets per-field callbacks for the new fields. The engine grows a single-issue skip in `merge_duplicated_issues` so single-issue templates retain their original `_cmd`. Schema update enforces the new required fields. Round-trip parser cosmetically updated (no behavior change).

**Tech Stack:** Python 3, `unittest`, `jsonschema`, `hashlib`. No new dependencies.

**Repository conventions:**
- Git: the user runs ALL git writes (commit, add, push). Each task ends with a "files to stage" list — do NOT run `git add` or `git commit`.
- Tests: `unittest`-style. Run a single file: `python -m unittest tests.test_<name> -v`. Run all: `python -m unittest discover -v`.
- The spec for this work lives at [`docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md`](../specs/2026-06-03-g3-underscore-fields-design.md). Refer to it for any decision rationale not duplicated here.

**File map:**
- Modify: [`libmagenta/engine.py`](../../../libmagenta/engine.py) — add SHA-1 helper, constants, `_g3_wrap_issue` method, hook into `run_parser`, single-issue skip in `merge_duplicated_issues`.
- Modify: [`libmagenta/merger/__init__.py`](../../../libmagenta/merger/__init__.py) — initial `merged` dict additions, six new collect/cleanup callbacks.
- Modify: [`templates/main.schema.json`](../../../templates/main.schema.json) — add new properties and required fields.
- Modify: [`parsers/magenta/magenta.py`](../../../parsers/magenta/magenta.py) — cosmetic cleanup only.
- Create: `tests/test_g3_underscore_wrap.py` — unit tests for the wrap helper.
- Create: `tests/test_merger_underscore.py` — unit tests for the merger callbacks.
- Modify: [`tests/test_cli.py`](../../../tests/test_cli.py) — end-to-end smoke tests.

**Task order rationale:** Tasks 1–4 add the wrap helper and merger callbacks (with unit tests passing in isolation, no schema dependency yet). Task 5 hooks the wrap helper into `run_parser`. Task 6 adds the single-issue skip. Task 7 tightens the schema — this is the moment the new fields become *required*; tasks 1–6 must be complete before this or every existing test breaks. Task 8 cleans up the round-trip parser cosmetically. Task 9 adds end-to-end smoke tests verifying the full pipeline.

---

## Task 1: Engine — SHA-1 streaming helper

**Files:**
- Modify: `libmagenta/engine.py` (add a module-level helper near the top, after the existing imports)
- Test: `tests/test_g3_underscore_wrap.py` (new file)

- [ ] **Step 1: Create the failing test**

Create `tests/test_g3_underscore_wrap.py`:

```python
import hashlib
import os
import tempfile
import unittest

from libmagenta.engine import _sha1_file


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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m unittest tests.test_g3_underscore_wrap -v
```

Expected: `ImportError` for `_sha1_file` from `libmagenta.engine` (the helper doesn't exist yet).

- [ ] **Step 3: Implement the helper**

Open `libmagenta/engine.py`. Locate the top-of-file imports (the block starting with `import subprocess` around line 12). Add `import hashlib` if not already present. Then, immediately after the import block but before the first class definition, add:

```python
def _sha1_file(filename):
    """Compute the SHA-1 hex digest of a file by streaming it in 64 KiB chunks.

    Streamed rather than read-then-hash so large inputs (multi-MB XML/JSON
    scan outputs) don't get loaded into memory at once.
    """
    hasher = hashlib.sha1()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
```

- [ ] **Step 4: Run to confirm pass**

```bash
python -m unittest tests.test_g3_underscore_wrap -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Files to stage (user commits)**

```
libmagenta/engine.py
tests/test_g3_underscore_wrap.py
```

---

## Task 2: Engine — underscore vocabulary constants

**Files:**
- Modify: `libmagenta/engine.py` (add two module-level frozenset constants near `_sha1_file`)
- Test: `tests/test_g3_underscore_wrap.py` (extend with vocabulary assertions)

- [ ] **Step 1: Add the failing test**

Append to `tests/test_g3_underscore_wrap.py`:

```python
from libmagenta.engine import (
    KNOWN_IGNORED_UNDERSCORE_FIELDS,
    RECOGNIZED_UNDERSCORE_FIELDS,
)


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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m unittest tests.test_g3_underscore_wrap.TestUnderscoreVocabulary -v
```

Expected: `ImportError` for the two constants.

- [ ] **Step 3: Add the constants**

In `libmagenta/engine.py`, immediately above the `_sha1_file` helper, add:

```python
# G3-aligned underscore vocabulary. The wrap step accepts these on parser output
# and on round-trip ingestion; everything else starting with an underscore is
# either silently stripped (KNOWN_IGNORED) or warned-and-stripped (the catch-all).
# See docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md §2.2.
RECOGNIZED_UNDERSCORE_FIELDS = frozenset(
    {"_type", "_tool", "_fp", "_cmd", "_start", "_end"}
)
KNOWN_IGNORED_UNDERSCORE_FIELDS = frozenset({"_scanid", "_taskid", "_id"})
```

- [ ] **Step 4: Run to confirm pass**

```bash
python -m unittest tests.test_g3_underscore_wrap -v
```

Expected: 6 tests pass.

- [ ] **Step 5: Files to stage**

```
libmagenta/engine.py
tests/test_g3_underscore_wrap.py
```

---

## Task 3: Engine — `_g3_wrap_issue` helper

**Files:**
- Modify: `libmagenta/engine.py` (add method on `MagentaReporter` class)
- Test: `tests/test_g3_underscore_wrap.py` (add `TestG3WrapIssue` class)

- [ ] **Step 1: Add failing tests**

Append to `tests/test_g3_underscore_wrap.py`:

```python
import io
import sys
from contextlib import redirect_stderr
from libmagenta.engine import MagentaReporter


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
        self.path = _write_tmp(b"hello")  # sha1 = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
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
        issue = {"_type": "issue", "template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_type"], "issue")

    def test_rejects_wrong_type(self):
        issue = {"_type": "host", "template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        with self.assertRaises(ValueError):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)

    def test_rejects_wrong_tool(self):
        issue = {"_tool": "nmap", "template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        with self.assertRaises(ValueError):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)

    def test_fp_set_union_with_parser_supplied(self):
        issue = {"_fp": ["nmap 10.0.0.1"], "template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(sorted(issue["_fp"]), sorted([self.expected_fp, "nmap 10.0.0.1"]))

    def test_fp_set_union_with_duplicate_engine_fp(self):
        # Parser already supplied the engine-style fingerprint; should not duplicate.
        issue = {"_fp": [self.expected_fp], "template": "x", "tools": ["nmap"], "severity": "low", "affects": []}
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_fp"], [self.expected_fp])

    def test_strips_known_ignored_silently(self):
        issue = {
            "_scanid": "abc", "_taskid": "def", "_id": "ghi",
            "template": "x", "tools": ["nmap"], "severity": "low", "affects": [],
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
            "template": "x", "tools": ["nmap"], "severity": "low", "affects": [],
        }
        buf = io.StringIO()
        with redirect_stderr(buf):
            self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertNotIn("_foobar", issue)
        self.assertIn("_foobar", buf.getvalue())
        self.assertIn("nmap", buf.getvalue())

    def test_preserves_cmd_start_end(self):
        issue = {
            "_cmd": "nmap -A 10.0.0.1", "_start": 1700000000, "_end": 1700000060,
            "template": "x", "tools": ["nmap"], "severity": "low", "affects": [],
        }
        self.engine._g3_wrap_issue(issue, "nmap", self.path)
        self.assertEqual(issue["_cmd"], "nmap -A 10.0.0.1")
        self.assertEqual(issue["_start"], 1700000000)
        self.assertEqual(issue["_end"], 1700000060)
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m unittest tests.test_g3_underscore_wrap.TestG3WrapIssue -v
```

Expected: `AttributeError: 'MagentaReporter' object has no attribute '_g3_wrap_issue'` on every test.

- [ ] **Step 3: Implement `_g3_wrap_issue`**

Open `libmagenta/engine.py`. Locate the `validate_issue` method around line 537. Add the following method immediately before it (so they sit together as the "wrap then validate" pair):

```python
    def _g3_wrap_issue(self, issue, tool, filename):
        """Inject G3-aligned underscore fields onto a parser-emitted issue dict.

        Mutates `issue` in place:
        - Validates `_type == "issue"` and `_tool == "magenta"` if the parser
          supplied them (hard error otherwise).
        - Set-unions `_fp` with the engine-computed fingerprint of `filename`.
        - Silently strips KNOWN_IGNORED_UNDERSCORE_FIELDS.
        - Warns once on stderr and strips any other unrecognized underscore field.
        - Injects the `_type` and `_tool` constants.

        `tool` and `filename` are used only for diagnostic messages and the
        fingerprint computation.

        See docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md §4.
        """
        # 1-2. Hard-validate the constants if the parser supplied them.
        if "_type" in issue and issue["_type"] != "issue":
            raise ValueError(
                "Parser '%s' emitted _type=%r; only 'issue' is supported "
                "(asset types are deferred)." % (tool, issue["_type"])
            )
        if "_tool" in issue and issue["_tool"] != "magenta":
            raise ValueError(
                "Parser '%s' emitted _tool=%r; must be 'magenta' "
                "(the producing g3 plugin, not the detecting security tool). "
                "Put the security tool name in tools[] instead."
                % (tool, issue["_tool"])
            )

        # 3. Compute the engine fingerprint.
        engine_fp = "magenta " + _sha1_file(filename)

        # 4. Set-union _fp.
        existing_fp = issue.get("_fp", [])
        issue["_fp"] = sorted(set(existing_fp) | {engine_fp})

        # 5-6. Strip known-ignored silently; warn-and-strip unknowns.
        for key in list(issue.keys()):
            if not key.startswith("_"):
                continue
            if key in RECOGNIZED_UNDERSCORE_FIELDS:
                continue
            if key in KNOWN_IGNORED_UNDERSCORE_FIELDS:
                del issue[key]
                continue
            sys.stderr.write(
                "note: stripped unknown underscore field '%s' from %s/%s\n"
                % (key, tool, filename)
            )
            del issue[key]

        # 7. Inject the constants (idempotent).
        issue["_type"] = "issue"
        issue["_tool"] = "magenta"
```

- [ ] **Step 4: Run to confirm pass**

```bash
python -m unittest tests.test_g3_underscore_wrap -v
```

Expected: all tests in the file pass (3 from Task 1 + 3 from Task 2 + 9 from Task 3 = 15 tests).

- [ ] **Step 5: Files to stage**

```
libmagenta/engine.py
tests/test_g3_underscore_wrap.py
```

---

## Task 4: Merger framework — initial dict + callbacks

**Files:**
- Modify: `libmagenta/merger/__init__.py` (extend initial dict, add six new callback methods)
- Test: `tests/test_merger_underscore.py` (new file)

- [ ] **Step 1: Create the failing test file**

Create `tests/test_merger_underscore.py`:

```python
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m unittest tests.test_merger_underscore -v
```

Expected: failures on every test. The default cleanup `sorted(set(...))` will crash on the string `_type`/`_tool` values (`set("issue")` is `{'i','s','u','e'}`), or the test assertions will mismatch.

- [ ] **Step 3: Update `libmagenta/merger/__init__.py`**

Open the file. At [line 56-63](../../../libmagenta/merger/__init__.py#L56), the initial `merged` dict is:

```python
merged = {
    "template": self.template_name,
    "tools": [],
    "severity": "none",
    "affects": [],
    "taxonomy": [],
    "references": [],
}
```

Replace with:

```python
merged = {
    "_type": "issue",
    "_tool": "magenta",
    "_fp": [],
    "_cmd": None,
    "_start": None,
    "_end": None,
    "template": self.template_name,
    "tools": [],
    "severity": "none",
    "affects": [],
    "taxonomy": [],
    "references": [],
}
```

Then, in the same file, locate the existing built-in property callbacks (around [line 136 onwards](../../../libmagenta/merger/__init__.py#L136), the `do_template_init` and following methods). Add the following six pairs at the end of that block (before the closing of the `Merger` class):

```python
    # G3-aligned underscore field callbacks.
    # See docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md §5.

    def do__type_collect(self, merged, issue):
        return "issue"

    def do__type_cleanup(self, value):
        return "issue"

    def do__tool_collect(self, merged, issue):
        return "magenta"

    def do__tool_cleanup(self, value):
        return "magenta"

    # _cmd: matches g3's per-plugin merger pattern (plugins/recon/nmap/g3m.py:79-82).
    # Always synthesize "magenta merge" on merge; never attempt to preserve or
    # reconcile input _cmd values. (Single-issue templates skip the merger
    # entirely via MagentaReporter.merge_duplicated_issues, preserving their original _cmd.)
    def do__cmd_collect(self, merged, issue):
        return "magenta merge"

    def do__cmd_cleanup(self, value):
        return value

    # _start: earliest seen. The `is None` check handles the case where the
    # framework's default initialization gave us [] (an empty list) — min([], int)
    # would raise TypeError. Initializing merged["_start"] to None in run() and
    # checking `is None` here avoids that.
    def do__start_collect(self, merged, issue):
        return issue if merged is None else min(merged, issue)

    def do__start_cleanup(self, value):
        return value

    # _end: latest seen.
    def do__end_collect(self, merged, issue):
        return issue if merged is None else max(merged, issue)

    def do__end_cleanup(self, value):
        return value
```

- [ ] **Step 4: Run to confirm pass**

```bash
python -m unittest tests.test_merger_underscore -v
```

Expected: 6 tests pass.

Also re-run the wrap tests and confirm nothing regressed:

```bash
python -m unittest tests.test_g3_underscore_wrap -v
```

Expected: 15 tests still pass.

- [ ] **Step 5: Files to stage**

```
libmagenta/merger/__init__.py
tests/test_merger_underscore.py
```

---

## Task 5: Engine — hook the wrap step into `run_parser`

**Files:**
- Modify: `libmagenta/engine.py` (`run_parser` method)

This task has no new unit tests of its own — it's a one-line wiring change verified by the existing tests (which still pass), the existing parser pipeline behavior, and the end-to-end smoke tests added in Task 9.

- [ ] **Step 1: Modify `run_parser`**

In `libmagenta/engine.py`, locate `run_parser` at [line 999](../../../libmagenta/engine.py#L999). The current body after `issues = json.loads(p.stdout)` is:

```python
        issues = json.loads(p.stdout)
        validated = []
        for issue in issues:
            try:
                self.validate_issue(issue)
            except Exception:
                sys.stderr.write(
                    "Warning, discarded malformed issue object from '%s' parser when processing file '%s':\n"
                    % (tool, filename)
                )
                traceback.print_exc()
                sys.stderr.write("\n")
                continue
            validated.append(issue)
        return validated
```

Change it to:

```python
        issues = json.loads(p.stdout)
        validated = []
        for issue in issues:
            try:
                self._g3_wrap_issue(issue, tool, filename)
                self.validate_issue(issue)
            except Exception:
                sys.stderr.write(
                    "Warning, discarded malformed issue object from '%s' parser when processing file '%s':\n"
                    % (tool, filename)
                )
                traceback.print_exc()
                sys.stderr.write("\n")
                continue
            validated.append(issue)
        return validated
```

The only change is the addition of the `self._g3_wrap_issue(issue, tool, filename)` line before `self.validate_issue(issue)`. The error-handling `try` block already wraps it, so any wrap-step `ValueError` (e.g., a parser emitted `_type:"host"`) lands in the same "discarded malformed issue" diagnostic path.

- [ ] **Step 2: Run existing tests to confirm no regression**

```bash
python -m unittest discover -v
```

Expected: existing tests still pass. (The schema doesn't yet require the new underscore fields, so issues that pass through `_g3_wrap_issue` and gain `_type`/`_tool`/`_fp` are valid both pre- and post-wrap.)

If `tmp/samples/` is present, `test_cli.py` will also run; otherwise it skips per its `unittest.skipUnless` decorators.

- [ ] **Step 3: Files to stage**

```
libmagenta/engine.py
```

---

## Task 6: Engine — single-issue skip in `merge_duplicated_issues`

**Files:**
- Modify: `libmagenta/engine.py` (`merge_duplicated_issues` method)
- Test: extend `tests/test_g3_underscore_wrap.py` with a new `TestSingleIssueSkip` class

- [ ] **Step 1: Add failing test**

Append to `tests/test_g3_underscore_wrap.py`:

```python
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m unittest tests.test_g3_underscore_wrap.TestSingleIssueSkip -v
```

Expected: AssertionError or an exception from `run_merger` trying to find the merger script for `cleartext_open_ports` — either way, the test fails because the skip isn't in place yet.

- [ ] **Step 3: Modify `merge_duplicated_issues`**

In `libmagenta/engine.py`, locate `merge_duplicated_issues` at [line 1071](../../../libmagenta/engine.py#L1071). Current body:

```python
    def merge_duplicated_issues(self, issues):
        templates = sorted(
            set(issue["template"] for issue in issues if issue["template"] != "manual")
        )
        merged = [
            self.run_merger(
                template, [issue for issue in issues if issue["template"] == template]
            )
            for template in templates
        ]
        merged.extend(issue for issue in issues if issue["template"] == "manual")
        return merged
```

Replace with:

```python
    def merge_duplicated_issues(self, issues):
        templates = sorted(
            set(issue["template"] for issue in issues if issue["template"] != "manual")
        )
        merged = []
        for template in templates:
            grouped = [issue for issue in issues if issue["template"] == template]
            if len(grouped) == 1:
                # Single-issue template: skip the merger so the original _cmd
                # (and any other parser-supplied scalar) is preserved rather
                # than being rewritten to "magenta merge". Matches g3's
                # "received a single issue to merge" warning posture.
                # See spec §5.5.
                merged.append(grouped[0])
            else:
                merged.append(self.run_merger(template, grouped))
        merged.extend(issue for issue in issues if issue["template"] == "manual")
        return merged
```

- [ ] **Step 4: Run to confirm pass**

```bash
python -m unittest tests.test_g3_underscore_wrap.TestSingleIssueSkip -v
```

Expected: 1 test passes.

Re-run all unit tests added so far:

```bash
python -m unittest tests.test_g3_underscore_wrap tests.test_merger_underscore -v
```

Expected: 22 tests pass (15 wrap + 6 merger + 1 skip).

- [ ] **Step 5: Files to stage**

```
libmagenta/engine.py
tests/test_g3_underscore_wrap.py
```

---

## Task 7: Schema — require the new underscore fields

**Files:**
- Modify: `templates/main.schema.json`

This task tightens validation. Tasks 1–6 must be complete before this task: once `_type`/`_tool`/`_fp` are required, any issue that didn't pass through the wrap step would fail validation. The wrap step is now wired in (Task 5), so this is safe.

- [ ] **Step 1: Update the schema**

Replace the entire contents of `templates/main.schema.json` with:

```json
{
    "$schema": "https://json-schema.org/draft/2019-09/schema",
    "type": "object",
    "properties": {
        "_type":    {"const": "issue"},
        "_tool":    {"const": "magenta"},
        "_fp":      {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "_cmd":     {"type": "string"},
        "_start":   {"type": "integer", "minimum": 0},
        "_end":     {"type": "integer", "minimum": 0},
        "template": {"type": "string"},
        "tools":    {"type": "array", "items": {"type": "string"}},
        "severity": {"enum": ["none", "low", "medium", "high", "critical"]},
        "affects":  {"type": "array", "items": {"type": "string"}},
        "taxonomy": {"type": "array", "items": {"type": "string", "minLength": 3, "pattern": "^[0-9A-Z][ :\\-0-9A-Z]+$"}},
        "references": {"type": "array", "items": {"type": "string", "pattern": "^https?://"}},
        "vulnid":   {"type": "string"}
    },
    "required": ["_type", "_tool", "_fp", "template", "tools", "severity", "affects"]
}
```

Key changes from the previous version:
- Added `_type` (const `"issue"`), `_tool` (const `"magenta"`), `_fp` (non-empty string array), `_cmd` (string), `_start` (integer ≥ 0), `_end` (integer ≥ 0).
- Added `_type`, `_tool`, `_fp` to `required`.
- All existing properties and the existing required set are preserved.

- [ ] **Step 2: Run all unit tests to confirm no regression**

```bash
python -m unittest discover -v
```

Expected: all tests still pass. The wrap step (Task 5) ensures every parser-emitted issue has the new required fields by the time it reaches `validate_issue`. The merger framework (Task 4) ensures merger output has them too.

Specifically: if `tmp/samples/` is present, `test_cli.py` runs Magenta end-to-end against real samples; that's the highest-confidence regression check at this point.

- [ ] **Step 3: Files to stage**

```
templates/main.schema.json
```

---

## Task 8: Round-trip parser — cosmetic cleanup

**Files:**
- Modify: `parsers/magenta/magenta.py`

This task makes no behavior change — it's a cosmetic readability improvement called out by the spec (§6) for completeness. The round-trip parser already does the right thing for underscore fields (it preserves them all by default; the engine wrap step handles them on re-ingestion).

- [ ] **Step 1: Modify `parsers/magenta/magenta.py`**

Replace the entire contents of `parsers/magenta/magenta.py` with:

```python
#!/usr/bin/python3

import json
import sys


def main():
    results = json.load(sys.stdin)["issues"]
    for issue in results:
        # vulnid is post-merge UI metadata; re-derived after the next merge pass.
        issue.pop("vulnid", None)
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
```

The only change is replacing the `try/except KeyError` block with `issue.pop("vulnid", None)` and adding a one-line comment explaining why `vulnid` is dropped.

- [ ] **Step 2: Run all tests to confirm no regression**

```bash
python -m unittest discover -v
```

Expected: all tests still pass.

- [ ] **Step 3: Files to stage**

```
parsers/magenta/magenta.py
```

---

## Task 9: End-to-end smoke tests

**Files:**
- Modify: `tests/test_cli.py`

Add three end-to-end assertions on top of the existing CLI tests. These run only when `tmp/samples/` is present, per the existing test file's `unittest.skipUnless` guard.

- [ ] **Step 1: Inspect the existing test file structure**

Read `tests/test_cli.py` to find the existing test class that runs Magenta against samples (likely a class that uses `subprocess.run(MAGENTA_PY, ...)` with a samples directory). The new tests will be added either as a new test class in the same file, or as new test methods on the existing class — whichever matches the file's prevailing style.

- [ ] **Step 2: Add the failing tests**

Append a new test class to `tests/test_cli.py`. Adjust the existing-style invocation pattern to match what the file already uses; the assertions are what matter:

```python
@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
class TestG3UnderscoreFieldsE2E(unittest.TestCase):
    """End-to-end verification that Magenta-emitted issues carry the
    G3-aligned underscore fields. See docs/superpowers/specs/2026-06-03-g3-underscore-fields-design.md."""

    def _run_magenta_emit_json(self, input_dir, out_json):
        """Invoke magenta to produce a JSON issues file. Match the existing
        test_cli.py invocation conventions — this stub shows the assertions;
        replace the subprocess call with whatever pattern the file already uses
        (e.g. via the `magenta` CLI's JSON output mode).
        """
        # Example pattern, adapt to the file's existing style:
        result = subprocess.run(
            [sys.executable, MAGENTA_PY, "report", "--input", input_dir,
             "--output", out_json, "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result

    def test_emitted_issues_have_underscore_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "out.json")
            self._run_magenta_emit_json(samples, out)
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
            self._run_magenta_emit_json(samples, out1)

            # Stage out1 as a magenta-named input for re-ingestion.
            second_input_dir = os.path.join(tmp, "round2")
            os.makedirs(second_input_dir)
            shutil.copy2(out1, os.path.join(second_input_dir, "magenta.json"))

            out2 = os.path.join(tmp, "second.json")
            self._run_magenta_emit_json(second_input_dir, out2)

            with open(out1) as f:
                first = json.load(f)
            with open(out2) as f:
                second = json.load(f)

            # Same number of issues, same templates.
            self.assertEqual(len(first["issues"]), len(second["issues"]))

            # For each second-pass issue, every fp from the first pass appears,
            # plus at least one new fp (the round-trip file's hash).
            # Match by (template, affects) which should be stable.
            def key(issue):
                return (issue["template"], tuple(sorted(issue.get("affects", []))))
            first_by_key = {key(i): i for i in first["issues"]}
            for issue in second["issues"]:
                k = key(issue)
                if k not in first_by_key:
                    continue  # merge boundaries may shift; skip non-matching
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

    def test_single_issue_template_preserves_cmd(self):
        """If a sample produces exactly one issue for some template, its _cmd
        (if any) must NOT be rewritten to 'magenta merge'. See spec §5.5."""
        with tempfile.TemporaryDirectory() as tmp:
            samples = _make_filtered_samples_dir(tmp)
            out = os.path.join(tmp, "out.json")
            self._run_magenta_emit_json(samples, out)
            with open(out) as f:
                report = json.load(f)

            # Group emitted issues by template.
            by_template = {}
            for issue in report["issues"]:
                by_template.setdefault(issue["template"], []).append(issue)

            # For any template that produced exactly one issue, assert _cmd
            # is NOT the synthetic label. (Currently no parser extracts _cmd,
            # so the field will be absent — which is the correct outcome too.
            # The negative assertion is what matters.)
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
                    issue.get("_cmd"), "magenta merge",
                    "single-issue template %s should not have synthetic merge "
                    "label as _cmd" % template,
                )
```

Note: the `_run_magenta_emit_json` stub above shows the assertion structure but the exact CLI flags depend on `magenta.py`'s actual interface. Read the existing `test_cli.py` patterns first and copy the invocation form they already use to produce JSON output. The point of the task is the *assertions*; the invocation should match conventions.

- [ ] **Step 3: Run to confirm failure (if any test was already passing)**

```bash
python -m unittest tests.test_cli.TestG3UnderscoreFieldsE2E -v
```

If `tmp/samples/` is absent, the tests skip — that's fine. If it's present, all three should pass after Tasks 1–8 are done. If any fails, that's a real regression in the implementation that needs investigation before moving on.

- [ ] **Step 4: Run the full suite**

```bash
python -m unittest discover -v
```

Expected: full suite passes (or skips as appropriate).

- [ ] **Step 5: Files to stage**

```
tests/test_cli.py
```

---

## Final verification

After all 9 tasks complete:

- [ ] **Run the full test suite once more**

```bash
python -m unittest discover -v
```

- [ ] **Spot-check the emitted JSON manually (if `tmp/samples/` is present)**

```bash
python magenta.py report --input tmp/samples --output /tmp/magenta-out.json --format json
python -c "import json; r = json.load(open('/tmp/magenta-out.json')); print(json.dumps(r['issues'][0], indent=2))"
```

Expected: the printed issue has `_type: "issue"`, `_tool: "magenta"`, and a non-empty `_fp` array whose first entry starts with `"magenta "`.

- [ ] **Tell the user the implementation is complete and list the modified/created files for review.**

Files touched in this change:

```
libmagenta/engine.py
libmagenta/merger/__init__.py
templates/main.schema.json
parsers/magenta/magenta.py
tests/test_g3_underscore_wrap.py     (new)
tests/test_merger_underscore.py       (new)
tests/test_cli.py
```
