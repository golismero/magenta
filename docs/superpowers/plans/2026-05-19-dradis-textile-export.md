# Dradis & Textile Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two new output formats to Magenta — `textile` (single .textile file via pandoc) and `dradis` (Dradis project ZIP package importable into Dradis CE).

**Architecture:** A thin format-agnostic pypandoc wrapper (`libmagenta/pandoc.py`) handles all Markdown→X conversions. Dradis-specific cleanup, mapping evaluation, XML building, and ZIP packaging live in `libmagenta/dradis.py`. User-overridable mapping config lives in `formats/dradis/mapping.json5`. The lua filter ships internally in `libmagenta/` (not user-overridable in v1, security rationale in the spec).

**Tech Stack:** Python 3, Click (CLI), Jinja2 (sandboxed environment for user expressions), pypandoc + system pandoc, stdlib `xml.etree.ElementTree`, stdlib `zipfile`, stdlib `unittest` (tests skip when pandoc unavailable).

**Reference spec:** `docs/superpowers/specs/2026-05-19-dradis-textile-export-design.md`. The spec is the source of truth for behavior — consult it if anything in this plan is unclear or contradictory.

**Tests live in:** `tests/test_pandoc.py`, `tests/test_dradis.py`, `tests/test_cli.py`. The project has no existing test suite, so we're establishing one. Use stdlib `unittest` (no extra deps).

**Convention reminders:**
- Magenta uses Click, not argparse.
- Magenta's CLI entry is `magenta.py`. The Python package is `libmagenta/`.
- `MAGENTA_HOME` env var (default: directory of `magenta.py`) is the root for resolving relative paths like `formats/dradis/`.
- The existing engine method `MagentaReporter.export_as_obsidian()` ([libmagenta/engine.py:1216](libmagenta/engine.py#L1216)) is the structural model for the new `export_as_dradis()` method.

**Git workflow note:** The user controls git operations themselves. After each task, **stop and tell the user the task is complete so they can commit**. Do not run `git add`, `git commit`, `git push`, or any other write-side git command.

---

## File Structure

**New files:**

| Path | Responsibility |
|---|---|
| `libmagenta/pandoc.py` | Thin pypandoc wrapper. One function: `convert_from_markdown()`. Format-agnostic. No cleanup. |
| `libmagenta/dradis.py` | Dradis-specific logic: textile cleanup, mapping loader, Jinja2 evaluator, XML builder, ZIP packager. |
| `libmagenta/table_linebreak_fix_gfm.lua` | Pandoc filter (copied from DradisMD). Internal asset, not user-overridable. |
| `formats/dradis/mapping.json5` | Shipped default mapping for the Dradis CE "welcome" template kit. User-overridable via `--dradis-templates DIR`. |
| `tests/__init__.py` | Empty (makes `tests/` a package). |
| `tests/test_pandoc.py` | Unit tests for `libmagenta/pandoc.py`. |
| `tests/test_dradis.py` | Unit + integration tests for `libmagenta/dradis.py`. |
| `tests/test_cli.py` | Tests for CLI format dispatch and autodetection. |

**Modified files:**

| Path | What changes |
|---|---|
| `libmagenta/engine.py` | Add `export_as_dradis(report, output_path, dradis_templates_dir)` method. |
| `magenta.py` | Add `textile` and `dradis` to `--format` choices, add `--dradis-templates` flag, update autodetection block. |
| `Dockerfile` | Add `pandoc` to the `apt-get install` line. |
| `CONTRIB.md` | Add attribution note for the lua filter (MIT-licensed, borrowed from DradisMD). |

**Already done by the user:** `requirements.txt` already contains `pypandoc` (line 9). No change needed.

---

## Task 1: Pandoc system dependency + thin wrapper module

**Files:**
- Modify: `Dockerfile:19-22` (add `pandoc` to the apt-get list)
- Create: `libmagenta/pandoc.py`
- Create: `tests/__init__.py`
- Create: `tests/test_pandoc.py`

### Step 1.1: Add pandoc to Dockerfile

- [ ] Open `Dockerfile`. The `apt-get install` line at line 20 currently is:

```dockerfile
    apt-get install -y --no-install-recommends fontconfig fonts-dejavu-core && \
```

Change it to:

```dockerfile
    apt-get install -y --no-install-recommends fontconfig fonts-dejavu-core pandoc && \
```

### Step 1.2: Create empty `tests/__init__.py`

- [ ] Create `tests/__init__.py` with no content. This makes `tests/` a Python package so the test files can be discovered by `python -m unittest discover`.

### Step 1.3: Write a failing test for `convert_from_markdown`

- [ ] Create `tests/test_pandoc.py`:

```python
import unittest

try:
    import pypandoc
    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False

from libmagenta.pandoc import convert_from_markdown


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed on this system")
class TestConvertFromMarkdown(unittest.TestCase):
    def test_basic_paragraph_to_textile(self):
        result = convert_from_markdown("Hello world.", "textile")
        self.assertIn("Hello world.", result)

    def test_gfm_table_to_textile_produces_nonempty_output(self):
        md = "| A | B |\n|---|---|\n| 1 | 2 |\n"
        result = convert_from_markdown(md, "textile")
        self.assertTrue(len(result) > 0)
        # Cell values should survive
        self.assertIn("1", result)
        self.assertIn("2", result)

    def test_code_fence_survives(self):
        md = "```\nprint('hi')\n```\n"
        result = convert_from_markdown(md, "textile")
        self.assertIn("print('hi')", result)

    def test_extra_args_passed_through(self):
        # --wrap=none is always-on in our wrapper; this just sanity-checks
        # that extra_args reach pandoc. We pass an empty list explicitly.
        result = convert_from_markdown("Hello.", "textile", extra_args=[])
        self.assertIn("Hello.", result)


class TestConvertFromMarkdownWithoutPandoc(unittest.TestCase):
    def test_missing_pandoc_raises_clear_error(self):
        # We can't easily simulate pandoc-missing without mocking, so this
        # test is illustrative — it asserts the function defines a helpful
        # error class/message. Skip if pandoc IS available (we can't test
        # the unhappy path then).
        if PANDOC_AVAILABLE:
            self.skipTest("pandoc is available; cannot test missing-pandoc path")
        with self.assertRaises(RuntimeError) as ctx:
            convert_from_markdown("hello", "textile")
        msg = str(ctx.exception).lower()
        self.assertIn("pandoc", msg)
```

### Step 1.4: Run the test to verify it fails

- [ ] Run: `python -m unittest tests.test_pandoc -v`
- Expected: `ImportError` or `ModuleNotFoundError` for `libmagenta.pandoc`.

### Step 1.5: Implement `libmagenta/pandoc.py`

- [ ] Create `libmagenta/pandoc.py`:

```python
"""Thin pypandoc wrapper used by every pandoc-backed output format.

Returns pandoc output untouched. No cleanup, no entity-unescaping, no escape
stripping. Format-specific post-processing is the caller's job (see
libmagenta/dradis.py for the Dradis-flavored cleanup).
"""

import pypandoc


_INSTALL_HINT = (
    "pandoc is required for this output format but was not found on PATH.\n"
    "  macOS:  brew install pandoc\n"
    "  Debian: apt install pandoc\n"
    "  Fallback (bundles a private pandoc binary): pip install pypandoc-binary"
)


def convert_from_markdown(md_text, output_format, extra_args=None):
    """Convert GFM Markdown to the given pandoc output format.

    No post-processing is applied. Callers that want format-specific cleanup
    (escape stripping, entity decoding, HTML-table rewriting, etc.) must do
    that themselves.
    """
    try:
        pypandoc.get_pandoc_version()
    except Exception as exc:
        raise RuntimeError(_INSTALL_HINT) from exc
    args = ["--wrap=preserve"]
    if extra_args:
        args.extend(extra_args)
    return pypandoc.convert_text(md_text, output_format, format="gfm", extra_args=args)
```

### Step 1.6: Run the test to verify it passes

- [ ] Run: `python -m unittest tests.test_pandoc -v`
- Expected: all `TestConvertFromMarkdown` tests PASS (if pandoc is installed). `TestConvertFromMarkdownWithoutPandoc.test_missing_pandoc_raises_clear_error` skips when pandoc is available.

### Step 1.7: Manual sanity check

- [ ] Run: `python -c "from libmagenta.pandoc import convert_from_markdown; print(convert_from_markdown('# Hello\n\nWorld.', 'textile'))"`
- Expected: prints valid Textile (something like `h1. Hello\n\nWorld.\n`).

### Step 1.8: Stop and notify the user

- [ ] Stop. Report to the user: "Task 1 complete (Dockerfile pandoc dep + libmagenta/pandoc.py + tests/test_pandoc.py + tests/__init__.py). Ready for you to commit."

---

## Task 2: Wire `textile` format into the CLI (smallest end-to-end vertical slice)

This task proves the pandoc pipeline end-to-end with no cleanup, before we start layering Dradis-specific behavior.

**Files:**
- Modify: `magenta.py:81-89` (format choices), `:113-170` (format dispatch)
- Create: `tests/test_cli.py`

### Step 2.1: Write a failing test

- [ ] Create `tests/test_cli.py`:

```python
import os
import subprocess
import tempfile
import unittest

try:
    import pypandoc
    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False


MAGENTA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAGENTA_PY = os.path.join(MAGENTA_ROOT, "magenta.py")
SAMPLES_DIR = os.path.join(MAGENTA_ROOT, "tmp", "samples")


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestTextileFormat(unittest.TestCase):
    def test_textile_extension_autodetects(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.textile")
            subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))
            with open(out, "r", encoding="utf-8") as fd:
                content = fd.read()
            self.assertGreater(len(content), 0)

    def test_textile_explicit_format_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.out")
            subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out,
                 "-f", "textile"],
                check=True,
                cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))
```

### Step 2.2: Run the test to verify it fails

- [ ] Run: `python -m unittest tests.test_cli -v`
- Expected: subprocess FAILS because `textile` is not a valid `--format` choice yet (Click rejects it). Click's exit code is 2.

### Step 2.3: Add `textile` to format choices

- [ ] In `magenta.py`, find the `@click.option("-f", "--format", ...)` decorator at lines 82-89. Change:

```python
@click.option(
    "-f",
    "--format",
    default="auto",
    type=click.Choice(
        choices=("auto", "markdown", "json", "obsidian"), case_sensitive=False
    ),
    help="Output file format. Defaults to 'auto'.",
)
```

to:

```python
@click.option(
    "-f",
    "--format",
    default="auto",
    type=click.Choice(
        choices=("auto", "markdown", "json", "obsidian", "textile"),
        case_sensitive=False,
    ),
    help="Output file format. Defaults to 'auto'.",
)
```

### Step 2.4: Add `.textile` autodetection

- [ ] In `magenta.py`, find the autodetect block at lines 122-135:

```python
    elif format == "auto":
        if output == "-":
            format = "markdown"
        else:
            ext = os.path.splitext(output)[1].lower()
            if not ext:
                format = "obsidian"
            elif ext in (".md", ".txt"):
                format = "markdown"
            elif ext in (".json", ".js"):
                format = "json"
            else:
                click.echo("error: cannot guess file format for extension: '%s'" % ext)
                return
```

Add a `.textile` branch:

```python
    elif format == "auto":
        if output == "-":
            format = "markdown"
        else:
            ext = os.path.splitext(output)[1].lower()
            if not ext:
                format = "obsidian"
            elif ext in (".md", ".txt"):
                format = "markdown"
            elif ext in (".json", ".js"):
                format = "json"
            elif ext == ".textile":
                format = "textile"
            else:
                click.echo("error: cannot guess file format for extension: '%s'" % ext)
                return
```

### Step 2.5: Wire `textile` dispatch

- [ ] In `magenta.py`, find the dispatch block at lines 157-170:

```python
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
            else:
                assert False
```

Add an `elif format == "textile":` branch and the import at the top of the file:

```python
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

The import is intentionally local (not at module top) so that users who don't use textile/dradis formats don't pay the pypandoc import cost on every CLI invocation.

### Step 2.6: Run the test to verify it passes

- [ ] Run: `python -m unittest tests.test_cli -v`
- Expected: both tests PASS. (They skip if `tmp/samples/` doesn't exist or pandoc isn't installed.)

### Step 2.7: Manual smoke

- [ ] If `tmp/samples/` exists, run:

```bash
python3 magenta.py report tmp/samples -o /tmp/smoke.textile -f textile
```

Verify `/tmp/smoke.textile` is a non-empty file with Textile content (no markdown syntax remaining).

### Step 2.8: Stop and notify the user

- [ ] Stop. Report: "Task 2 complete (textile format end-to-end). Ready for you to commit."

---

## Task 3: Copy the lua filter into `libmagenta/`

**Files:**
- Create: `libmagenta/table_linebreak_fix_gfm.lua` (copy from `tmp/DradisMD/dradismd/`)
- Modify: `CONTRIB.md` (add attribution)

### Step 3.1: Copy the lua filter

- [ ] Copy `tmp/DradisMD/dradismd/table_linebreak_fix_gfm.lua` to `libmagenta/table_linebreak_fix_gfm.lua` exactly as-is. Do not modify the content.

Verification:

```bash
diff tmp/DradisMD/dradismd/table_linebreak_fix_gfm.lua libmagenta/table_linebreak_fix_gfm.lua
```

Expected: no output (files are identical).

### Step 3.2: Add attribution to `CONTRIB.md`

- [ ] Open `CONTRIB.md`. If a "Third-party assets" or "Acknowledgements" section already exists, add an entry there. Otherwise, append this section at the end of the file:

```markdown
## Third-party assets

- `libmagenta/table_linebreak_fix_gfm.lua` — pandoc filter, MIT-licensed, borrowed from [DradisMD](https://github.com/GoSecure/dradis-md). Used internally by the `dradis` exporter to coerce multi-line GFM table cells into clean Textile tables.
```

### Step 3.3: Stop and notify the user

- [ ] Stop. Report: "Task 3 complete (lua filter + attribution). Ready for you to commit."

---

## Task 4: Dradis-flavored textile cleanup (`markdown_to_dradis_textile`)

This is the empirical task — the spec calls out that the exact escape-strip list needs to be determined by running real fixtures through pandoc, not by copying DradisMD's list verbatim. Write the fixtures first; iterate the strip set until they pass.

**Files:**
- Create: `libmagenta/dradis.py` (skeleton with this one function)
- Create: `tests/test_dradis.py`

### Step 4.1: Write failing tests with concrete fixtures

- [ ] Create `tests/test_dradis.py`:

```python
import os
import unittest

try:
    import pypandoc
    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False

from libmagenta.dradis import markdown_to_dradis_textile


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestMarkdownToDradisTextile(unittest.TestCase):
    def test_intraword_underscore_not_escaped(self):
        # pandoc tends to write "pay\_Q5qo" — we want clean "pay_Q5qo"
        md = "Transaction id `pay_Q5qoUpiHgdmOF` was processed.\n"
        result = markdown_to_dradis_textile(md)
        self.assertNotIn("\\_", result)

    def test_ampersand_not_html_encoded(self):
        # pandoc's textile writer emits &amp; — we want literal &
        md = "Use Foo & Bar together.\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("&", result)
        self.assertNotIn("&amp;", result)

    def test_less_than_not_html_encoded(self):
        md = "If x < 5 then halt.\n"
        result = markdown_to_dradis_textile(md)
        self.assertNotIn("&lt;", result)

    def test_asterisk_in_code_not_escaped(self):
        md = "Use the `*` wildcard.\n"
        result = markdown_to_dradis_textile(md)
        # Either the asterisk survives literally or pandoc preserves it
        # inside the textile code span — but it must not be backslash-escaped
        self.assertNotIn("\\*", result)

    def test_link_list_survives(self):
        md = "- https://example.com/foo\n- https://example.org/bar\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("example.com", result)
        self.assertIn("example.org", result)

    def test_code_fence_block_preserved(self):
        md = "```\nfoo bar\nbaz\n```\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("foo bar", result)
        self.assertIn("baz", result)

    def test_simple_gfm_table_becomes_textile_table(self):
        md = "| Col A | Col B |\n|-------|-------|\n| a1    | b1    |\n| a2    | b2    |\n"
        result = markdown_to_dradis_textile(md)
        # Textile tables use pipe delimiters too — just check we have cell values
        # and that pandoc did NOT fall back to <table> HTML
        self.assertIn("a1", result)
        self.assertIn("b2", result)
        self.assertNotIn("<table", result)

    def test_multiline_table_cell_uses_textile_linebreak(self):
        # When a GFM table cell contains a line break, pandoc falls back to
        # raw <table> HTML. Our cleanup should detect and re-convert these.
        md = (
            "| Field | Notes |\n"
            "|-------|-------|\n"
            "| A     | line 1<br>line 2 |\n"
        )
        result = markdown_to_dradis_textile(md)
        # The cleanup must have re-converted any HTML table back to textile
        self.assertNotIn("<table", result)
        self.assertNotIn("<br", result)
        self.assertIn("line 1", result)
        self.assertIn("line 2", result)

    def test_unsplit_double_backslash(self):
        # Pandoc may emit `\\` in some contexts — we want this collapsed to `\`
        md = "Path: `C:\\Users\\foo`\n"
        result = markdown_to_dradis_textile(md)
        # Either the backslashes are preserved literally inside code span,
        # or they're collapsed — but not doubled
        self.assertNotIn("\\\\\\\\", result)  # No quadrupled backslashes
```

The lua filter resolution is internal to `dradis.py`. Tests don't pass it explicitly.

### Step 4.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: `ModuleNotFoundError` because `libmagenta/dradis.py` doesn't exist yet.

### Step 4.3: Implement `libmagenta/dradis.py` (skeleton + the cleanup function)

- [ ] Create `libmagenta/dradis.py`:

```python
"""Dradis-specific output logic: textile cleanup, mapping evaluation,
XML repository builder, and ZIP packager.

The plain `textile` format does NOT use anything from this module — see
libmagenta/pandoc.py for that. Everything here is Dradis-flavored, including
the textile cleanup, which exists because Dradis renders raw HTML tables and
HTML-encoded entities less reliably than native Textile constructs.
"""

import html
import os
import re

from libmagenta.pandoc import convert_from_markdown


_HERE = os.path.dirname(os.path.abspath(__file__))
_LUA_FILTER = os.path.join(_HERE, "table_linebreak_fix_gfm.lua")


# Characters pandoc tends to escape but Dradis renders fine unescaped.
# This list is empirical — verify against the test fixtures and adjust.
# Order matters: process double-backslash before single-character escapes.
_BACKSLASH_ESCAPES_TO_STRIP = (
    ("\\\\", "\\"),
    ("\\_", "_"),
    ("\\*", "*"),
    ("\\[", "["),
    ("\\]", "]"),
    ("\\#", "#"),
    ("\\<", "<"),
    ("\\>", ">"),
    ("\\|", "|"),
    ("\\~", "~"),
    ("\\..", ".."),
)


_HTML_TABLE_PATTERN = re.compile(r"<table[\s\S]*?</table>", re.IGNORECASE)


def _re_convert_html_table(html_table):
    """Convert a raw HTML <table>...</table> block back into Textile.

    Two-step pass: HTML → GFM (using the lua filter to coerce multi-line
    cells into a single line via the {{linebreak}} placeholder) → Textile.
    """
    # HTML → GFM via the lua filter (so cell <br> becomes {{linebreak}})
    import pypandoc
    gfm = pypandoc.convert_text(
        html_table,
        "gfm",
        format="html",
        extra_args=["--lua-filter=" + _LUA_FILTER],
    )
    # {{linebreak}} → textile line break syntax (`\` then newline)
    gfm = gfm.replace("{{linebreak}}", "\\\n")
    # GFM → Textile (standard wrapper, no extra cleanup)
    return convert_from_markdown(gfm, "textile")


def markdown_to_dradis_textile(md_text):
    """Convert GFM Markdown to Dradis-flavored Textile.

    Calls pandoc once, then applies three cleanup passes:
      1. Re-convert any raw <table>...</table> HTML blocks back to Textile.
      2. html.unescape() to undo entity encoding (&amp; -> &, etc.).
      3. Strip backslash-escapes that Dradis renders better without.
    """
    text = convert_from_markdown(md_text, "textile")

    # Pass 1: HTML tables
    def _replace(match):
        return _re_convert_html_table(match.group(0))
    text = _HTML_TABLE_PATTERN.sub(_replace, text)

    # Pass 2: HTML entities
    text = html.unescape(text)

    # Pass 3: backslash escapes
    for old, new in _BACKSLASH_ESCAPES_TO_STRIP:
        text = text.replace(old, new)

    return text
```

### Step 4.4: Run the tests; iterate on the strip list

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: most tests pass. If any fail because of a specific escape that pandoc emits and we didn't strip, add it to `_BACKSLASH_ESCAPES_TO_STRIP` and re-run.
- If a test fails because pandoc emits a structure we didn't anticipate (e.g., HTML other than tables), STOP and consult the user — don't just delete the assertion. The CLAUDE.md says: "Never attempt to 'fix' a failing test or Ruff warning by deleting code or weakening assertions without asking first."

### Step 4.5: Stop and notify the user

- [ ] Stop. Report: "Task 4 complete (markdown_to_dradis_textile + 9 cleanup fixtures passing). Final escape strip list: [list the contents of `_BACKSLASH_ESCAPES_TO_STRIP`]. Ready for you to commit."

---

## Task 5: Ship the default `mapping.json5`

This is a pure data-file task with no tests of its own (the file's correctness is tested transitively in Tasks 6–8).

**Files:**
- Create: `formats/dradis/mapping.json5`

### Step 5.1: Create the directory and the file

- [ ] Create `formats/dradis/mapping.json5`:

```json5
// Default Dradis section mapping for Magenta.
//
// This file is consumed by the `dradis` output format. It controls:
//   * which #[Section]# markers appear in the <issue><text> CDATA, in what
//     order, and how each section's body is populated;
//   * the same for evidence files (when evidence_nodes: true);
//   * the JSON properties stored on the Dradis "Report content" node.
//
// The default targets the Dradis CE *welcome* template kit (the out-of-box
// default). To use this with the OWASP kit, MITRE kit, or a custom kit:
//   1. Copy this directory:    cp -r $MAGENTA_HOME/formats/dradis ~/my-templates
//   2. Edit ~/my-templates/mapping.json5 to match your kit's field set.
//   3. Pass it on the CLI:     magenta.py ... -f dradis --dradis-templates ~/my-templates
//
// The `value` of each entry is a Jinja2 expression evaluated against the
// per-issue context. After evaluation, the rendered Markdown body is converted
// to Dradis-flavored Textile via pandoc + libmagenta/dradis.py cleanup.
//
// LIQUID ESCAPE: Dradis itself uses Liquid for in-Dradis computed fields.
// If you want a Liquid expression to survive into the Dradis output (so
// Dradis evaluates it at display time, not Magenta at render time), wrap
// it in Jinja2's raw block:   {% raw %}{% assign x = ... %}{% endraw %}
{
  // true  → emit <evidence> elements under host nodes (one per [issue, host]
  //         pair). Standard Dradis CE workflow.
  // false → no Nodes/Evidences/ created. Use this if your issue.textile
  //         template carries Affects/Details fields inline.
  evidence_nodes: true,

  // Ordered list. Position controls #[Section]# order in the issue body.
  // Default fields target the Dradis CE welcome kit:
  //   Title, CVSSv4.BaseScore, CVSSv4.BaseVector, Type, Description,
  //   Solution, References
  issue_sections: [
    { name: "Title",             value: "{{ title }}" },
    { name: "CVSSv4.BaseScore",  value: "" },             // Magenta has no CVSS — fill in via Dradis
    { name: "CVSSv4.BaseVector", value: "" },             // ditto
    { name: "Type",              value: "" },             // Internal | External
    { name: "Description",       value: "{{ description }}" },
    { name: "Solution",          value: "{{ recommendations }}" },
    { name: "References",        value: "{% for url in references %}* {{ url }}\n{% endfor %}" },
  ],

  // Used only when evidence_nodes: true. One render per entry in
  // issue.affects (where `affected` = the host string for that evidence).
  // Default targets the welcome kit's Location+Output evidence template.
  evidence_sections: [
    { name: "Location", value: "{{ affected }}" },
    { name: "Output",   value: "{{ details }}" },
  ],

  // Dradis "Report content" node properties (type-id=4). Stored as a JSON
  // object in the node's <properties> CDATA. Evaluated against
  // metadata.project_info. Keys that evaluate to an empty string are omitted.
  project_properties: {
    "dradis.productname":          "{{ product_name }}",
    "dradis.businessunit":         "{{ client_name }}",
    "dradis.project_start_date":   "{{ start_date }}",
    "dradis.project_end_date":     "{{ end_date }}",
    "dradis.report_delivery_date": "{{ report_date }}",
    "dradis.type_of_engagement":   "{{ test_type }}",
  },
}
```

### Step 5.2: Verify the file parses as valid JSON5

- [ ] Run:

```bash
python3 -c "import json5; print(json5.load(open('formats/dradis/mapping.json5')))"
```

Expected: prints a Python dict containing `evidence_nodes`, `issue_sections`, `evidence_sections`, `project_properties`.

### Step 5.3: Stop and notify the user

- [ ] Stop. Report: "Task 5 complete (default mapping.json5). Ready for you to commit."

---

## Task 6: Mapping loader + Jinja2 expression evaluator

**Files:**
- Modify: `libmagenta/dradis.py` (add new functions)
- Modify: `tests/test_dradis.py` (add new test class)

### Step 6.1: Write failing tests

- [ ] Append to `tests/test_dradis.py`:

```python
import json5
import tempfile

from libmagenta.dradis import (
    load_mapping,
    render_section_body,
    InvalidMappingError,
)


class TestLoadMapping(unittest.TestCase):
    def test_loads_valid_mapping(self):
        mapping_text = """
{
  evidence_nodes: true,
  issue_sections: [{ name: "Title", value: "{{ title }}" }],
  evidence_sections: [{ name: "Location", value: "{{ affected }}" }],
  project_properties: { "k": "{{ x }}" },
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(mapping_text)
            path = fd.name
        try:
            m = load_mapping(path)
            self.assertEqual(m["evidence_nodes"], True)
            self.assertEqual(len(m["issue_sections"]), 1)
            self.assertEqual(m["issue_sections"][0]["name"], "Title")
        finally:
            os.unlink(path)

    def test_missing_required_key_raises(self):
        # Missing evidence_nodes
        bad = '{ issue_sections: [], evidence_sections: [], project_properties: {} }'
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(bad)
            path = fd.name
        try:
            with self.assertRaises(InvalidMappingError):
                load_mapping(path)
        finally:
            os.unlink(path)

    def test_wrong_type_for_issue_sections_raises(self):
        bad = """
{ evidence_nodes: true, issue_sections: {}, evidence_sections: [],
  project_properties: {} }
"""
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(bad)
            path = fd.name
        try:
            with self.assertRaises(InvalidMappingError):
                load_mapping(path)
        finally:
            os.unlink(path)


class TestRenderSectionBody(unittest.TestCase):
    def test_simple_variable_substitution(self):
        result = render_section_body("{{ title }}", {"title": "SQL Injection"})
        self.assertEqual(result, "SQL Injection")

    def test_literal_string_passes_through(self):
        result = render_section_body("Internal | External", {})
        self.assertEqual(result, "Internal | External")

    def test_loop_over_list(self):
        ctx = {"references": ["https://a", "https://b"]}
        expr = "{% for url in references %}* {{ url }}\n{% endfor %}"
        result = render_section_body(expr, ctx)
        self.assertIn("* https://a", result)
        self.assertIn("* https://b", result)

    def test_missing_variable_yields_empty_string(self):
        # Jinja2 default behavior: undefined → empty when used in expression.
        # Our wrapper uses StrictUndefined? Let's pick lenient (empty) so a
        # missing field in one issue doesn't break the whole report.
        result = render_section_body("{{ missing }}", {})
        self.assertEqual(result, "")

    def test_jinja_raw_passes_through_unevaluated(self):
        # Liquid escape: {% raw %}...{% endraw %} should preserve content
        # verbatim so it survives into the Dradis output.
        expr = "{% raw %}{% assign x = 1 %}{% endraw %}"
        result = render_section_body(expr, {})
        self.assertIn("{% assign x = 1 %}", result)
```

### Step 6.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: `ImportError: cannot import name 'load_mapping'` etc.

### Step 6.3: Implement the mapping loader and renderer

- [ ] Append to `libmagenta/dradis.py`:

```python
import json5
import jinja2


class InvalidMappingError(Exception):
    """Raised when the mapping.json5 file is malformed or missing required keys."""


_REQUIRED_KEYS = ("evidence_nodes", "issue_sections", "evidence_sections", "project_properties")


def load_mapping(path):
    """Load and validate a dradis mapping.json5 file.

    Raises InvalidMappingError if required keys are missing or have wrong types.
    Returns the parsed dict.
    """
    try:
        with open(path, "r", encoding="utf-8") as fd:
            mapping = json5.load(fd, allow_duplicate_keys=False)
    except FileNotFoundError:
        raise InvalidMappingError("mapping file not found: %s" % path)
    except Exception as exc:
        raise InvalidMappingError("could not parse %s: %s" % (path, exc))

    for key in _REQUIRED_KEYS:
        if key not in mapping:
            raise InvalidMappingError("missing required key '%s' in %s" % (key, path))

    if not isinstance(mapping["evidence_nodes"], bool):
        raise InvalidMappingError("'evidence_nodes' must be a boolean")
    if not isinstance(mapping["issue_sections"], list):
        raise InvalidMappingError("'issue_sections' must be a list")
    if not isinstance(mapping["evidence_sections"], list):
        raise InvalidMappingError("'evidence_sections' must be a list")
    if not isinstance(mapping["project_properties"], dict):
        raise InvalidMappingError("'project_properties' must be an object")
    for i, entry in enumerate(mapping["issue_sections"]):
        if not (isinstance(entry, dict) and "name" in entry and "value" in entry):
            raise InvalidMappingError(
                "issue_sections[%d] must be an object with 'name' and 'value' keys" % i
            )
    for i, entry in enumerate(mapping["evidence_sections"]):
        if not (isinstance(entry, dict) and "name" in entry and "value" in entry):
            raise InvalidMappingError(
                "evidence_sections[%d] must be an object with 'name' and 'value' keys" % i
            )
    return mapping


# Sandboxed Jinja2 environment for user-supplied expressions. SandboxedEnvironment
# blocks attribute access to underscored names and disallows calling unsafe
# methods, which mitigates "I downloaded someone else's mapping.json5 and now
# it's running shutil.rmtree" scenarios.
_JINJA_ENV = jinja2.sandbox.SandboxedEnvironment(
    autoescape=False,
    undefined=jinja2.Undefined,  # Missing vars render as empty, not an error
    keep_trailing_newline=True,
)


def render_section_body(expression, context):
    """Render a single Jinja2 expression from the mapping against a context dict.

    Returns the rendered string. Missing context variables render as empty
    strings rather than raising (so one malformed issue doesn't kill the run).
    """
    try:
        tpl = _JINJA_ENV.from_string(expression)
        return tpl.render(**context)
    except jinja2.TemplateSyntaxError as exc:
        raise InvalidMappingError(
            "syntax error in mapping expression %r: %s" % (expression, exc)
        )
```

### Step 6.4: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: all `TestLoadMapping` and `TestRenderSectionBody` tests PASS. (Earlier `TestMarkdownToDradisTextile` tests still pass.)

### Step 6.5: Stop and notify the user

- [ ] Stop. Report: "Task 6 complete (mapping loader + Jinja2 renderer). Ready for you to commit."

---

## Task 7: XML builder — Part 1: Report content node + Targets/host nodes

We're going to grow `build_repository_xml()` over Tasks 7–10. Start with the skeleton that emits a minimal valid `<dradis-template version="4">` containing only the Report content node and Targets node tree.

**Files:**
- Modify: `libmagenta/dradis.py`
- Modify: `tests/test_dradis.py`

### Step 7.1: Write failing tests

- [ ] Append to `tests/test_dradis.py`:

```python
import json
from xml.etree import ElementTree as ET

from libmagenta.dradis import build_repository_xml


def _minimal_mapping():
    """Bare mapping for XML structure tests — section bodies don't matter here."""
    return {
        "evidence_nodes": True,
        "issue_sections": [{"name": "Title", "value": "{{ title }}"}],
        "evidence_sections": [{"name": "Location", "value": "{{ affected }}"}],
        "project_properties": {
            "dradis.productname": "{{ product_name }}",
            "dradis.businessunit": "{{ client_name }}",
        },
    }


def _minimal_report(issues=None):
    """Bare report dict for XML structure tests."""
    return {
        "metadata": {
            "project_info": {
                "product_name": "VoiceTools",
                "client_name": "Acme",
                "start_date": "2026-05-11",
                "end_date": "2026-05-15",
                "report_date": "2026-05-20",
                "test_type": "MPT",
                "report_team": "Magenta",
                "report_author": "tester@example.com",
            },
        },
        "issues": issues or [],
        "sections": {"issues": {}},
    }


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlSkeleton(unittest.TestCase):
    def test_root_element_is_dradis_template_v4(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        self.assertEqual(root.tag, "dradis-template")
        self.assertEqual(root.attrib.get("version"), "4")

    def test_report_content_node_present_with_properties(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        report_content = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Report content":
                report_content = node
                break
        self.assertIsNotNone(report_content, "Report content node missing")
        self.assertEqual(report_content.findtext("type-id"), "4")
        props_text = report_content.findtext("properties")
        self.assertIsNotNone(props_text)
        props = json.loads(props_text)
        self.assertEqual(props["dradis.productname"], "VoiceTools")
        self.assertEqual(props["dradis.businessunit"], "Acme")

    def test_empty_property_value_is_omitted(self):
        # If project_info lacks `client_name`, the dradis.businessunit key
        # should not appear in the JSON (not even with an empty string).
        report = _minimal_report()
        del report["metadata"]["project_info"]["client_name"]
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Report content":
                props = json.loads(node.findtext("properties"))
                self.assertNotIn("dradis.businessunit", props)
                return
        self.fail("Report content node missing")

    def test_targets_node_with_per_host_children(self):
        report = _minimal_report(issues=[
            {"title": "X", "affects": ["host-a", "host-b"], "details": "",
             "description": "", "recommendations": "", "severity": "low",
             "taxonomy": [], "references": [], "tools": [], "vulnid": "1.1"},
            {"title": "Y", "affects": ["host-b", "host-c"], "details": "",
             "description": "", "recommendations": "", "severity": "low",
             "taxonomy": [], "references": [], "tools": [], "vulnid": "1.2"},
        ])
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)

        targets = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Targets":
                targets = node
                break
        self.assertIsNotNone(targets, "Targets node missing")
        targets_id = targets.findtext("id")

        # Find child nodes whose parent-id == targets_id
        children = [
            n for n in root.findall(".//nodes/node")
            if n.findtext("parent-id") == targets_id
        ]
        labels = sorted(n.findtext("label") for n in children)
        self.assertEqual(labels, ["host-a", "host-b", "host-c"])

    def test_empty_top_level_elements(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        self.assertIsNotNone(root.find("tags"))
        self.assertIsNotNone(root.find("methodologies"))
        self.assertIsNotNone(root.find("categories"))

    def test_archive_ids_are_unique(self):
        report = _minimal_report(issues=[
            {"title": "X", "affects": ["a"], "details": "", "description": "",
             "recommendations": "", "severity": "low", "taxonomy": [],
             "references": [], "tools": [], "vulnid": "1.1"},
        ])
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)
        all_ids = [el.text for el in root.iter("id")]
        self.assertEqual(len(all_ids), len(set(all_ids)),
                         "Duplicate <id> values in archive: %r" % all_ids)
```

### Step 7.2: Run the tests; verify they fail

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: `ImportError: cannot import name 'build_repository_xml'`.

### Step 7.3: Implement the XML builder skeleton

- [ ] Add the new imports to the top of `libmagenta/dradis.py` (keep them with the existing imports near the top of the file):

```python
import json
from xml.etree import ElementTree as ET
```

- [ ] Append the rest to the bottom of `libmagenta/dradis.py`:

```python
class _IdAllocator:
    """Assigns sequential archive-local IDs starting at 1.

    Archive IDs only need to be unique within the zip — Dradis maps them
    to fresh DB IDs on import via lookup_table.
    """
    def __init__(self):
        self._next = 1

    def next(self):
        nid = self._next
        self._next += 1
        return nid


def _set_cdata(element, text):
    """ElementTree has no CDATA support out of the box. We use a sentinel
    placeholder + post-process the serialized XML in build_repository_xml.
    Each `text` payload is wrapped here; the post-processor substitutes
    the actual CDATA syntax."""
    # Insert a unique marker pair that the post-processor will find and
    # rewrite into <![CDATA[ ... ]]>. We use control characters that won't
    # legitimately appear in textile / JSON content.
    element.text = "\x01CDATA_OPEN\x01" + text + "\x01CDATA_CLOSE\x01"


def _cdata_post_process(xml_str):
    return (
        xml_str.replace("\x01CDATA_OPEN\x01", "<![CDATA[")
               .replace("\x01CDATA_CLOSE\x01", "]]>")
    )


def _make_node(parent_el, ids, label, type_id, parent_id=None, properties=None):
    """Emit a <node> with the standard set of children Dradis expects."""
    node = ET.SubElement(parent_el, "node")
    ET.SubElement(node, "id").text = str(ids.next())
    ET.SubElement(node, "label").text = label
    pid = ET.SubElement(node, "parent-id")
    if parent_id is not None:
        pid.text = str(parent_id)
    ET.SubElement(node, "position").text = "0"
    props_el = ET.SubElement(node, "properties")
    _set_cdata(props_el, properties if properties is not None else "{\n}")
    ET.SubElement(node, "type-id").text = str(type_id)
    ET.SubElement(node, "notes")
    ET.SubElement(node, "evidence")
    ET.SubElement(node, "activities")
    return node


def _build_project_properties_json(mapping, project_info):
    """Evaluate each project_properties expression and return a JSON string.

    Keys that evaluate to an empty string are omitted entirely (not emitted
    as empty-string values).
    """
    out = {}
    for key, expr in mapping["project_properties"].items():
        value = render_section_body(expr, project_info or {}).strip()
        if value:
            out[key] = value
    # Mimic the format we observed in tmp/dradis-export/dradis-repository.xml:
    # multi-line indented JSON inside the CDATA.
    return "{\n" + ",\n".join('  "%s": %s' % (k, json.dumps(v)) for k, v in out.items()) + "\n}"


def _unique_hosts(issues):
    seen = set()
    out = []
    for issue in issues:
        for host in issue.get("affects", []):
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out


def build_repository_xml(report, mapping):
    """Build the dradis-repository.xml string for a Magenta report.

    Returns a CDATA-correct UTF-8 string ready to write into the zip archive.
    The output is NOT pretty-printed; Dradis doesn't care.
    """
    ids = _IdAllocator()
    root = ET.Element("dradis-template", attrib={"version": "4"})
    nodes_el = ET.SubElement(root, "nodes")

    # 1. "Report content" node (type-id=4)
    props_json = _build_project_properties_json(
        mapping, report["metadata"].get("project_info", {})
    )
    _make_node(nodes_el, ids, "Report content", type_id=4, properties=props_json)

    # 2. "Targets" node and one child per unique affected host
    targets_node = _make_node(nodes_el, ids, "Targets", type_id=0)
    targets_id = targets_node.findtext("id")
    for host in _unique_hosts(report["issues"]):
        _make_node(nodes_el, ids, host, type_id=0, parent_id=int(targets_id))

    # Empty top-level elements Dradis expects
    ET.SubElement(root, "issues")  # Issues added in Task 8
    ET.SubElement(root, "tags")
    ET.SubElement(root, "methodologies")
    ET.SubElement(root, "categories")

    raw = ET.tostring(root, encoding="utf-8").decode("utf-8")
    return '<?xml version="1.0" encoding="UTF-8"?>' + _cdata_post_process(raw)


```

### Step 7.4: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: all `TestBuildRepositoryXmlSkeleton` tests PASS. Previous tests continue to pass.

### Step 7.5: Stop and notify the user

- [ ] Stop. Report: "Task 7 complete (XML skeleton: Report content + Targets/host nodes + empty top-level elements). Ready for you to commit."

---

## Task 8: XML builder — Part 2: Issues with `#[Section]#` bodies

**Files:**
- Modify: `libmagenta/dradis.py` (extend `build_repository_xml`)
- Modify: `tests/test_dradis.py`

### Step 8.1: Write failing tests

- [ ] Append to `tests/test_dradis.py`:

```python
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlIssues(unittest.TestCase):
    def _report_with_one_issue(self):
        return {
            "metadata": {"project_info": {}},
            "issues": [{
                "title": "SQL Injection",
                "description": "The login form is vulnerable.",
                "recommendations": "Use parameterized queries.",
                "details": "The `username` parameter accepts SQL.",
                "severity": "high",
                "affects": ["api.example.com"],
                "taxonomy": [],
                "references": ["https://owasp.org/sqli"],
                "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

    def test_one_issue_emitted(self):
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        root = ET.fromstring(xml_str)
        issues = root.findall("issues/issue")
        self.assertEqual(len(issues), 1)

    def test_issue_text_has_section_markers_in_order(self):
        mapping = {
            "evidence_nodes": False,
            "issue_sections": [
                {"name": "Title", "value": "{{ title }}"},
                {"name": "Description", "value": "{{ description }}"},
                {"name": "Solution", "value": "{{ recommendations }}"},
            ],
            "evidence_sections": [],
            "project_properties": {},
        }
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        root = ET.fromstring(xml_str)
        text = root.findtext("issues/issue/text")
        self.assertIsNotNone(text)
        # Markers must appear in the configured order
        title_idx = text.index("#[Title]#")
        desc_idx = text.index("#[Description]#")
        sol_idx = text.index("#[Solution]#")
        self.assertLess(title_idx, desc_idx)
        self.assertLess(desc_idx, sol_idx)
        # Bodies are populated
        self.assertIn("SQL Injection", text)
        self.assertIn("login form is vulnerable", text)
        self.assertIn("parameterized queries", text)

    def test_issue_has_required_fields(self):
        mapping = _minimal_mapping()
        report = self._report_with_one_issue()
        report["metadata"]["project_info"]["report_author"] = "alice@x.com"
        xml_str = build_repository_xml(report, mapping)
        root = ET.fromstring(xml_str)
        issue = root.find("issues/issue")
        self.assertEqual(issue.findtext("state"), "published")
        self.assertEqual(issue.findtext("author"), "alice@x.com")
        self.assertIsNotNone(issue.findtext("id"))

    def test_issue_author_falls_back_to_magenta(self):
        mapping = _minimal_mapping()
        report = self._report_with_one_issue()
        report["metadata"]["project_info"] = {}  # No report_author
        xml_str = build_repository_xml(report, mapping)
        root = ET.fromstring(xml_str)
        self.assertEqual(root.findtext("issues/issue/author"), "magenta")

    def test_empty_section_value_keeps_marker(self):
        # When a section's Jinja expression evaluates to empty (e.g. an issue
        # has no taxonomy and the value is a for-loop), the #[Section]#
        # marker is still emitted (matches the standard Dradis convention).
        mapping = {
            "evidence_nodes": False,
            "issue_sections": [
                {"name": "Title", "value": "{{ title }}"},
                {"name": "CVSSv4.BaseScore", "value": ""},
            ],
            "evidence_sections": [],
            "project_properties": {},
        }
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        text = ET.fromstring(xml_str).findtext("issues/issue/text")
        self.assertIn("#[CVSSv4.BaseScore]#", text)
```

### Step 8.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_dradis.TestBuildRepositoryXmlIssues -v`
- Expected: tests fail because `<issues>` is empty (Task 7 left it as a placeholder).

### Step 8.3: Extend `build_repository_xml`

- [ ] In `libmagenta/dradis.py`, find the line `ET.SubElement(root, "issues")  # Issues added in Task 8` and replace it with this implementation:

```python
    issues_el = ET.SubElement(root, "issues")
    project_info = report["metadata"].get("project_info", {})
    fallback_author = project_info.get("report_author") or "magenta"
    for issue_data in report["issues"]:
        _build_issue_element(issues_el, ids, issue_data, mapping, fallback_author)
```

Then add the helper functions to the same module (before `build_repository_xml`):

```python
def _render_issue_text(issue_data, mapping):
    """Build the #[Section]#-marker textile body for one issue.

    Each issue_sections entry is evaluated as a Jinja2 expression against the
    per-issue context, then Markdown→Textile-converted with Dradis cleanup.
    Sections that evaluate to empty still emit their marker (no body).
    """
    parts = []
    for entry in mapping["issue_sections"]:
        name = entry["name"]
        expr = entry["value"]
        body_md = render_section_body(expr, issue_data)
        if body_md.strip():
            body_textile = markdown_to_dradis_textile(body_md).strip()
            parts.append("#[%s]#\n%s\n" % (name, body_textile))
        else:
            parts.append("#[%s]#\n" % name)
    return "\n".join(parts)


def _build_issue_element(parent_el, ids, issue_data, mapping, fallback_author):
    issue_el = ET.SubElement(parent_el, "issue")
    ET.SubElement(issue_el, "id").text = str(ids.next())
    ET.SubElement(issue_el, "author").text = fallback_author
    ET.SubElement(issue_el, "state").text = "published"
    text_el = ET.SubElement(issue_el, "text")
    _set_cdata(text_el, _render_issue_text(issue_data, mapping))
    return issue_el
```

### Step 8.4: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: all `TestBuildRepositoryXmlIssues` tests PASS plus all previous tests still PASS.

### Step 8.5: Stop and notify the user

- [ ] Stop. Report: "Task 8 complete (issues with #[Section]# bodies). Ready for you to commit."

---

## Task 9: XML builder — Part 3: Evidence nodes (when `evidence_nodes: true`)

**Caveat — verify before relying on this in production:** The exact XML schema that dradis-projects 5.0's v4 importer expects *inside* `<evidence>` elements (specifically how an evidence cross-references its parent issue) was not fully confirmed from the importer code. The spec sample (`tmp/dradis-export/`) had empty `<evidence></evidence>` everywhere because the user's company doesn't use them. **Before declaring this task done, either**: (a) read `tmp/dradis-projects/lib/dradis/plugins/projects/upload/v4/template.rb` (and `category_spec.rb`/`evidence_spec.rb` if present) to confirm the expected `<evidence>` payload structure, OR (b) verify by uploading a generated `.zip` (with `evidence_nodes: true`) to a live Dradis CE instance and confirming the evidence appears linked to the right issue. If the cross-reference is wrong, fix the `<issue>` sub-element shape in `_build_evidence_element` and re-test.

**Files:**
- Modify: `libmagenta/dradis.py`
- Modify: `tests/test_dradis.py`

### Step 9.1: Write failing tests

- [ ] Append to `tests/test_dradis.py`:

```python
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlEvidence(unittest.TestCase):
    def _two_host_report(self):
        return {
            "metadata": {"project_info": {}},
            "issues": [{
                "title": "Open Port",
                "description": "Port is open.",
                "recommendations": "Close it.",
                "details": "Detected on port 22 via nmap.",
                "severity": "low",
                "affects": ["host-a", "host-b"],
                "taxonomy": [], "references": [], "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

    def test_evidence_nodes_true_emits_evidence_under_host(self):
        mapping = _minimal_mapping()  # evidence_nodes: True
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)

        # Each host node should have exactly one <evidence> child
        host_a = None
        host_b = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "host-a":
                host_a = node
            elif node.findtext("label") == "host-b":
                host_b = node
        self.assertIsNotNone(host_a)
        self.assertIsNotNone(host_b)

        evidence_a = host_a.findall("evidence/evidence")
        evidence_b = host_b.findall("evidence/evidence")
        self.assertEqual(len(evidence_a), 1)
        self.assertEqual(len(evidence_b), 1)

        # Each evidence content should reference its host
        self.assertIn("host-a", evidence_a[0].findtext("content"))
        self.assertIn("host-b", evidence_b[0].findtext("content"))

    def test_evidence_nodes_false_emits_no_evidence(self):
        mapping = _minimal_mapping()
        mapping["evidence_nodes"] = False
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)
        # No <evidence> with content anywhere
        for ev in root.iter("evidence"):
            children = list(ev)
            self.assertEqual(len(children), 0, "Expected empty <evidence>, found children")

    def test_evidence_content_uses_section_markers(self):
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "host-a":
                content = node.findtext("evidence/evidence/content")
                self.assertIn("#[Location]#", content)
                self.assertIn("#[Output]#", content)
                self.assertIn("host-a", content)
                self.assertIn("port 22", content)
                return
        self.fail("host-a evidence not found")
```

### Step 9.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_dradis.TestBuildRepositoryXmlEvidence -v`
- Expected: tests fail — Task 7's `_make_node` emits empty `<evidence>` only.

### Step 9.3: Extend `build_repository_xml` for evidence nodes

- [ ] In `libmagenta/dradis.py`, modify the section that creates host child nodes. Currently:

```python
    targets_node = _make_node(nodes_el, ids, "Targets", type_id=0)
    targets_id = targets_node.findtext("id")
    for host in _unique_hosts(report["issues"]):
        _make_node(nodes_el, ids, host, type_id=0, parent_id=int(targets_id))
```

Change to:

```python
    targets_node = _make_node(nodes_el, ids, "Targets", type_id=0)
    targets_id = targets_node.findtext("id")
    host_nodes = {}  # host string → <node> Element
    for host in _unique_hosts(report["issues"]):
        host_nodes[host] = _make_node(
            nodes_el, ids, host, type_id=0, parent_id=int(targets_id)
        )

    # Evidence nodes attached to each host node (when evidence_nodes: true).
    # Order: for each issue, for each host in issue.affects.
    if mapping["evidence_nodes"]:
        for issue_data in report["issues"]:
            for host in issue_data.get("affects", []):
                host_node = host_nodes.get(host)
                if host_node is None:
                    continue
                _build_evidence_element(host_node, ids, issue_data, host, mapping)
```

And add the helper near the other builders:

```python
def _render_evidence_content(issue_data, affected, mapping):
    """Build the #[Section]#-marker textile body for one evidence entry.

    Context = issue dict + `affected` = the host string for this evidence.
    """
    ctx = dict(issue_data)
    ctx["affected"] = affected
    parts = []
    for entry in mapping["evidence_sections"]:
        name = entry["name"]
        expr = entry["value"]
        body_md = render_section_body(expr, ctx)
        if body_md.strip():
            body_textile = markdown_to_dradis_textile(body_md).strip()
            parts.append("#[%s]#\n%s\n" % (name, body_textile))
        else:
            parts.append("#[%s]#\n" % name)
    return "\n".join(parts)


def _build_evidence_element(host_node, ids, issue_data, affected, mapping):
    evidence_parent = host_node.find("evidence")
    # In the XML schema, evidence elements live as <evidence><evidence>...
    # nested. The outer one is the container per node; each individual piece
    # of evidence is a child <evidence>.
    ev = ET.SubElement(evidence_parent, "evidence")
    ET.SubElement(ev, "id").text = str(ids.next())
    content_el = ET.SubElement(ev, "content")
    _set_cdata(content_el, _render_evidence_content(issue_data, affected, mapping))
    # Issue cross-reference: the importer's lookup table maps these IDs.
    # We use a placeholder text reference here that Dradis will resolve via
    # the lookup_table[:issues] mapping during import.
    issue_ref = ET.SubElement(ev, "issue")
    ET.SubElement(issue_ref, "title").text = issue_data["title"]
    return ev
```

### Step 9.4: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: all evidence tests PASS plus all previous tests still PASS.

### Step 9.5: Stop and notify the user

- [ ] Stop. Report: "Task 9 complete (evidence nodes, conditional on evidence_nodes flag). Ready for you to commit."

---

## Task 10: XML builder — Part 4: Chart attachment node + ZIP packager

**Files:**
- Modify: `libmagenta/dradis.py`
- Modify: `tests/test_dradis.py`

### Step 10.1: Write failing tests

- [ ] Append to `tests/test_dradis.py`:

```python
import base64
import io
import zipfile


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestChartAttachmentAndZip(unittest.TestCase):
    def _report_with_chart(self):
        # Minimal valid PNG header (8 bytes) — enough for the byte plumbing.
        png_bytes = b"\x89PNG\r\n\x1a\n"
        return {
            "metadata": {
                "project_info": {"product_name": "X"},
                "chart": base64.b64encode(png_bytes).decode("ascii"),
            },
            "issues": [],
            "sections": {"issues": {}},
        }

    def test_chart_node_present_when_chart_in_metadata(self):
        from libmagenta.dradis import build_repository_xml
        xml_str = build_repository_xml(self._report_with_chart(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        labels = [n.findtext("label") for n in root.findall(".//nodes/node")]
        self.assertIn("Uploaded files", labels)

    def test_no_chart_node_when_chart_absent(self):
        from libmagenta.dradis import build_repository_xml
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        labels = [n.findtext("label") for n in root.findall(".//nodes/node")]
        self.assertNotIn("Uploaded files", labels)

    def test_package_zip_writes_xml_and_attachments(self):
        from libmagenta.dradis import package_zip
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as fd:
            zip_path = fd.name
        try:
            xml = "<?xml version=\"1.0\"?><dradis-template version=\"4\"/>"
            attachments = {"5/chart.png": b"\x89PNG\r\n\x1a\n"}
            package_zip(xml, attachments, zip_path)

            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                self.assertIn("dradis-repository.xml", names)
                self.assertIn("5/chart.png", names)
                with zf.open("dradis-repository.xml") as fd:
                    self.assertIn(b"dradis-template", fd.read())
                with zf.open("5/chart.png") as fd:
                    self.assertEqual(fd.read(), b"\x89PNG\r\n\x1a\n")
        finally:
            os.unlink(zip_path)

    def test_archive_chart_path_matches_uploaded_files_node_id(self):
        # The chart bytes folder name in the zip MUST match the archive
        # node id of the "Uploaded files" node. We test the helper that
        # produces both pieces of info in lockstep.
        from libmagenta.dradis import build_repository_xml_with_attachments
        report = self._report_with_chart()
        xml_str, attachments = build_repository_xml_with_attachments(
            report, _minimal_mapping()
        )
        root = ET.fromstring(xml_str)
        uploaded_node_id = None
        for n in root.findall(".//nodes/node"):
            if n.findtext("label") == "Uploaded files":
                uploaded_node_id = n.findtext("id")
                break
        self.assertIsNotNone(uploaded_node_id)
        # Attachment key uses that ID as the folder name
        expected_key = "%s/chart.png" % uploaded_node_id
        self.assertIn(expected_key, attachments)
```

### Step 10.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_dradis.TestChartAttachmentAndZip -v`
- Expected: tests fail — `package_zip` and `build_repository_xml_with_attachments` don't exist; `build_repository_xml` doesn't emit "Uploaded files" yet.

### Step 10.3: Refactor — split chart out into a dedicated helper

The cleanest API is one entry point that returns both the XML and the dict of attachments to bundle. Existing callers can keep using `build_repository_xml` for XML-only, and the new top-level exporter uses `build_repository_xml_with_attachments`.

In `libmagenta/dradis.py`, refactor:

```python
def build_repository_xml(report, mapping):
    """XML-only entry point (chart attachment is silently dropped). Kept
    for tests; production code should use build_repository_xml_with_attachments."""
    xml_str, _ = build_repository_xml_with_attachments(report, mapping)
    return xml_str


def build_repository_xml_with_attachments(report, mapping):
    """Build the dradis-repository.xml AND collect attachment payloads.

    Returns (xml_str, attachments) where attachments is a dict mapping
    "<archive-node-id>/<filename>" to raw bytes. The caller writes both
    into the zip at the right paths.
    """
    ids = _IdAllocator()
    attachments = {}
    root = ET.Element("dradis-template", attrib={"version": "4"})
    nodes_el = ET.SubElement(root, "nodes")

    # 1. "Report content" node (type-id=4)
    props_json = _build_project_properties_json(
        mapping, report["metadata"].get("project_info", {})
    )
    _make_node(nodes_el, ids, "Report content", type_id=4, properties=props_json)

    # 2. "Targets" node and one child per unique affected host
    targets_node = _make_node(nodes_el, ids, "Targets", type_id=0)
    targets_id = targets_node.findtext("id")
    host_nodes = {}
    for host in _unique_hosts(report["issues"]):
        host_nodes[host] = _make_node(
            nodes_el, ids, host, type_id=0, parent_id=int(targets_id)
        )

    if mapping["evidence_nodes"]:
        for issue_data in report["issues"]:
            for host in issue_data.get("affects", []):
                host_node = host_nodes.get(host)
                if host_node is None:
                    continue
                _build_evidence_element(host_node, ids, issue_data, host, mapping)

    # 3. Chart node (only when metadata.chart is present)
    chart_b64 = report["metadata"].get("chart")
    if chart_b64:
        chart_node = _make_node(nodes_el, ids, "Uploaded files", type_id=0)
        chart_node_id = chart_node.findtext("id")
        attachments["%s/chart.png" % chart_node_id] = base64.b64decode(chart_b64)

    # 4. Issues
    issues_el = ET.SubElement(root, "issues")
    project_info = report["metadata"].get("project_info", {})
    fallback_author = project_info.get("report_author") or "magenta"
    for issue_data in report["issues"]:
        _build_issue_element(issues_el, ids, issue_data, mapping, fallback_author)

    # 5. Empty top-level elements
    ET.SubElement(root, "tags")
    ET.SubElement(root, "methodologies")
    ET.SubElement(root, "categories")

    raw = ET.tostring(root, encoding="utf-8").decode("utf-8")
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>' + _cdata_post_process(raw)
    return xml_str, attachments
```

And add the new imports at the top of `libmagenta/dradis.py` (with the other module-level imports):

```python
import base64
import zipfile
```

### Step 10.4: Implement `package_zip`

- [ ] Append to `libmagenta/dradis.py`:

```python
def package_zip(repository_xml, attachments, output_path):
    """Write the dradis project package zip to output_path.

    attachments is a dict of archive paths → bytes (e.g. {"5/chart.png": b"..."}).
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dradis-repository.xml", repository_xml)
        for path, content in attachments.items():
            zf.writestr(path, content)
```

### Step 10.5: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_dradis -v`
- Expected: all tests in `TestChartAttachmentAndZip` PASS. All previous tests still PASS.

### Step 10.6: Stop and notify the user

- [ ] Stop. Report: "Task 10 complete (chart node + ZIP packager). Ready for you to commit."

---

## Task 11: Engine method `export_as_dradis()`

**Files:**
- Modify: `libmagenta/engine.py` (add new method)
- Modify: `tests/test_dradis.py`

### Step 11.1: Write a failing end-to-end test

- [ ] Append to `tests/test_dradis.py`:

```python
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestExportAsDradisEngineMethod(unittest.TestCase):
    def test_export_writes_valid_zip(self):
        from libmagenta.engine import MagentaReporter

        # Build a synthetic `report` dict shaped like process_files() output.
        report = {
            "metadata": {
                "project_info": {
                    "product_name": "X",
                    "client_name": "Acme",
                    "report_author": "tester@example.com",
                    "start_date": "2026-01-01",
                    "end_date": "2026-01-05",
                    "report_date": "2026-01-10",
                    "test_type": "MPT",
                },
                "report_sections_order": [],
                "issue_subsections_order": [],
            },
            "issues": [{
                "title": "Test Issue",
                "description": "A description.",
                "recommendations": "A fix.",
                "details": "Detected on host.",
                "severity": "medium",
                "affects": ["host-1"],
                "taxonomy": [], "references": [], "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

        with tempfile.TemporaryDirectory() as tmp:
            out_zip = os.path.join(tmp, "out.zip")
            dradis_templates = os.path.join(MAGENTA_ROOT, "formats", "dradis")

            magenta = MagentaReporter()  # uses MAGENTA_HOME for config
            magenta.set_language("en")
            magenta.export_as_dradis(report, out_zip, dradis_templates)

            self.assertTrue(os.path.isfile(out_zip))
            with zipfile.ZipFile(out_zip) as zf:
                self.assertIn("dradis-repository.xml", zf.namelist())
                with zf.open("dradis-repository.xml") as fd:
                    xml_content = fd.read().decode("utf-8")
                root = ET.fromstring(xml_content)
                self.assertEqual(root.tag, "dradis-template")
                self.assertEqual(root.attrib["version"], "4")
                # Has our issue
                issues = root.findall("issues/issue")
                self.assertEqual(len(issues), 1)
```

We use `MAGENTA_ROOT` from the top of the test file (defined in Task 2).

### Step 11.2: Run the test to verify it fails

- [ ] Run: `python -m unittest tests.test_dradis.TestExportAsDradisEngineMethod -v`
- Expected: `AttributeError: 'MagentaReporter' object has no attribute 'export_as_dradis'`.

### Step 11.3: Add `export_as_dradis()` to the engine

- [ ] In `libmagenta/engine.py`, find the existing `export_as_obsidian()` method at line 1216 (`def export_as_obsidian(self, report, pathname, exist_ok=False):`). Add the new method directly after it:

```python
    # Export a generated report as a Dradis project package (.zip).
    def export_as_dradis(self, report, output_path, dradis_templates_dir):
        """Export a Magenta report as a Dradis-importable ZIP archive.

        :param report: dict returned by self.process_files().
        :param output_path: filesystem path where the .zip will be written.
        :param dradis_templates_dir: directory containing mapping.json5
            (typically MAGENTA_HOME/formats/dradis, overridable via the
            --dradis-templates CLI flag).
        """
        # Import lazily so callers using non-pandoc formats don't pay the
        # pypandoc import cost.
        from libmagenta.dradis import (
            load_mapping,
            build_repository_xml_with_attachments,
            package_zip,
        )

        mapping_path = os.path.join(dradis_templates_dir, "mapping.json5")
        mapping = load_mapping(mapping_path)
        xml_str, attachments = build_repository_xml_with_attachments(report, mapping)
        package_zip(xml_str, attachments, output_path)
```

### Step 11.4: Run the test to verify it passes

- [ ] Run: `python -m unittest tests.test_dradis.TestExportAsDradisEngineMethod -v`
- Expected: PASS.

### Step 11.5: Stop and notify the user

- [ ] Stop. Report: "Task 11 complete (export_as_dradis engine method). Ready for you to commit."

---

## Task 12: Wire `dradis` format into the CLI

**Files:**
- Modify: `magenta.py` (add format choice, --dradis-templates flag, dispatch)
- Modify: `tests/test_cli.py`

### Step 12.1: Write failing tests

- [ ] Append to `tests/test_cli.py`:

```python
import zipfile
from xml.etree import ElementTree as ET


@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestDradisFormat(unittest.TestCase):
    def test_dradis_explicit_flag_produces_valid_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.zip")
            subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out,
                 "-f", "dradis"],
                check=True, cwd=MAGENTA_ROOT,
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
            out = os.path.join(tmp, "dradis-export.zip")
            subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out],
                check=True, cwd=MAGENTA_ROOT,
            )
            self.assertTrue(os.path.isfile(out))

    def test_custom_dradis_templates_dir(self):
        # Drop a mapping.json5 with only Title section into a temp dir;
        # verify the output reflects the override.
        with tempfile.TemporaryDirectory() as tmp:
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
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out,
                 "-f", "dradis", "--dradis-templates", templates_dir],
                check=True, cwd=MAGENTA_ROOT,
            )
            with zipfile.ZipFile(out) as zf:
                with zf.open("dradis-repository.xml") as fd:
                    xml = fd.read().decode("utf-8")
            # Only #[Title]# markers should be present, no #[Description]# etc.
            self.assertIn("#[Title]#", xml)
            self.assertNotIn("#[Description]#", xml)
            self.assertNotIn("#[Solution]#", xml)
```

### Step 12.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_cli.TestDradisFormat -v`
- Expected: subprocess fails with `Invalid value for '-f' / '--format': 'dradis' is not one of...`.

### Step 12.3: Add `dradis` to format choices

- [ ] In `magenta.py`, find the `@click.option("-f", "--format", ...)` decorator and update the choices to include `dradis`:

```python
    type=click.Choice(
        choices=("auto", "markdown", "json", "obsidian", "textile", "dradis"),
        case_sensitive=False,
    ),
```

### Step 12.4: Add `--dradis-templates` flag to the `report` command

- [ ] In `magenta.py`, find the `report` command decorators block at lines 67-103. Add a new `@click.option` for `--dradis-templates` immediately before `@click.pass_context`:

```python
@click.option(
    "--dradis-templates",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    default=None,
    help="Directory containing the Dradis mapping.json5. "
         "Defaults to <MAGENTA_HOME>/formats/dradis. Only used with -f dradis.",
)
```

Then add `dradis_templates` to the function signature (between `metadata` and `ctx.invoked_subcommand`):

```python
def report(ctx, pathname, output, format, language, metadata, dradis_templates):
```

### Step 12.5: Add `dradis-export.zip` autodetection

- [ ] In `magenta.py`, find the autodetect block (now in Task 2 we added `.textile`). Update to also handle `dradis-export.zip` and reject other `.zip` files:

```python
    elif format == "auto":
        if output == "-":
            format = "markdown"
        else:
            base = os.path.basename(output).lower()
            ext = os.path.splitext(output)[1].lower()
            if base == "dradis-export.zip":
                format = "dradis"
            elif ext == ".zip":
                click.echo("error: ambiguous .zip extension; pass -f explicitly "
                           "(use exact filename 'dradis-export.zip' to autodetect)")
                return
            elif not ext:
                format = "obsidian"
            elif ext in (".md", ".txt"):
                format = "markdown"
            elif ext in (".json", ".js"):
                format = "json"
            elif ext == ".textile":
                format = "textile"
            else:
                click.echo("error: cannot guess file format for extension: '%s'" % ext)
                return
```

### Step 12.6: Wire `dradis` dispatch

- [ ] In `magenta.py`, find the dispatch block (the `if format == "obsidian": ... else:` chain). Replace the structure to handle `dradis` (which also writes a directory-like output but is a single .zip file):

Before the existing `if format == "obsidian":` block, add:

```python
    if format == "dradis":
        if dradis_templates is None:
            dradis_templates = os.path.join(MAGENTA_HOME, "formats", "dradis")
        magenta.export_as_dradis(result, output, dradis_templates)
        return
    if format == "obsidian":
        magenta.export_as_obsidian(result, output)
    else:
        # ... existing file-writing branch unchanged ...
```

The existing else branch (markdown, json, textile) is unchanged.

### Step 12.7: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_cli -v`
- Expected: all `TestDradisFormat` tests PASS. All `TestTextileFormat` tests still PASS.

### Step 12.8: Manual smoke test

- [ ] If you have access to a Dradis CE instance:

```bash
python3 magenta.py report tmp/samples -o /tmp/smoke-dradis.zip -f dradis
```

Upload `/tmp/smoke-dradis.zip` to Dradis CE via the "Project upload" UI. Verify the project loads, the Targets node has child host nodes, issues appear with `#[Title]#`/`#[Description]#`/... fields populated. **Do not declare done until this step passes** — the manual smoke test is the primary defense against XML-schema misunderstandings.

If Dradis import fails, capture the error message and report it back. Do not try to fix it by deleting failing assertions or by silently restructuring the XML — consult the user.

### Step 12.9: Stop and notify the user

- [ ] Stop. Report: "Task 12 complete (dradis format wired end-to-end + manual smoke). Ready for you to commit."

---

## Task 13: Autodetection — deprecation warning for trailing-slash → obsidian

The spec calls for a one-release deprecation warning when users rely on trailing-slash → obsidian autodetection.

**Files:**
- Modify: `magenta.py` (autodetect block)
- Modify: `tests/test_cli.py`

### Step 13.1: Write failing tests

- [ ] Append to `tests/test_cli.py`:

```python
@unittest.skipUnless(os.path.isdir(SAMPLES_DIR), "tmp/samples/ not present")
class TestAutodetectionDeprecation(unittest.TestCase):
    def test_trailing_slash_obsidian_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "vault") + os.sep  # trailing slash
            result = subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out],
                cwd=MAGENTA_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("deprecated", combined.lower())
            self.assertIn("obsidian", combined.lower())

    def test_explicit_obsidian_flag_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "vault")
            result = subprocess.run(
                ["python3", MAGENTA_PY, "report", SAMPLES_DIR, "-o", out,
                 "-f", "obsidian"],
                cwd=MAGENTA_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertNotIn("deprecated", combined.lower())
```

### Step 13.2: Run the tests to verify they fail

- [ ] Run: `python -m unittest tests.test_cli.TestAutodetectionDeprecation -v`
- Expected: `test_trailing_slash_obsidian_warns` fails because no warning is emitted yet.

### Step 13.3: Emit the deprecation warning

- [ ] In `magenta.py`, find the line in the autodetect block:

```python
            elif not ext:
                format = "obsidian"
```

Change to:

```python
            elif not ext:
                format = "obsidian"
                click.echo(
                    "warning: autodetecting 'obsidian' format from a directory-style "
                    "output path is deprecated and will be removed in a future release. "
                    "Pass '-f obsidian' explicitly.",
                    err=True,
                )
```

### Step 13.4: Run the tests to verify they pass

- [ ] Run: `python -m unittest tests.test_cli -v`
- Expected: all tests PASS.

### Step 13.5: Stop and notify the user

- [ ] Stop. Report: "Task 13 complete (deprecation warning for trailing-slash autodetect). Ready for you to commit."

---

## Task 14: Final manual end-to-end smoke test

This task is mostly verification — no new code, just confirming everything works against a live Dradis CE instance and that all the spec's behavior holds end-to-end.

### Step 14.1: Run the full test suite

- [ ] Run: `python -m unittest discover tests -v`
- Expected: all tests PASS or SKIP (depending on `tmp/samples/` and pandoc availability). No failures.

### Step 14.2: Manual smoke — `textile` format

- [ ] Run:

```bash
python3 magenta.py report tmp/samples -o /tmp/smoke.textile -f textile
```

- Open `/tmp/smoke.textile`. Verify: it's a single non-empty Textile file, all sections from the original Markdown are present, headings use Textile syntax (`h1.`, `h2.`, etc.).

### Step 14.3: Manual smoke — `dradis` format with welcome-kit defaults

- [ ] Run:

```bash
python3 magenta.py report tmp/samples -o /tmp/smoke-dradis.zip -f dradis
```

- Upload to Dradis CE via "Project upload". Verify:
  - Project loads without error.
  - "Targets" node exists with child host nodes for every affected host.
  - Each host node has Evidence entries (if any of your sample issues have `affects`).
  - Issues are populated with `#[Title]#`, `#[Description]#`, `#[Solution]#`, `#[References]#` fields visible.
  - "Uploaded files" node contains `chart.png` if the chart was enabled.
  - "Report content" node properties show the project metadata in the Doc Properties panel.

### Step 14.4: Manual smoke — custom mapping override

- [ ] Copy `formats/dradis/` to `/tmp/owasp-mapping/`. Edit `/tmp/owasp-mapping/mapping.json5` to reflect the OWASP kit (replace `issue_sections` with `Title`, `OWASP Domain`, `OWASP Top 10`, `Description Short`, `Description Long`, `Impact`, `Likelihood`, `Risk`, `Risk Score`, `Remediation Status`, `References`).

- Run:

```bash
python3 magenta.py report tmp/samples -o /tmp/owasp.zip -f dradis --dradis-templates /tmp/owasp-mapping
```

- Open the resulting `dradis-repository.xml` (don't have to upload, just inspect). Verify the issue `<text>` CDATA uses the OWASP section names in the configured order.

### Step 14.5: Manual smoke — autodetection rules

- [ ] Run each of these and confirm correct format autodetection (or appropriate error):

```bash
python3 magenta.py report tmp/samples -o /tmp/x.textile          # → textile
python3 magenta.py report tmp/samples -o /tmp/dradis-export.zip   # → dradis
python3 magenta.py report tmp/samples -o /tmp/x.zip               # → error
python3 magenta.py report tmp/samples -o /tmp/x.md                # → markdown
python3 magenta.py report tmp/samples -o /tmp/vault/              # → obsidian + WARN
```

### Step 14.6: Stop and notify the user

- [ ] Stop. Report: "All tasks complete. Test suite green. Manual smoke tests pass (or any failures documented). Ready for the user to commit anything outstanding and close out the feature."

---

## Self-review checklist (run before declaring the plan done)

- [ ] Every spec requirement maps to a task above.
- [ ] No `TODO`, `TBD`, `fill in details`, or other placeholder language.
- [ ] Function names and signatures are consistent across tasks (`build_repository_xml`, `build_repository_xml_with_attachments`, `markdown_to_dradis_textile`, `load_mapping`, `render_section_body`, `package_zip`, `export_as_dradis`).
- [ ] Every code step shows the actual code (no "implement the function").
- [ ] Every test step has expected output (PASS / FAIL / specific error).
- [ ] Test fixtures don't depend on `tmp/samples/` or pandoc unless the test is gated with `@unittest.skipUnless`.
- [ ] Git operations are not executed by Claude — each task ends with "stop and notify the user."
