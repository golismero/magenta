# shcheck Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Magenta parser at `parsers/shcheck/` that ingests output from both `santoru/shcheck` and `MarioVilas/shcheck`, in JSON and console-text form, and emits security-header findings.

**Architecture:** A four-way input sniffer feeds format-specific adapters that converge on one normalized per-URL record; a portable, Magenta-free analysis module grades header values; an emitter turns records into Magenta issues against the existing `missing_security_headers` template and a new `information_disclosure_headers` template.

**Tech Stack:** Python 3.12 stdlib only. `unittest` for tests. `ruff` for lint and format. Templates in JSON5 with Jinja2 expressions, validated by `jsonschema`.

**Design spec:** [2026-08-07-shcheck-parser-design.md](../specs/2026-08-07-shcheck-parser-design.md) — read it before starting. This plan implements it; where they disagree, the spec wins.

## Global Constraints

- **No git operations.** The repository owner manages all commits, branches, and staging. Every task ends with a **Checkpoint** listing files to review — never run `git add`, `git commit`, `git branch`, or `git stash`.
- **Stdlib only** for `parsers/shcheck/*.py`. No third-party imports, including `lxml`.
- **`parsers/shcheck/headers.py` must not import from Magenta**, reference Magenta severities, or perform I/O, and must **name no project anywhere in it** — not Magenta, not shcheck, not a repo or URL, in code, comments, or docstrings. It must stay liftable into another codebase as a single file that reads correctly there.
- **All parser work lives inside functions**, behind `if __name__ == "__main__":`. `parsers/wafw00f/wafw00f.py` reads stdin at module scope; do not copy that pattern — it makes the module unimportable by the tests.
- **Severity vocabulary** is exactly `none`, `low`, `medium`, `high`, `critical` ([templates/main.schema.json:13](../../../templates/main.schema.json#L13)).
- **Issue objects require** `template`, `tools`, `severity`, `affects` ([templates/main.schema.json:19](../../../templates/main.schema.json#L19)). The engine injects `_type`, `_tool`, and `_fp`; the parser must not emit underscore fields.
- **Parser contract:** input on stdin, JSON array on stdout, 10-second timeout ([engine.py:1089-1104](../../../libmagenta/engine.py#L1089-L1104)). Non-zero exit means file-level failure.
- **Lint gate:** `ruff check --select E4,E7,E9,F` and `ruff format --check` must both pass on the files you touch. Use **exactly** that `--select`. A bare `ruff check` on this machine enables ~830 rules and reports 254 errors against the *existing* codebase — it is not the standard this repo is written to, and chasing it produces code inconsistent with every neighbouring file.
- **Match house style, which means `%` string formatting.** `libmagenta/engine.py` and every existing parser use `"...%s..." % value`. Do not convert to `.format()` or f-strings to silence UP031; that rule is outside the gate above. Where the plan gives you a string, transcribe it exactly as written.
- **`# noqa: E402` is the house pattern** for the `sys.path.insert` that must precede an import (see `templates/burp/missing_security_headers.py`). E402 is inside the gate, so the noqa is required, not optional.
- **Test command:** `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
- **Pre-existing failure, not yours:** `tests.test_nikto_parser` errors with `ModuleNotFoundError: No module named 'lxml'` in the current venv. The full suite reports `Ran 89 tests ... FAILED (errors=1, skipped=11)` before any of this work. Do not try to fix it; do not let it mask a real regression.
- **Tool source references** are pinned: original `santoru/shcheck` at `c29405c`, fork `MarioVilas/shcheck` at `0896c9d`, both checked out under `tmp/` (gitignored).

---

### Task 1: `headers.py` — CSP analysis

The largest rule group, and the one the fork will eventually import. Build it first and alone.

**Files:**
- Create: `parsers/shcheck/headers.py`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Finding = collections.namedtuple("Finding", "header code message")`
  - `parse_csp(value: str) -> dict[str, list[str]]`
  - `analyze(name: str, value: str) -> list[Finding]` — dispatches on header name; returns `[]` for unknown headers or a `None` value.

Message strings must read as a continuation of `"<Header> - "`, e.g. `"present but allows 'unsafe-inline' ..."`. Task 5 renders them as `"%s - %s" % (finding.header, finding.message)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_shcheck_parser.py`:

```python
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER_DIR = os.path.join(_HERE, "..", "parsers", "shcheck")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_PARSER_DIR, filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


headers = _load("shcheck_headers", "headers.py")


def codes(findings):
    return sorted(f.code for f in findings)


class TestParseCsp(unittest.TestCase):
    def test_splits_directives_and_sources(self):
        self.assertEqual(
            headers.parse_csp("default-src 'self'; script-src 'self' cdn.example.com"),
            {
                "default-src": ["'self'"],
                "script-src": ["'self'", "cdn.example.com"],
            },
        )

    def test_directive_names_are_lowercased(self):
        self.assertEqual(headers.parse_csp("DEFAULT-SRC 'none'"), {"default-src": ["'none'"]})

    def test_source_case_is_preserved(self):
        self.assertEqual(
            headers.parse_csp("img-src CDN.Example.COM/Path"),
            {"img-src": ["CDN.Example.COM/Path"]},
        )

    def test_duplicate_directive_ignored_per_spec(self):
        self.assertEqual(
            headers.parse_csp("script-src 'self'; script-src *"),
            {"script-src": ["'self'"]},
        )

    def test_empty_segments_and_trailing_semicolon(self):
        self.assertEqual(headers.parse_csp("default-src 'self';;"), {"default-src": ["'self'"]})

    def test_valueless_directive(self):
        self.assertEqual(headers.parse_csp("upgrade-insecure-requests"), {"upgrade-insecure-requests": []})


class TestCspRules(unittest.TestCase):
    # A policy with nothing wrong with it, used as the baseline for each rule.
    CLEAN = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )

    def test_clean_policy_has_no_findings(self):
        self.assertEqual(headers.analyze("Content-Security-Policy", self.CLEAN), [])

    def test_unsafe_inline_in_script_src(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-inline'")
        self.assertIn("csp-unsafe-inline", codes(headers.analyze("Content-Security-Policy", value)))

    def test_unsafe_inline_in_style_src(self):
        value = self.CLEAN.replace("style-src 'self'", "style-src 'unsafe-inline'")
        self.assertIn("csp-unsafe-inline", codes(headers.analyze("Content-Security-Policy", value)))

    def test_unsafe_inline_reported_once_for_both_directives(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-inline'")
        value = value.replace("style-src 'self'", "style-src 'unsafe-inline'")
        found = [f for f in headers.analyze("Content-Security-Policy", value) if f.code == "csp-unsafe-inline"]
        self.assertEqual(len(found), 1)
        self.assertIn("script-src", found[0].message)
        self.assertIn("style-src", found[0].message)

    def test_unsafe_inline_inherited_through_default_src(self):
        # script-src absent, so it falls back to default-src.
        value = "default-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn("csp-unsafe-inline", codes(headers.analyze("Content-Security-Policy", value)))

    def test_unsafe_inline_not_inherited_when_script_src_overrides(self):
        value = (
            "default-src 'unsafe-inline'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        self.assertNotIn("csp-unsafe-inline", codes(headers.analyze("Content-Security-Policy", value)))

    def test_unsafe_eval(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-eval'")
        self.assertIn("csp-unsafe-eval", codes(headers.analyze("Content-Security-Policy", value)))

    def test_keyword_source_matching_is_case_insensitive(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'UNSAFE-EVAL'")
        self.assertIn("csp-unsafe-eval", codes(headers.analyze("Content-Security-Policy", value)))

    def test_wildcard_source(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src *")
        self.assertIn("csp-wildcard", codes(headers.analyze("Content-Security-Policy", value)))

    def test_wildcard_subdomain_is_not_a_bare_wildcard(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src *.example.com")
        self.assertNotIn("csp-wildcard", codes(headers.analyze("Content-Security-Policy", value)))

    def test_no_default_src_and_no_script_src(self):
        value = "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn("csp-no-default-src", codes(headers.analyze("Content-Security-Policy", value)))

    def test_no_frame_ancestors(self):
        value = "default-src 'none'; object-src 'none'; base-uri 'none'"
        self.assertIn("csp-no-frame-ancestors", codes(headers.analyze("Content-Security-Policy", value)))

    def test_no_object_src_without_default_src(self):
        value = "script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn("csp-no-object-src", codes(headers.analyze("Content-Security-Policy", value)))

    def test_object_src_covered_by_default_src(self):
        value = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertNotIn("csp-no-object-src", codes(headers.analyze("Content-Security-Policy", value)))

    def test_no_base_uri(self):
        value = "default-src 'none'; object-src 'none'; frame-ancestors 'none'"
        self.assertIn("csp-no-base-uri", codes(headers.analyze("Content-Security-Policy", value)))

    def test_header_name_matching_is_case_insensitive(self):
        self.assertEqual(headers.analyze("CONTENT-SECURITY-POLICY", self.CLEAN), [])

    def test_unknown_header_returns_nothing(self):
        self.assertEqual(headers.analyze("X-Whatever", "value"), [])

    def test_none_value_returns_nothing(self):
        self.assertEqual(headers.analyze("Content-Security-Policy", None), [])

    def test_finding_header_field_is_the_canonical_name(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-eval'")
        found = headers.analyze("content-security-policy", value)
        self.assertEqual(found[0].header, "Content-Security-Policy")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: collection error — `FileNotFoundError` on `parsers/shcheck/headers.py`.

- [ ] **Step 3: Write the implementation**

Create `parsers/shcheck/headers.py`:

```python
#!/usr/bin/python3

"""Portable HTTP security header analysis.

Reports *what* is wrong with a header value, never *how bad* it is: severity is
policy and belongs to the caller. Findings are facts.

This module is a backport target for MarioVilas/shcheck. Keep it stdlib-only,
free of I/O, and free of any Magenta concept, so it stays liftable as one file.
"""

import collections

Finding = collections.namedtuple("Finding", "header code message")

CSP = "Content-Security-Policy"

# Fetch directives fall back to default-src when they are absent.
# https://www.w3.org/TR/CSP3/#directives-fetch
FETCH_DIRECTIVES = frozenset(
    [
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "worker-src",
    ]
)


def parse_csp(value):
    """Parse a CSP header into an ordered {directive: [source, ...]} mapping.

    Directive names are lowercased. Source expressions keep their case, because
    host sources are case-sensitive in their path component. Repeated
    directives are ignored after the first, which is what the spec requires of
    user agents.
    """
    directives = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives:
            continue
        directives[name] = parts[1:]
    return directives


def _sources(directives, name):
    """Effective sources for a fetch directive, honouring the default-src fallback.

    Returns None when the directive is neither set nor inherited.
    """
    if name in directives:
        return directives[name]
    if name in FETCH_DIRECTIVES and "default-src" in directives:
        return directives["default-src"]
    return None


def _has_keyword(sources, keyword):
    return sources is not None and any(s.lower() == keyword for s in sources)


def _analyze_csp(value):
    findings = []
    directives = parse_csp(value)

    inline_in = [
        name
        for name in ("script-src", "style-src")
        if _has_keyword(_sources(directives, name), "'unsafe-inline'")
    ]
    if inline_in:
        findings.append(
            Finding(
                CSP,
                "csp-unsafe-inline",
                "present but allows 'unsafe-inline' in %s, defeating most of the "
                "cross-site scripting protection a policy provides"
                % " and ".join(inline_in),
            )
        )

    if _has_keyword(_sources(directives, "script-src"), "'unsafe-eval'"):
        findings.append(
            Finding(
                CSP,
                "csp-unsafe-eval",
                "present but allows 'unsafe-eval' in script-src, permitting "
                "strings to be executed as code",
            )
        )

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-default-src",
                "present but sets neither default-src nor script-src, so script "
                "loading is left unrestricted",
            )
        )

    wildcarded = sorted(
        name
        for name, sources in directives.items()
        if name in FETCH_DIRECTIVES and any(s == "*" for s in sources)
    )
    if wildcarded:
        findings.append(
            Finding(
                CSP,
                "csp-wildcard",
                "present but uses a wildcard source (*) in %s, allowing content "
                "from any origin" % ", ".join(wildcarded),
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-frame-ancestors",
                "present but sets no frame-ancestors directive, so the page can "
                "be framed by any origin",
            )
        )

    if "object-src" not in directives and "default-src" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-object-src",
                "present but sets neither object-src nor default-src, so plugin "
                "content is left unrestricted",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-base-uri",
                "present but sets no base-uri directive, so an injected <base> "
                "tag can redirect every relative URL on the page",
            )
        )

    return findings


_ANALYZERS = {
    "content-security-policy": _analyze_csp,
}


def analyze(name, value):
    """Findings for one header in isolation.

    Unknown header names and None values yield no findings.
    """
    if value is None:
        return []
    analyzer = _ANALYZERS.get(name.strip().lower())
    if analyzer is None:
        return []
    return analyzer(value)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 25 tests.

- [ ] **Step 5: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck tests/test_shcheck_parser.py`
Expected: `All checks passed!` and `1 file already formatted` (or equivalent). If `format --check` fails, run `ruff format parsers/shcheck tests/test_shcheck_parser.py` and re-run the tests.

- [ ] **Step 6: Checkpoint**

Report to the repository owner for review — **do not commit**:
- `parsers/shcheck/headers.py` (new)
- `tests/test_shcheck_parser.py` (new)

---

### Task 2: `headers.py` — remaining headers and cross-header suppression

**Files:**
- Modify: `parsers/shcheck/headers.py`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: `Finding`, `analyze`, `_ANALYZERS` from Task 1.
- Produces: `analyze_all(present: dict[str, str]) -> list[Finding]` — runs `analyze` over every present header, then applies cross-header suppression. This is the parser-facing entry point; Task 5 calls it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_shcheck_parser.py`, before the `if __name__` block:

```python
class TestHstsRules(unittest.TestCase):
    def test_clean_hsts(self):
        value = "max-age=31536000; includeSubDomains"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_max_age_zero(self):
        found = codes(headers.analyze("Strict-Transport-Security", "max-age=0; includeSubDomains"))
        self.assertIn("hsts-max-age-zero", found)
        self.assertNotIn("hsts-max-age-short", found)

    def test_short_max_age(self):
        found = codes(headers.analyze("Strict-Transport-Security", "max-age=3600; includeSubDomains"))
        self.assertIn("hsts-max-age-short", found)
        self.assertNotIn("hsts-max-age-zero", found)

    def test_six_months_exactly_is_acceptable(self):
        value = "max-age=15768000; includeSubDomains"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_missing_include_subdomains(self):
        found = codes(headers.analyze("Strict-Transport-Security", "max-age=31536000"))
        self.assertEqual(found, ["hsts-no-include-subdomains"])

    def test_include_subdomains_is_case_insensitive(self):
        value = "max-age=31536000; INCLUDESUBDOMAINS"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_no_max_age_at_all(self):
        self.assertEqual(codes(headers.analyze("Strict-Transport-Security", "includeSubDomains")), ["hsts-malformed"])

    def test_non_numeric_max_age(self):
        self.assertEqual(codes(headers.analyze("Strict-Transport-Security", "max-age=forever")), ["hsts-malformed"])

    def test_quoted_max_age(self):
        value = 'max-age="31536000"; includeSubDomains'
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])


class TestSimpleHeaderRules(unittest.TestCase):
    def test_xfo_deny_is_clean(self):
        self.assertEqual(headers.analyze("X-Frame-Options", "DENY"), [])

    def test_xfo_sameorigin_is_clean_and_case_insensitive(self):
        self.assertEqual(headers.analyze("X-Frame-Options", "sameorigin"), [])

    def test_xfo_allow_from(self):
        found = codes(headers.analyze("X-Frame-Options", "ALLOW-FROM https://example.com"))
        self.assertEqual(found, ["xfo-allow-from"])

    def test_xfo_garbage(self):
        self.assertEqual(codes(headers.analyze("X-Frame-Options", "yes please")), ["xfo-invalid"])

    def test_xcto_nosniff_is_clean(self):
        self.assertEqual(headers.analyze("X-Content-Type-Options", "nosniff"), [])

    def test_xcto_other_value(self):
        self.assertEqual(codes(headers.analyze("X-Content-Type-Options", "sniff")), ["xcto-invalid"])

    def test_referrer_policy_clean(self):
        self.assertEqual(headers.analyze("Referrer-Policy", "strict-origin-when-cross-origin"), [])

    def test_referrer_policy_unsafe_url(self):
        self.assertEqual(codes(headers.analyze("Referrer-Policy", "unsafe-url")), ["referrer-unsafe-url"])

    def test_referrer_policy_unsafe_url_in_a_token_list(self):
        value = "no-referrer, unsafe-url"
        self.assertIn("referrer-unsafe-url", codes(headers.analyze("Referrer-Policy", value)))

    def test_referrer_policy_unrecognised(self):
        self.assertEqual(codes(headers.analyze("Referrer-Policy", "whatever")), ["referrer-invalid"])

    def test_coop_same_origin_is_clean(self):
        self.assertEqual(headers.analyze("Cross-Origin-Opener-Policy", "same-origin"), [])

    def test_coop_unsafe_none(self):
        self.assertEqual(codes(headers.analyze("Cross-Origin-Opener-Policy", "unsafe-none")), ["coop-unsafe-none"])

    def test_coop_invalid_value_is_treated_as_unsafe_none(self):
        # Browsers fall back to unsafe-none for unrecognised values, so this is
        # the same defect, not a separate one.
        self.assertEqual(codes(headers.analyze("Cross-Origin-Opener-Policy", "bogus")), ["coop-unsafe-none"])

    def test_coep_valid_values(self):
        for value in ("unsafe-none", "require-corp", "credentialless"):
            self.assertEqual(headers.analyze("Cross-Origin-Embedder-Policy", value), [], value)

    def test_coep_invalid(self):
        self.assertEqual(codes(headers.analyze("Cross-Origin-Embedder-Policy", "nope")), ["coep-invalid"])

    def test_corp_valid_values(self):
        for value in ("same-site", "same-origin", "cross-origin"):
            self.assertEqual(headers.analyze("Cross-Origin-Resource-Policy", value), [], value)

    def test_corp_invalid(self):
        self.assertEqual(codes(headers.analyze("Cross-Origin-Resource-Policy", "nope")), ["corp-invalid"])

    def test_permissions_policy_is_presence_only(self):
        self.assertEqual(headers.analyze("Permissions-Policy", "geolocation=*"), [])


class TestAnalyzeAll(unittest.TestCase):
    NO_ANCESTORS = "default-src 'none'; object-src 'none'; base-uri 'none'"

    def test_runs_every_header(self):
        found = codes(
            headers.analyze_all(
                {
                    "Content-Security-Policy": TestCspRules.CLEAN,
                    "X-Content-Type-Options": "sniff",
                    "Strict-Transport-Security": "max-age=1",
                }
            )
        )
        self.assertEqual(found, ["hsts-max-age-short", "hsts-no-include-subdomains", "xcto-invalid"])

    def test_frame_ancestors_suppressed_by_valid_xfo(self):
        found = codes(
            headers.analyze_all(
                {"Content-Security-Policy": self.NO_ANCESTORS, "X-Frame-Options": "DENY"}
            )
        )
        self.assertNotIn("csp-no-frame-ancestors", found)

    def test_frame_ancestors_reported_when_xfo_absent(self):
        found = codes(headers.analyze_all({"Content-Security-Policy": self.NO_ANCESTORS}))
        self.assertIn("csp-no-frame-ancestors", found)

    def test_frame_ancestors_reported_when_xfo_is_invalid(self):
        # A broken X-Frame-Options protects nothing, so it cannot excuse the
        # missing frame-ancestors directive.
        found = codes(
            headers.analyze_all(
                {"Content-Security-Policy": self.NO_ANCESTORS, "X-Frame-Options": "ALLOW-FROM https://x.example"}
            )
        )
        self.assertIn("csp-no-frame-ancestors", found)

    def test_empty_input(self):
        self.assertEqual(headers.analyze_all({}), [])

    def test_none_header_value_does_not_crash(self):
        # analyze() tolerates a None value, so analyze_all must too -- the
        # suppression path reaches _analyze_xfo without going through analyze().
        found = codes(
            headers.analyze_all({"Content-Security-Policy": self.NO_ANCESTORS, "X-Frame-Options": None})
        )
        self.assertIn("csp-no-frame-ancestors", found)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: FAIL — `AttributeError: module 'shcheck_headers' has no attribute 'analyze_all'`, plus assertion failures on every new header rule (they currently return `[]`).

- [ ] **Step 3: Write the implementation**

In `parsers/shcheck/headers.py`, add these constants below `FETCH_DIRECTIVES`:

```python
HSTS = "Strict-Transport-Security"
XFO = "X-Frame-Options"
XCTO = "X-Content-Type-Options"
REFERRER = "Referrer-Policy"
COOP = "Cross-Origin-Opener-Policy"
COEP = "Cross-Origin-Embedder-Policy"
CORP = "Cross-Origin-Resource-Policy"

# Six months, the floor recommended for a policy that is meant to stick.
HSTS_MIN_MAX_AGE = 15768000

REFERRER_TOKENS = frozenset(
    [
        "",
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ]
)
COEP_VALUES = frozenset(["unsafe-none", "require-corp", "credentialless"])
CORP_VALUES = frozenset(["same-site", "same-origin", "cross-origin"])
```

Add these analyzers after `_analyze_csp`:

```python
def _parse_directives(value):
    """Parse a semicolon-separated `key[=value]` header into a lowercased mapping.

    Valueless directives map to None. Values are unquoted.
    """
    directives = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, sep, val = chunk.partition("=")
        directives[key.strip().lower()] = val.strip().strip('"') if sep else None
    return directives


def _analyze_hsts(value):
    directives = _parse_directives(value)

    if directives.get("max-age") is None:
        return [
            Finding(
                HSTS,
                "hsts-malformed",
                "present but specifies no max-age, so browsers ignore the policy "
                "entirely",
            )
        ]
    try:
        max_age = int(directives["max-age"])
    except ValueError:
        return [
            Finding(
                HSTS,
                "hsts-malformed",
                "present but its max-age is not a number (%s), so browsers ignore "
                "the policy entirely" % directives["max-age"],
            )
        ]

    findings = []
    if max_age == 0:
        findings.append(
            Finding(
                HSTS,
                "hsts-max-age-zero",
                "present but set to max-age=0, which tells browsers to forget the "
                "policy and permits plaintext connections again",
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            Finding(
                HSTS,
                "hsts-max-age-short",
                "present but its max-age is only %d seconds, below the "
                "recommended minimum of %d (six months)" % (max_age, HSTS_MIN_MAX_AGE),
            )
        )

    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                HSTS,
                "hsts-no-include-subdomains",
                "present but does not set includeSubDomains, leaving subdomains "
                "reachable over plaintext HTTP",
            )
        )

    return findings


def _analyze_xfo(value):
    normalized = value.strip().upper()
    if normalized.startswith("ALLOW-FROM"):
        return [
            Finding(
                XFO,
                "xfo-allow-from",
                "present but uses ALLOW-FROM, which no current browser supports; "
                "a CSP frame-ancestors directive is the replacement",
            )
        ]
    if normalized not in ("DENY", "SAMEORIGIN"):
        return [
            Finding(
                XFO,
                "xfo-invalid",
                "present but has an unrecognised value (%s), so browsers ignore it "
                "and the page stays framable" % value.strip(),
            )
        ]
    return []


def _analyze_xcto(value):
    if value.strip().lower() != "nosniff":
        return [
            Finding(
                XCTO,
                "xcto-invalid",
                "present but set to %s rather than nosniff, so MIME type sniffing "
                "stays enabled" % value.strip(),
            )
        ]
    return []


def _analyze_referrer(value):
    tokens = [t.strip().lower() for t in value.split(",")]
    if any(t == "unsafe-url" for t in tokens):
        return [
            Finding(
                REFERRER,
                "referrer-unsafe-url",
                "present but set to unsafe-url, which leaks the full URL, query "
                "string included, to third-party origins",
            )
        ]
    if not any(t in REFERRER_TOKENS for t in tokens):
        return [
            Finding(
                REFERRER,
                "referrer-invalid",
                "present but carries no recognised policy token (%s), so the "
                "browser default applies instead" % value.strip(),
            )
        ]
    return []


def _analyze_coop(value):
    # Browsers fall back to unsafe-none for unrecognised values, so an invalid
    # value and an explicit unsafe-none are the same defect.
    if value.strip().lower() not in ("same-origin", "same-origin-allow-popups"):
        return [
            Finding(
                COOP,
                "coop-unsafe-none",
                "present but effectively unsafe-none (%s), which provides no "
                "cross-origin isolation" % value.strip(),
            )
        ]
    return []


def _analyze_coep(value):
    if value.strip().lower() not in COEP_VALUES:
        return [
            Finding(
                COEP,
                "coep-invalid",
                "present but has an unrecognised value (%s); expected unsafe-none, "
                "require-corp or credentialless" % value.strip(),
            )
        ]
    return []


def _analyze_corp(value):
    if value.strip().lower() not in CORP_VALUES:
        return [
            Finding(
                CORP,
                "corp-invalid",
                "present but has an unrecognised value (%s); expected same-site, "
                "same-origin or cross-origin" % value.strip(),
            )
        ]
    return []
```

Replace the `_ANALYZERS` dict with:

```python
_ANALYZERS = {
    "content-security-policy": _analyze_csp,
    "cross-origin-embedder-policy": _analyze_coep,
    "cross-origin-opener-policy": _analyze_coop,
    "cross-origin-resource-policy": _analyze_corp,
    "referrer-policy": _analyze_referrer,
    "strict-transport-security": _analyze_hsts,
    "x-content-type-options": _analyze_xcto,
    "x-frame-options": _analyze_xfo,
}
```

Append `analyze_all` and its helper at the end of the file:

```python
def _suppress_redundant(findings, present):
    """Drop findings a sibling header has already made moot.

    csp-no-frame-ancestors and a missing X-Frame-Options describe one gap, not
    two. The opposite direction is already handled upstream: a scanner that sees
    frame-ancestors in the CSP does not report X-Frame-Options as missing. An
    invalid X-Frame-Options protects nothing, so it does not earn the
    suppression.
    """
    for name, value in present.items():
        if name.strip().lower() != "x-frame-options" or value is None:
            continue
        if not _analyze_xfo(value):
            return [f for f in findings if f.code != "csp-no-frame-ancestors"]
    return findings


def analyze_all(present):
    """analyze() across every present header, plus cross-header suppressions.

    `present` maps header names to their raw values. This is the entry point
    callers should use; analyze() is public for unit testing and for reuse in a
    per-header display loop.
    """
    findings = []
    for name, value in present.items():
        findings.extend(analyze(name, value))
    return _suppress_redundant(findings, present)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 57 tests (25 from Task 1 + 32 new).

- [ ] **Step 5: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck tests/test_shcheck_parser.py`
Expected: clean.

- [ ] **Step 6: Checkpoint**

Report for review — **do not commit**:
- `parsers/shcheck/headers.py` (modified)
- `tests/test_shcheck_parser.py` (modified)

---

### Task 3: JSON adapters and normalization

**Files:**
- Create: `parsers/shcheck/shcheck.py`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: nothing from `headers.py` yet.
- Produces:
  - `DEPRECATED_HEADER_NAMES: tuple[str, ...]`
  - `new_record(url: str) -> dict` — a normalized record with every key present and empty.
  - `normalize_json(data: dict, warnings: list[str]) -> list[dict]` — handles both variants; appends human-readable strings to `warnings`.

Record keys, exactly: `url`, `present`, `missing`, `unsafe`, `deprecated`, `info_disclosure`, `request`, `response`. `info_disclosure` is `None` when the check never ran and `{}` when it ran clean — that distinction is load-bearing and later tasks depend on it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_shcheck_parser.py`. Add `shcheck = _load("shcheck_parser", "shcheck.py")` immediately after the existing `headers = _load(...)` line, then add:

```python
class TestNormalizeJson(unittest.TestCase):
    FORK = {
        "https://example.com/app": {
            "present": {"X-Frame-Options": "DENY"},
            "missing": ["Content-Security-Policy"],
            "unsafe": {"Strict-Transport-Security": "max-age=0"},
            "deprecated": {"X-XSS-Protection": "1; mode=block"},
            "information_disclosure": {"Server": "nginx/1.10.3"},
            "caching": {"ETag": "abc"},
        }
    }
    ORIGINAL = {
        "https://example.com/app": {
            "present": {"X-Frame-Options": "DENY", "X-XSS-Protection": "1; mode=block"},
            "missing": ["Content-Security-Policy", "Expect-CT", "X-Permitted-Cross-Domain-Policies"],
            "information_disclosure": {"Server": "nginx/1.10.3"},
        }
    }

    def test_fork_record(self):
        [record] = shcheck.normalize_json(self.FORK, [])
        self.assertEqual(record["url"], "https://example.com/app")
        self.assertEqual(record["present"], {"X-Frame-Options": "DENY"})
        self.assertEqual(record["missing"], ["Content-Security-Policy"])
        self.assertEqual(record["unsafe"], {"Strict-Transport-Security": "max-age=0"})
        self.assertEqual(record["deprecated"], {"X-XSS-Protection": "1; mode=block"})
        self.assertEqual(record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_caching_is_discarded(self):
        [record] = shcheck.normalize_json(self.FORK, [])
        self.assertNotIn("caching", record)

    def test_original_deprecated_headers_leave_missing(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["missing"], ["Content-Security-Policy"])

    def test_original_deprecated_headers_move_out_of_present(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["present"], {"X-Frame-Options": "DENY"})
        self.assertEqual(record["deprecated"], {"X-XSS-Protection": "1; mode=block"})

    def test_original_has_no_unsafe_map(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["unsafe"], {})

    def test_both_variants_normalize_alike(self):
        [fork] = shcheck.normalize_json(self.FORK, [])
        [original] = shcheck.normalize_json(self.ORIGINAL, [])
        for key in ("url", "present", "missing", "deprecated", "info_disclosure"):
            self.assertEqual(fork[key], original[key], key)

    def test_info_disclosure_none_when_check_not_run(self):
        data = {"https://x.example": {"present": {}, "missing": [], "unsafe": {}}}
        [record] = shcheck.normalize_json(data, [])
        self.assertIsNone(record["info_disclosure"])

    def test_info_disclosure_empty_dict_when_check_ran_clean(self):
        data = {"https://x.example": {"present": {}, "missing": [], "unsafe": {}, "information_disclosure": {}}}
        [record] = shcheck.normalize_json(data, [])
        self.assertEqual(record["info_disclosure"], {})

    def test_evidence_is_decoded(self):
        data = {
            "https://x.example": {
                "present": {},
                "missing": [],
                "unsafe": {},
                "request": "SEVBRCAv",
                "response": "SFRUUC8xLjEgMjAwIE9L",
            }
        }
        [record] = shcheck.normalize_json(data, [])
        self.assertEqual(record["request"], b"HEAD /")
        self.assertEqual(record["response"], b"HTTP/1.1 200 OK")

    def test_absent_evidence_is_none(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertIsNone(record["request"])
        self.assertIsNone(record["response"])

    def test_undecodable_evidence_is_dropped_with_a_warning(self):
        data = {"https://x.example": {"present": {}, "missing": [], "unsafe": {}, "response": "!!!not base64!!!"}}
        warnings = []
        [record] = shcheck.normalize_json(data, warnings)
        self.assertIsNone(record["response"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("response", warnings[0])

    def test_malformed_entry_is_skipped_but_siblings_survive(self):
        data = {
            "https://good.example": {"present": {}, "missing": ["X-Frame-Options"], "unsafe": {}},
            "https://bad.example": "not an object",
        }
        warnings = []
        records = shcheck.normalize_json(data, warnings)
        self.assertEqual([r["url"] for r in records], ["https://good.example"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad.example", warnings[0])

    def test_multiple_urls_preserve_input_order(self):
        data = {
            "https://b.example": {"present": {}, "missing": [], "unsafe": {}},
            "https://a.example": {"present": {}, "missing": [], "unsafe": {}},
        }
        records = shcheck.normalize_json(data, [])
        self.assertEqual([r["url"] for r in records], ["https://b.example", "https://a.example"])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: collection error — `FileNotFoundError` on `parsers/shcheck/shcheck.py`.

- [ ] **Step 3: Write the implementation**

Create `parsers/shcheck/shcheck.py`:

```python
#!/usr/bin/python3

"""Magenta parser for shcheck, in both its original and forked form.

Handles four input shapes -- JSON and console text, from santoru/shcheck and
from MarioVilas/shcheck -- by converging them on one normalized per-URL record
before any analysis happens. Nothing downstream of normalize_* knows which
variant produced the data.
"""

import base64

# Headers the original tool still lists in sec_headers, so it reports them as
# *missing*. Browsers dropped all three years ago; a report must never advise
# adding one. The fork already models them as deprecated-when-present.
DEPRECATED_HEADER_NAMES = (
    "Expect-CT",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
)


def new_record(url):
    """An empty normalized record.

    info_disclosure starts as None, meaning "the -i check never ran". An empty
    dict means it ran and found nothing; the two must not be conflated or the
    report will claim a clean result for a scan that never looked.
    """
    return {
        "url": url,
        "present": {},
        "missing": [],
        "unsafe": {},
        "deprecated": {},
        "info_disclosure": None,
        "request": None,
        "response": None,
    }


def _decode_evidence(entry, url, warnings):
    decoded = {}
    for key in ("request", "response"):
        blob = entry.get(key)
        if not blob:
            decoded[key] = None
            continue
        try:
            decoded[key] = base64.b64decode(blob, validate=True)
        except Exception:
            warnings.append(
                "could not decode the base64 %s for %s; evidence dropped" % (key, url)
            )
            decoded[key] = None
    return decoded


def _normalize_json_entry(url, entry, warnings):
    record = new_record(url)
    record["present"] = dict(entry.get("present") or {})
    record["missing"] = list(entry.get("missing") or [])
    record["unsafe"] = dict(entry.get("unsafe") or {})
    record["deprecated"] = dict(entry.get("deprecated") or {})

    # Rewrite the original variant's deprecated headers into the fork's model.
    # A no-op on fork data, which never puts these in present or missing.
    for name in DEPRECATED_HEADER_NAMES:
        while name in record["missing"]:
            record["missing"].remove(name)
        if name in record["present"]:
            record["deprecated"][name] = record["present"].pop(name)

    # Absent key means the check never ran; both variants agree on this.
    if "information_disclosure" in entry:
        record["info_disclosure"] = dict(entry["information_disclosure"] or {})

    record.update(_decode_evidence(entry, url, warnings))
    return record


def normalize_json(data, warnings):
    """Normalize either variant's JSON into records, in input order.

    A malformed entry costs its own URL and nothing more: partial results beat
    discarding a whole file over one bad host.
    """
    records = []
    for url, entry in data.items():
        if not isinstance(entry, dict):
            warnings.append("skipped malformed entry for %s" % url)
            continue
        try:
            records.append(_normalize_json_entry(url, entry, warnings))
        except Exception as error:
            warnings.append("skipped malformed entry for %s (%s)" % (url, error))
    return records
```

`headers.py` is deliberately **not** imported yet — nothing in this task calls it, and an unused import fails `ruff check` with `F401`. Task 5 adds the import together with its first use.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 71 tests (58 from Tasks 1-2 + 13 new).

- [ ] **Step 5: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck tests/test_shcheck_parser.py`
Expected: clean. If `F401 unused import` appears, you left the `headers` import in — remove it per the note in Step 3.

- [ ] **Step 6: Checkpoint**

Report for review — **do not commit**:
- `parsers/shcheck/shcheck.py` (new)
- `tests/test_shcheck_parser.py` (modified)

---

### Task 4: Text adapters

Console output from both variants, with ANSI colour stripped. Lossier than JSON, but the fork's `-r` blocks still carry full evidence.

**Files:**
- Modify: `parsers/shcheck/shcheck.py`
- Create: `tests/fixtures/shcheck/fork.txt`, `tests/fixtures/shcheck/original.txt`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: `new_record`, `DEPRECATED_HEADER_NAMES` from Task 3.
- Produces:
  - `strip_ansi(text: str) -> str`
  - `normalize_text(text: str, warnings: list[str]) -> list[dict]` — same record shape as `normalize_json`, handles both variants.

- [ ] **Step 1: Write the fixtures**

Create `tests/fixtures/shcheck/fork.txt` — fork console output, `-A -r`, colours off:

```text

======================================================
 > shcheck.py - santoru ..............................
------------------------------------------------------
 Simple tool to check security headers on a webserver 
======================================================

[*] Analyzing headers of https://example.com/app
---
HTTP Request:
	HEAD /app HTTP/1.1
	Host: example.com
	Connection: close
	
---
HTTP Response:
	HTTP/1.1 200 OK
	Server: nginx/1.10.3
	X-Frame-Options: DENY
	Strict-Transport-Security: max-age=0
	Connection: close
	
---
[*] Header X-Frame-Options is present! (Value: DENY)
[!] Insecure header Strict-Transport-Security is set! (Value: max-age=0)
[!] Header Content-Security-Policy is present but potentially unsafe!
Value:
	default-src 'self' 'unsafe-inline';
[!] Security header missing: Referrer-Policy
[!] Deprecated security header X-XSS-Protection is present! (Value: 1; mode=block)
[!] Possible information disclosure: header Server is present! (Value: nginx/1.10.3)
[!] Cache control header ETag is present! (Value: "abc")
-------------------------------------------------------
[!] Headers analysis results for https://example.com/app
[+] 1 security header(s) present and safe
[-] 2 security header(s) present but unsafe
[-] 1 security header(s) missing
[-] 1 deprecated security header(s) found
[-] 1 potential information disclosure header(s) found

```

Create `tests/fixtures/shcheck/original.txt` — original console output, `-i -x -k`:

```text

======================================================
 > shcheck.py - santoru ..............................
------------------------------------------------------
 Simple tool to check security headers on a webserver 
======================================================

[*] Analyzing headers of https://example.com/app
[*] Effective URL: https://example.com/app
[*] Header X-Frame-Options is present! (Value: DENY)
[!] Insecure header Strict-Transport-Security is set! (Value: max-age=0)
[*] Header Content-Security-Policy is present!
Value:
	default-src: 'self' 'unsafe-inline'
[*] Header X-XSS-Protection is present! (Value: 1; mode=block)
[!] Security header missing: Referrer-Policy
[!] Security header missing: Expect-CT

[!] Possible information disclosure: header Server is present! (Value: nginx/1.10.3)

[!] Cache control header ETag is present! (Value: "abc")
-------------------------------------------------------
[!] Analyzing headers for https://example.com/app
[+] 1 security header(s) present
[-] 2 security header(s) missing

```

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_shcheck_parser.py`:

```python
_FIXTURES = os.path.join(_HERE, "fixtures", "shcheck")


def read_fixture(name):
    with open(os.path.join(_FIXTURES, name), "r", encoding="utf-8") as handle:
        return handle.read()


class TestStripAnsi(unittest.TestCase):
    def test_removes_colour_codes(self):
        self.assertEqual(shcheck.strip_ansi("\033[94mhttps://x\033[0m"), "https://x")

    def test_leaves_plain_text_alone(self):
        self.assertEqual(shcheck.strip_ansi("plain"), "plain")


class TestNormalizeTextFork(unittest.TestCase):
    def setUp(self):
        self.warnings = []
        [self.record] = shcheck.normalize_text(read_fixture("fork.txt"), self.warnings)

    def test_url(self):
        self.assertEqual(self.record["url"], "https://example.com/app")

    def test_present_header_with_value(self):
        self.assertEqual(self.record["present"]["X-Frame-Options"], "DENY")

    def test_insecure_header_lands_in_present_and_unsafe(self):
        self.assertEqual(self.record["present"]["Strict-Transport-Security"], "max-age=0")
        self.assertIn("Strict-Transport-Security", self.record["unsafe"])

    def test_policy_header_value_recovered_from_indented_block(self):
        self.assertEqual(
            self.record["present"]["Content-Security-Policy"],
            "default-src 'self' 'unsafe-inline'",
        )
        self.assertIn("Content-Security-Policy", self.record["unsafe"])

    def test_missing(self):
        self.assertEqual(self.record["missing"], ["Referrer-Policy"])

    def test_deprecated(self):
        self.assertEqual(self.record["deprecated"], {"X-XSS-Protection": "1; mode=block"})

    def test_information_disclosure(self):
        self.assertEqual(self.record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_caching_is_ignored(self):
        self.assertNotIn("ETag", self.record["present"])

    def test_raw_evidence_recovered(self):
        self.assertIn(b"HEAD /app HTTP/1.1", self.record["request"])
        self.assertIn(b"HTTP/1.1 200 OK", self.record["response"])
        self.assertIn(b"\r\n", self.record["request"])


class TestNormalizeTextOriginal(unittest.TestCase):
    def setUp(self):
        self.warnings = []
        [self.record] = shcheck.normalize_text(read_fixture("original.txt"), self.warnings)

    def test_effective_url_wins_over_target(self):
        self.assertEqual(self.record["url"], "https://example.com/app")

    def test_present_header_with_value(self):
        self.assertEqual(self.record["present"]["X-Frame-Options"], "DENY")

    def test_csp_value_recovered_from_indented_block(self):
        self.assertEqual(
            self.record["present"]["Content-Security-Policy"],
            "default-src: 'self' 'unsafe-inline'",
        )

    def test_deprecated_header_moved_out_of_present(self):
        self.assertNotIn("X-XSS-Protection", self.record["present"])
        self.assertEqual(self.record["deprecated"], {"X-XSS-Protection": "1; mode=block"})

    def test_deprecated_header_removed_from_missing(self):
        self.assertEqual(self.record["missing"], ["Referrer-Policy"])

    def test_insecure_header_lands_in_present_and_unsafe(self):
        self.assertEqual(self.record["present"]["Strict-Transport-Security"], "max-age=0")
        self.assertIn("Strict-Transport-Security", self.record["unsafe"])

    def test_information_disclosure(self):
        self.assertEqual(self.record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_no_evidence_available(self):
        self.assertIsNone(self.record["request"])
        self.assertIsNone(self.record["response"])


class TestNormalizeTextEdgeCases(unittest.TestCase):
    def test_ansi_coloured_input_is_handled(self):
        text = read_fixture("fork.txt").replace(
            "https://example.com/app", "\033[94mhttps://example.com/app\033[0m"
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertEqual(record["url"], "https://example.com/app")

    def test_info_disclosure_none_when_check_not_run(self):
        text = "\n".join(
            line
            for line in read_fixture("fork.txt").splitlines()
            if "information disclosure" not in line
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertIsNone(record["info_disclosure"])

    def test_original_no_disclosure_line_means_check_ran_clean(self):
        text = read_fixture("original.txt").replace(
            "[!] Possible information disclosure: header Server is present! (Value: nginx/1.10.3)",
            "[*] No information disclosure headers detected",
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertEqual(record["info_disclosure"], {})

    def test_two_urls_produce_two_records(self):
        text = read_fixture("fork.txt")
        doubled = text + text.replace("example.com", "other.example")
        records = shcheck.normalize_text(doubled, [])
        self.assertEqual([r["url"] for r in records], ["https://example.com/app", "https://other.example/app"])

    def test_unrecognised_lines_produce_one_counted_warning(self):
        text = read_fixture("fork.txt") + "\n[?] something entirely new\n[?] and another\n"
        warnings = []
        shcheck.normalize_text(text, warnings)
        self.assertEqual(len(warnings), 1)
        self.assertIn("2", warnings[0])

    def test_text_with_no_target_line_yields_nothing(self):
        self.assertEqual(shcheck.normalize_text("banner only\n", []), [])
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: FAIL — `AttributeError: module 'shcheck_parser' has no attribute 'strip_ansi'`.

- [ ] **Step 4: Write the implementation**

Add `import re` to the imports in `parsers/shcheck/shcheck.py`, then append:

```python
ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# Lines both variants emit. The fork drops "Effective URL" unless a redirect
# occurred, so the target line is the fallback.
RE_TARGET = re.compile(r"^\[\*\] Analyzing headers of (\S+)")
RE_EFFECTIVE = re.compile(r"^\[\*\] Effective URL: (\S+)")
RE_PRESENT = re.compile(r"^\[\*\] Header (\S+) is present! \(Value: (.*)\)$")
RE_PRESENT_NO_VALUE = re.compile(r"^\[\*\] Header (\S+) is present!$")
RE_INSECURE = re.compile(r"^\[!\] Insecure header (\S+) is set! \(Value: (.*)\)$")
RE_UNSAFE_POLICY = re.compile(r"^\[!\] Header (\S+) is present but potentially unsafe!$")
RE_MISSING = re.compile(r"^\[!\] Security header missing: (\S+)")
RE_DEPRECATED = re.compile(r"^\[!\] Deprecated security header (\S+) is present! \(Value: (.*)\)$")
RE_DISCLOSURE = re.compile(
    r"^\[!\] Possible information disclosure: header (\S+) is present! \(Value: (.*)\)$"
)
RE_NO_DISCLOSURE = re.compile(r"^\[\*\] No information disclosure headers detected")
RE_DISCLOSURE_TALLY = re.compile(r"^\[-\] \d+ potential information disclosure header")

# Lines that are real output but carry nothing we report on.
RE_IGNORED = re.compile(
    r"^(\[!\] Cache control header |\[\*\] No caching headers detected|"
    r"\[\+\] \d+ security header|\[-\] \d+ (security|deprecated)|"
    r"\[!\] (Analyzing headers for|Headers analysis results for)|"
    r"[-=]{3,}|\s*>|\s*Simple tool|\s*$)"
)


def strip_ansi(text):
    return ANSI_RE.sub("", text)


def _flush(record, records):
    if record is not None:
        for name in DEPRECATED_HEADER_NAMES:
            while name in record["missing"]:
                record["missing"].remove(name)
            if name in record["present"]:
                record["deprecated"][name] = record["present"].pop(name)
        records.append(record)


def _collect_indented(lines, index):
    """Consume a tab-indented `Value:` block, returning (text, next_index).

    Both variants pretty-print policy headers across several lines, splitting on
    ';' and re-joining. Whitespace does not survive the round trip; the
    directives do.
    """
    parts = []
    while index < len(lines) and lines[index].startswith("\t"):
        part = lines[index].strip().rstrip(";")
        if part:
            parts.append(part)
        index += 1
    return "; ".join(parts), index


def _collect_raw_block(lines, index):
    """Consume a fork `-r` HTTP block, returning (bytes, next_index)."""
    parts = []
    while index < len(lines) and (lines[index].startswith("\t") or not lines[index].strip()):
        if not lines[index].strip() and not lines[index].startswith("\t"):
            break
        parts.append(lines[index][1:] if lines[index].startswith("\t") else "")
        index += 1
    return ("\r\n".join(parts).rstrip("\r\n") + "\r\n\r\n").encode("utf-8"), index


def normalize_text(text, warnings):
    """Normalize either variant's console output into records, in output order."""
    lines = strip_ansi(text).splitlines()
    records = []
    record = None
    unrecognised = 0
    index = 0

    while index < len(lines):
        line = lines[index]
        index += 1

        match = RE_TARGET.match(line)
        if match:
            _flush(record, records)
            record = new_record(match.group(1))
            continue

        if record is None:
            if not RE_IGNORED.match(line):
                unrecognised += 1
            continue

        match = RE_EFFECTIVE.match(line)
        if match:
            record["url"] = match.group(1)
            continue

        match = RE_PRESENT.match(line)
        if match:
            record["present"][match.group(1)] = match.group(2)
            continue

        match = RE_INSECURE.match(line)
        if match:
            record["present"][match.group(1)] = match.group(2)
            record["unsafe"][match.group(1)] = match.group(2)
            continue

        match = RE_DEPRECATED.match(line)
        if match:
            record["deprecated"][match.group(1)] = match.group(2)
            continue

        match = RE_MISSING.match(line)
        if match:
            record["missing"].append(match.group(1))
            continue

        match = RE_DISCLOSURE.match(line)
        if match:
            if record["info_disclosure"] is None:
                record["info_disclosure"] = {}
            record["info_disclosure"][match.group(1)] = match.group(2)
            continue

        if RE_NO_DISCLOSURE.match(line) or RE_DISCLOSURE_TALLY.match(line):
            if record["info_disclosure"] is None:
                record["info_disclosure"] = {}
            continue

        # A policy header printed across an indented block. The fork announces
        # it as unsafe; the original just prints the value.
        match = RE_UNSAFE_POLICY.match(line) or RE_PRESENT_NO_VALUE.match(line)
        if match:
            name = match.group(1)
            unsafe = bool(RE_UNSAFE_POLICY.match(line))
            if index < len(lines) and lines[index].strip() == "Value:":
                index += 1
            value, index = _collect_indented(lines, index)
            record["present"][name] = value
            if unsafe:
                record["unsafe"][name] = value
            continue

        if line.strip() == "HTTP Request:":
            record["request"], index = _collect_raw_block(lines, index)
            continue

        if line.strip() == "HTTP Response:":
            record["response"], index = _collect_raw_block(lines, index)
            continue

        if not RE_IGNORED.match(line):
            unrecognised += 1

    _flush(record, records)

    if unrecognised:
        warnings.append(
            "ignored %d unrecognised line(s) in text output; the tool version may "
            "be newer than this parser" % unrecognised
        )
    return records
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 96 tests (71 from Tasks 1-3 + 25 new). If the raw-block or indented-block tests fail, adjust `_collect_raw_block` / `_collect_indented` — the fixtures are the specification here, and the trailing tab-only line inside each `-r` block is deliberate (the fork emits it).

- [ ] **Step 6: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck tests/test_shcheck_parser.py`
Expected: clean.

- [ ] **Step 7: Checkpoint**

Report for review — **do not commit**:
- `parsers/shcheck/shcheck.py` (modified)
- `tests/fixtures/shcheck/fork.txt` (new)
- `tests/fixtures/shcheck/original.txt` (new)
- `tests/test_shcheck_parser.py` (modified)

---

### Task 5: Severity, emission, sniffing, and `main`

Turns records into Magenta issues and wires up stdin/stdout. After this task the parser runs end to end for `missing_security_headers`; the second template arrives in Task 6.

**Files:**
- Modify: `parsers/shcheck/shcheck.py`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: `normalize_json`, `normalize_text`, `new_record` (Tasks 3-4); `headers.analyze_all` (Task 2).
- Produces:
  - `SEVERITY_BY_CODE: dict[str, str]`, `DEFAULT_SEVERITY = "low"`, `SEVERITY_ORDER: tuple[str, ...]`
  - `split_url(url: str) -> tuple[str, str]` — returns `(host, path)`
  - `build_issues(record: dict, warnings: list[str]) -> list[dict]`
  - `sniff(raw: str) -> str` — returns `"json"` or `"text"`, raises `ValueError` otherwise
  - `main() -> int`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_shcheck_parser.py`:

```python
import json
import subprocess

_PARSER = os.path.join(_PARSER_DIR, "shcheck.py")


def run_parser(payload):
    """Run the parser as the engine does: stdin in, JSON array out."""
    result = subprocess.run(
        [sys.executable, _PARSER],
        input=payload,
        capture_output=True,
        text=True,
    )
    return result


class TestSplitUrl(unittest.TestCase):
    def test_path_present(self):
        self.assertEqual(shcheck.split_url("https://example.com/app"), ("https://example.com", "/app"))

    def test_no_path_becomes_root(self):
        self.assertEqual(shcheck.split_url("https://example.com"), ("https://example.com", "/"))

    def test_query_is_kept_on_the_path(self):
        self.assertEqual(shcheck.split_url("https://example.com/a?b=c"), ("https://example.com", "/a?b=c"))

    def test_port_stays_on_the_host(self):
        self.assertEqual(shcheck.split_url("https://example.com:8443/x"), ("https://example.com:8443", "/x"))


class TestBuildIssues(unittest.TestCase):
    def _record(self, **overrides):
        record = shcheck.new_record("https://example.com/app")
        record.update(overrides)
        return record

    def test_missing_headers_produce_a_low_issue(self):
        [issue] = shcheck.build_issues(self._record(missing=["Content-Security-Policy"]), [])
        self.assertEqual(issue["template"], "missing_security_headers")
        self.assertEqual(issue["tools"], ["shcheck"])
        self.assertEqual(issue["severity"], "low")
        self.assertEqual(issue["affects"], ["https://example.com/app"])
        self.assertEqual(issue["issues"][0]["host"], "https://example.com")
        self.assertEqual(issue["issues"][0]["path"], "/app")
        self.assertEqual(issue["issues"][0]["details"], ["Content-Security-Policy - missing"])

    def test_hsts_max_age_zero_escalates_to_medium(self):
        record = self._record(present={"Strict-Transport-Security": "max-age=0; includeSubDomains"})
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["severity"], "medium")

    def test_severity_is_the_max_across_details(self):
        record = self._record(
            missing=["Content-Security-Policy"],
            present={"Strict-Transport-Security": "max-age=0; includeSubDomains"},
        )
        [issue] = shcheck.build_issues(record, [])
        details = issue["issues"][0]["details"]
        # A low detail and a medium detail both landed, and the issue took the max.
        # Asserted on content rather than count: a count assertion breaks every time
        # a header rule is added or tuned, without indicating anything is wrong.
        self.assertEqual(issue["severity"], "medium")
        self.assertIn("Content-Security-Policy - missing", details)
        self.assertTrue(any("max-age=0" in d for d in details))

    def test_deprecated_headers_are_reported_as_removable(self):
        record = self._record(deprecated={"X-XSS-Protection": "1; mode=block"})
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["severity"], "low")
        self.assertIn("deprecated", issue["issues"][0]["details"][0])
        self.assertIn("X-XSS-Protection", issue["issues"][0]["details"][0])

    def test_analysis_details_are_header_dash_message(self):
        record = self._record(present={"X-Content-Type-Options": "sniff"})
        [issue] = shcheck.build_issues(record, [])
        self.assertTrue(issue["issues"][0]["details"][0].startswith("X-Content-Type-Options - present but "))

    def test_details_are_sorted_and_unique(self):
        record = self._record(missing=["X-Frame-Options", "Content-Security-Policy", "X-Frame-Options"])
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(
            issue["issues"][0]["details"],
            ["Content-Security-Policy - missing", "X-Frame-Options - missing"],
        )

    def test_evidence_is_re_encoded_as_base64(self):
        record = self._record(missing=["X-Frame-Options"], request=b"HEAD /", response=b"HTTP/1.1 200 OK")
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["issues"][0]["request"], "SEVBRCAv")
        self.assertEqual(issue["issues"][0]["response"], "SFRUUC8xLjEgMjAwIE9L")

    def test_evidence_keys_absent_when_unavailable(self):
        [issue] = shcheck.build_issues(self._record(missing=["X-Frame-Options"]), [])
        self.assertNotIn("request", issue["issues"][0])
        self.assertNotIn("response", issue["issues"][0])

    def test_clean_record_produces_no_issue(self):
        record = self._record(present={"X-Frame-Options": "DENY"}, info_disclosure={})
        self.assertEqual(shcheck.build_issues(record, []), [])

    def test_shcheck_disagreement_is_noted(self):
        # shcheck flagged it, our analysis cleared it: worth a note, not a finding.
        record = self._record(
            present={"X-Content-Type-Options": "nosniff"},
            unsafe={"X-Content-Type-Options": "nosniff"},
        )
        warnings = []
        shcheck.build_issues(record, warnings)
        self.assertEqual(len(warnings), 1)
        self.assertIn("X-Content-Type-Options", warnings[0])

    def test_self_only_disagreement_is_silent(self):
        # shcheck flags any policy containing "self"; that is its bug, not a finding.
        record = self._record(
            present={"Content-Security-Policy": TestCspRules.CLEAN},
            unsafe={"Content-Security-Policy": TestCspRules.CLEAN},
        )
        warnings = []
        shcheck.build_issues(record, warnings)
        self.assertEqual(warnings, [])


class TestSniff(unittest.TestCase):
    def test_json_object(self):
        self.assertEqual(shcheck.sniff('{"https://x": {"present": {}, "missing": [], "unsafe": {}}}'), "json")

    def test_fork_text(self):
        self.assertEqual(shcheck.sniff("[!] Headers analysis results for https://x"), "text")

    def test_original_text(self):
        self.assertEqual(shcheck.sniff("[!] Analyzing headers for https://x"), "text")

    def test_target_line_alone_is_enough(self):
        self.assertEqual(shcheck.sniff("[*] Analyzing headers of https://x"), "text")

    def test_json_array_is_rejected(self):
        with self.assertRaises(ValueError):
            shcheck.sniff("[1, 2, 3]")

    def test_unrelated_text_is_rejected(self):
        with self.assertRaises(ValueError):
            shcheck.sniff("this is a shopping list")


class TestParserSubprocess(unittest.TestCase):
    def test_json_input_round_trip(self):
        payload = json.dumps(
            {"https://example.com/app": {"present": {}, "missing": ["X-Frame-Options"], "unsafe": {}}}
        )
        result = run_parser(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        [issue] = json.loads(result.stdout)
        self.assertEqual(issue["template"], "missing_security_headers")

    def test_text_input_round_trip(self):
        result = run_parser(read_fixture("fork.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)
        issues = json.loads(result.stdout)
        self.assertTrue(issues)

    def test_unrecognised_input_exits_nonzero(self):
        result = run_parser("this is a shopping list")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_json_array_exits_nonzero(self):
        result = run_parser("[1, 2, 3]")
        self.assertEqual(result.returncode, 1)

    def test_clean_scan_emits_empty_array_and_exits_zero(self):
        payload = json.dumps(
            {"https://example.com": {"present": {"X-Frame-Options": "DENY"}, "missing": [], "unsafe": {}}}
        )
        result = run_parser(payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), [])
        self.assertIn("no findings", result.stderr.lower())
```

Add `import sys` to the test file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: FAIL — `AttributeError: module 'shcheck_parser' has no attribute 'split_url'`.

- [ ] **Step 3: Write the implementation**

At the top of `parsers/shcheck/shcheck.py`, add `import json`, `import os`, `import urllib.parse`, and — now that it is used — the module import:

```python
import base64
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import headers as hdr  # noqa: E402  (requires the sys.path line above)
```

Append to the file:

```python
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")
DEFAULT_SEVERITY = "low"

# Everything is low by default. A partial control must never rate worse than a
# missing one, or the report rewards deleting headers. max-age=0 is different
# in kind: it tears down protection the browser had already cached.
SEVERITY_BY_CODE = {
    "hsts-max-age-zero": "medium",
}


def _worst(severities):
    return max(severities, key=SEVERITY_ORDER.index)


def split_url(url):
    """Split a URL into the (host, path) pair the templates expect.

    The templates render `host + path`, so the two must recombine exactly.
    """
    parts = urllib.parse.urlsplit(url)
    host = "%s://%s" % (parts.scheme, parts.netloc)
    path = parts.path or "/"
    if parts.query:
        path = "%s?%s" % (path, parts.query)
    return host, path


def _evidence(record):
    evidence = {}
    if record["request"]:
        evidence["request"] = base64.b64encode(record["request"]).decode("ascii")
    if record["response"]:
        evidence["response"] = base64.b64encode(record["response"]).decode("ascii")
    return evidence


def _note_disagreements(record, findings, warnings):
    """Note where shcheck flagged a header our analysis cleared.

    Suppressed when 'self' was the only trigger: shcheck flags any policy header
    containing the substring "unsafe" or "self", so `script-src 'self'` -- good
    practice -- trips it on nearly every well-configured site.
    """
    flagged = {f.header.lower() for f in findings}
    for name, value in record["unsafe"].items():
        if name.lower() in flagged:
            continue
        lowered = (value or "").lower()
        if "self" in lowered and "unsafe" not in lowered:
            continue
        warnings.append(
            "shcheck flagged %s as unsafe but our analysis found nothing wrong "
            "with it (value: %s)" % (name, value)
        )


def build_issues(record, warnings):
    """Turn one normalized record into zero or more Magenta issues."""
    issues = []
    host, path = split_url(record["url"])
    evidence = _evidence(record)

    details = []
    severities = []

    for name in record["missing"]:
        details.append("%s - missing" % name)
        severities.append(DEFAULT_SEVERITY)

    for name, value in record["deprecated"].items():
        details.append(
            "%s - deprecated header present (value: %s); it should be removed "
            "rather than corrected" % (name, value)
        )
        severities.append(DEFAULT_SEVERITY)

    findings = hdr.analyze_all(record["present"])
    for finding in findings:
        details.append("%s - %s" % (finding.header, finding.message))
        severities.append(SEVERITY_BY_CODE.get(finding.code, DEFAULT_SEVERITY))

    _note_disagreements(record, findings, warnings)

    if details:
        entry = {"host": host, "path": path, "details": sorted(set(details))}
        entry.update(evidence)
        issues.append(
            {
                "template": "missing_security_headers",
                "tools": ["shcheck"],
                "severity": _worst(severities),
                "affects": [record["url"]],
                "issues": [entry],
            }
        )

    if record["info_disclosure"]:
        entry = {"host": host, "path": path, "headers": dict(record["info_disclosure"])}
        entry.update(evidence)
        issues.append(
            {
                "template": "information_disclosure_headers",
                "tools": ["shcheck"],
                "severity": DEFAULT_SEVERITY,
                "affects": [record["url"]],
                "issues": [entry],
            }
        )

    return issues


def sniff(raw):
    """Decide whether the input is shcheck JSON or shcheck console text.

    Raises ValueError when it is neither.
    """
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            raise ValueError("input starts like JSON but does not parse") from None
        if not isinstance(data, dict) or not all(
            isinstance(v, (dict, str)) for v in data.values()
        ):
            raise ValueError("JSON input is not an object of per-URL objects")
        return "json"
    text = strip_ansi(raw)
    for marker in (
        "[!] Headers analysis results for",
        "[!] Analyzing headers for",
        "[*] Analyzing headers of",
    ):
        if marker in text:
            return "text"
    raise ValueError("input does not look like shcheck output")


def main():
    raw = sys.stdin.read()
    warnings = []

    try:
        kind = sniff(raw)
    except ValueError as error:
        sys.stderr.write("ERROR: %s, ignoring input file.\n" % error)
        return 1

    if kind == "json":
        records = normalize_json(json.loads(raw), warnings)
    else:
        records = normalize_text(raw, warnings)

    issues = []
    for record in records:
        issues.extend(build_issues(record, warnings))

    for warning in warnings:
        sys.stderr.write("WARNING: %s\n" % warning)
    if not issues:
        sys.stderr.write(
            "WARNING: no findings in input file. Are you sure this is the right file?\n"
        )

    json.dump(issues, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 122 tests (96 from Tasks 1-4 + 26 new).

- [ ] **Step 5: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck tests/test_shcheck_parser.py`
Expected: clean.

- [ ] **Step 6: Checkpoint**

Report for review — **do not commit**:
- `parsers/shcheck/shcheck.py` (modified)
- `tests/test_shcheck_parser.py` (modified)

---

### Task 6: The `information_disclosure_headers` template

Task 5 already emits issues against this template; without it the engine rejects them with `Unsupported issue template`.

**Files:**
- Create: `templates/shcheck/information_disclosure_headers.json5`
- Create: `templates/shcheck/information_disclosure_headers.es.json5`
- Create: `templates/shcheck/information_disclosure_headers.schema.json`
- Create: `templates/shcheck/information_disclosure_headers.py`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: issue objects from `build_issues` (Task 5) with `issues[].headers` as a name→value map.
- Produces: a template the engine can resolve, and `InfoDisclosureMerger`.

Template names are global by basename ([engine.py:513-563](../../../libmagenta/engine.py#L513-L563)), so `information_disclosure_headers` must not collide with any existing template — it does not today. Required template keys are `title`, `summary`, `description`, `recommendations`, `details` ([engine.py:258](../../../libmagenta/engine.py#L258)); `summary` must be single-line.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_shcheck_parser.py`:

```python
_ROOT = os.path.join(_HERE, "..")
_TEMPLATE_DIR = os.path.join(_ROOT, "templates", "shcheck")


class TestInfoDisclosureTemplate(unittest.TestCase):
    def test_all_four_files_exist(self):
        for name in (
            "information_disclosure_headers.json5",
            "information_disclosure_headers.es.json5",
            "information_disclosure_headers.schema.json",
            "information_disclosure_headers.py",
        ):
            self.assertTrue(os.path.exists(os.path.join(_TEMPLATE_DIR, name)), name)

    def test_template_has_the_required_keys(self):
        import json5

        with open(os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.json5")) as handle:
            data = json5.load(handle)
        for key in ("title", "summary", "description", "recommendations", "details"):
            self.assertIn(key, data)
        self.assertNotIn("\n", data["summary"])

    def test_spanish_template_has_the_required_keys(self):
        import json5

        with open(os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.es.json5")) as handle:
            data = json5.load(handle)
        for key in ("title", "summary", "description", "recommendations", "details"):
            self.assertIn(key, data)

    def test_emitted_issue_validates_against_the_schema(self):
        import jsonschema

        with open(os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.schema.json")) as handle:
            schema = json.load(handle)
        record = shcheck.new_record("https://example.com/app")
        record["info_disclosure"] = {"Server": "nginx/1.10.3"}
        issues = [i for i in shcheck.build_issues(record, []) if i["template"] == "information_disclosure_headers"]
        self.assertEqual(len(issues), 1)
        jsonschema.validate(issues[0], schema)

    def test_missing_security_headers_issue_validates_against_burp_schema(self):
        import jsonschema

        path = os.path.join(_ROOT, "templates", "burp", "missing_security_headers.schema.json")
        with open(path) as handle:
            schema = json.load(handle)
        record = shcheck.new_record("https://example.com/app")
        record["missing"] = ["X-Frame-Options"]
        record["response"] = b"HTTP/1.1 200 OK"
        [issue] = shcheck.build_issues(record, [])
        jsonschema.validate(issue, schema)


class TestInfoDisclosureMerger(unittest.TestCase):
    def _run_merger(self, issues):
        script = os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.py")
        env = dict(os.environ, MAGENTA_HOME=os.path.abspath(_ROOT))
        result = subprocess.run(
            [sys.executable, script],
            input=json.dumps(issues),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def _issue(self, url, headers):
        host, path = shcheck.split_url(url)
        return {
            "template": "information_disclosure_headers",
            "tools": ["shcheck"],
            "severity": "low",
            "affects": [url],
            "issues": [{"host": host, "path": path, "headers": headers}],
        }

    def test_headers_are_unioned_for_the_same_url(self):
        merged = self._run_merger(
            [
                self._issue("https://example.com/app", {"Server": "nginx"}),
                self._issue("https://example.com/app", {"X-Powered-By": "PHP/7.4"}),
            ]
        )
        self.assertEqual(len(merged["issues"]), 1)
        self.assertEqual(merged["issues"][0]["headers"], {"Server": "nginx", "X-Powered-By": "PHP/7.4"})

    def test_different_urls_stay_separate(self):
        merged = self._run_merger(
            [
                self._issue("https://a.example/", {"Server": "nginx"}),
                self._issue("https://b.example/", {"Server": "apache"}),
            ]
        )
        self.assertEqual(len(merged["issues"]), 2)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: FAIL — the four-files assertion fails first.

- [ ] **Step 3: Write the schema**

Create `templates/shcheck/information_disclosure_headers.schema.json`:

```json
{
    "$schema": "https://json-schema.org/draft/2019-09/schema",
    "type": "object",
    "properties": {
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "path": {"type": "string"},
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "minProperties": 1
                    },
                    "request": {"type": "string"},
                    "response": {"type": "string"}
                },
                "required": ["host", "headers"]
            }
        }
    },
    "required": ["issues"]
}
```

- [ ] **Step 4: Write the English template**

Create `templates/shcheck/information_disclosure_headers.json5`.

The details block renders a **bullet list, not a table**: a header value may contain a `|`, which would silently break a GFM table, and Markdown escaping here is context-dependent enough to be worth avoiding entirely. This also keeps the rendering consistent with `missing_security_headers`.

```json5
{
    title: "Information Disclosure in HTTP Headers",

    summary: "{% if affects|length > 1 %}Some web servers were{% else %}A web server was{% endif %} found to be returning HTTP headers that disclose information about the underlying software and its version.",

    description: "{% include 'summary' %}",

    recommendations: "Configure the web server and application framework to suppress or genericise these headers. Most servers offer a directive for this — for example `server_tokens off` in nginx, `ServerTokens Prod` combined with `ServerSignature Off` in Apache, or removing the `X-Powered-By` header in the application framework's configuration. Note that this is a hardening measure rather than a fix for a specific vulnerability: it raises the effort required to fingerprint the stack and match it against known exploits, but does not by itself prevent any attack.",

    details: "{% for x in issues %}***{{ x.host + x.path }}***\n\nThe following HTTP response headers disclosed software information:\n\n{% for k, v in x.headers.items() %}* **{{ k }}**: `{{ v }}`\n{% endfor %}\n{% if x.response is defined %}The following HTTP {% if x.request is defined %}dialog{% else %}response{% endif %} illustrates the issue:\n\n{% if x.request is defined %}**HTTP Request:**\n\n{{ x.request|b64decode|http2md }}\n{% endif %}**HTTP Response Headers:**\n\n{{ x.response|b64decode|http2md(headersonly=True) }}\n{% endif %}{% endfor %}",

    taxonomy: ["CWE-200"],

    references: [
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    ],
}
```

- [ ] **Step 5: Write the Spanish template**

Create `templates/shcheck/information_disclosure_headers.es.json5`. Mirror the structure of `templates/burp/missing_security_headers.es.json5` exactly — same keys, same Jinja expressions, Spanish prose.

```json5
{
    title: "Divulgación de Información en Cabeceras HTTP",

    summary: "{% if affects|length > 1 %}Se encontró que algunos servidores web devolvían{% else %}Se encontró que un servidor web devolvía{% endif %} cabeceras HTTP que revelan información sobre el software subyacente y su versión.",

    description: "{% include 'summary' %}",

    recommendations: "Configure el servidor web y el framework de la aplicación para suprimir o generalizar estas cabeceras. La mayoría de los servidores ofrecen una directiva para ello — por ejemplo `server_tokens off` en nginx, `ServerTokens Prod` junto con `ServerSignature Off` en Apache, o eliminar la cabecera `X-Powered-By` en la configuración del framework. Tenga en cuenta que se trata de una medida de fortalecimiento y no de la corrección de una vulnerabilidad concreta: aumenta el esfuerzo necesario para identificar la tecnología utilizada y buscar exploits conocidos, pero por sí sola no impide ningún ataque.",

    details: "{% for x in issues %}***{{ x.host + x.path }}***\n\nLas siguientes cabeceras de respuesta HTTP revelaron información sobre el software:\n\n{% for k, v in x.headers.items() %}* **{{ k }}**: `{{ v }}`\n{% endfor %}\n{% if x.response is defined %}{% if x.request is defined %}El siguiente diálogo HTTP ilustra{% else %}La siguiente respuesta HTTP ilustra{% endif %} el problema:\n\n{% if x.request is defined %}**Petición HTTP:**\n\n{{ x.request|b64decode|http2md }}\n{% endif %}**Respuesta HTTP (sólo cabeceras):**\n\n{{ x.response|b64decode|http2md(headersonly=True) }}\n{% endif %}{% endfor %}",

    taxonomy: ["CWE-200"],

    references: [
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    ],
}
```

Flag in the Checkpoint that this translation needs a native review pass before it goes into a client report.

- [ ] **Step 6: Write the merger**

Create `templates/shcheck/information_disclosure_headers.py`:

```python
#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger.burp import BurpMerger  # noqa: E402


class InfoDisclosureMerger(BurpMerger):
    """BurpMerger, but unioning the headers map instead of dropping duplicates.

    BurpMerger keys on host+path+method+request+response and keeps only the
    first issue for a given key. That would silently discard a second scan's
    extra headers, so union them first and let BurpMerger handle the rest.
    """

    def do_issues_cleanup(self, issues):
        unioned = {}
        for issue in issues:
            key = (
                issue["host"] + issue.get("path", ""),
                issue.get("request", ""),
                issue.get("response", ""),
            )
            if key in unioned:
                unioned[key]["headers"].update(issue.get("headers", {}))
            else:
                unioned[key] = dict(issue, headers=dict(issue.get("headers", {})))
        return super().do_issues_cleanup(list(unioned.values()))


if __name__ == "__main__":
    InfoDisclosureMerger().run()
```

`Merger.__init__` derives the template name by walking the stack for the first frame outside `libmagenta/merger/`, using `abspath` rather than `realpath` ([merger/\_\_init\_\_.py:22-28](../../../libmagenta/merger/__init__.py#L22-L28)). Running this file directly yields `information_disclosure_headers`, which is correct.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 129 tests (122 from Tasks 1-5 + 7 new).

- [ ] **Step 8: Lint**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck templates/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck templates/shcheck tests/test_shcheck_parser.py`
Expected: clean.

- [ ] **Step 9: Checkpoint**

Report for review — **do not commit**. Say explicitly that the Spanish prose is machine-drafted and wants a native review:
- `templates/shcheck/information_disclosure_headers.json5` (new)
- `templates/shcheck/information_disclosure_headers.es.json5` (new — **needs review**)
- `templates/shcheck/information_disclosure_headers.schema.json` (new)
- `templates/shcheck/information_disclosure_headers.py` (new)
- `tests/test_shcheck_parser.py` (modified)

---

### Task 7: Parser metadata and end-to-end verification

**Files:**
- Create: `parsers/shcheck/shcheck.json5`
- Create: `tests/fixtures/shcheck/shcheck.json`
- Test: `tests/test_shcheck_parser.py`

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: a parser the engine discovers and runs.

The metadata schema allows only `hidden`, `status`, `formats`, `name`, `url`, `description`, and requires `url` and `description` unless hidden ([engine.py:227-244](../../../libmagenta/engine.py#L227-L244)). Extension filtering uses `formats` verbatim, so input files must be named `shcheck.json` or `shcheck.txt`.

- [ ] **Step 1: Write the metadata**

Create `parsers/shcheck/shcheck.json5`:

```json5
{
    name: "shcheck",
    url: "https://github.com/santoru/shcheck",
    description: {
        en: "shcheck checks which security headers are enabled on a web server, and which are missing or misconfigured.",
        es: "shcheck comprueba qué cabeceras de seguridad están habilitadas en un servidor web, y cuáles faltan o están mal configuradas.",
    },
    status: "development",
    formats: ["json", "txt"]
}
```

- [ ] **Step 2: Write the end-to-end fixture**

Create `tests/fixtures/shcheck/shcheck.json` — fork JSON with `-A -r`, exercising a missing header, a misconfigured HSTS, a deprecated header, and an information-disclosure header:

```json
{
  "https://example.com/app": {
    "present": {
      "X-Frame-Options": "DENY",
      "Strict-Transport-Security": "max-age=0; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    },
    "missing": ["Referrer-Policy", "Permissions-Policy"],
    "unsafe": {"Strict-Transport-Security": "max-age=0; includeSubDomains"},
    "deprecated": {"X-XSS-Protection": "1; mode=block"},
    "information_disclosure": {"Server": "nginx/1.10.3"},
    "caching": {"ETag": "\"abc\""},
    "request": "SEVBRCAvYXBwIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo=",
    "response": "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMTAuMw0KDQo="
  }
}
```

- [ ] **Step 3: Write the failing tests**

Append to `tests/test_shcheck_parser.py`:

```python
class TestParserMetadata(unittest.TestCase):
    def test_metadata_validates(self):
        import json5
        import jsonschema

        sys.path.insert(0, os.path.abspath(_ROOT))
        from libmagenta.engine import MagentaReporter

        with open(os.path.join(_PARSER_DIR, "shcheck.json5")) as handle:
            data = json5.load(handle)
        jsonschema.validate(data, MagentaReporter.SCHEMA_PARSER)

    def test_formats_cover_both_extensions(self):
        import json5

        with open(os.path.join(_PARSER_DIR, "shcheck.json5")) as handle:
            data = json5.load(handle)
        self.assertEqual(sorted(data["formats"]), ["json", "txt"])


class TestEndToEnd(unittest.TestCase):
    def test_engine_renders_a_report_from_the_fixture(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            target = os.path.join(workdir, "shcheck.json")
            with open(target, "w") as handle:
                handle.write(read_fixture("shcheck.json"))

            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        # process_files returns a dict, not a tuple:
        # {"metadata", "issues", "sections", "report", "skipped"}
        self.assertEqual(result["skipped"], 0)
        report = result["report"]
        self.assertIn("Missing Security Headers", report)
        self.assertIn("Information Disclosure in HTTP Headers", report)
        self.assertIn("Referrer-Policy", report)
        self.assertIn("nginx/1.10.3", report)

    def test_both_issue_types_survive_validation(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            with open(os.path.join(workdir, "shcheck.json"), "w") as handle:
                handle.write(read_fixture("shcheck.json"))
            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        templates = sorted(issue["template"] for issue in result["issues"])
        self.assertEqual(
            templates, ["information_disclosure_headers", "missing_security_headers"]
        )

    def test_both_templates_resolve(self):
        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        magenta = MagentaReporter()
        magenta.set_language("en")
        self.assertIn("missing_security_headers", magenta.templates)
        self.assertIn("information_disclosure_headers", magenta.templates)
```

`process_files(pathname, metadata=DEFAULT_METADATA, on_error="ignore")` returns a **dict** with keys `metadata`, `issues`, `sections`, `report`, and `skipped` ([engine.py:1183-1242](../../../libmagenta/engine.py#L1183-L1242)) — not a tuple. `DEFAULT_METADATA` carries no `language` key, and `process_files` only overrides the language when the metadata sets one, so the `set_language("en")` call above holds.

- [ ] **Step 4: Run the tests to verify they fail**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: FAIL on the metadata file, then on the end-to-end render.

- [ ] **Step 5: Run the tests to verify they pass**

With Steps 1 and 2 done, run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest tests.test_shcheck_parser -v`
Expected: PASS, 134 tests (129 from Tasks 1-6 + 5 new).

- [ ] **Step 6: Run the whole suite for regressions**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 -m unittest discover -s tests -t .`
Expected: the pre-existing `lxml` error in `test_nikto_parser` and nothing else new. Compare against the baseline recorded in Global Constraints: `Ran 89 tests ... FAILED (errors=1, skipped=11)`. The new total should be 89 + 134 = 223, still with exactly one error and 11 skips.

- [ ] **Step 7: Verify the parser is listed**

Run: `MAGENTA_HOME=$PWD .venv/bin/python3 magenta.py tools`
Expected: `shcheck` appears with `development` status and its English description. The subcommand is `tools` ([magenta.py:240](../../../magenta.py#L240)), not `parsers`.

- [ ] **Step 8: Lint everything**

Run: `ruff check --select E4,E7,E9,F parsers/shcheck templates/shcheck tests/test_shcheck_parser.py && ruff format --check parsers/shcheck templates/shcheck tests/test_shcheck_parser.py`
Expected: clean. Do **not** run a bare `ruff check .` — it reports 254 pre-existing errors across the repo under this machine's ruleset and tells you nothing about your work.

- [ ] **Step 9: Checkpoint**

Report for review — **do not commit**:
- `parsers/shcheck/shcheck.json5` (new)
- `tests/fixtures/shcheck/shcheck.json` (new)
- `tests/test_shcheck_parser.py` (modified)

Then report the full deliverable: seven new files under `parsers/shcheck/` and `templates/shcheck/`, three fixtures, one test module, and no modifications to any existing file.

---

## Follow-ups, deliberately out of scope

Do not do these as part of this plan. Raise them at the final Checkpoint.

- **Backport `headers.py` into `MarioVilas/shcheck`**, replacing the substring-based policy check with directive-level analysis. This is why the module is Magenta-free.
- **Promote the parser to `testing`** in `parsers/shcheck/shcheck.json5` and add a row to the maturity table in `CONTRIB.md` once it has been used against real scans.
- **Native review of the Spanish template.**
- **Rename `BurpMerger`** to something like `HttpIssueMerger`, since two templates now use it and neither is burp-specific.
- **Per-header prose in `missing_security_headers`**, closing the TBDs at lines 6-7 and 10-11 of that template. shcheck now supplies structured per-header data that would make this worthwhile, but it changes burp's output shape too.
