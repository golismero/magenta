# Nikto Parser Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `parsers/nikto/nikto.py` so it parses XML, JSON, and CSV output from all tagged Nikto versions (2.1.5/2.1.6, 2.5.0, 2.6.0, main), classifying references correctly and fixing the broken OSVDB→CVE lookup.

**Architecture:** Normalize-then-emit in a single file. Three format readers (`read_xml`/`read_json`/`read_csv`) each tolerate every version variant and produce a common list of `Finding` records. One `classify_references` applies the full token ruleset; one `build_issues` groups by host and emits the Magenta issue object. `main()` detects the format and dispatches.

**Tech Stack:** Python 3, `lxml` (XML), stdlib `csv`/`json`/`re`. Tests via `unittest`/`pytest`; end-to-end via `magenta.py report`.

**Spec:** `docs/superpowers/specs/2026-05-25-nikto-parser-update-design.md`

---

## File Structure

- **Modify (rewrite):** `parsers/nikto/nikto.py` — the parser. Sections: module setup + `osvdb2cve` load + regexes; `classify_references` (+ helpers); `Finding`; `read_xml`/`read_json`/`read_csv`; `build_issues`; `main`.
- **Modify:** `templates/nikto/multiple_nikto_issues.schema.json` — per-finding `cve` type `string` → `array`.
- **Already done (verify only):** `parsers/nikto/osvdb2cve.json` — contains `OSVDB:11144`/`OSVDB:11145` → `CVE-2002-0764`.
- **Create:** `tests/test_nikto_parser.py` — unit tests (module loaded by path) + reader tests over inline fixtures.
- **Create:** `tmp/samples/nikto/` — sample output files for the `test_cli.py` end-to-end harness.

### Test module loader (used by `tests/test_nikto_parser.py`)

The parser is a standalone script, not a package. Tests load it by path. This snippet is the top of the test file (repeated reference; do not abbreviate):

```python
import os
import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER = os.path.join(_HERE, "..", "parsers", "nikto", "nikto.py")
_spec = importlib.util.spec_from_file_location("nikto_parser", _PARSER)
nikto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nikto)
```

---

## Task 1: Module skeleton + `classify_references` core (tokenize, CVE/CWE/URL)

**Files:**
- Modify: `parsers/nikto/nikto.py`
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_nikto_parser.py`:

```python
import os
import importlib.util
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER = os.path.join(_HERE, "..", "parsers", "nikto", "nikto.py")
_spec = importlib.util.spec_from_file_location("nikto_parser", _PARSER)
nikto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nikto)


class TestClassifyCore(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            nikto.classify_references(""),
            {"cve": [], "taxonomy": [], "references": []},
        )

    def test_single_cve(self):
        out = nikto.classify_references("CVE-2002-0764")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])
        self.assertEqual(out["taxonomy"], [])
        self.assertEqual(out["references"], [])

    def test_comma_and_space_tokenization(self):
        out = nikto.classify_references("CVE-2000-0413,CVE-2000-0709 CVE-2000-0710")
        self.assertEqual(
            out["cve"], ["CVE-2000-0413", "CVE-2000-0709", "CVE-2000-0710"]
        )

    def test_trailing_punctuation_stripped(self):
        out = nikto.classify_references("CVE-2000-0538.")
        self.assertEqual(out["cve"], ["CVE-2000-0538"])

    def test_cwe_goes_to_taxonomy_not_cve(self):
        out = nikto.classify_references("CWE-79")
        self.assertEqual(out["cve"], [])
        self.assertEqual(out["taxonomy"], ["CWE-79"])

    def test_url_goes_to_references(self):
        out = nikto.classify_references("https://example.com/x")
        self.assertEqual(out["references"], ["https://example.com/x"])
        self.assertEqual(out["cve"], [])

    def test_mixed_cve_url(self):
        out = nikto.classify_references(
            "CVE-2002-0599,https://sourceforge.net/projects/blahzdns/"
        )
        self.assertEqual(out["cve"], ["CVE-2002-0599"])
        self.assertEqual(out["references"], ["https://sourceforge.net/projects/blahzdns/"])

    def test_dedup_preserves_order(self):
        out = nikto.classify_references("CVE-2001-0001 CVE-2001-0001 CVE-2001-0002")
        self.assertEqual(out["cve"], ["CVE-2001-0001", "CVE-2001-0002"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestClassifyCore -v`
Expected: FAIL — `module 'nikto_parser' has no attribute 'classify_references'` (or AttributeError on import while the old `main`-only module loads).

- [ ] **Step 3: Replace the top of `parsers/nikto/nikto.py` with the new module setup + core classifier**

Replace lines 1–48 (the imports, `INCLUDE_INFO`, `osvdb2cve` load, and `remove_namespaces`) with:

```python
#!/usr/bin/python3

import io
import re
import csv
import sys
import json
import os.path
import traceback
from collections import namedtuple
from datetime import datetime

from lxml import etree
from lxml.objectify import deannotate

# Set to True to include informational findings (those with no specific
# vulnerability tag) in the report. Mirrors the old OSVDB-0 behaviour.
INCLUDE_INFO = False

# Load the OSVDB to CVE map. Keys are colon-form: "OSVDB:<n>".
osvdb2cve = {}
try:
    with open(os.path.join(os.path.dirname(__file__), "osvdb2cve.json")) as fd:
        osvdb2cve = json.load(fd)
    del fd
except Exception:
    traceback.print_exc()

# A normalized finding produced by every format reader.
Finding = namedtuple("Finding", ["host_url", "path", "method", "refs_str", "nikto_id", "msg"])

# --- reference token patterns -------------------------------------------------
# Specific-vulnerability identifiers (go in the per-finding "cve" column).
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
_MS_RE = re.compile(r"^MS\d{2}-\d+$")               # Microsoft bulletins, e.g. MS00-078
_CNVD_RE = re.compile(r"^CNVD(?:-C)?-\d{4}-\d+$")   # incl. the -C- sub-series
_OSVDB_RE = re.compile(r"^OSVDB-(\d+)$", re.I)
# General-concept / other taxonomy (go in issue-level taxonomy only).
_CWE_RE = re.compile(r"^CWE-\d+$")
_CAPEC_RE = re.compile(r"^CAPEC-\d+$")
_RFC_RE = re.compile(r"^RFC-(\d+)$", re.I)
_MSKB_RE = re.compile(r"^MSKB:Q?(\d+)$", re.I)
_BID_RE = re.compile(r"^BID-\d+$", re.I)
_URL_RE = re.compile(r"^https?://", re.I)

# Token-keyed overrides for known-bad upstream references. Each maps a token to
# (cve, taxonomy, references) contributions. Keyed on the token (not nikto_id),
# because CSV output carries no id column. Each token is unique to its test.
_TOKEN_OVERRIDES = {
    # Phorum 3.3.2a admin GLOBALS[message] XSS. main corrupted OSVDB-11144 into
    # OSVCVE-2011-339244 and mis-tagged the companion test with CVE-2011-3392
    # (a different, later Phorum 5.2.17 vuln). Correct CVE for both: CVE-2002-0764.
    "OSVCVE-2011-339244": (["CVE-2002-0764"], [], []),
    "CVE-2011-3392": (["CVE-2002-0764"], [], []),
}
# Concept-only hardcodes (no specific CVE exists).
# CA-2000-02 is the 2000 CERT advisory that introduced XSS as a concept; the only
# tests using it (000767/768/769) are ASP/ASP.NET reflected XSS -> CWE-79.
_CONCEPT_HARDCODE = {"CA-2000-02": "CWE-79"}
# Known DB-bug junk tokens: token -> the only nikto_id it legitimately appears on.
_KNOWN_JUNK = {"WS_FTP.LOG": "001353"}

# OSVDB lookup hit-rate counters (drift guard). Reset per run in main().
_osvdb_stats = {"mapped": 0, "unmapped": 0}


def reset_osvdb_stats():
    _osvdb_stats["mapped"] = 0
    _osvdb_stats["unmapped"] = 0


def _dedup(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# https://stackoverflow.com/a/71886208/426293
def remove_namespaces(root):
    for elem in root.getiterator():
        if not (
            isinstance(elem, etree._Comment)
            or isinstance(elem, etree._ProcessingInstruction)
        ):
            localname = etree.QName(elem).localname
            if elem.tag != localname:
                elem.tag = etree.QName(elem).localname
            for attr_name in elem.attrib:
                local_attr_name = etree.QName(attr_name).localname
                if attr_name != local_attr_name:
                    attr_value = elem.attrib[attr_name]
                    del elem.attrib[attr_name]
                    elem.attrib[local_attr_name] = attr_value
    deannotate(root, cleanup_namespaces=True)


def classify_references(refs_str, nikto_id=None):
    """Split a Nikto references string into:
      - cve:        specific-vulnerability ids (CVE, MS bulletin, CNVD, OSVDB->CVE)
      - taxonomy:   general-concept tags (CWE, CAPEC, RFC, KB)
      - references: external URLs
    Tokens are split on whitespace and commas. Unknown tokens warn loudly."""
    cve, taxonomy, references = [], [], []
    if refs_str:
        for raw in re.split(r"[\s,]+", refs_str.strip()):
            tok = raw.strip().strip('"\'')
            if tok:
                _classify_token(tok, nikto_id, cve, taxonomy, references)
    return {"cve": _dedup(cve), "taxonomy": _dedup(taxonomy), "references": _dedup(references)}


def _classify_token(tok, nikto_id, cve, taxonomy, references):
    # URLs first — never strip trailing punctuation from a URL.
    if _URL_RE.match(tok):
        references.append(tok)
        return
    # Strip trailing sentence punctuation from id-style tokens.
    tok = tok.rstrip(".;:")
    if not tok:
        return
    if _CVE_RE.match(tok) or _MS_RE.match(tok) or _CNVD_RE.match(tok):
        cve.append(tok)
        return
    if _CWE_RE.match(tok) or _CAPEC_RE.match(tok):
        taxonomy.append(tok)
        return
```

(The remaining token branches — OSVDB, overrides, hardcodes, junk, RFC/MSKB, BID, unknown — are added in Tasks 2 and 3. For now `_classify_token` ends after the CWE/CAPEC branch, so unknown tokens silently fall through; Task 3 adds the loud warning.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestClassifyCore -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): add classify_references core (tokenize, CVE/CWE/URL)"
```

---

## Task 2: OSVDB resolution + hit-rate drift guard

**Files:**
- Modify: `parsers/nikto/nikto.py` (extend `_classify_token`; add `_resolve_osvdb`, `osvdb_hitrate_warning`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_nikto_parser.py`:

```python
class TestOsvdb(unittest.TestCase):
    def test_mapped_osvdb_becomes_cve(self):
        # OSVDB:11144 -> CVE-2002-0764 is present in osvdb2cve.json.
        out = nikto.classify_references("OSVDB-11144")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_unmapped_osvdb_keeps_raw_tag(self):
        out = nikto.classify_references("OSVDB-999999999")
        self.assertEqual(out["cve"], ["OSVDB-999999999"])

    def test_hitrate_guard_warns_when_none_map(self, ):
        import io as _io
        import contextlib
        nikto.reset_osvdb_stats()
        for n in range(12):
            nikto.classify_references("OSVDB-99000%d" % n)  # all unmapped
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.osvdb_hitrate_warning()
        self.assertIn("OSVDB", buf.getvalue())
        self.assertIn("none", buf.getvalue().lower())

    def test_hitrate_guard_silent_when_some_map(self):
        import io as _io
        import contextlib
        nikto.reset_osvdb_stats()
        nikto.classify_references("OSVDB-11144")  # maps
        for n in range(5):
            nikto.classify_references("OSVDB-99000%d" % n)
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.osvdb_hitrate_warning()
        self.assertEqual(buf.getvalue(), "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestOsvdb -v`
Expected: FAIL — `OSVDB-11144` currently falls through unclassified (cve == []), and `osvdb_hitrate_warning` does not exist.

- [ ] **Step 3: Add the OSVDB branch + helpers**

In `_classify_token`, immediately after the CWE/CAPEC branch (before the function ends), add:

```python
    m = _OSVDB_RE.match(tok)
    if m:
        cve.extend(_resolve_osvdb(m.group(1)))
        return
```

Add these module-level functions (next to `reset_osvdb_stats`):

```python
def _resolve_osvdb(num):
    mapped = osvdb2cve.get("OSVDB:" + num)
    if mapped:
        _osvdb_stats["mapped"] += 1
        return list(mapped)
    _osvdb_stats["unmapped"] += 1
    return ["OSVDB-" + num]


def osvdb_hitrate_warning():
    total = _osvdb_stats["mapped"] + _osvdb_stats["unmapped"]
    if total >= 10 and _osvdb_stats["mapped"] == 0:
        sys.stderr.write(
            "WARNING: %d OSVDB ids seen but none mapped to a CVE; the "
            "osvdb2cve.json key format may have drifted (expected 'OSVDB:<n>').\n"
            % total
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestOsvdb -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): resolve OSVDB->CVE with dash/colon fix and hit-rate guard"
```

---

## Task 3: Special-case tokens (overrides, hardcodes, junk, RFC/MSKB/BID, unknown warning)

**Files:**
- Modify: `parsers/nikto/nikto.py` (extend `_classify_token`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_nikto_parser.py`:

```python
import io as _io
import contextlib


class TestSpecialTokens(unittest.TestCase):
    def test_phorum_corrupted_token(self):
        out = nikto.classify_references("OSVCVE-2011-339244")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_phorum_wrong_cve_override(self):
        out = nikto.classify_references("CVE-2011-3392")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_ca_advisory_becomes_cwe79(self):
        out = nikto.classify_references("CA-2000-02")
        self.assertEqual(out["cve"], [])
        self.assertEqual(out["taxonomy"], ["CWE-79"])

    def test_ws_ftp_log_dropped_silently_on_known_id(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("WS_FTP.LOG", nikto_id="001353")
        self.assertEqual(out, {"cve": [], "taxonomy": [], "references": []})
        self.assertEqual(buf.getvalue(), "")

    def test_ws_ftp_log_warns_on_other_id(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.classify_references("WS_FTP.LOG", nikto_id="000001")
        self.assertIn("WS_FTP.LOG", buf.getvalue())

    def test_rfc_dash_normalized_to_space(self):
        out = nikto.classify_references("RFC-5785")
        self.assertEqual(out["taxonomy"], ["RFC 5785"])

    def test_mskb_normalized_to_kb(self):
        out = nikto.classify_references("MSKB:Q231368")
        self.assertEqual(out["taxonomy"], ["KB231368"])

    def test_ms_bulletin_is_cve_bucket(self):
        out = nikto.classify_references("MS00-078")
        self.assertEqual(out["cve"], ["MS00-078"])

    def test_cnvd_is_cve_bucket(self):
        out = nikto.classify_references("CNVD-C-2019-48814")
        self.assertEqual(out["cve"], ["CNVD-C-2019-48814"])

    def test_bid_dropped_silently(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("BID-4684")
        self.assertEqual(out, {"cve": [], "taxonomy": [], "references": []})
        self.assertEqual(buf.getvalue(), "")

    def test_unknown_token_warns_and_drops(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("FROBNICATE-42", nikto_id="012345")
        self.assertEqual(out["cve"], [])
        self.assertIn("FROBNICATE-42", buf.getvalue())
        self.assertIn("012345", buf.getvalue())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestSpecialTokens -v`
Expected: FAIL — overrides/hardcodes/junk/RFC/MSKB/BID/unknown branches not implemented yet.

- [ ] **Step 3: Complete `_classify_token`**

The override/junk/hardcode checks must run BEFORE the generic CVE branch (e.g. `CVE-2011-3392` must hit the override, not the plain CVE branch). Restructure `_classify_token` so the body is exactly (replacing the current partial body):

```python
def _classify_token(tok, nikto_id, cve, taxonomy, references):
    # URLs first — never strip trailing punctuation from a URL.
    if _URL_RE.match(tok):
        references.append(tok)
        return

    # Token-keyed overrides for known-bad upstream references.
    if tok in _TOKEN_OVERRIDES:
        c, t, r = _TOKEN_OVERRIDES[tok]
        cve.extend(c)
        taxonomy.extend(t)
        references.extend(r)
        return

    # Known DB-bug junk tokens. Silent on the test that legitimately carries
    # them; loud anywhere else (we may have a new bug).
    if tok in _KNOWN_JUNK:
        expected = _KNOWN_JUNK[tok]
        if nikto_id is not None and nikto_id != expected:
            sys.stderr.write(
                "WARNING: junk reference token %r on unexpected nikto_id=%s; dropping.\n"
                % (tok, nikto_id)
            )
        return

    # Concept-only hardcodes (e.g. CA-2000-02 -> CWE-79).
    if tok in _CONCEPT_HARDCODE:
        taxonomy.append(_CONCEPT_HARDCODE[tok])
        return

    # Strip trailing sentence punctuation from id-style tokens.
    tok = tok.rstrip(".;:")
    if not tok:
        return

    if _CVE_RE.match(tok) or _MS_RE.match(tok) or _CNVD_RE.match(tok):
        cve.append(tok)
        return
    if _CWE_RE.match(tok) or _CAPEC_RE.match(tok):
        taxonomy.append(tok)
        return
    m = _OSVDB_RE.match(tok)
    if m:
        cve.extend(_resolve_osvdb(m.group(1)))
        return
    m = _RFC_RE.match(tok)
    if m:
        taxonomy.append("RFC " + m.group(1))  # normalize dash->space for url_from_tag
        return
    m = _MSKB_RE.match(tok)
    if m:
        taxonomy.append("KB" + m.group(1))    # normalize MSKB:Q<n> -> KB<n>
        return
    if _BID_RE.match(tok):
        return  # dead taxonomy, no shipped map; drop (known class)

    # Anything else: do not guess. Warn loudly (future-version safety).
    sys.stderr.write(
        "WARNING: unrecognized Nikto reference token %r (nikto_id=%s); dropping.\n"
        % (tok, nikto_id)
    )
```

- [ ] **Step 4: Run the full classifier suite**

Run: `python -m pytest tests/test_nikto_parser.py -k "Classify or Osvdb or SpecialTokens" -v`
Expected: PASS (all classifier tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): special-case tokens (Phorum overrides, CA->CWE, RFC/MSKB norm, BID/unknown)"
```

---

## Task 4: CSV reader (all versions)

**Files:**
- Modify: `parsers/nikto/nikto.py` (replace `parse_nikto_csv` with `read_csv`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
class TestReadCsv(unittest.TestCase):
    OLD = (
        '"Nikto - v2.1.5"\n'
        '"victim.example","10.0.0.1","80","","","","Apache/2.2.3"\n'
        '"victim.example","10.0.0.1","80","OSVDB-3268","GET","/icons/","Directory indexing found."\n'
    )
    NEW = (
        '"Nikto - v2.5.0"\n'
        '"victim.example","10.0.0.1","443","","","","Apache"\n'
        '"victim.example","10.0.0.1","443","CVE-2002-0764","GET","/phorum/admin/footer.php","XSS"\n'
        '"victim.example","10.0.0.1","443","000137","GET","/","SSL Certificate Subject: CN=x"\n'
    )

    def test_old_csv_host_and_finding(self):
        f = nikto.read_csv(self.OLD)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].host_url, "http://victim.example:80")
        self.assertEqual(f[0].path, "/icons/")
        self.assertEqual(f[0].method, "GET")
        self.assertEqual(f[0].refs_str, "OSVDB-3268")
        self.assertEqual(f[0].msg, "Directory indexing found.")

    def test_new_csv_https_and_skips_ssl_row(self):
        f = nikto.read_csv(self.NEW)
        self.assertEqual(len(f), 1)  # SSL 000137 row skipped
        self.assertEqual(f[0].host_url, "https://victim.example:443")
        self.assertEqual(f[0].refs_str, "CVE-2002-0764")

    def test_csv_injection_apostrophe_stripped(self):
        data = (
            '"Nikto - v2.6.0"\n'
            '"h","1.2.3.4","80","\'=CVE-2021-1","GET","/x","msg"\n'
        )
        f = nikto.read_csv(data)
        self.assertEqual(f[0].refs_str, "=CVE-2021-1")

    def test_empty_csv_returns_empty(self):
        self.assertEqual(nikto.read_csv('"Nikto - v2.1.5"\n'), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadCsv -v`
Expected: FAIL — `read_csv` does not exist.

- [ ] **Step 3: Replace `parse_nikto_csv` (old lines ~202–289) with `read_csv`**

```python
def _host_url(hostname, ip, port):
    host = hostname or ip
    use_ssl = str(port) == "443"
    scheme = "https" if use_ssl else "http"
    return "%s://%s:%s" % (scheme, host, port)


def _strip_csv_injection(cell):
    # Nikto prefixes a "'" to cells starting with = + @ - (CSV-injection guard).
    if cell[:1] == "'" and cell[1:2] in ("=", "+", "@", "-"):
        return cell[1:]
    return cell


def read_csv(input_data):
    fd = io.StringIO(input_data)
    fd.readline()  # discard the '"Nikto - v..."' header line
    findings = []
    for row in csv.reader(fd):
        if len(row) < 7:
            continue  # blank/short line
        hostname, ip, port, col4, method, uri, msg = (
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )
        # Host-start rows have empty method+uri (banner sits in col7). Skip.
        if not method and not uri:
            continue
        col4 = _strip_csv_injection(col4)
        # SSL-info rows (2.6.0+) use the pseudo test id 000137 in col4. Skip.
        if col4 == "000137":
            continue
        findings.append(
            Finding(
                host_url=_host_url(hostname, ip, port),
                path=uri,
                method=method,
                refs_str=col4,
                nikto_id=None,  # CSV has no id column
                msg=msg,
            )
        )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadCsv -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): CSV reader for all versions (refs/OSVDB col4, SSL-row skip, injection strip)"
```

---

## Task 5: XML reader (all versions, multi-host, doubled niktoscan, osvdblink vs references)

**Files:**
- Modify: `parsers/nikto/nikto.py` (replace `parse_nikto_xml` with `read_xml`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
class TestReadXml(unittest.TestCase):
    OLD = (
        '<?xml version="1.0" ?>\n'
        '<niktoscan nxmlversion="1.2">'
        '<scandetails targetip="10.0.0.1" targethostname="victim.example" targetport="80">'
        '<item id="000823" osvdbid="11144" osvdblink="http://osvdb.org/11144" method="GET">'
        "<description><![CDATA[Phorum XSS]]></description>"
        "<uri><![CDATA[/phorum/admin/footer.php]]></uri>"
        "<namelink><![CDATA[http://victim.example:80/phorum/admin/footer.php]]></namelink>"
        "<iplink><![CDATA[http://10.0.0.1:80/phorum/admin/footer.php]]></iplink>"
        "</item></scandetails></niktoscan>"
    )
    NEW_MULTIHOST = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<niktoscans>"
        '<niktoscan nxmlversion="1.2"><scandetails targetip="10.0.0.1" targethostname="a.example" targetport="443">'
        '<item id="000100" method="GET"><description><![CDATA[d1]]></description>'
        "<uri><![CDATA[/a]]></uri><namelink><![CDATA[https://a.example:443/a]]></namelink>"
        "<iplink><![CDATA[https://10.0.0.1:443/a]]></iplink>"
        "<references><![CDATA[CVE-2021-1]]></references></item></scandetails></niktoscan>"
        '<niktoscan nxmlversion="1.2"><scandetails targetip="10.0.0.2" targethostname="b.example" targetport="80">'
        '<item id="000200" method="GET"><description><![CDATA[d2]]></description>'
        "<uri><![CDATA[/b]]></uri><namelink><![CDATA[http://b.example:80/b]]></namelink>"
        "<iplink><![CDATA[http://10.0.0.2:80/b]]></iplink>"
        "<references><![CDATA[CVE-2021-2]]></references></item></scandetails></niktoscan>"
        "</niktoscans>"
    )

    def test_old_xml_osvdblink(self):
        f = nikto.read_xml(self.OLD)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].host_url, "http://victim.example:80")
        self.assertEqual(f[0].path, "/phorum/admin/footer.php")
        self.assertEqual(f[0].refs_str, "OSVDB-11144")
        self.assertEqual(f[0].nikto_id, "000823")

    def test_new_xml_references_child_multihost(self):
        f = nikto.read_xml(self.NEW_MULTIHOST)
        self.assertEqual(len(f), 2)
        hosts = sorted(x.host_url for x in f)
        self.assertEqual(hosts, ["http://b.example:80", "https://a.example:443"])
        self.assertEqual(
            sorted(x.refs_str for x in f), ["CVE-2021-1", "CVE-2021-2"]
        )

    def test_doubled_niktoscan_wrapper(self):
        doubled = self.OLD.replace(
            '<niktoscan nxmlversion="1.2">',
            '<niktoscan><niktoscan nxmlversion="1.2">',
        ).replace("</scandetails></niktoscan>", "</scandetails></niktoscan></niktoscan>")
        f = nikto.read_xml(doubled)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].path, "/phorum/admin/footer.php")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadXml -v`
Expected: FAIL — `read_xml` does not exist.

- [ ] **Step 3: Add `read_xml`**

```python
def _parse_xml_tolerant(input_data):
    """Parse Nikto XML, tolerating its historically not-well-formed output."""
    try:
        return etree.fromstring(input_data.encode("utf-8")
                                if isinstance(input_data, str) else input_data)
    except etree.XMLSyntaxError:
        # Strip the XML declaration and wrap the remainder in a single root.
        body = re.sub(r"^\s*<\?xml[^>]*\?>", "", input_data, count=1).strip()
        wrapped = "<niktontwrap>%s</niktontwrap>" % body
        return etree.fromstring(wrapped.encode("utf-8"))


def _text(elem, tag):
    child = elem.find(tag)
    return child.text if child is not None and child.text is not None else None


def read_xml(input_data):
    root = _parse_xml_tolerant(input_data)
    remove_namespaces(root)
    findings = []
    # Iterate every <scandetails> regardless of niktoscan/niktoscans nesting
    # (handles single root, plural wrapper, and the doubled-niktoscan quirk).
    scandetails_list = list(root.iter("scandetails"))
    if root.tag == "scandetails":
        scandetails_list = [root]
    for sd in scandetails_list:
        host_url = _host_url(
            sd.attrib.get("targethostname"),
            sd.attrib.get("targetip"),
            sd.attrib.get("targetport") or "80",
        )
        for item in sd.iter("item"):
            uri = _text(item, "uri")
            if uri is None:
                continue  # informational scanner message (no uri); not a finding
            # References: <references> child (2.5.0+) or osvdblink attr (old).
            refs_str = _text(item, "references")
            if not refs_str:
                link = item.attrib.get("osvdblink")
                if link:
                    num = link.rstrip("/").rsplit("/", 1)[-1]
                    refs_str = "OSVDB-" + num
                else:
                    refs_str = ""
            findings.append(
                Finding(
                    host_url=host_url,
                    path=uri,
                    method=item.attrib.get("method", ""),
                    refs_str=refs_str,
                    nikto_id=item.attrib.get("id"),
                    msg=_text(item, "description") or "",
                )
            )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadXml -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): XML reader (multi-host, doubled niktoscan, osvdblink+references)"
```

---

## Task 6: JSON reader (2.6.0/main array + 2.5.0 fragment repair)

**Files:**
- Modify: `parsers/nikto/nikto.py` (add `read_json`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
class TestReadJson(unittest.TestCase):
    MODERN = json.dumps([
        {
            "host": "a.example", "ip": "10.0.0.1", "port": "443",
            "server_banner": "Apache",
            "vulnerabilities": [
                {"id": "000100", "references": "CVE-2021-1",
                 "method": "GET", "url": "https://a.example:443/a", "msg": "m1"},
            ],
        },
        {
            "host": "b.example", "ip": "10.0.0.2", "port": "80",
            "server_banner": "nginx",
            "vulnerabilities": [
                {"id": "000200", "references": "", "method": "GET",
                 "url": "http://b.example:80/b", "msg": "m2"},
            ],
        },
    ])
    # 2.5.0 hand-built, multi-host -> invalid JSON (two objects, no array/commas)
    OLD_FRAGMENT = (
        '{"host":"a.example","ip":"10.0.0.1","port":"443","banner":"Apache",'
        '"vulnerabilities":[{"id": "000100","references": "CVE-2021-1",'
        '"method":"GET","url":"https://a.example:443/a","msg":"m1"}]}'
        '{"host":"b.example","ip":"10.0.0.2","port":"80","banner":"nginx",'
        '"vulnerabilities":[{"id": "000200","method":"GET",'
        '"url":"http://b.example:80/b","msg":"m2"}]}'
    )

    def test_modern_array(self):
        f = nikto.read_json(self.MODERN)
        self.assertEqual(len(f), 2)
        a = [x for x in f if x.host_url == "https://a.example:443"][0]
        self.assertEqual(a.path, "/a")
        self.assertEqual(a.refs_str, "CVE-2021-1")
        self.assertEqual(a.nikto_id, "000100")

    def test_old_fragment_repaired(self):
        f = nikto.read_json(self.OLD_FRAGMENT)
        self.assertEqual(len(f), 2)
        self.assertEqual(sorted(x.path for x in f), ["/a", "/b"])

    def test_unrepairable_warns_and_returns_empty(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.read_json("{ totally not json ][")
        self.assertEqual(out, [])
        self.assertIn("JSON", buf.getvalue())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadJson -v`
Expected: FAIL — `read_json` does not exist.

- [ ] **Step 3: Add `read_json`**

```python
def _path_from_url(url, host_url):
    if url and url.startswith(host_url):
        return url[len(host_url):] or "/"
    return url or "/"


def _findings_from_json_hosts(hosts):
    findings = []
    for host in hosts:
        host_url = _host_url(host.get("host"), host.get("ip"), host.get("port") or "80")
        for v in host.get("vulnerabilities", []):
            url = v.get("url", "")
            findings.append(
                Finding(
                    host_url=host_url,
                    path=_path_from_url(url, host_url),
                    method=v.get("method", ""),
                    refs_str=v.get("references", "") or "",
                    nikto_id=v.get("id"),
                    msg=v.get("msg", "") or "",
                )
            )
    return findings


def read_json(input_data):
    data = None
    try:
        data = json.loads(input_data)
    except ValueError:
        # 2.5.0 emitted concatenated per-host objects (invalid for >1 host).
        # Repair: insert commas between adjacent objects and wrap in an array.
        repaired = input_data.strip().replace("}{", "},{")
        if not repaired.startswith("["):
            repaired = "[" + repaired + "]"
        try:
            data = json.loads(repaired)
        except ValueError:
            sys.stderr.write(
                "WARNING: could not parse Nikto JSON (and 2.5.0 fragment repair "
                "failed); skipping.\n"
            )
            return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        sys.stderr.write("WARNING: unexpected Nikto JSON shape; skipping.\n")
        return []
    return _findings_from_json_hosts(data)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestReadJson -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): JSON reader (2.6.0 array + 2.5.0 fragment repair)"
```

---

## Task 7: `build_issues` (grouping, inclusion rule, taxonomy/references split, dedup)

**Files:**
- Modify: `parsers/nikto/nikto.py` (add `build_issues`)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
class TestBuildIssues(unittest.TestCase):
    def _f(self, host, path, refs, msg, nid=None, method="GET"):
        return nikto.Finding(host, path, method, refs, nid, msg)

    def test_basic_issue_shape(self):
        findings = [self._f("http://h:80", "/a", "CVE-2021-1", "m1")]
        issues = nikto.build_issues(findings)
        self.assertEqual(len(issues), 1)
        iss = issues[0]
        self.assertEqual(iss["tools"], ["nikto"])
        self.assertEqual(iss["template"], "multiple_nikto_issues")
        self.assertEqual(iss["severity"], "high")
        self.assertEqual(iss["affects"], ["http://h:80/a"])
        self.assertEqual(iss["taxonomy"], ["CVE-2021-1"])
        self.assertEqual(iss["issues"], {"http://h:80": [
            {"path": "/a", "cve": ["CVE-2021-1"], "msg": "m1"}]})

    def test_untagged_finding_dropped_by_default(self):
        findings = [self._f("http://h:80", "/x", "", "interesting file", nid="000001")]
        self.assertEqual(nikto.build_issues(findings), [])

    def test_ca_finding_reported_with_cwe_taxonomy_empty_cve_column(self):
        findings = [self._f("http://h:80", "/y.aspx", "CA-2000-02", "xss", nid="000767")]
        issues = nikto.build_issues(findings)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["taxonomy"], ["CWE-79"])
        # per-finding cve column is empty (CWE is a concept, not a specific vuln id)
        self.assertEqual(issues[0]["issues"]["http://h:80"][0]["cve"], [])

    def test_url_reference_goes_to_issue_references(self):
        findings = [self._f("http://h:80", "/z", "CVE-2021-9 https://ref.example/x", "m")]
        issues = nikto.build_issues(findings)
        self.assertEqual(issues[0]["references"], ["https://ref.example/x"])

    def test_multi_host_grouping_and_dedup(self):
        findings = [
            self._f("http://h:80", "/a", "CVE-2021-1", "m1"),
            self._f("http://h:80", "/a", "CVE-2021-1", "m1"),  # dup
            self._f("https://k:443", "/b", "CVE-2021-2", "m2"),
        ]
        issues = nikto.build_issues(findings)
        self.assertEqual(set(issues[0]["issues"].keys()), {"http://h:80", "https://k:443"})
        self.assertEqual(len(issues[0]["issues"]["http://h:80"]), 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestBuildIssues -v`
Expected: FAIL — `build_issues` does not exist.

- [ ] **Step 3: Add `build_issues`**

```python
def build_issues(findings):
    by_host = {}            # host_url -> list[ {path, cve, msg} ]
    all_taxonomy = []
    all_references = []
    affects = []
    for f in findings:
        cls = classify_references(f.refs_str, f.nikto_id)
        tags = cls["cve"] + cls["taxonomy"]
        # Inclusion rule: report only findings carrying >=1 taxonomy tag.
        # Untagged findings are informational (old OSVDB-0 behaviour).
        if not tags and not INCLUDE_INFO:
            continue
        entry = {"path": f.path, "cve": cls["cve"], "msg": f.msg}
        host_list = by_host.setdefault(f.host_url, [])
        if entry not in host_list:
            host_list.append(entry)
        affects.append(f.host_url + f.path)
        all_taxonomy.extend(tags)
        all_references.extend(cls["references"])
    if not by_host:
        return []
    issue = {
        "tools": ["nikto"],
        "template": "multiple_nikto_issues",
        "severity": "high",
        "affects": sorted(set(affects)),
        "taxonomy": sorted(set(all_taxonomy)),
        "references": sorted(set(all_references)),
        "issues": by_host,
    }
    if not issue["taxonomy"]:
        del issue["taxonomy"]
    if not issue["references"]:
        del issue["references"]
    return [issue]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestBuildIssues -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): build_issues with tag-based inclusion rule and host grouping"
```

---

## Task 8: `main()` dispatch + remove dead code

**Files:**
- Modify: `parsers/nikto/nikto.py` (rewrite `main`; delete old `parse_nikto_xml`/`parse_nikto_csv` remnants)
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
import subprocess
import sys as _sys


class TestMainDispatch(unittest.TestCase):
    def _run(self, stdin_text):
        p = subprocess.run(
            [_sys.executable, _PARSER],
            input=stdin_text, capture_output=True, text=True,
        )
        return p

    def test_xml_end_to_end(self):
        p = self._run(TestReadXml.OLD)
        out = json.loads(p.stdout)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["template"], "multiple_nikto_issues")
        self.assertIn("CVE-2002-0764", out[0]["taxonomy"])

    def test_csv_end_to_end(self):
        p = self._run(TestReadCsv.NEW)
        out = json.loads(p.stdout)
        self.assertEqual(out[0]["issues"]["https://victim.example:443"][0]["cve"],
                         ["CVE-2002-0764"])

    def test_json_end_to_end(self):
        p = self._run(TestReadJson.MODERN)
        out = json.loads(p.stdout)
        self.assertEqual(len(out), 1)

    def test_empty_input(self):
        p = self._run("")
        self.assertEqual(json.loads(p.stdout), [])

    def test_garbage_input(self):
        p = self._run("this is not nikto output\n")
        self.assertEqual(json.loads(p.stdout), [])
        self.assertIn("nikto", p.stderr.lower())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestMainDispatch -v`
Expected: FAIL — old `main` still references removed `parse_nikto_xml`/`parse_nikto_csv`.

- [ ] **Step 3: Rewrite `main` and remove dead functions**

Replace the existing `main()` (and ensure the old `parse_nikto_xml`/`parse_nikto_csv` are fully removed — they are superseded by `read_xml`/`read_csv`) with:

```python
def main():
    input_data = sys.stdin.read()

    if not input_data.strip():
        sys.stderr.write("Empty file received, surely this is an error?\n")
        json.dump([], sys.stdout)
        return

    reset_osvdb_stats()
    stripped = input_data.lstrip()

    if stripped.startswith("<?xml") or stripped.startswith("<niktoscan"):
        findings = read_xml(input_data)
    elif stripped[:1] in ("[", "{"):
        findings = read_json(input_data)
    elif re.match(r'"Nikto - v.*"', stripped):
        findings = read_csv(input_data)
    else:
        sys.stderr.write(
            "Invalid file type, are you sure this was generated by nikto.pl?\n"
        )
        json.dump([], sys.stdout)
        return

    output = build_issues(findings)
    osvdb_hitrate_warning()
    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest tests/test_nikto_parser.py -v`
Expected: PASS (all classes).

- [ ] **Step 5: Lint**

Run: `ruff check parsers/nikto/nikto.py`
Expected: no errors. (Fix any unused-import warnings from the rewrite.)

- [ ] **Step 6: Commit**

```bash
git add tests/test_nikto_parser.py parsers/nikto/nikto.py
git commit -m "feat(nikto): format-detecting main dispatch; remove legacy parse functions"
```

---

## Task 9: Schema fix (per-finding `cve` string → array)

**Files:**
- Modify: `templates/nikto/multiple_nikto_issues.schema.json:13`
- Test: `tests/test_nikto_parser.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
class TestSchema(unittest.TestCase):
    def test_cve_is_array_in_schema(self):
        path = os.path.join(_HERE, "..", "templates", "nikto",
                            "multiple_nikto_issues.schema.json")
        with open(path) as fd:
            schema = json.load(fd)
        cve = (schema["properties"]["issues"]["additionalProperties"]
               ["items"]["properties"]["cve"])
        self.assertEqual(cve["type"], "array")
        self.assertEqual(cve["items"]["type"], "string")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_nikto_parser.py::TestSchema -v`
Expected: FAIL — `cve.type` is currently `"string"`.

- [ ] **Step 3: Edit the schema**

In `templates/nikto/multiple_nikto_issues.schema.json`, change:

```json
                        "cve": {"type": "string"},
```

to:

```json
                        "cve": {"type": "array", "items": {"type": "string"}},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_nikto_parser.py::TestSchema -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add templates/nikto/multiple_nikto_issues.schema.json tests/test_nikto_parser.py
git commit -m "fix(nikto): schema per-finding cve is an array of strings"
```

---

## Task 10: End-to-end sample + `magenta.py report` rendering

**Files:**
- Create: `tmp/samples/nikto/scan.xml` (a real-shaped fixture)
- Test: manual `magenta.py` run (sample dir is consumed by `tests/test_cli.py`)

- [ ] **Step 1: Create a representative sample**

Create `tmp/samples/nikto/scan.xml` (modern multi-finding, single host):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<niktoscans>
  <niktoscan nxmlversion="1.2">
    <scandetails targetip="10.0.0.1" targethostname="victim.example" targetport="443" starttime="2026-05-25 10:00:00">
      <item id="000823" method="GET">
        <description><![CDATA[Phorum 3.3.2a and below is vulnerable to XSS.]]></description>
        <uri><![CDATA[/phorum/admin/footer.php]]></uri>
        <namelink><![CDATA[https://victim.example:443/phorum/admin/footer.php]]></namelink>
        <iplink><![CDATA[https://10.0.0.1:443/phorum/admin/footer.php]]></iplink>
        <references><![CDATA[OSVCVE-2011-339244]]></references>
      </item>
      <item id="000767" method="GET">
        <description><![CDATA[XSS is allowed with .aspx file requests.]]></description>
        <uri><![CDATA[/~/<script>alert(1)</script>.aspx]]></uri>
        <namelink><![CDATA[https://victim.example:443/x.aspx]]></namelink>
        <iplink><![CDATA[https://10.0.0.1:443/x.aspx]]></iplink>
        <references><![CDATA[CA-2000-02]]></references>
      </item>
    </scandetails>
  </niktoscan>
</niktoscans>
```

- [ ] **Step 2: Verify the parser handles it**

Run: `python parsers/nikto/nikto.py < tmp/samples/nikto/scan.xml`
Expected: a one-element JSON array; `taxonomy` contains `CVE-2002-0764` and `CWE-79`; no WARNING on stderr.

- [ ] **Step 3: Render end-to-end via magenta**

Run: `python magenta.py report tmp/samples -o /tmp/nikto-report.md -f markdown` (use a format your build supports; `textile`/`dradis` require pandoc).
Expected: exits 0; the output references the Nikto findings table.

- [ ] **Step 4: Run the project test suite**

Run: `python -m pytest tests/ -v`
Expected: PASS (new `test_nikto_parser.py` plus existing tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add tmp/samples/nikto/scan.xml
git commit -m "test(nikto): add end-to-end XML sample for report rendering"
```

---

## Optional follow-up (not required for Phase A completion)

- Generate real fixtures by running each tagged Nikto (`2.1.6`, `2.5.0`, `2.6.0`, `main`) against a throwaway local HTTP server in XML/JSON/CSV, and add them under `tmp/samples/nikto/` and as reader tests. Also fold in dradis-nikto's `sample_v2.1.4.xml` / `sample_v2.5.0.xml`.
- Update `CONTRIB.md` to move Nikto out of any "outdated" status note now that multi-version support exists (line numbers there will have shifted).
