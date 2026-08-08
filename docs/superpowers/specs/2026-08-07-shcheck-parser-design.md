# shcheck parser

**Date:** 2026-08-07
**Status:** Approved design, pending implementation plan
**Author:** Mario Vilas (with Claude Code)

## Problem

Magenta has no parser for [shcheck](https://github.com/santoru/shcheck), a security-header
scanner. Two variants of the tool are in use and both must be supported by a single parser:

- **Original** — `santoru/shcheck`, pinned at commit `c29405c` for this design.
- **Fork** — `MarioVilas/shcheck`, pinned at commit `0896c9d`, which adds an `unsafe{}`
  verdict map, a `deprecated{}` map, raw HTTP request/response capture (`-r`), an output
  file option (`-o`), and a library-shaped `Scanner` class.

The two variants emit JSON with overlapping but non-identical schemas, and they disagree
semantically about deprecated headers. Both also emit a human-readable console format that
users capture by redirection.

## Goals

- One parser at `parsers/shcheck/` handling both variants, in both JSON and text form.
- Reuse the existing `missing_security_headers` template rather than duplicating it.
- Perform Magenta's own header-value analysis so the original tool reaches the same
  finding quality as the fork.
- Keep that analysis portable, so it can later be backported into the fork.

## Non-goals

- **Caching headers are not reported.** shcheck's `-x` lists cache headers without passing
  judgement; any finding derived from them would be Magenta inventing a verdict shcheck
  never made. Revisit only if a concrete cacheable-sensitive-response rule is wanted.
- **CSP bypass research.** Directive-level analysis only — no JSONP endpoint or
  bypassable-CDN knowledge base.
- **`Permissions-Policy` value analysis.** Presence-only; generic judgement of a policy
  list produces noise rather than findings.

## Context: how Magenta dispatches parsers

Three engine mechanics constrain this design.

**Files are matched by name, then filtered by extension.**
[`process_files`](../../../libmagenta/engine.py#L1196-L1209) globs `<tool>.*` under the
input directory and drops any match whose extension is absent from the parser's `formats`
list. Input files must therefore be named `shcheck.json` or `shcheck.txt` (infixes such as
`shcheck.prod.json` are permitted by the glob).

**Parsers are subprocesses over stdin/stdout.**
[`run_parser`](../../../libmagenta/engine.py#L1089-L1104) opens the file as stdin, expects
a JSON array of issue objects on stdout, and enforces a 10-second timeout. The engine then
adds the g3 underscore fields via `_g3_wrap_issue` and validates each issue against its
template schema, discarding — not failing on — individual malformed issues.

**Template names are global.**
[`_find_templates`](../../../libmagenta/engine.py#L513-L563) walks `templates/`
recursively and keys every template by **basename alone**, asserting global uniqueness at
[engine.py:557](../../../libmagenta/engine.py#L557). Subdirectories are organisational
only. Two consequences: `templates/burp/missing_security_headers.json5` is reachable from
any parser, and a `templates/shcheck/missing_security_headers.json5` would be a name
collision, not an override.

## Architecture

```text
stdin ──► sniff ──► normalize (1 of 4) ──► analyze ──► emit
              │            │                  │           │
       json.loads?    per-format         headers.py    Magenta
       ANSI strip     adapters          (portable)     issues
```

Four input adapters converge on one normalized record; a single analysis stage consumes it
without knowing which variant produced the data. Adding a future shcheck output revision
costs one adapter and nothing else.

### Files

| Path | Status | Purpose |
|---|---|---|
| `parsers/shcheck/shcheck.py` | new | Sniffing, normalization, emission |
| `parsers/shcheck/shcheck.json5` | new | Metadata; `formats: ["json", "txt"]`, `status: "development"` |
| `parsers/shcheck/headers.py` | new | Portable header-value analysis |
| `templates/shcheck/information_disclosure_headers.json5` | new | `-i` findings |
| `templates/shcheck/information_disclosure_headers.es.json5` | new | Spanish translation |
| `templates/shcheck/information_disclosure_headers.schema.json` | new | Input schema |
| `templates/shcheck/information_disclosure_headers.py` | new | Merger — instantiates `BurpMerger` |
| `templates/burp/missing_security_headers.*` | **unchanged** | Reused for missing / unsafe / deprecated |

The parser must keep all work inside functions behind `if __name__ == "__main__":`, as
nikto and graphqlcop do. `parsers/wafw00f/wafw00f.py` reads stdin at module scope, which
makes it unimportable and untestable by the `importlib` pattern used in
`tests/test_nikto_parser.py`; that pattern is not followed here.

## Input detection

| Shape | Discriminator |
|---|---|
| Fork JSON | `json.loads()` succeeds; dict of dicts, each value carries an `"unsafe"` key |
| Original JSON | `json.loads()` succeeds; dict of dicts with `"present"` + `"missing"`, no `"unsafe"` |
| Fork text | Not JSON; contains `[!] Headers analysis results for` |
| Original text | Not JSON; contains `[!] Analyzing headers for`, and `security header(s) present` without `and safe` |

ANSI escape sequences are stripped before text detection. A redirected terminal session
retains colour codes unless `--colours=none` was passed, and both variants colourize by
default.

## Normalized record

One record per scanned URL:

```python
{
    "url": "https://example.com/",
    "present":    {"Content-Security-Policy": "default-src *", ...},   # name -> raw value
    "missing":    ["X-Frame-Options", ...],                            # deprecated names removed
    "unsafe":     {"Strict-Transport-Security": "max-age=0"},          # tool verdict, advisory
    "deprecated": {"X-XSS-Protection": "1; mode=block"},               # present and obsolete
    "info_disclosure": {"Server": "nginx/1.10.3"},   # or None = check not run
    "request":  b"HEAD / HTTP/1.1\r\n...",           # or None
    "response": b"HTTP/1.1 200 OK\r\n...",           # or None
}
```

`None` versus `{}` for `info_disclosure` is load-bearing. Both variants write an empty dict
when the check ran and found nothing, and omit the key entirely when the check never ran —
the fork documents this explicitly in a comment above its deprecated-header loop. A report
must not claim a clean information-disclosure result for a scan that never passed `-i`.

### Normalization rules

**Deprecated headers, original variant.** The original keeps `X-XSS-Protection`,
`Expect-CT`, and `X-Permitted-Cross-Domain-Policies` inside its `sec_headers` dict
(`shcheck/shcheck.py:63-76` at `c29405c`), so with `-k` they are reported as *missing*. Fed
through verbatim, Magenta would advise a client to **add Expect-CT**, dead since Chrome
107. The adapter therefore:

- removes those three names from `missing[]`;
- moves them from `present{}` into `deprecated{}`.

The fork already models them this way in its own `DEPRECATED_HEADERS` dict. After the
rewrite, the two variants' records are structurally identical.

**`unsafe{}` is advisory, never load-bearing.** Magenta analyses raw values from
`present{}` itself, so the original variant reaches full parity on misconfiguration
detection despite never emitting `unsafe`. The fork's `unsafe{}` serves only as a
cross-check (see *Known disagreement* below).

**Text mode is lossy, but not evidence-free.** Fork text captured with `-r` carries the
complete raw request and response as tab-indented blocks, so evidence survives. Original
text carries no raw HTTP at all. CSP values in both text modes pass through a pretty-printer
that splits on `;` and re-joins, so they are recoverable with whitespace normalized. The
parser emits a stderr warning naming exactly what was degraded.

## Analysis: `headers.py`

Pure module — stdlib only, no I/O, no Magenta concepts. Two entry points:

```python
Finding = namedtuple("Finding", "header code message")

def analyze(name: str, value: str) -> list[Finding]
    """Findings for one header in isolation."""

def analyze_all(present: dict[str, str]) -> list[Finding]
    """analyze() across every present header, plus cross-header suppressions."""
```

The parser calls `analyze_all`. `analyze` is public because it is the unit-testable core
and the more natural shape for a future backport into shcheck's per-header display loop.

It reports **what is wrong**, never **how bad it is**. Severity is policy and lives in the
parser; findings are facts and live here. That split is what allows the module to be
dropped into the fork, whose severity vocabulary (`error` / `warning` / `info` colour tags)
is incompatible with Magenta's (`none` → `critical`).

| Header | Code | Trigger |
|---|---|---|
| Content-Security-Policy | `csp-unsafe-inline` | `'unsafe-inline'` in `script-src`/`style-src`, honouring `default-src` fallback |
| | `csp-unsafe-eval` | `'unsafe-eval'` in `script-src` |
| | `csp-wildcard` | bare `*` as a source in a fetch directive |
| | `csp-no-default-src` | neither `default-src` nor `script-src` present |
| | `csp-no-frame-ancestors` | no `frame-ancestors` directive |
| | `csp-no-object-src` | no `object-src` and no `default-src` |
| | `csp-no-base-uri` | no `base-uri` directive |
| Strict-Transport-Security | `hsts-max-age-zero` | `max-age=0` |
| | `hsts-max-age-short` | `max-age` < 15768000 (six months) |
| | `hsts-no-include-subdomains` | directive absent |
| | `hsts-malformed` | no `max-age` directive at all |
| X-Frame-Options | `xfo-allow-from` | `ALLOW-FROM`, unsupported by every current browser |
| | `xfo-invalid` | value is neither `DENY` nor `SAMEORIGIN` |
| X-Content-Type-Options | `xcto-invalid` | value other than `nosniff` |
| Referrer-Policy | `referrer-unsafe-url` | `unsafe-url` |
| | `referrer-invalid` | unrecognised token |
| Cross-Origin-Opener-Policy | `coop-unsafe-none` | `unsafe-none`, the no-op default |
| Cross-Origin-Embedder-Policy | `coep-invalid` | value outside the spec's allowed set |
| Cross-Origin-Resource-Policy | `corp-invalid` | value outside the spec's allowed set |

`Permissions-Policy` is deliberately absent from this table — see *Non-goals*.

### Avoiding double-reported clickjacking

`csp-no-frame-ancestors` and a missing `X-Frame-Options` describe the same gap. shcheck
already handles one direction: when CSP carries `frame-ancestors`, it drops
`X-Frame-Options` from the check entirely (original `shcheck/shcheck.py:376-380`, fork
`shcheck/shcheck.py:418-422`). The parser handles the other direction —
`csp-no-frame-ancestors` is suppressed when a valid `X-Frame-Options` is present, so a
host protected by one of the two mechanisms is never told it is missing both.

This makes `analyze()` insufficient on its own for CSP: the suppression needs the sibling
header. `headers.py` therefore also exposes a whole-record entry point that runs
`analyze()` across every present header and then applies cross-header suppressions, and
the parser calls that rather than looping over `analyze()` itself.

### Known disagreement with shcheck

shcheck flags a policy header unsafe when the raw string contains `"unsafe"` **or**
`"self"` (fork `shcheck/shcheck.py:436-441`). The check is directive-unaware:
`script-src 'self'` (good practice) and `script-src 'unsafe-inline'` (not) trip it
identically, while `default-src *` trips neither.

Magenta's directive-level analysis will therefore clear headers shcheck condemned. When
shcheck flagged a header and our analysis produced no findings for it, the parser writes a
stderr note — **except** when `'self'` was the only trigger, a known false positive that
would otherwise fire on nearly every well-configured site.

This is the specific behaviour worth backporting into the fork once `headers.py` exists.

## Severity

Low by default for both templates; Medium reserved for specific cases.

| Finding | Severity |
|---|---|
| Any missing security header | `low` |
| Any deprecated header present | `low` |
| Any information disclosure header | `low` |
| Every value-analysis code above | `low` |
| **`hsts-max-age-zero`** | **`medium`** |

An issue takes the maximum severity across its own details.

Exactly one Medium case is defined, on the principle that **a partial control must never
rate worse than a missing one** — otherwise the report rewards removing headers to lower
the score. A CSP containing `unsafe-inline` is still stronger than no CSP, and no CSP is
Low. `max-age=0` differs in kind: it does not fail to add protection, it actively tears
down protection the browser had already cached. The table is straightforward to extend.

## Emission

One issue per URL per template, with a single-element `issues[]` array — the same
granularity the burp parser produces, which is what allows the merger to join shcheck and
burp findings for the same host.

```json
{
  "template": "missing_security_headers",
  "tools": ["shcheck"],
  "severity": "medium",
  "affects": ["https://example.com"],
  "issues": [{
    "host": "https://example.com",
    "path": "/",
    "details": ["Content-Security-Policy - missing",
                "Strict-Transport-Security - present but max-age=0, which disables HSTS"],
    "request": "<base64>",
    "response": "<base64>"
  }]
}
```

The issue is `medium` because one of its two details is `hsts-max-age-zero`; the missing
CSP alone would have produced `low`. This is the max rule at work.

`host` is scheme + netloc and `path` is path + query, so the template's `x.host + x.path`
reconstructs the URL. Detail strings follow the burp convention of `Name - explanation`.

A URL with no findings produces no issue.

### The `information_disclosure_headers` template

Same issue shape, its own template. Schema:

```json
{
  "issues": [{
    "host": "https://example.com",
    "path": "/",
    "headers": {"Server": "nginx/1.10.3 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
    "request": "<base64>",
    "response": "<base64>"
  }]
}
```

`headers` is a name→value map rather than burp's flat `details[]` list, because the value
*is* the finding here — a report that says "the Server header is present" without quoting
the banner is useless. The template renders it as a two-column table per host, with the
same `|b64decode|http2md` evidence block as `missing_security_headers`. Required key:
`issues[].host`; `headers` must be non-empty for the issue to be emitted at all.

### Mergers

`missing_security_headers` already uses
[`BurpMerger`](../../../libmagenta/merger/burp.py) via `templates/burp/missing_security_headers.py`;
no change is needed. Its dedup key — host+path, method, request, response, redirected —
fits shcheck's issue shape, and it unions the `tools` list, so a merged issue reports both
tools. Burp and shcheck findings for the same URL carry different request/response
evidence, so they merge into one issue as separate `issues[]` entries rather than
collapsing.

The new `information_disclosure_headers` template reuses `BurpMerger` as well. It is a
generic HTTP-issue merger that happens to carry burp's name; renaming it is out of scope
here but worth noting as a future cleanup.

## Error handling

Follows the parser contract established in
[the parser-error policy design](2026-06-10-parser-error-policy-design.md).

| Condition | Behaviour |
|---|---|
| Input matches no known shape | stderr message, `exit(1)` → file-level error, `--on-error` decides |
| JSON parses but is not a dict of dicts | stderr message, `exit(1)` |
| A single URL entry is malformed | skip that URL, warn, keep the rest |
| `request`/`response` base64 undecodable | drop the evidence, keep the findings, warn |
| Unrecognised text lines | tally and warn once with a count; banners and blanks are expected |
| Scan ran clean, no findings | `[]` on stdout, `exit(0)`, stderr warning |

Partial results beat none: a malformed entry for one URL must not discard the other URLs in
the same file.

## Testing

`tests/test_shcheck_parser.py`, following `tests/test_nikto_parser.py` — `importlib` module
load, unit tests over pure functions, plus subprocess round-trips.

- **`headers.py` units** — one test per rule code, plus `default-src` fallback behaviour
  and CSP quoting/casing edge cases.
- **Cross-header suppression** — `analyze_all` must not emit `csp-no-frame-ancestors` when
  a valid `X-Frame-Options` is present, and must still emit it when there is none.
- **Adapter equivalence** — the same scan captured as fork JSON, original JSON, fork text,
  and original text must normalize to equivalent records, modulo evidence availability and
  text-mode value fidelity.
- **Deprecated-header rewrite** — original output captured with `-k` must never leave
  `Expect-CT`, `X-XSS-Protection`, or `X-Permitted-Cross-Domain-Policies` in `missing[]`.
- **`None` versus `{}`** — a scan without `-i` must not produce a clean-information-disclosure
  claim.
- **Emission** — issue objects validate against `missing_security_headers.schema.json` and
  the new template's schema.
- **End to end** — `shcheck.json` and `shcheck.txt` through the real engine, rendered to
  Markdown.

Fixtures live in `tests/fixtures/shcheck/` and are **hand-written**, not captured from live
hosts. The fork's own `tests/samples/json_output.json` targets a host with no security
headers at all, which exercises none of the value-analysis rules; fixtures need a real CSP,
a short-max-age HSTS, and a `max-age=0` HSTS.

## Open items for implementation

- Spanish translation of `information_disclosure_headers.es.json5` will be drafted and
  needs a native review pass before use in client reports.
- Parser `status` starts at `development`; promote to `testing` once the test suite lands,
  per the maturity table in `CONTRIB.md`.
