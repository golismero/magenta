# Nikto Parser Update — Design

**Date:** 2026-05-25
**Status:** Approved (Phase A in scope; Phase B deferred)
**Component:** `parsers/nikto/` (+ `templates/nikto/`)

## 1. Problem & goal

The current Nikto parser (`parsers/nikto/nikto.py`) only understands the output of a very old Nikto (~2.1.5): old-style XML (single `niktoscan` root, `osvdblink` attributes) and old-style CSV (column 2 = OSVDB id). It breaks or silently misparses output from every Nikto release since.

**Goal (Phase A):** rewrite the parser to correctly parse **XML, JSON, and CSV** output from **all tagged Nikto versions** — 2.1.5/2.1.6, 2.5.0, 2.6.0, and current `main` — emitting the same Magenta issue contract we use today. Fix the long-standing OSVDB→CVE bug along the way.

**Out of scope:** paskto and wikto (unrelated/abandoned formats); NBE/TXT/HTML/SQL Nikto formats; CVE→severity (CVSS) enrichment (severity stays `high`); per-vulnerability-category template mapping (that is Phase B).

## 2. Background: how Nikto output changed across versions

(Researched directly from the Nikto report plugins/templates at each tag.)

- **The 2.5.0 break:** OSVDB IDs were removed everywhere (OSVDB shut down in 2016) and replaced by a free-text **`references`** field — mostly CVEs, but also OSVDB-, MS-, CWE-, CA-, BID-, CNVD-, RFC- tokens and raw URLs, delimited by **whitespace and commas**, sometimes with trailing punctuation.
- **XML:** root `niktoscan` → `niktoscans` wrapper (2.5.0, multi-host); `<item>` lost `osvdbid`/`osvdblink` attributes and gained a `<references>` CDATA child; 2.6.0 rewrote the writer (adds `encoding="UTF-8"`, indentation, a DTD, and `<ssl cn=...>`). `nxmlversion` stayed `"1.2"` throughout — **useless for version detection**. dradis-nikto notes Nikto's XML can appear with a **doubled `<niktoscan>`** wrapper and is historically not well-formed (single-root issues).
- **JSON:** added in 2.5.0 (hand-built, per-host, possibly invalid for multi-host); rewritten in 2.6.0 into a valid pretty-printed **array** of host objects (`banner`→`server_banner`, added `ssl_info`/`start_time`/`end_time`; vuln keys `id`/`references`/`method`/`url`/`msg`).
- **CSV:** stable 7-column finding rows; column 4 went OSVDB → references (2.5.0); CSV-injection escaping (leading `'`) added (2.5.0); SSL-info rows (test id `000137`) added (2.6.0).

### Two finding engines, one discriminator

Nikto findings come from two engines, but **the meaningful split is the taxonomy tag, not the engine**:

- **Signature DB (`db_tests`)** — the bulk. Each entry probes a known URL for a known issue in a *specific* product/CGI. ~59% carry a reference (CVE/OSVDB/…); **~41% (2,964 of 7,237 in `main`) carry no reference at all** and are generic recon/exposure/software-id observations (e.g. "`/config.php` may contain DB passwords", "`/index.html.bak` directory listing").
- **Check plugins** (`nikto_headers`, `nikto_cookies`, `nikto_put_del_test`, `nikto_ssl`, `nikto_robots`, `nikto_options`, …) — emit generic config/hygiene findings **usually without a CVE** (PUT enabled, directory listing, robots entries, SSL info). But when they *do* emit a CVE it is always because the probe identified a *specific* software's known vuln (Apache ETag `CVE-2003-1418`, Jetty JetLeak `CVE-2015-2080`, Cisco cookie IP leak `CVE-2006-4352`, Apache userdir enum `CVE-2001-1013`, Shellshock, Optionsbleed).

**Consequence:** a finding that resolves to a specific-vulnerability tag is tied to vulnerable software and is worth reporting; a finding with no such tag is informational. This is exactly what the old parser already did via the `OSVDB-0` marker ("no specific vuln id"). The references field is present in **every** output format, so this bucketing needs **no plugin-source pre-parsing and no bundled category DB.**

## 3. Architecture: normalize-then-emit (single file)

`parsers/nikto/nikto.py` stays a single file (repo convention) but is restructured into three layers:

```
main()                         detect format → dispatch → json.dump(build_issues(findings))
  ├─ read_xml(text)   ─┐
  ├─ read_json(text)  ─┼─►  list[Finding]
  └─ read_csv(text)   ─┘
        Finding = { host_url, path, method, refs_str, nikto_id, msg }

classify_references(refs_str, nikto_id) ─► { cve: [...], taxonomy: [...], references: [...] }   # written ONCE
build_issues(findings)                  ─► [issue_obj]                                          # written ONCE
```

Each reader tolerates every version variant of its format and emits neutral `Finding` records. All token logic and output-shaping live once in `classify_references`/`build_issues`. This isolates the tricky part, makes it unit-testable in isolation, and lets multi-host fall out naturally.

A per-finding **template-selection seam** in `build_issues` (a function returning the template name, defaulting to `multiple_nikto_issues`) is the single extension point Phase B will fill — Phase A does not branch on it.

## 4. Format & version detection

- **Empty input** → `[]` (with stderr note, as today).
- **XML** — input starts with `<?xml`. Parsed with a **hardened `lxml` parser** (`resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False`) since this is untrusted tool output — neutralizes XXE / billion-laughs (entity refs stay unexpanded; `remove_namespaces` skips `_Entity` nodes). One structural reader: parse, strip namespaces, then **recursively find every `<item>`** regardless of `niktoscan` vs `niktoscans` nesting (single **or** doubled wrapper). Tolerate Nikto's not-well-formed XML by applying dradis-nikto's wrapping workaround only if a strict parse fails; if it *still* fails, emit a loud warning and return `[]` (never an uncaught traceback). Per item: read `id`/`method` attributes; `description`, `uri`, `namelink`, `iplink` children; references from the **`osvdblink` attribute** (old) **or** the **`<references>` child** (2.5.0+), whichever exists. Build the per-host base URL from `scandetails` (`targethostname`/`targetip` + `targetport`; ssl inferred from port). **Drop** the old `nxmlversion=="1.2"` and single-`scandetails` assertions. Handle multiple hosts.
- **JSON** — input starts with `[` or `{`. Prefer `json.loads`. `main`/2.6.0 = array of host objects (`server_banner`, `ssl_info`, `vulnerabilities[]` with `id`/`references`/`method`/`url`/`msg`). If `json.loads` fails, attempt a documented repair for the known 2.5.0 concatenated-fragment shape; if that also fails → **loud warning** + `[]`.
- **CSV** — first line matches `"Nikto - v…"`. Reader handles: header line, per-host start row (hostname/ip/port/…/banner), and 7-column finding rows (hostname, ip, port, **references-or-OSVDB**, method, uri, msg). Strip the CSV-injection leading `'`. **Skip SSL-info rows** (test id `000137`). Detect old vs new column-4 semantics by token shape (numeric/`OSVDB-` vs free-text refs). Handle multiple host blocks.
- **Unrecognized** → stderr error + `[]` (as today).

## 5. Reference classification (`classify_references`)

Tokenize `refs_str` on **whitespace and commas**; strip surrounding quotes/trailing punctuation from each token. Classify into three buckets:

| Token | Bucket / action |
|---|---|
| `CVE-####-…` | `cve` (and issue taxonomy) |
| `OSVDB-0` | **informational marker** ("no specific vulnerability") → drop, no tag, not counted in the hit-rate guard. Mirrors the old parser's `OSVDB-0` skip. |
| `OSVDB-<n>` (n≠0) | look up **`OSVDB:<n>`** (colon) in `osvdb2cve.json` → CVE(s) into `cve`; **unmapped → keep `OSVDB-<n>`** in `cve` |
| `MS##-###` (bulletin) | `cve` (specific-vuln id) |
| `CNVD-…` / `CNVD-C-…` | `cve` (verify URL form during impl) |
| `CWE-…`, `CAPEC-…` | `taxonomy` only (general concept — never the per-finding `cve` column) |
| `RFC-<n>` | normalize → `RFC <n>` (space), `taxonomy` only |
| `MSKB:Q<n>` / `MSKB:<n>` | normalize → `KB<n>`, `taxonomy` only |
| `CA-2000-02` | hardcode → `CWE-79` in `taxonomy` (it is the classic XSS advisory; affects tests `000767/768/769`, which have no CVE) |
| `BID-<n>` | **drop** (dead taxonomy, no shipped map). Future: optional BID→CVE map |
| `http(s)://…` | `references` (URL) |
| token `OSVCVE-2011-339244` | known-corrupt token (was `OSVDB-11144`) → `CVE-2002-0764`; **silent** (see Phorum note) |
| token `CVE-2011-3392` | upstream mis-mapping (wrong Phorum vuln) → `CVE-2002-0764`; **silent** (see Phorum note) |
| token `WS_FTP.LOG` | known DB bug (ref column got the URI, test `001353`); **drop silently** |
| junk/non-token that is not one of the known special tokens above | **loud warning** + drop |
| **anything else** | **loud warning** + drop (do not guess; future-version safety) |

**Special-cases key on the reference token (and/or URI), not `nikto_id`** — because CSV output (all versions) carries no `nikto_id` column, only the reference token, method, URI and message. Each special token above is unique to its test, so token-keying is safe across XML/JSON/CSV alike.

**Phorum 3.3.2a XSS note (tests `000822` header.php / `000823` footer.php, `GLOBALS[message]`).** The correct CVE is **`CVE-2002-0764`**, which explicitly covers both files — OSVDB split it into `11144`/`11145`. Across versions Nikto emits this reference inconsistently: 2.1.6 = raw `11145`/`11144`; 2.5.0 = `OSVDB-11145`/`OSVDB-11144`; `main` = `CVE-2011-3392` (a *different*, later Phorum 5.2.17 `control.php`/`real_name` XSS — wrong vuln) and the corrupted `OSVCVE-2011-339244`. Resolution: (a) **added `OSVDB:11144 → CVE-2002-0764` and `OSVDB:11145 → CVE-2002-0764` to `osvdb2cve.json`** (fixes 2.1.6 / 2.5.0 via the normal map path), and (b) the two token overrides above fold `main`'s bad tokens to `CVE-2002-0764`. All silent, since the mapping is certain.

Per-finding `cve` column = specific-vulnerability identifiers (CVE, MS, CNVD, unmapped OSVDB). General-concept tags (CWE/CAPEC/RFC/KB) and URLs never appear in that column; they feed the issue-level Taxonomy / References sections.

**Inclusion rule (matches the old parser's `OSVDB-0` behavior):** a finding is **reported** if it resolves to ≥1 specific-vulnerability tag *or* a concept tag we synthesized (e.g. CA→CWE-79). A finding that resolves to **no tag at all** is **informational** and is **dropped by default**; the existing `INCLUDE_INFO` flag surfaces them.

### Correctness guards (per the project's "loud warnings, never silent fallbacks" rule)

- **OSVDB hit-rate guard:** if a scan contains OSVDB tokens but the map resolves an implausibly low fraction (≈0%), emit a **loud warning** — this would have caught the historical dash/colon bug (below) and guards against future key-format drift.
- **Catch-all warning:** any reference token not matching a known pattern triggers a loud warning rather than a silent drop, so a future Nikto token type can't slip through unnoticed.

### Bug being fixed

`osvdb2cve.json` keys are colon-form (`OSVDB:11144`); the current parser builds **dash-form** lookup keys (`OSVDB-11144`, `nikto.py:141`), so OSVDB→CVE translation has **always missed 100%** and silently fallen back to the raw `OSVDB-` tag. Phase A fixes the key format and adds the hit-rate guard. The data file is otherwise correct (verified: it is a superset of a fresh Wayback regeneration, zero conflicting values); the only edit is the two added Phorum entries (`OSVDB:11144`/`11145 → CVE-2002-0764`) described in §5.

## 6. Output & templates

`build_issues` groups `Finding`s by `host_url` into the existing issue object:

```
{ tools: ["nikto"], template: "multiple_nikto_issues", severity: "high",
  affects: [sorted host+path urls], taxonomy: [sorted union of cve+taxonomy tags],
  references: [sorted union of URL refs], issues: { host_url: [ {path, cve, msg}, … ] } }
```

- Multi-host → multiple keys in `issues` (natural).
- Dedup identical `(path, cve, msg)` per host (as today).
- **Template consolidation:** today the CSV path emits `template:"nikto"`, but the only template that exists is `multiple_nikto_issues` — so CSV findings have pointed at a non-existent template (latent bug). **All three readers use `multiple_nikto_issues`.**
- **Schema fix:** `templates/nikto/multiple_nikto_issues.schema.json` declares per-finding `cve` as `string`, but it is (and always was) an array. Change the schema to `array of string`. The per-finding column stays labeled "CVE" (now accurate: specific-vuln ids only).
- **Merger fix (pre-existing latent bug):** `templates/nikto/multiple_nikto_issues.py`'s `do_issues_collect()` mutated `merged_dict` in place but never `return`ed it, so the engine set `merged["issues"] = None` and then dropped the key, producing a merged issue that fails schema validation (`'issues' is a required property`). Add `return merged_dict`. This was dormant because nikto previously never emitted a mergeable (tagged) issue — every shipped sample finding was `OSVDB-0` and dropped; the multi-version parser is the first to surface it.
- **`_start` dropped.** The old parser set `issue["_start"]` to a `datetime`, but (a) nothing in `libmagenta` consumes `_start`, and (b) a `datetime` is not JSON-serializable, so `json.dump` would have crashed whenever `starttime` was present — a latent bug. It is removed in the rewrite (dead code).

## 7. Testing (TDD)

- **`classify_references` unit tests** — one assertion per row of the §5 table, including all special cases (`000823`, `001353`, `CA-2000-02`, BID-only, unmapped OSVDB, comma+space tokenization, trailing punctuation, unknown-token loud warning).
- **Per-reader tests** over real fixtures: generate output from each tagged Nikto (`2.1.6`, `2.5.0`, `2.6.0`, `main`) — Perl, runnable locally against a throwaway HTTP target — in XML/JSON/CSV. Supplement with dradis-nikto's real sample XML (`sample_v2.1.4.xml`, `sample_v2.5.0.xml`) and small hand-crafted fixtures for edge cases (doubled `niktoscan`, multi-host, invalid 2.5.0 JSON, empty scan).
- **End-to-end**: drop fixtures under `tmp/samples/nikto/` so `tests/test_cli.py`'s `magenta.py report` harness exercises parser→template rendering.
- **Regression**: the OSVDB→CVE fix must demonstrably resolve real CVEs (hit-rate guard test).

## 8. Phase B (deferred — improvement, not required now)

Surface the informational/generic findings (untagged) and route the common ones to **mostly-existing** templates: `nikto_cookies`→`burp/insecure_cookies_found`, `nikto_headers`(missing headers)→`burp/missing_security_headers`, `nikto_ssl`→`multiple_ssl_issues`, `nikto_robots`→`burp/robots_txt_file`; ~1 new template for "dangerous HTTP methods enabled" (`put_del_test`/`options`). Routing uses the §3 template-selection seam; everything without a dedicated template continues to fall back to `multiple_nikto_issues`. A separate, optional Magenta `url_from_tag` plan may add `CA-`/`BID-` support and fix `RFC `/`MSKB:` matching — but Phase A already normalizes those parser-side, so it is not a blocker.
