# Data Model Comparison: magenta vs g3

A source-level comparison of the data models used by `magenta` (this repository) and its companion tool `g3` (Golismero3, at `../g3`).

This document is based on the source code of both tools, not on sample files.

## 1. Modeling Philosophy

| | **magenta** | **g3** |
|---|---|---|
| Validation strategy | JSON Schema, fail-closed | Lax map, fail-open (only 3 required fields) |
| Schema location | `templates/*.schema.json` (per template) | Implicit in `IsValidData()` at `src/g3lib/common.go:162-239` |
| Wire type | `dict` validated against schemas | `map[string]interface{}` (Go) / dict (Python) |
| Polyglot? | Python only | Go core, Python plugin scripts, JSON5 manifests |
| Distribution model | Single CLI process | Microservices: MongoDB + MariaDB + Redis + MQTT + Docker |

The comment at `src/g3lib/common.go:133-134` openly states g3 keeps the model lax for plugin flexibility, with a TODO at line 160 (*"In the future we could have a fully fledged data model here"*). Magenta took the opposite path and shipped a full schema system from the start.

## 2. Top-Level Unit of Data

The most fundamental divergence:

- **magenta**: the unit is an **issue** (a finding). A "report" is `{issues: [...], metadata: {...}}`. Hosts, ports, services exist only as strings inside `affects` or inside template-specific nested objects. There is no first-class "host" record.
- **g3**: the unit is a **G3Data object**, polymorphic via `_type`. Possible `_type` values include `host`, `issue`, `domain`, `cidr`, `url`, `nil` (see `src/g3lib/script.go:219-364` and `src/g3lib/common.go:203`). A `.g3` file is an array of mixed-type objects — hosts and issues coexist as siblings.

Concretely, an nmap scan in g3 produces both a `_type:host` object (with full `services[]`, `os_matches[]`, `ipv4`, etc.) AND a `_type:issue` object (e.g., the plaintext-port finding). In magenta, the same scan produces only issues; the host metadata is lost or smushed into a custom field like `plaintext_ports[]` (`parsers/nmap/nmap.py`).

## 3. Required-Field Comparison

| Concept | magenta | g3 |
|---|---|---|
| Type discriminator | `template` (string, names a JSON schema) | `_type` (string, regex `^[a-z]+$`) |
| Origin tool | `tools` (**array** of strings) | `_tool` (**single** string) |
| Identity / dedup | implicit, per-merger; see §6 | `_fp` (array of `"tool token..."` strings) |
| Targets affected | `affects` (array of strings) | `affects` (array of strings) — only required for issues |
| Severity | `severity` (string enum, **5 levels**) | `severity` (int, **4 levels** — issues only) |

Note the `tools` vs `_tool` mismatch: magenta's `tools` is an array because magenta's merger merges across tools (the same issue can be detected by burp + nessus), so the merged record carries both names. G3 keeps `_tool` singular because g3 mergers operate per-plugin only (see `g3m.py` files), so cross-tool reconciliation never happens at the merger level.

## 4. Severity — A Hard Incompatibility

- magenta (`templates/main.schema.json:7`): `["none", "low", "medium", "high", "critical"]` — string enum, **5 levels including "none"**
- g3 (`src/g3lib/common.go:227-234`): integer 0–3, **4 levels**, no "none"/"info":
  - `0=LOW`, `1=MEDIUM`, `2=HIGH`, `3=CRITICAL` (confirmed in `src/g3lib/report.go:88-97`)

This means a one-to-one translation in either direction loses information:

- g3 → magenta: fine, but `none` will never appear from g3 sources.
- magenta → g3: anything tagged `none` has no destination value (would need to be dropped or coerced to `0`/LOW).

## 5. Identity, Fingerprints, and Deduplication

This is the most architecturally interesting difference.

**g3** uses an explicit fingerprint string array in every G3Data object (`_fp`, mandatory, never empty — `src/g3lib/common.go:218-224`). Each fingerprint takes the form `"toolname token1 token2..."`, and the plugin author writes Go templates in the `.g3p` manifest that produce these fingerprints (see `plugins/recon/nmap/nmap.g3p`). Dedup at the engine level is done by comparing `_fp` strings; merging at the plugin level (`g3m.py`) takes the **union of `_fp`, `affects`, `taxonomy`, `references` plus the maximum severity** (`plugins/recon/nmap/g3m.py:48,66-69`). There is no per-issue dedup key — merging is field-set union.

**magenta** has no global identity field. Each merger subclass at `libmagenta/merger/*.py` defines its own dedup key via callback methods:

- `libmagenta/merger/burp.py:18-23` — key is `(host+path, method, request, response, redirected)`
- `libmagenta/merger/codevuln.py` — key is `(file, line)`

The merger framework at `libmagenta/merger/__init__.py:15-169` uses a callback-per-property pattern (`do_<prop>_init/default/collect/cleanup`) so each property has its own merge semantics. This is more expressive than g3's "union everything" approach but tightly coupled to template type.

## 6. Round-Trip Self-Parsing

Both tools can re-ingest their own output, but the canonical formats are different shapes:

- magenta: `parsers/magenta/magenta.py:1-14` — strips `vulnid` and emits the issues array. The canonical form is `{issues: [...]}`.
- g3: native `.g3` files are simply arrays of G3Data objects in JSON. The g3 importer for any plugin can read its own emitted G3Data because importers accept G3Data on stdin (see `plugins/*/g3i.py`).

**Neither format is a drop-in replacement for the other** — a `.g3` file mixes hosts with issues; a magenta JSON contains only issues plus report metadata.

## 7. Per-Issue Custom Fields

Both tools allow plugin/template-specific fields beyond the common skeleton:

- magenta enforces these via per-template JSON schemas (`templates/<name>.schema.json`), e.g.:
  - `multiple_ssl_issues`: `hosts[].bad_ciphers[]`, `clientsimulations[]`, `grade`, `grade_cap`
  - `generic_source_code_issue`: `code[].file/line/trace[]`, `bandit[]` rule IDs
  - `generic_nessus_vulnerability`: `nessus[].plugin_id/plugin_name/...`
- g3 allows arbitrary additional fields with no schema enforcement — `IsValidData()` only refuses unknown *underscore* fields (`src/g3lib/common.go:180-198`); regular fields pass through unchecked.

Effective schemas are similar in spirit (custom payload alongside common skeleton), but magenta will reject malformed ones and g3 won't.

## 8. Targets / Hosts / Ports / URLs

| | **magenta** | **g3** |
|---|---|---|
| Host | string in `affects` | first-class `_type:host` with `ipv4`, `ipv6`, `services[]`, `os_matches[]`, `os_fingerprint`, `uptime`, `starttime` |
| URL | string in `affects` | `_type:url` with `scheme`, `host`, `path`, `username`, `password` (`src/g3lib/script.go:219-364`) |
| CIDR | not modeled | `_type:cidr` |
| Domain | not modeled | `_type:domain` |
| Service/port | inside template-specific custom field | nested `services[]` on a host (`port`, `protocol`, `service`, `state`) |

Magenta's modeling is **finding-centric**: anything that's not a finding is a side string. G3's modeling is **asset-graph-centric**: targets, hosts, services exist independently and findings reference them via `affects`.

## 9. Plugin / Parser Mechanics

| | **magenta** | **g3** |
|---|---|---|
| Plugin home | `parsers/<tool>/` | `plugins/<category>/<tool>/` |
| Manifest | `<tool>.json5` | `<tool>.g3p` (JSON5) |
| Executor | bare script reading stdin, writing JSON to stdout | Docker container (`Dockerfile`, `g3p.sh` entrypoint) |
| Importer | the parser script itself | `g3i.py` |
| Merger | optional `libmagenta/merger/<name>.py`, per-template | `g3m.py`, per-plugin |
| Templating in manifest | none | Go templates for `condition`, `fingerprint`, `command`, `dockeropt` (`src/g3lib/plugin.go:24-30`) |

Common plugins across both tools: **nmap, nikto, hydra, testssl** — but the importer/merger contracts are not interchangeable.

## 10. Report Rendering

Both render to markdown via templating; the engines differ.

| | **magenta** | **g3** |
|---|---|---|
| Templates | per-issue-template `.json5` files | per-plugin i18n `i18n/{lang}.json` |
| Engine | Jinja2 (`libmagenta/template.py`) | Go `text/template` (`src/g3config/g3config.go:138`) |
| Section list | `engine.py:778-790` | `src/g3lib/report.go:324-348` |
| Sections (common) | severity, affects, description, details, recommendations, taxonomy, references, tools | severity, affects, description, details, recommendations, taxonomy, references, summary |

Section sets are nearly identical. Magenta has a `tools` section because of its multi-tool merging; g3 has a `summary` section in its template list. Both have configurable section ordering and filter-by-min-severity.

## 11. Taxonomy Auto-Linking

Both implement nearly the same set of identifier prefixes with auto-generated URLs:

- Common: CVE-, CWE-, CAPEC-, CNVD-, JVNDB-, JVN, BDU:, USN-, RHSA-, DSA-, KB, MS, MFSA, EDB-ID:, 1337DAY-ID-, RFC
- magenta-only: WPVDB
- g3-only: SECURITYVULNS:, OBB-

Cited at `libmagenta/engine.py:615-691` (`url_from_tag`) vs `src/g3lib/report.go:426-461`. This is the closest one-to-one feature parity in the two codebases.

## 12. Identity / Persistence Metadata

| | **magenta** | **g3** |
|---|---|---|
| Per-finding ID | `vulnid` (rendered post-merge, format `Section.Severity.Index`, stripped on round-trip) | `_id` (MongoDB ObjectID, only when persisted) |
| Provenance | `tools[]` only | `_tool`, `_cmd`, `_start`, `_end`, `_scanid`, `_taskid` |
| Scan grouping | none — one report = one run | `_scanid` UUID; per-scan MongoDB DB `scan-{scanid}` (`src/g3lib/datastore.go:253-322`) |

G3 carries far richer execution provenance per object because it's a distributed system that needs to correlate workers, tasks, and scans. Magenta operates as a one-shot pipeline so this is unnecessary.

## 13. Quick Translation Table

| magenta field | g3 equivalent | Notes |
|---|---|---|
| `template` | (none — implicit per-plugin) | g3 has no template-name layer; plugins own their own templates |
| `tools[]` | `_tool` | g3 is singular; lossy in g3→magenta if you wanted to preserve multi-tool credit |
| `severity` (string×5) | `severity` (int×4) | `none` has no g3 mapping |
| `affects[]` | `affects[]` | direct |
| `taxonomy[]` | `taxonomy[]` | direct |
| `references[]` | `references[]` | direct |
| `vulnid` | `_id` | semantically different (UI key vs DB key) |
| (n/a) | `_type` | magenta everything-is-an-issue assumption hides this |
| (n/a) | `_fp` | magenta dedup is per-merger; no exposed key |
| (n/a) | `_cmd` / `_start` / `_end` | magenta doesn't track command provenance |
| custom per-template fields (`hosts[]`, `nessus[]`, `code[]`, etc.) | arbitrary extra fields | magenta validates them; g3 doesn't |

## Bottom-Line Assessment

The two tools share a clear surface vocabulary — `severity`, `affects`, `taxonomy`, `references`, parser-per-tool, markdown output, MITRE auto-linking — but their underlying data shapes diverge in ways that prevent direct interop:

1. **g3 is asset-and-finding; magenta is finding-only.** A `.g3` is a stream of typed records (hosts, services, issues); a magenta report is a list of issues with metadata.
2. **g3 dedups by explicit `_fp`; magenta dedups by per-template merger logic.** Translating either way means picking a fingerprint scheme.
3. **Severity scales differ by both type (int vs string) and count (4 vs 5 levels).** No lossless round-trip.
4. **g3's `_tool` is singular; magenta's `tools[]` is plural** because magenta merges across detectors.
5. **g3 enforces almost nothing; magenta enforces a lot** via JSON Schema.

If you want bridging: a magenta parser for `.g3` files would be straightforward (read the array, keep only `_type:issue` records, map severity, fold custom fields into a magenta template), but the reverse — a g3 importer that consumes magenta output — would require synthesizing `_type:host` records out of `affects` strings, which is lossy.
