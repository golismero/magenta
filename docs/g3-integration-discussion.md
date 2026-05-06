# magenta + g3: Integration Design Discussion

Reference notes from a design conversation about integrating `magenta` as a reporter plugin for `g3` (Golismero3). Companion document to [`data-model-comparison.md`](./data-model-comparison.md), which contains the underlying source-level comparison of the two tools' data models.

## Background

g3 was developed first and abandoned due to scope creep. magenta was built afterwards as a focused report-generation tool, with a data model originally based on g3's but simplified. magenta was then also paused. Both projects are now being revived (2026), with the goal of:

1. Stripping all reporting functionality out of g3, leaving it as a pure tool orchestrator.
2. Adding magenta as a reporter plugin for g3 (a new plugin type).
3. Eventually allowing additional reporter plugins (PDF, JIRA, etc.).

## Two integration approaches considered

### Approach A — file passthrough

g3 persists each tool's raw output file (nmap XML, nikto XML, etc.) and hands the directory to magenta. Magenta runs its existing parsers as today.

**Pros**
- Zero changes to magenta's parsers — they already do this.
- Magenta stays usable standalone (can run on a `nmap.xml` from any source).
- Clean decoupling: a magenta version bump can't break g3, and vice versa.
- No cross-repo schema coordination problem.

**Cons**
- Requires file persistence in g3 (which contradicts a pure-streaming pipeline).
- Re-parses already-parsed data (negligible cost at typical scan sizes).
- Doesn't leverage anything g3 *added* to the data (cross-run merging, enrichment).

### Approach B — G3Data passthrough

g3 sends G3Data JSON objects to magenta; magenta gains a G3Data-aware input path.

**Pros**
- No file stage; works for streaming (MQTT → magenta), fitting g3's existing infrastructure.
- Lets magenta consume *enriched* G3Data (merged across multiple runs, augmented from external sources like vulners).
- Conceptually cleaner once committed to the asset-vs-issue split (g3 owns the asset model, magenta owns the issue model).
- Forces an explicit, versioned schema between the tools.

**Cons**
- **Cross-repo schema coupling.** Today g3's `_type:host` shape is "whatever the importer happens to emit" — `IsValidData()` at `src/g3lib/common.go:162-239` enforces only `_type`/`_tool`/`_fp`. magenta would depend on an unstated contract.
- Requires a per-tool G3Data adapter in magenta (or one polymorphic one), mirroring each g3 importer — duplicated knowledge across repos.
- magenta loses standalone utility unless both input paths are maintained.
- Removing g3's issue-derivation is itself a non-trivial g3 refactor; the rules in `g3i.py` files (e.g., the plaintext-port flag at `plugins/recon/nmap/g3i.py:287-298`) have to migrate somewhere.

## Key insight

Under the proposed split, g3 becomes "the **asset model**" (hosts, services, URLs, domains) and magenta becomes "the **issue model**" (findings, severity, reports). That's a clean conceptual line. The hard question is which side owns *issue derivation* — the rules like "an open plaintext port is a CWE-319 finding". Currently g3's importers do this; under the long-term plan, that logic moves into magenta.

The structural reason both approaches are feasible at all: magenta's parsers already follow the right contract — read structured input from stdin, emit JSON issues to stdout (`parsers/<tool>/<tool>.py`). They don't care whether stdin is XML, CSV, JSON, or G3Data. magenta's parsers conflate two responsibilities (parsing tool-native formats AND applying issue-detection rules), so a future G3Data adapter is *smaller* than the current XML parser — it skips the parsing half.

## Adopted plan (short term)

A refined version of Approach A:

1. **Add reporter selection to g3.** Treat reporting as a new plugin type, parallel to the existing command / importer / merger blocks in `.g3p` files. The current built-in reporter stays as `--reporter=builtin` (the default); magenta becomes `--reporter=magenta`. Future reporters (PDF, HTML, JIRA, etc.) plug in the same way.
2. **Persist tool output files in g3.** This was already a desired change for independent reasons:
   - re-parsing capability when magenta or g3 ships parser updates,
   - including raw output snippets as evidence in reports.
3. **Magenta consumes the file directory.** No changes to magenta's existing parsers. g3 hands magenta a directory of tool outputs plus a manifest.
4. **vulners-as-output-file.** For enrichment plugins like vulners, persist API requests/responses as files. magenta reads them like any other tool's output and applies its own correlation/issue-derivation. Vulners response payloads are self-describing (keyed by CPE), so re-correlation in magenta is feasible without an explicit asset map — though a small manifest tying each vulners file to its triggering asset would make it more robust.

This is feasible and constitutes a quick win. The long-term Approach B remains the architecturally cleaner destination but is gated on first formalizing the G3Data schema (the TODO at `src/g3lib/common.go:160` literally anticipates this).

## Recommended long-term sequence (if/when Approach B is pursued)

1. **Formalize the G3Data schema.** Replace `map[string]interface{}` with proper Go structs and `validate` tags per `_type` and per `_tool`. Without this, Approach B is a coupling time bomb.
2. **Add a G3Data input path in magenta** as a parallel parser family (e.g., `parsers/g3data/<tool>.py`) — alongside the existing parsers, not replacing them. Each adapter knows how to read a `_type:host` from a given `_tool` and emit magenta issues.
3. **Migrate issue-derivation rules from g3 to magenta** by deleting `_type:issue` emission in each `g3i.py` and porting the rule into the corresponding magenta G3Data parser. One tool at a time, behind the new plugin boundary.

A useful side benefit: when issue derivation moves out of g3, the int-vs-string severity mismatch between the tools becomes a non-issue — issues only exist on the magenta side.

## magenta dedup behavior (verified)

A specific question raised: does magenta deduplicate when the same IP is scanned twice by nmap? **Yes**, with one structural caveat.

Verified path:
- The nmap parser emits `template: "cleartext_open_ports"` with `plaintext_ports[]` items shaped `{address, port, service}` (`parsers/nmap/nmap.py:386`).
- magenta groups all issues by template and runs the matching merger.
- For nmap, `templates/nmap/cleartext_open_ports.py:14-30` provides a custom collect/cleanup that converts each port record to a tuple `(address, port, proto, service)`, runs `sorted(set(...))` on the tuples, then converts back to dicts. Same `(192.168.1.1, 80, tcp, http)` from two scans collapses to one entry.
- Severity also dedups correctly: the default merger at `libmagenta/merger/__init__.py:158-163` keeps the *maximum* severity across merged issues. String-array fields (`tools`, `affects`, `taxonomy`, `references`) get `sorted(set(...))` cleanup at line 126.

### Structural rule embedded in the merger

Any template whose custom field is a **list of dicts** (rather than a list of strings) MUST ship its own merger, because the default cleanup at `libmagenta/merger/__init__.py:126` does `sorted(set(value))` — and dicts aren't hashable in Python. Templates that ship a `.py` file next to their `.json5` are exactly the ones with non-string custom payloads:

- `cleartext_open_ports.py`
- `multiple_ssl_issues.py`
- `generic_nessus_vulnerability.py`
- `iis_short_name_8_3_disclosure.py`
- `multiple_graphql_vulnerabilities.py`
- `generic_source_code_issue.py`

Simpler templates (string lists only) get correct dedup for free via the default `sorted(set(...))`.

### Caveat — dedup is per-template

If two different templates flag overlapping data (e.g., nmap's `cleartext_open_ports` and a hypothetical `unencrypted_service` from a different parser both reporting port 21), magenta will not reconcile them — they remain separate findings with overlapping `affects[]`. That's the contract: **templates are the unit of identity**.

## Open design points to nail down

Before starting implementation, the following need explicit decisions:

1. **Reporter input contract.** Cleanest proposal: g3 hands the reporter a directory containing all tool output files plus a `manifest.json` describing the scan (target, scanid, tools run, timestamps, file→tool mapping). The manifest is small and lets magenta reconstruct everything without parsing g3-specific blob shapes.

2. **File naming convention.** magenta currently identifies tool by directory under `parsers/<tool>/`. With g3 producing files, a convention like `<tool>.<runid>.<ext>` or a directory layout is needed — otherwise magenta can't tell `nmap.xml` from a generic `out.xml`. The manifest from point 1 resolves this.

3. **`--reporter=builtin` regression-free guarantee.** If keeping the built-in g3 reporter as a default option, that constrains how aggressively reporting code can be removed from g3 — it has to remain as one option, not be gutted. Worth confirming this is the intent.

4. **Rules-portability tracking.** For the long-term path, the issue-derivation rules currently in g3's `g3i.py` files need to migrate into magenta. Tracking which rules exist where (e.g., a `RULES.md` per g3 plugin) would prevent drift before the migration happens.

## Key file references

| Component | File | Purpose |
|---|---|---|
| g3 G3Data validator | `src/g3lib/common.go:162-239` | Mandatory-field check; the "lax" model contract |
| g3 plugin manifest type | `src/g3lib/plugin.go:44-52` | `G3Plugin` struct (commands/importer/merger blocks) |
| g3 nmap importer (issue derivation) | `plugins/recon/nmap/g3i.py:287-298` | Plaintext-port issue rule |
| magenta canonical issue schema | `templates/main.schema.json:13` | Required fields for any issue |
| magenta default merger | `libmagenta/merger/__init__.py:126,158-163` | Dedup of strings, max of severities |
| magenta nmap parser | `parsers/nmap/nmap.py:386` | Emits `cleartext_open_ports` template |
| magenta nmap merger | `templates/nmap/cleartext_open_ports.py:14-30` | Tuple-based dict dedup |
