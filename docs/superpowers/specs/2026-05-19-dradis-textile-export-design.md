# Dradis & Textile Export — Design

**Date:** 2026-05-19
**Status:** Design approved, ready for implementation planning

## Goal

Add support to Magenta for generating reports in Textile format, with two output flavors:

1. **`textile`** — a single `.textile` file produced by pandoc-converting Magenta's existing Markdown report. For non-Dradis use and quick previews.
2. **`dradis`** — a complete Dradis project package (`.zip` containing `dradis-repository.xml` plus attachment folders) that can be uploaded directly into a modern Dradis CE instance via its native "Project upload" feature.

The implementation must work cleanly with stock Dradis CE (default "welcome" template kit) while supporting custom Dradis templates (e.g., OWASP kit, MITRE ATT&CK kit, organization-specific kits) via a single mapping file the user can override.

## Non-goals (deferred)

- **DradisMD-style folder format** (`dradis-md`). DradisMD is a separate third-party tool; users who want round-trip filesystem editing can use it on top of our `dradis` output (download from Dradis → `dradismd`). Not in v1.
- **Dradis CSV format** (single CSV per project, one row per issue). Useful but lossy and orthogonal to the main use case. Deferred.
- **Dradis project upload via API.** Magenta stays "produce files." Users push to Dradis via Dradis's own UI/CLI import.
- **Round-trip Textile → Markdown import.** Magenta is one-way (parsers → Markdown → Textile).
- **Per-host Dradis evidence beyond the simple `Location`/`Output` shape.** The shipped default matches the welcome kit's evidence template; richer evidence formats are configurable via the mapping file but not pre-baked.
- **Tags, methodologies, categories, content blocks.** The XML schema supports these but Magenta has no source data; we emit them as empty elements. Future work.
- **Auto-computed `dradis.overall_risk`** from issue severities. Could be added later as a Jinja expression once severity counts are exposed to the property-mapping context.
- **CVSS data.** Magenta tracks categorical severity (none/low/medium/high/critical), not CVSS vectors. CVSS fields in the shipped mapping are left empty for users to fill in via Dradis. Auto-generating a CVSS score from the severity bucket was considered and rejected: CVSS standardizes vector → score (per FIRST), but the reverse mapping is not standardized; emitting a numeric score paired with an empty/synthetic vector would signal data corruption to reviewers and encourage users to skip filling in the real vector. The right long-term fix is for Magenta to track CVSS vectors at the parser/template level, at which point the mapping becomes a direct `{{ cvss_vector }}` / `{{ cvss_score }}` substitution — out of scope for this design.

## Background

Magenta's current architecture renders all reports through a Markdown pipeline (`MagentaReporter.process_files()` → `{metadata, issues, sections, report}`). Three output formats consume that result today: `markdown` (single file), `json` (raw structured dump), and `obsidian` (directory of `.md` files via `export_as_obsidian()`).

Dradis is an open-source collaborative reporting tool for security assessments. Its native import format is a ZIP archive containing `dradis-repository.xml` (a structured XML representation of the entire project) plus per-node attachment folders. Issue bodies inside `<issue><text>` CDATA use a section-marker syntax: `#[FieldName]#\n<body text>\n\n#[NextField]#\n...`. Section bodies are Textile-formatted.

Three template kits ship with Dradis CE (`tmp/dradis-ce/lib/tasks/templates/`):

- **welcome** (out-of-box default): `Title`, `CVSSv4.BaseScore`, `CVSSv4.BaseVector`, `Type`, `Description`, `Solution`, `References`. Evidence: `Location`, `Output`.
- **owasp**: `Title`, `OWASP Domain`, `OWASP Top 10`, `Description Short`, `Description Long`, `Impact`, `Likelihood`, `Risk` (auto), `Risk Score` (auto), `Remediation Status`, `References`.
- **redteam**: `Title`, `Severity`, `Tactic`, `Technique`, `Technique ID`, `Detection`, `Key Finding`, `Description`, `Attack Narrative`, `Business Impact`, `Recommendations`, `References`.

Organizations also ship custom kits with their own field names. Magenta's design must accommodate any of these without code changes — only the shipped `mapping.json5` needs to be replaced.

Two reference projects were used as input for this design:

- **`tmp/DradisMD/`** — third-party tool that round-trips Dradis projects through a filesystem-based textile representation. Provided the pypandoc invocation pattern (`gfm` input format, `table_linebreak_fix_gfm.lua` filter, post-pandoc escape-stripping) and the issue/evidence textile section format.
- **`tmp/dradis-export/`** — a real modern Dradis project export (`<dradis-template version="4">`). Provided the ground truth for the XML schema we generate.

## Architecture

### Overview

The engine's existing pipeline is **not modified**. `process_files()`, `render_report()`, and `render_issue()` produce all the data the new exporters need:

- `report["report"]` — full Markdown (consumed by `textile` format).
- `report["sections"]["issues"][vulnid]` — dict of already-rendered per-subsection Markdown for each issue (consumed by `dradis` for section-by-section pandoc conversion).
- `report["issues"]` — structured issue data including `affects`, `details`, `severity`, `taxonomy`, `references`, `tools`, `description`, `recommendations` (consumed for both Jinja mapping evaluation and per-host evidence generation).
- `report["metadata"]["project_info"]` — source for the `type-id=4` "Report content" node properties.
- `report["metadata"]["chart"]` (when chart generation is enabled) — base64-encoded PNG embedded in the Markdown header; decoded and written as a node attachment in `dradis`.

Two new format options are added to the CLI dispatcher (`textile`, `dradis`). A new helper module owns the pandoc invocation. A new method on `MagentaReporter` builds the `dradis` package.

### Files added

```
magenta/
├── formats/
│   └── dradis/
│       └── mapping.json5                 ← issue_sections + evidence_sections + project_properties + evidence_nodes
│                                            (the only user-editable file; `--dradis-templates` overrides this dir)
├── libmagenta/
│   ├── pandoc.py                         ← thin pypandoc wrapper, format-agnostic, no cleanup
│   ├── dradis.py                         ← XML builder + ZIP packager + Dradis-specific textile cleanup
│   ├── table_linebreak_fix_gfm.lua       ← pandoc filter shipped with the dradis exporter (MIT, from DradisMD,
│   │                                       attributed in CONTRIB.md). Internal asset, not user-overridable.
│   └── engine.py                         ← +1 method: export_as_dradis()
├── magenta.py                            ← +2 format choices, autodetection rules, --dradis-templates flag
├── requirements.txt                      ← +pypandoc
└── tests/
    └── test_dradis_export.py             ← stdlib unittest, skips when pandoc unavailable
```

### Module responsibilities

**`libmagenta/pandoc.py`** — single function:

```python
def convert_from_markdown(md_text: str, output_format: str, extra_args: list[str] | None = None) -> str
```

Thin wrapper around `pypandoc.convert_text(md_text, output_format, format="gfm", extra_args=[...])`. Returns pandoc output untouched — **no cleanup, no entity-unescaping, no escape stripping, no HTML-table rewriting**. Any format-specific cleanup is the caller's responsibility.

Always passes `--wrap=preserve` to preserve source line wrapping (otherwise pandoc reflows paragraphs). Beyond that, callers pass any format-specific args via `extra_args` (e.g., the Dradis exporter passes `--lua-filter=...` when re-converting HTML tables).

Raises a `RuntimeError` with a clear install message if `pypandoc.get_pandoc_version()` fails — *not* on import; only when actually invoked. This keeps Magenta usable for non-pandoc formats even when pandoc is missing.

This module is intentionally format-agnostic so that future pandoc-backed formats (asciidoc, rst, jira, mediawiki, etc.) can be added by registering a new `--format` choice and a one-line exporter that calls `convert_from_markdown()`. None of them inherit Dradis's cleanup quirks.

**`libmagenta/dradis.py`** — three functions:

```python
def markdown_to_dradis_textile(md_text: str) -> str
def build_repository_xml(report, mapping) -> str
def package_zip(repository_xml: str, attachments: dict[str, bytes], output_path: str) -> None
```

`markdown_to_dradis_textile` is the Dradis-flavored converter. It calls `pandoc.convert_from_markdown(md_text, "textile")` then applies three Dradis-specific cleanup steps:

1. **HTML-table re-conversion.** Pandoc falls back to raw `<table>` HTML when GFM tables have multi-line cells. Dradis renders such tables less reliably than native Textile tables, so we detect HTML table blocks in the output and re-convert them (HTML → GFM → Textile with `table_linebreak_fix_gfm.lua` as a `--lua-filter` on the second pass). The lua filter is resolved internally relative to `dradis.py`'s own location (`os.path.join(os.path.dirname(__file__), "table_linebreak_fix_gfm.lua")`); it is **not** read from `--dradis-templates` because lua filters are arbitrary code executed by pandoc and conflating them with user config would be a security footgun. DradisMD does this in [`multi_line_table_fix()`](https://github.com/GoSecure/dradis-md/blob/main/dradismd/dradismd.py#L1085).
2. **`html.unescape()`.** Pandoc's textile writer entity-encodes `&` → `&amp;`, `<` → `&lt;`, etc. Standards-compliant but ugly in Dradis. We undo it.
3. **Backslash-escape stripping.** Pandoc escapes characters it considers ambiguous; many escapes are unnecessary in Textile and look noisy in Dradis. The exact set to strip must be **verified empirically** during implementation rather than copy-pasted from DradisMD's list (which was tuned for markdown round-trips). Starting point for testing: `\< \> \* \_ \[ \] \# \| \~ \..` plus double backslashes. Underlying pandoc behavior is tracked in [jgm/pandoc#6259](https://github.com/jgm/pandoc/issues/6259) — closed administratively but still present in pandoc 3.x as of 2025.

All three steps are **Dradis-only.** The plain `textile` format never runs them — it ships raw pandoc output.

`build_repository_xml` consumes the engine's `report` dict and the parsed `mapping.json5`, returns the full XML as a string. For each `issue_sections` / `evidence_sections` entry, it evaluates the Jinja2 expression to Markdown, then calls `markdown_to_dradis_textile()` to convert to clean Textile, then slots the result between `#[Section]#` markers.

`package_zip` writes the archive with the XML plus any attachment files. The split exists so `build_repository_xml` is unit-testable without filesystem I/O.

**`libmagenta/engine.py`** — adds `export_as_dradis(report, output_path, mapping_path)` method, parallel to the existing `export_as_obsidian()`. Loads the mapping, calls into `dradis.py`. Pure orchestration.

**`magenta.py`** — adds `textile` and `dradis` to the `--format` argparse choices, adds a `--dradis-templates DIR` flag (default `<MAGENTA_HOME>/formats/dradis`), and updates the autodetection logic.

## Output format details

### `textile` format

Single-file output. Implementation:

1. Run the existing pipeline to produce `report["report"]` (the full Markdown).
2. Call `pandoc.convert_from_markdown(report["report"], "textile")`.
3. Write the result to the output path.

No mapping file is consulted. No lua filter. No Dradis-specific cleanup. **Output is exactly what pandoc produces** — valid Textile that may contain HTML entities (`&amp;`), raw HTML `<table>` blocks for multi-line cells, and pandoc's standard backslash-escaping. Users who want cleaner output can post-process themselves or use the `dradis` format and rename the file. This isolation keeps the plain Textile format honest for non-Dradis use cases (RedMine wikis, JIRA, etc.) and means future pandoc-backed formats can be added without inheriting Dradis-specific quirks.

The chart PNG embedded as a base64 data: URI in the Markdown header survives unchanged through pandoc as a Textile image link (may not render in all viewers; documented as a known limitation).

### `dradis` format

Produces a ZIP archive at the output path. Inside:

```
dradis-repository.xml
<node-id>/<attachment files>     ← only if charts enabled and chart node was emitted
```

#### XML structure (`<dradis-template version="4">`)

Generated from the schema observed in `tmp/dradis-export/dradis-repository.xml`. Minimal-viable project content:

**`<nodes>` element contains:**

1. One `<node>` with `type-id="4"` labeled "Report content". Its `<properties>` is a CDATA-wrapped JSON object built by evaluating each entry in `mapping.project_properties` against `report["metadata"]["project_info"]`. Keys with empty/missing source data are omitted (not emitted as empty strings).

2. One `<node>` with `type-id="0"` labeled "Targets", parent of one child `<node>` per unique host string from the union of all issues' `affects` lists. Each child has `type-id="0"` and `parent-id` referencing the Targets node.

3. (When evidence_nodes is true) `<evidence>` elements attached to each host node — one per `(issue, host)` pair where the host appears in the issue's `affects`. Each evidence's `<content>` CDATA is built by evaluating `mapping.evidence_sections` against a per-evidence context (issue dict + `affected` = the host string).

4. (When the severity chart is enabled and produced) One `<node>` with `type-id="0"` labeled "Uploaded files". The chart PNG bytes are written into the zip at `<archive-node-id>/chart.png`, where `<archive-node-id>` is the same archive ID we assigned to the "Uploaded files" node in the XML. Dradis's importer iterates the node lookup table, finds `tmp/zip/<archive-node-id>/`, and moves the contents into `Attachment.pwd/<new-db-id>/` after the node's real DB ID is assigned. Archive IDs are local labels — there is no risk of clobbering a real Dradis DB record.

**`<issues>` element** contains one `<issue>` per Magenta issue. For each issue:
- `<id>` — integer assigned sequentially starting from 1. Verified against dradis-projects 5.0 ([package.rb](https://github.com/dradis/dradis-projects/blob/main/lib/dradis/plugins/projects/upload/package.rb), [v4/template.rb](https://github.com/dradis/dradis-projects/blob/main/lib/dradis/plugins/projects/upload/v4/template.rb)): the importer builds a `lookup_table` mapping each archive `<id>` to a fresh DB ID, then rewrites parent-child references and attachment URLs accordingly. Archive IDs only need to be unique within the zip; we never collide with real Dradis DB IDs because Dradis never reuses them as-is. The same numbering scheme applies to `<issue>` and `<node>` elements — separate lookup namespaces, but using one shared sequence keeps the XML easier to read and diff.
- `<author>` — `report_author` from project_info, or `"magenta"` if absent.
- `<state>` — `published`.
- `<text>` — CDATA containing the Textile-encoded section-marker body built by walking the ordered `mapping.issue_sections` list. For each entry: evaluate the `value` as a Jinja2 expression against the per-issue context (the full issue dict plus all keys from `report["sections"]["issues"][vulnid]`); pandoc-convert the resulting Markdown to Textile; emit `#[<name>]#\n<textile body>\n\n`. Entries that evaluate to an empty string still emit the marker with no body (this matches the standard Dradis template convention of carrying placeholder fields).

**Empty elements emitted at the root** (Dradis accepts these as empty):
- `<tags></tags>`
- `<methodologies></methodologies>`
- `<categories></categories>`

XML generation uses `xml.etree.ElementTree` from the stdlib. ZIP packaging uses `zipfile` (also stdlib). No new dependencies beyond `pypandoc`.

#### Per-issue Jinja2 evaluation context

When evaluating `issue_sections` for one issue, the context dict contains:

- All keys from the structured issue dict: `title`, `severity`, `affects` (list of strings), `details`, `description`, `recommendations`, `tools` (list of parser dicts), `taxonomy` (list of `{tag, url?}` dicts), `references` (list of strings), `vulnid`.
- The pre-rendered Markdown subsection bodies as separate keys for users who want the same Markdown the engine produces internally rather than re-rendering from raw data — these come from `report["sections"]["issues"][vulnid]`.

For `evidence_sections`, the context additionally includes `affected` — the single host string for this evidence row — and `evidence_index` (1-based) for users who want to title evidence files like the DradisMD convention (`Evidence-N-<title>`).

For `project_properties`, the context is `report["metadata"]["project_info"]` directly. Keys: `report_team`, `report_author`, `client_name`, `product_name`, `test_type`, `start_date`, `end_date`, `report_date`.

#### Liquid-vs-Jinja2 escape

Dradis itself uses Liquid for in-Dradis computed fields (e.g., the owasp kit's auto-computed Risk field). Magenta's `mapping.json5` uses Jinja2, evaluated at render time. If a user wants a Liquid expression to *survive* into the Dradis output (so Dradis re-evaluates it at display time), they wrap it in Jinja2's `{% raw %}...{% endraw %}` block. Documented in the shipped `mapping.json5` as a comment.

## Configuration

### `formats/dradis/mapping.json5` (shipped default)

Targets the welcome kit (Dradis CE's out-of-box default):

```json5
{
  // When true, per-host data goes into Dradis evidence nodes under the host's <node> in the tree
  // (default Dradis CE workflow: one Evidence per [issue, host] pair, using the welcome kit's
  // Location+Output evidence template).
  //
  // When false, no <evidence> elements are emitted. Users who don't use evidence nodes are
  // expected to add #[Affects]# / #[Details]# (or equivalent) entries to issue_sections below
  // so per-host data isn't silently dropped.
  evidence_nodes: true,

  // Ordered list. Controls which #[Section]# markers appear in <issue><text> CDATA, their
  // order, and how each body is populated. Each `value` is a Jinja2 expression evaluated
  // against the per-issue context. The rendered body is then Markdown→Textile-converted.
  //
  // To preserve a Liquid expression for Dradis to evaluate at display-time (not render-time),
  // wrap it in {% raw %}...{% endraw %} so Jinja2 leaves it alone.
  issue_sections: [
    { name: "Title",             value: "{{ title }}" },
    { name: "CVSSv4.BaseScore",  value: "" },              // Magenta has no CVSS data — user fills in
    { name: "CVSSv4.BaseVector", value: "" },
    { name: "Type",              value: "" },              // Internal | External — user picks
    { name: "Description",       value: "{{ description }}" },
    { name: "Solution",          value: "{{ recommendations }}" },
    { name: "References",        value: "{% for url in references %}* {{ url }}\n{% endfor %}" },
  ],

  // Used only when evidence_nodes: true. One render per entry in each issue's `affects` list.
  evidence_sections: [
    { name: "Location", value: "{{ affected }}" },
    { name: "Output",   value: "{{ details }}" },
  ],

  // Filled into the <properties> CDATA of the type-id=4 "Report content" node, as a JSON object.
  // Keys evaluating to empty string are omitted entirely from the JSON.
  project_properties: {
    "dradis.productname":         "{{ product_name }}",
    "dradis.businessunit":        "{{ client_name }}",
    "dradis.project_start_date":  "{{ start_date }}",
    "dradis.project_end_date":    "{{ end_date }}",
    "dradis.report_delivery_date":"{{ report_date }}",
    "dradis.type_of_engagement":  "{{ test_type }}",
  },
}
```

### Customization

Users with non-welcome Dradis templates (OWASP, MITRE, custom org kits) override the `formats/dradis/` directory:

```bash
cp -r $MAGENTA_HOME/formats/dradis ~/my-dradis-templates
# edit ~/my-dradis-templates/mapping.json5
python3 magenta.py scans/ -o report.zip -f dradis --dradis-templates ~/my-dradis-templates
```

The directory must contain `mapping.json5`. Missing file raises a clear error at startup. The pandoc lua filter used during Dradis-flavored Textile cleanup ships inside `libmagenta/` and is not user-overridable in v1 — see the CLI section for the security rationale.

**Worked example — CVSS score auto-fill.** Some consulting firms attach a placeholder CVSS score to every issue based on the severity bucket, leaving the vector blank for the analyst to fine-tune. Custom mappings can do this with a one-line Jinja expression:

```json5
{ name: "CVSSv4.BaseScore",
  value: "{{ {'critical':'9.5','high':'8.0','medium':'5.5','low':'2.0','none':'0.0'}[severity] }}" },
```

The shipped default leaves this blank because score-without-vector signals data corruption to reviewers (see Non-goals). Users who want this behavior opt in explicitly. Note: we deliberately do **not** show a worked example for `CVSSv4.BaseVector` — vectors encode attack-vector, complexity, privileges-required, scope, and impact triads, none of which can be inferred from a severity bucket. Inventing them would be misleading regardless of the customization context.

## CLI changes

### New `--format` choices

`auto, markdown, json, obsidian, textile, dradis` (was: `auto, markdown, json, obsidian`).

### New `--dradis-templates DIR` flag

- Default: `<MAGENTA_HOME>/formats/dradis`.
- Resolved like the existing `parsers_directory` / `templates_directory` config keys (relative paths resolved against `MAGENTA_HOME`; absolute paths used as-is).
- Used by the `dradis` format only — points at a directory containing `mapping.json5`. The lua filter that the Dradis exporter uses internally is shipped inside `libmagenta/` and is not user-overridable in v1 (treating user-supplied lua as trusted config would be a security footgun; can be opened up later behind an explicit opt-in flag if a real use case emerges). The plain `textile` format does not consult this directory.

### Revised autodetection rules

Format auto-detection is intentionally conservative. Only unambiguous file-extension cues auto-select a format; everything else requires explicit `-f`.

| Output path | Detected format |
|---|---|
| `-` (stdin/stdout) | `markdown` |
| `*.md`, `*.txt` | `markdown` |
| `*.json`, `*.js` | `json` |
| `*.textile` | `textile` |
| Exact filename `dradis-export.zip` | `dradis` |
| `*.zip` (any other filename) | Error: "ambiguous .zip extension, pass -f explicitly" |
| Trailing slash (directory output) | `obsidian` **with deprecation warning** |
| Anything else | Error: "cannot auto-detect format from path; pass -f explicitly" |

The trailing-slash → obsidian rule is kept for one release as a back-compat fallback since the user noted it serves as a useful fallback mechanism. The deprecation warning instructs users to pass `-f obsidian` explicitly. To be removed in a subsequent release.

## Pandoc dependency

Added to `requirements.txt`: `pypandoc` (not `pypandoc-binary`, to keep the wheel small — pandoc must be installed system-wide). The Dockerfile's package list adds `pandoc`.

**Detection:** `libmagenta/pandoc.py` calls `pypandoc.get_pandoc_version()` lazily on first use (not at import). On failure, raises `RuntimeError` with platform-specific install hints (`brew install pandoc` / `apt install pandoc` / `pip install pypandoc-binary` if all else fails).

**Performance:** For the `dradis` format, pandoc is invoked once per `issue_sections` entry per issue, plus once per `evidence_sections` entry per evidence (≈10–20 invocations per issue, ×N issues), plus once per detected HTML table block during cleanup. DradisMD does the same and it's been adequate; if it becomes a bottleneck, a batch-conversion optimization is straightforward (concatenate all sections with sentinel separators, single pandoc call, split). Out of scope for v1. The plain `textile` format makes a single pandoc call total.

## Testing

`tests/test_dradis_export.py` using stdlib `unittest`. Tests skip with a clear message if `pypandoc.get_pandoc_version()` raises. No new test-deps. Covers:

1. **`pandoc.convert_from_markdown()` basics** — a few sanity-check fixtures (GFM table, code fence, link list) round-trip through pandoc and the output is non-empty, parseable Textile. No cleanup assertions — the wrapper just returns pandoc's output.

2. **`dradis.markdown_to_dradis_textile()` cleanup** — fixture-driven: representative GFM inputs (single-line table, multi-line table, code fence, link list, intraword underscores, ampersand-in-text, asterisk-in-text) each produce the expected clean Dradis-flavored Textile after all three cleanup steps. These fixtures double as the empirical test bed for tuning the escape-strip list. **The plain `textile` format must NOT produce identical output to this** — that's the test that the two layers are correctly separated.

3. **Mapping evaluation** — given a synthetic issue dict, each `issue_sections` entry's Jinja expression renders to the expected string; ordered list preserves order; literal `value` strings pass through unchanged; missing context variables raise a clear error (not a silent empty).

4. **`dradis.build_repository_xml()` structure** — given a tiny synthetic `report` dict with one issue and two affected hosts, the produced XML has: the expected `<dradis-template version="4">` root, a `type-id=4` "Report content" node with the right JSON properties, a "Targets" node with two child host nodes, two `<evidence>` elements (one per host) under the right node, one `<issue>` with `#[Title]#`/`#[Description]#`/... markers in the configured order in its `<text>` CDATA.

5. **`evidence_nodes: false` path** — the same fixture with `evidence_nodes: false` produces XML with no `<evidence>` elements anywhere; `issue_sections` carrying an explicit `Affects` entry renders the host list correctly inline.

6. **Empty `project_properties` values** — a fixture where `project_info.test_type` is missing produces a `<properties>` JSON without the `dradis.type_of_engagement` key (not with an empty string value).

7. **End-to-end zip** — the produced `.zip` unzips cleanly; `dradis-repository.xml` is parseable; if a chart is enabled, the attachment file exists at the expected path.

8. **Custom `--dradis-templates`** — pointing at a fixture dir whose `mapping.json5` uses different section names produces a zip whose issue `<text>` uses those names instead of the defaults.

9. **Autodetection** — `.textile` → `textile`, `dradis-export.zip` → `dradis`, other `.zip` → error, trailing slash → obsidian + warning, unknown extension → error.

**Manual smoke test before declaring done:**

1. Run `python3 magenta.py tmp/samples/ -o /tmp/out.textile -f textile` and open the result — should be a single well-formed Textile file.
2. Run `python3 magenta.py tmp/samples/ -o /tmp/out.zip -f dradis --dradis-templates formats/dradis` and import the result into the user's accessible Dradis CE instance via Project upload. Verify: project loads without error, host nodes appear under Targets, issues appear with correct field population, evidence (if any) appears under host nodes.

## Open risks

- **Pandoc output stability across versions.** The post-pandoc escape-stripping reference list comes from DradisMD, which was written against an older pandoc and primarily for markdown round-trips. The textile writer in current pandoc 3.x may produce a different escape set. Mitigation: during implementation, write a small fixture-driven test suite that runs known inputs through pandoc and asserts the output is clean Dradis-flavored Textile; iterate on the strip list until the fixtures pass. The escape-stripping function lives in one place (`dradis.py`) so updating it is a one-touch fix. Also: pandoc#6259 is closed but the behavior persists — don't expect upstream to fix it. Note that this risk applies *only* to the `dradis` format; the plain `textile` format ships raw pandoc output by design.
- **Dradis schema drift.** The XML schema generator targets `<dradis-template version="4">`, verified against dradis-projects 5.0 (current as of 2026-05). Low priority concern — Dradis has historically maintained backwards compatibility for project imports and the v4 importer code exists alongside v1/v2/v3 importers in the same gem, so older archives continue to work. Action only required if v4 becomes unsupported upstream or a user requests a v5+ feature. Mitigation in the meantime: keep schema-generation code minimal and centralized in `dradis.py`.

## Implementation order

1. `libmagenta/pandoc.py` (thin pypandoc wrapper) + pypandoc dependency wiring.
2. `textile` format end-to-end (smallest end-to-end vertical slice — proves the pandoc pipeline, ships raw pandoc output, no cleanup).
3. `libmagenta/dradis.py` — Dradis-flavored cleanup function (`markdown_to_dradis_textile`) with the fixture-driven test loop to tune the escape-strip list against real pandoc output.
4. `libmagenta/dradis.py` — XML builder against a hardcoded mapping (no JSON5 parsing yet).
5. Wire the shipped `mapping.json5` parsing and Jinja2 evaluation.
6. ZIP packaging + chart attachment handling.
7. `dradis` format end-to-end.
8. `--dradis-templates` override path.
9. CLI autodetection changes.
10. Full test suite.
11. Manual smoke test against live Dradis CE.
