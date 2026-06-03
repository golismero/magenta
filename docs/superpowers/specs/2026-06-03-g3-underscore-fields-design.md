# G3-aligned underscore fields on Magenta issues

> Status: design, 2026-06-03. Step 1 of the Magenta⇄Golismero data-model
> convergence. Companion docs:
> [`docs/data-model-comparison.md`](../../data-model-comparison.md),
> [`docs/g3-integration-discussion.md`](../../g3-integration-discussion.md),
> [`../../../../../g3/docs/future/knife-integration-design.md`](../../../../g3/docs/future/knife-integration-design.md).

## 1. Goal & scope

Make Magenta issues recognizable as G3Data records so that g3 can ingest
Magenta output through its normal G3Data pipeline (routing, caching, merging
dispatch). This step changes **only Magenta's issue records** — adding the
underscore-prefixed routing/provenance fields that g3 expects on every
G3Data object.

**In scope:**

- Add `_type`, `_tool`, `_fp` (required) and `_cmd`, `_start`, `_end`
  (optional) to Magenta issue records.
- Enforce constants where they exist (`_type == "issue"`, `_tool == "magenta"`).
- Define merger semantics for the new fields.
- Define round-trip behavior for the new fields.
- Define the "strip unknown / known-ignored" policy for underscore fields
  that Magenta doesn't handle (e.g., g3-only fields like `_scanid`).

**Out of scope (deferred to later steps):**

- Asset types (`host`, `url`, `cidr`, `domain`, `service`). Magenta still
  produces only issues.
- The file envelope `{issues: [...], metadata: {...}}` stays unchanged.
- Magenta's severity model (5-level string) stays as-is. Severity reconciliation
  with g3's 4-level int is a g3-side wrapper concern, not Magenta's.
- The existing 11+ tool parsers stay untouched. The new fields are injected
  by the engine, not emitted by parsers (parsers MAY emit them, but don't need to).
- Parsers extracting `_cmd`/`_start`/`_end` from input files when those
  formats carry that information. Parsers can opt in incrementally; no
  parser is updated as part of this change.

## 2. Data model

Each Magenta issue gains six new G3-aligned fields:

| Field | Required | Value / source | Notes |
|---|---|---|---|
| `_type` | yes | constant `"issue"` | only valid value for now (asset types deferred). g3 dispatches per-`_type`; this routes Magenta records to g3's issue handling. |
| `_tool` | yes | constant `"magenta"` | the producing g3 plugin, not the detecting security tool. Distinct from `tools[]`. g3 dispatches per-`_tool` for merging; this routes the merge call back to Magenta. |
| `_fp` | yes (non-empty) | list of strings; engine injects `"magenta <sha1 of input>"`; parsers may add tool-specific entries; merger takes set-union | matches g3's cache-key semantics ("fingerprint of the execution that produced this record"). |
| `_cmd` | optional | string; parser, if input file carries it | not synthesized by Magenta. On merge, replaced with the synthetic label `"magenta merge"` (matching g3's per-plugin merger pattern). |
| `_start` | optional | integer (Unix epoch seconds); parser, if input file carries it | matches g3's convention ([common.go:217](../../../../g3/src/g3lib/common.go#L217)). On merge: min (earliest). |
| `_end` | optional | integer (Unix epoch seconds); parser, if input file carries it | matches g3's convention ([common.go:218](../../../../g3/src/g3lib/common.go#L218)). On merge: max (latest). |

### 2.1 `_tool` vs `tools[]`

These are decoupled by design:

- `_tool` (constant `"magenta"`) identifies the **producing g3 plugin**.
  g3 uses this to dispatch merge calls — forcing it to `"magenta"` means
  g3 will route the merge step back to Magenta rather than its own plugins.
- `tools[]` (Magenta-existing) identifies the **security tools that
  detected the issue** (nmap, burp, nessus, ...). Plural because Magenta
  merges across detectors.

They look superficially similar; they mean different things and never conflict.

### 2.2 Unknown underscore fields

Underscore-prefixed fields not in the recognized set are handled by the
engine on parser output and on round-trip ingest:

| Field name | Behavior |
|---|---|
| `_type`, `_tool`, `_fp`, `_cmd`, `_start`, `_end` | recognized, processed |
| `_scanid`, `_taskid`, `_id` | silently stripped (known-ignored — g3-only fields with no merge semantics in Magenta) |
| anything else starting with `_` | warning logged to stderr, then stripped |

Rationale: silently stripping the known g3-only fields prevents warning
fatigue for an expected, frequent case (g3-wrapped data flowing back).
Warning on genuinely unknown fields catches drift between Magenta's and
g3's underscore vocabularies before it becomes a silent data-loss problem.

The merge-ambiguity argument is the load-bearing one: Magenta cannot
defensibly merge two records carrying competing values of a field whose
semantics it doesn't know. Stripping at the boundary makes that situation
impossible by construction.

## 3. Schema changes

`templates/main.schema.json` becomes:

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

Notes:

- `_type` and `_tool` use JSON Schema `const` — any other value triggers a
  validation failure rather than a silent type-match. That's the drift detector.
- `_fp` requires at least one entry (matches g3's "never empty" invariant).
- `_cmd` is an optional string; `_start`/`_end` are optional non-negative
  integers (Unix epoch seconds, matching g3's
  [`common.go:217-218`](../../../../g3/src/g3lib/common.go#L217)).
- Per-template schemas (e.g. `templates/multiple_ssl_issues.schema.json`)
  compose on top of this via JSON Schema's `allOf` mechanism — already
  how they work today. They don't need to be aware of the new fields.

## 4. Engine wrap step

Hook point: [`libmagenta/engine.py:1014`](../../../libmagenta/engine.py#L1014),
immediately after `issues = json.loads(p.stdout)` and before the per-issue
`validate_issue()` loop in `run_parser(self, tool, filename)`.

A new method `MagentaReporter._g3_wrap_issue(self, issue, tool, filename)` performs, in order. (The `tool` argument is the parser name, taken from `run_parser`'s scope; it's needed for the diagnostic message in step 6.)

1. **Hard-validate `_type`** if present in the parser output: must equal
   `"issue"`. Mismatch → raise (drift detector).
2. **Hard-validate `_tool`** if present: must equal `"magenta"`. Mismatch
   → raise (drift detector).
3. **Compute the input fingerprint** by streaming the file in 64KB chunks
   (must not load the file in memory):

   ```python
   hasher = hashlib.sha1()
   with open(filename, "rb") as f:
       for chunk in iter(lambda: f.read(65536), b""):
           hasher.update(chunk)
   sha1 = hasher.hexdigest()
   engine_fp = f"magenta {sha1}"
   ```

4. **Inject/merge `_fp`**: if the issue lacks `_fp`, set it to
   `[engine_fp]`; if it has one, set-union with `[engine_fp]`. Equivalent to
   `sorted(set(existing + [engine_fp]))`.
5. **Strip known-ignored underscore fields silently**: the constant set
   `KNOWN_IGNORED_UNDERSCORE_FIELDS = {"_scanid", "_taskid", "_id"}`.
6. **Strip unknown underscore fields with a one-line stderr warning**:
   anything starting with `_` that is not in
   `RECOGNIZED_UNDERSCORE_FIELDS = {"_type", "_tool", "_fp", "_cmd", "_start", "_end"}`
   nor in `KNOWN_IGNORED_UNDERSCORE_FIELDS` triggers a
   `note: stripped unknown underscore field '_foo' from <tool>/<filename>`
   message and is removed.
7. **Inject the constants**: set `_type = "issue"` and `_tool = "magenta"`
   (idempotent if the parser already supplied them — they were validated
   in steps 1–2).

Control then returns to the existing per-issue `validate_issue()` loop,
which checks the schema (now including the new required fields).

Constants and helpers (`KNOWN_IGNORED_UNDERSCORE_FIELDS`,
`RECOGNIZED_UNDERSCORE_FIELDS`, `_g3_wrap_issue`) live near the top of
`libmagenta/engine.py` next to the existing imports. One file, one source
of truth for the underscore vocabulary.

## 5. Merger framework updates

The merger framework
([`libmagenta/merger/__init__.py`](../../../libmagenta/merger/__init__.py))
needs to know how to merge the new fields when multiple issues sharing the
same `template` are combined.

### 5.1 Default-path verification

- `_fp` is a list of strings. The framework's default behavior at
  [`__init__.py:94-98`](../../../libmagenta/merger/__init__.py#L94) extends
  lists, and the default cleanup at
  [`__init__.py:126`](../../../libmagenta/merger/__init__.py#L126) does
  `sorted(set(...))`. Set-union for `_fp` falls out **for free**.
- `_type`, `_tool`, `_cmd`, `_start`, `_end` are scalars (the constants
  and the optional provenance fields). Default `extend()` on a string would
  concatenate characters, which is broken. They need explicit callbacks.

### 5.2 Callbacks to add to the base `Merger` class

```python
def do__type_collect(self, merged, issue):   return "issue"
def do__type_cleanup(self, value):           return "issue"

def do__tool_collect(self, merged, issue):   return "magenta"
def do__tool_cleanup(self, value):           return "magenta"

def do__cmd_collect(self, merged, issue):    return "magenta merge"
def do__cmd_cleanup(self, value):            return value

def do__start_collect(self, merged, issue):
    return issue if merged is None else min(merged, issue)
def do__start_cleanup(self, value):          return value

def do__end_collect(self, merged, issue):
    return issue if merged is None else max(merged, issue)
def do__end_cleanup(self, value):            return value
```

The `is None` check is essential: the framework's default initialization
for an unknown key is `[]` (an empty list), and `min([], 1234567890)`
raises `TypeError`. Initializing `_cmd`/`_start`/`_end` to `None` in
the merged dict (§5.3) and handling `None` in the collect callback
avoids that crash without leaning on a sentinel-value convention.

### 5.3 Initial `merged` dict

Update the initialization at
[`__init__.py:56-63`](../../../libmagenta/merger/__init__.py#L56) so the
new constants are present even if the input issues somehow lack them:

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

The framework's cleanup loop at
[`__init__.py:129`](../../../libmagenta/merger/__init__.py#L129) prunes
keys whose final value is falsy and that aren't in
`mandatory_properties`. A `None` `_cmd` (no input issue had one) gets
deleted; a populated `_cmd` ("magenta merge") survives. Same for
`_start`/`_end`. `_fp` is required by the schema; the engine wrap step
guarantees every issue arrives with at least one entry, so the cleanup
pruning never triggers for it in practice.

### 5.4 `_cmd` semantics on merge

Matches g3's per-plugin merger pattern (e.g.,
[`plugins/recon/nmap/g3m.py:79-82`](../../../../g3/plugins/recon/nmap/g3m.py#L79)):
g3's mergers unconditionally overwrite `_cmd` with a synthetic
`"g3 merge ..."` label, never attempting to preserve or reconcile input
`_cmd` values. Magenta does the same — `"magenta merge"`. This avoids the
canonicalization/concat complexity of trying to combine command lines
that aren't meaningfully combinable.

### 5.5 Single-issue skip

g3's per-plugin mergers special-case "received a single issue to merge"
as a warning condition (e.g.,
[`plugins/recon/nmap/g3m.py:18-23`](../../../../g3/plugins/recon/nmap/g3m.py#L18))
and return the issue unchanged, preserving its original `_cmd`. Magenta's
generic framework currently has no such shortcut.

Add an engine-side skip: in the engine code that groups issues by template
and calls the merger, if a template has exactly one issue, return it
unchanged instead of invoking the merger. Preserves the original `_cmd`
(and any other parser-supplied scalar) when no actual merge happened, and
avoids the surprising behavior of a synthetic merge label appearing on a
record that wasn't merged.

## 6. Round-trip parser

[`parsers/magenta/magenta.py`](../../../parsers/magenta/magenta.py) becomes:

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

The round-trip parser **leaves every underscore field untouched**. The
engine wrap step (§4) handles the underscore vocabulary uniformly across
all parsers — the round-trip parser doesn't need to know about it.

Behavior on round-trip:

- Existing `_type:"issue"` / `_tool:"magenta"` survive validation (constant
  match) and the inject is a no-op.
- The round-trip file's SHA-1 is set-unioned into `_fp`. A record
  originally from `nmap.xml` (fingerprint `"magenta <sha1-of-nmap.xml>"`)
  re-ingested via `magenta.json` ends up with
  `_fp = ["magenta <sha1-of-nmap.xml>", "magenta <sha1-of-magenta.json>"]`.
  Each entry identifies an input that contributed to the record.
- `_scanid`/`_taskid`/`_id` are silently stripped (defensive — they
  shouldn't appear in a Magenta JSON in the first place, but might if
  the file was previously wrapped by g3).
- Genuinely unknown underscore fields get the warning + strip treatment.

## 7. Testing

Three layers, all using the existing `unittest` style under `tests/`.

### 7.1 Unit tests for `MagentaReporter._g3_wrap_issue`

New file `tests/test_g3_underscore_wrap.py`:

- SHA-1 of a known input matches the expected hex digest.
- Streaming SHA-1 of a multi-chunk file equals the one-shot SHA-1 (regression
  test for the chunked loop).
- Issue without underscore fields → `_type`, `_tool`, `_fp` injected correctly.
- Issue with `_type:"issue"` already set → no change, no error.
- Issue with `_type:"host"` → raises (validation failure).
- Issue with `_tool:"nmap"` → raises.
- Issue with parser-supplied `_fp:["nmap 10.0.0.1"]` → set-union with engine
  fingerprint, both entries present.
- Issue with `_scanid` → silently stripped, no warning on stderr.
- Issue with `_foo` → warning emitted to stderr, field stripped.
- Issue with `_cmd` / `_start` / `_end` → preserved unchanged.

### 7.2 Unit tests for merger callbacks

New file `tests/test_merger_underscore.py`:

- Merging two issues: `_fp` is set-union of the two inputs.
- Merging two issues with different `_cmd` → result is `"magenta merge"`.
- Merging two issues with different `_start` / `_end` → result is min / max.
- `_type` / `_tool` constants preserved through merge.

### 7.3 End-to-end smoke test

Added to `tests/test_cli.py`:

- Run any sample through Magenta. Inspect output JSON; assert each issue has
  `_type:"issue"`, `_tool:"magenta"`, and a non-empty `_fp` array whose
  entries start with `"magenta "`.
- Round-trip: feed the output back to Magenta, assert original `_fp`
  entries still present and the round-trip fingerprint added.
- Single-issue skip: a sample that produces exactly one issue for some
  template should retain whatever `_cmd` was extracted (or be absent if
  not extracted), **not** `"magenta merge"`.

No changes to existing tests — the new required fields appear in output but
existing assertions don't look at them, so they should keep passing.

## 8. Future considerations (not in this change)

1. **Asset types (`host`, `url`, `cidr`, `domain`, `service`)**: deferred
   to the parser-sharing step. When parsers start emitting asset records,
   `_type` will diversify beyond `"issue"`, the file envelope may need to
   grow, and the schema set expands.
2. **Rename `_tool` → `_parser`**: more accurate naming once Magenta's
   vocabulary fully internalizes the distinction (`_tool/_parser` =
   producing g3 plugin; `tools[]` = detecting security tools). Mechanical
   change, deferred to a quiet cleanup pass.
3. **`_scanid` / `_taskid` / `_id` real semantics**: currently silently
   stripped. If a downstream consumer ever genuinely needs Magenta to
   preserve them through merge, add the field to the recognized list and
   write the appropriate merge semantics for it. Reversible by design.
4. **Cache-staleness via timestamps**: the per-input-hash fingerprint
   assumes idempotent tools within a single scan. Cross-scan freshness
   (rescanning a week later) is a future g3-side concern — not Magenta's.
5. **g3 schema formalization**
   ([`src/g3lib/common.go:160`](../../../../g3/src/g3lib/common.go#L160) TODO):
   when g3 replaces its `map[string]interface{}` model with proper structs,
   cross-validate against Magenta's schema. Out of scope here; flagged as
   the natural follow-on.
6. **Parser sharing (step 2 of the roadmap)**: once both tools speak the
   same vocabulary, Magenta's parsers can be invoked by g3 directly, and
   they extend to emit asset records. This is what the current step enables.

## 9. Decision log

Key trade-offs settled during design:

| Question | Decision | Why |
|---|---|---|
| File envelope change? | No — `{issues, metadata}` stays | Asset types deferred; no need to change envelope yet |
| Asset types in this step? | No — deferred | Minimum-resistance path; parsers don't emit them yet |
| `_tool` vs `tools[]` | Both, decoupled. `_tool == "magenta"` constant; `tools[]` keeps Magenta semantics | They mean different things; no conflict once the producing-plugin vs detecting-tool distinction is made explicit |
| `_fp` computation | Engine-side, SHA-1 of input file, streaming reads | Engine is the natural seam (knows the input); streaming avoids OOM on large XML/JSON |
| Parsers emit underscore fields? | Optional. Engine validates the constants, injects when missing | 11+ existing parsers stay untouched; engine is the single source of truth |
| Unknown underscore fields | Known-ignored (`_scanid`/`_taskid`/`_id`) silently stripped; others warned + stripped | Prevents warning fatigue; catches drift. Strip-at-boundary avoids merge-ambiguity on unknown semantics |
| `_cmd` on merge | `"magenta merge"` synthetic label | Matches g3's per-plugin merger pattern; avoids canonicalization complexity |
| Single-issue merger call | Engine-side skip — return unchanged | Preserves original `_cmd`; matches g3's "received a single issue to merge" warning posture |
