# Parser-error policy

**Date:** 2026-06-10
**Status:** Approved design, pending implementation plan
**Author:** Mario Vilas (with Claude Code)

## Problem

When a parser fails on a file (e.g. an XML parse error), Magenta logs the failure and
silently continues, always exiting `0`. There is no way for the caller to choose a
stricter reaction or to learn from the exit code that something went wrong.

This matters when launching Magenta from an orchestrator such as **Golismero**: the wrapper
needs to distinguish "report generated cleanly", "report generated but some files failed",
and "aborted" — and it can only do that from a meaningful process exit code.

> **Note — earlier scope, now dropped.** This work originally also proposed an explicit
> `--file-list` input mode (and an `iter_directory`/`iter_file_list` refactor of
> `process_files`) to stop Magenta feeding the wrong artifacts to a parser — e.g. handing
> `nmap.txt` to the XML parser. That routing problem has since been solved directly by
> **per-parser file-extension filters** (commit `cbea779`): each parser declares a
> `formats` list in its `.json5`, and [`process_files`](../../../libmagenta/engine.py#L1190-L1199)
> skips any matched file whose extension isn't allowed. The file-list machinery is no
> longer needed and is out of scope. **The parser-error policy is all that remains.**

## What happens today

A parse failure has two granularities:

- **File-level crash** — the parser subprocess exits non-zero (e.g. XML parse error).
  [`engine.py:1206-1212`](../../../libmagenta/engine.py#L1206-L1212) catches it, prints
  `"Error processing file '…'"` plus a full `traceback.print_exc()`, and `continue`s. The
  whole file yields zero issues; the run still exits **0**.
- **Per-issue rejection** — the parser succeeds but some emitted issues fail schema
  validation. [`engine.py:1098-1112`](../../../libmagenta/engine.py#L1098-L1112) drops only
  the bad issues and keeps the good ones from the same file.

There is no CLI flag or config option controlling error tolerance, and the exit code
ignores parse failures entirely (exit `1` happens only on an uncaught top-level exception —
[`magenta.py:326-331`](../../../magenta.py#L326-L331)).

## Goal

Give the caller explicit control over how Magenta reacts to a **file-level** parser error,
with a meaningful, scriptable exit code.

## Non-goals (explicitly out of scope)

- **Explicit file-list input mode** and the `process_files` iterable refactor — dropped;
  superseded by per-parser extension filters (commit `cbea779`).
- **Extension- or content-based format sniffing** beyond the existing `formats` filter.
- **Evidence / console-output capture** (embedding `nmap.txt` content as issue evidence) —
  tracked separately.
- **Per-issue validation behavior** — unchanged: keep valid issues, drop invalid ones with
  a warning, in every mode.

## Design

One new option on the `report` command, additive and backwards compatible — the default
preserves today's behavior exactly.

### `--on-error {ignore,skip,halt}` — parser-error policy

Default **`ignore`** (= current behavior).

Applies to **file-level** parser failures only: any exception raised out of `run_parser`
([`engine.py:1207`](../../../libmagenta/engine.py#L1207)) — subprocess non-zero exit (XML
parse error etc.), JSON-decode failure on the parser's stdout, subprocess timeout, or an
unreadable input file.

| Mode     | On a file-level error                                          | Report produced?  | Exit code |
|----------|---------------------------------------------------------------|-------------------|-----------|
| `ignore` | Log error + traceback, skip the file, continue.               | Yes               | 0         |
| `skip`   | Log error + traceback, skip the file, continue.               | Yes               | 2 (if ≥1 skipped) |
| `halt`   | Log error + traceback, stop immediately, write **no** report. | No                | 3         |

Per-issue validation is **unchanged in all three modes**: a parser that succeeds but emits
some schema-invalid issues still keeps the good ones and drops the bad ones with a warning.
The `--on-error` policy never triggers on a per-issue validation failure, only on a
whole-file parser failure.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success — no file-level parse errors, or `ignore` mode. |
| 1 | Fatal / uncaught error — bad config, bad output path, usage error, etc. (**unchanged** top-level behavior.) |
| 2 | `skip` mode: report completed, but one or more files were skipped due to a parse error. |
| 3 | `halt` mode: aborted on a parse error; no report written. |

Distinct `2`/`3` codes let the Golismero wrapper branch on "partial report" vs. "aborted"
vs. "crashed" without parsing stderr.

### End-of-run summary

After processing, if any files were skipped, emit a single stderr line —
`"N file(s) skipped due to parse errors."` — so the exit code is interpretable at a glance.
(In `halt` mode the run stops at the first error, so this line is not reached.)

## Affected components

- **[`engine.py`](../../../libmagenta/engine.py) `process_files`**
  - Add an `on_error="ignore"` parameter. (Signature stays `process_files(self, pathname,
    metadata=DEFAULT_METADATA, on_error="ignore")`; the directory-walk + extension-filter
    task collection is unchanged.)
  - Implement the three modes around the existing
    [`try/except`](../../../libmagenta/engine.py#L1206-L1212): `ignore` keeps current
    behavior; `skip` additionally tracks a skipped count; `halt` raises a dedicated
    `ParseHaltError` to unwind immediately without merging/rendering.
  - Surface the skipped-file count (e.g. as an added key in the returned result dict) so the
    CLI can choose the exit code; let `ParseHaltError` propagate for the exit-3 path.

- **[`magenta.py`](../../../magenta.py) `report` command**
  - Add the `--on-error {ignore,skip,halt}` option (default `ignore`); pass it to
    `process_files`.
  - Map the outcome to `sys.exit(...)`: 0 / 2 (skipped) on normal completion, 3 on
    `ParseHaltError`.
  - Print the end-of-run summary line when files were skipped.

## Testing

Tests follow the existing pattern in
[`tests/test_cli.py`](../../../tests/test_cli.py): invoke `magenta.py report` as a
subprocess and assert on exit code, stderr, and produced output. Using a known-bad input
(a file with an allowed extension but unparseable content, so it passes the extension
filter and reaches the parser):

- `ignore` (and the no-flag default) → exit 0, file skipped, report still produced.
- `skip` → exit 2, file skipped, report still produced, summary line printed.
- `halt` → exit 3, no report written.
- Per-issue validation unaffected by mode: a parser emitting a mix of valid and
  schema-invalid issues keeps the valid ones in all three modes.

## Open questions

None outstanding. Decisions settled during brainstorming:
- Error policy is **file-level only**; per-issue validation stays lenient in all modes.
- Exit codes: distinct `2` (skip) / `3` (halt).
- Option name: `--on-error`; default mode `ignore` (backwards compatible).
