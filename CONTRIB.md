# So you want to contribute to this project...

<p align="center">
  <img src="captain_america.webp" alt="Captain America" width="256"/>
</p>

---

# Tools

Here are some links with collections of popular tools, if you think adding parsers for any of these makes sense, go for it!

- https://github.com/vavkamil/awesome-bugbounty-tools

---

# TODO

Pending work items tracked across the codebase. If you want to help me finish pending work rather than adding entirely new features, here's where I need a hand:

---

## Parser Maturity

The following parsers are not yet at production status:

| Parser      | Status      | Metadata file                           |
| ----------- | ----------- | --------------------------------------- |
| Bandit      | development | `parsers/bandit/bandit.json5`           |
| GraphQL Cop | development | `parsers/graphqlcop/graphqlcop.json5`   |
| testssl     | testing     | `parsers/testssl/testssl.json5`         |

---

## Parsers

### Nmap — Script Vulnerability Reporting Not Implemented

The section for reporting vulnerabilities discovered by Nmap scripts is entirely empty.

- `parsers/nmap/nmap.py` (lines 393–398)

### Bearer — Unsupported Input Formats

Only JSON and YAML inputs are supported. Four other formats raise `NotImplementedError`:

- SARIF — `parsers/bearer/bearer.py` (line 25)
- SAST — `parsers/bearer/bearer.py` (line 27)
- RDJSON — `parsers/bearer/bearer.py` (line 37)
- HTML — `parsers/bearer/bearer.py` (line 42)

Additionally, source/sink trace information is not included in the output:

- `parsers/bearer/bearer.py` (lines 45–47)

### SSLScan — Unfinished Handling

SSL compression support is unimplemented:

- `parsers/sslscan/sslscan.py` (line 166)

Uncertain field mapping for client renegotiation:

- `parsers/sslscan/sslscan.py` (line 155)

CWE taxonomy values should be more specific than the generic CWE-310:

- `parsers/sslscan/sslscan.py` (line 190)

### Nikto — Deduce Missing OSVDB→CVE Mappings from Source History (side project)

`parsers/nikto/osvdb2cve.json` (regenerated from the Wayback Machine) is incomplete. We can mine more mappings from Nikto's own source: each test's `nikto_id` is stable across versions, but its reference column mutated `OSVDB-N → CVE-…` over time, so joining a test ID across revisions yields `OSVDB-N → CVE` pairs for free.

Approach: build `id → references` from every tag *and* the full `git log -p -- program/databases/db_tests` history; for each `nikto_id`, pair older OSVDB tokens with newer CVE tokens. Keep clean 1:1 replacements as high confidence.

Tougher than it looks — **upstream's edits are noisy**: `CVE-2011-3392` was the wrong vuln, `OSVCVE-2011-339244` was corrupted, and in a quick `2.5.0→main` single-token sample 2 of 5 overlaps *disagreed* with the existing map. So this is candidate generation, not a blind merge: emit `candidates.json` + `conflicts.json` for manual review, cross-check against the existing map, and filter corruption (malformed prefixes, mismatched year ranges). Best done as a standalone throwaway script, not wired into the parser.

### GraphQL Cop — Structural Reorganization

Error handling differences between HTTP and curl responses are not addressed:

- `parsers/graphqlcop/graphqlcop.py` (lines 7–8)

Output should be reorganized into three lists, one per consequence:

- `parsers/graphqlcop/graphqlcop.py` (lines 10–11)

### Bandit — Code Snippet Formatting

Indentation normalization for code snippets is not implemented:

- `parsers/bandit/bandit.py` (lines 447–448)

Debug block should be cleaned up:

- `parsers/bandit/bandit.py` (lines 404–411)

---

## Engine / Library

### Template Rendering

HTTP-to-Markdown conversion (`http2md`) should add syntax highlighting in addition to truncation:

- `libmagenta/template.py` (lines 138–139)

### Engine

Hardcoded `"main"` template bucket name needs review:

- `libmagenta/engine.py` (line 837)

### Merger

Consider skipping "none"-risk issues when another risk level is present, instead of merging them:

- `libmagenta/merger/__init__.py` (line 53)

Merger implementations for cleartext open ports and weak credentials use workarounds that should be cleaned up:

- `templates/nmap/cleartext_open_ports.py` (lines 10–12)
- `templates/hydra/weak_credentials_discovered_via_bruteforce_attack.py` (line 10)

---

## Templates

### Main Template

Severity/word translations could be moved to template variables:

- `templates/main.json5` (line 5)

Sections and subsections may need to be separated:

- `templates/main.json5` (line 16)

Vulnerability ID scheme could include codes for client, project, SOW, etc.:

- `templates/main.json5` (line 36)

### Bearer Templates

Translation support for generated templates is pending:

- `templates/bearer/generator/bearer-template-generator.py` (line 3)

---

## Third-party assets

- `libmagenta/table_linebreak_fix_gfm.lua` — pandoc filter, MIT-licensed, borrowed from [DradisMD](https://github.com/GoSecure/dradis-md). Used internally by the `dradis` exporter to coerce multi-line GFM table cells into clean Textile tables.
