# So you want to contribute to this project...

<p align="center">
  <img src="captain_america.webp" alt="Captain America" width="256"/>
</p>

# Tools

This table shows some tools I personally think would be good to add to Magenta. I've asked an LLM to format this into a table with some advice on how to tackle the development of the parsers and templates - so take this with a grain of salt.

| Priority Tier | Tool            | Category          | Output           | Difficulty      | Difficulty Notes                                                                                                                                                                                                                                                                                                                             |
| ------------- | --------------- | ----------------- | ---------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tier 1**    | Nuclei          | Vuln Scanner      | JSON/JSONL/SARIF | **Medium**      | Clean JSON, but the breadth of Nuclei templates is vast. A `generic_nuclei_vulnerability` approach (like your Nessus fallback) keeps it manageable. Mapping specific template IDs to dedicated Magenta templates can be done incrementally.                                                                                                  |
|               | ZAP             | Web DAST          | XML/JSON         | **Medium-Hard** | Well-structured XML/JSON, but many distinct alert types to map. Similar scope to Burp (which you already have in development). Could share templates with Burp via symlinks for overlapping vulnerability types (XSS, SQLi, etc.), which reduces template work significantly.                                                                |
|               | Semgrep         | SAST              | JSON/SARIF       | **Medium**      | Clean JSON schema. Hundreds of rules, but a `generic_semgrep_finding` template (like `generic_bandit_issue`) makes the parser itself straightforward. Dedicated templates can be added incrementally per rule. Similar architecture to your Bandit parser.                                                                                   |
|               | SARIF (generic) | Meta-format       | JSON             | **Medium-Hard** | The SARIF spec itself is well-defined and a Python SDK exists. The hard part is designing templates that produce good reports without tool-specific knowledge - you'd likely need a `generic_sarif_finding` template that leans on the SARIF fields (ruleId, level, message, location). Getting this *right* for many tools takes iteration. |
| **Tier 2**    | Trivy           | SCA/Container/IaC | JSON/SARIF       | **Medium**      | Clean JSON, but the schema varies by scan type (vulnerabilities vs. misconfigurations vs. secrets). Effectively 2-3 sub-parsers under one roof, each needing its own template(s).                                                                                                                                                            |
|               | OWASP Dep-Check | SCA               | JSON/XML/SARIF   | **Easy-Medium** | Well-structured JSON/XML. Each finding is a dependency+CVE pair. A single `vulnerable_dependency` aggregate template (like your SSLScan aggregate) covers most cases. The format is stable and well-documented.                                                                                                                              |
|               | Gitleaks        | Secrets           | JSON/SARIF       | **Easy**        | Simple JSON array with flat objects (file, line, rule, commit, redacted secret). One template (`hardcoded_secrets_detected`). Comparable to wafw00f in complexity. A weekend project.                                                                                                                                                        |
|               | WPScan          | CMS Scanner       | JSON             | **Easy-Medium** | JSON is well-structured but nested by component (core/plugins/themes). Need 2-4 templates (outdated WordPress, vulnerable plugin, vulnerable theme, user enumeration). Moderate mapping work.                                                                                                                                                |
|               | Grype           | Container SCA     | JSON/SARIF       | **Easy-Medium** | Clean JSON, each finding is a package+CVE match with confidence indicator. A single `vulnerable_dependency` template works. Could share templates with OWASP Dep-Check.                                                                                                                                                                      |
|               | TruffleHog      | Secrets           | JSON             | **Easy**        | Very similar to Gitleaks - simple JSON, 1-2 templates. Could share template with Gitleaks. Adds a `verified` boolean which is trivially handled.                                                                                                                                                                                             |
| **Tier 3**    | OpenVAS/GVM     | Vuln Scanner      | XML              | **Hard**        | XML via GMP protocol, similar in complexity to Nessus but with a different schema. Hundreds of NVT (plugin) types. Would mirror the Nessus parser architecture (large plugin-to-template mapping dict). Substantial effort to get good coverage.                                                                                             |
|               | Checkov         | IaC Security      | JSON/SARIF       | **Easy-Medium** | Clean JSON, each finding has check ID + pass/fail + resource. A `iac_misconfiguration` aggregate template works. The parser itself is simple; the question is mostly about template wording for misconfigurations.                                                                                                                           |
|               | Prowler         | Cloud Security    | JSON-OCSF        | **Medium**      | JSON-OCSF is verbose with deeply nested structure. Many check types across AWS/Azure/GCP. A generic template handles the parser, but cloud-specific templates for common findings (public S3, open security groups) would make reports much better.                                                                                          |
|               | enum4linux-ng   | SMB Enumeration   | JSON/YAML        | **Easy-Medium** | Clean JSON/YAML output. Limited set of reportable findings (null session, guest account, weak password policy, open shares). 3-5 templates. Straightforward mapping.                                                                                                                                                                         |
|               | Gosec           | Go SAST           | JSON/SARIF       | **Easy**        | Almost identical architecture to Bandit - same "language-specific SAST with JSON output and rule IDs" pattern. Could model the parser directly after your Bandit parser. If you've done Bandit, you've essentially done this.                                                                                                                |
|               | Retire.js       | JS SCA            | JSON             | **Easy**        | Simple JSON: library name + version + CVEs. One aggregate template (`vulnerable_javascript_library`). Could reuse/symlink `outdated_javascript_library_found` if it fits. ~wafw00f complexity.                                                                                                                                               |
|               | Safety          | Python SCA        | JSON             | **Easy**        | Clean JSON with vulnerabilities array. One template (`vulnerable_python_dependency`). Trivial parser, ~50-70 lines.                                                                                                                                                                                                                          |
|               | Masscan         | Port Scanner      | JSON/XML         | **Easy**        | JSON output is a simple port list. Nmap-compatible XML *might* work with your existing Nmap parser with minimal changes (worth testing first - could be near-zero effort). If not, the JSON parser is ~wafw00f complexity since the output is just open ports.                                                                               |
| **Tier 4**    | Wapiti          | Web DAST          | JSON/XML         | **Medium**      | Clean JSON, but many vulnerability categories (XSS, SQLi, SSRF, command injection, etc.) each needing a template. Could share templates with ZAP/Burp for overlapping types, reducing work.                                                                                                                                                  |
|               | Brakeman        | Ruby SAST         | JSON             | **Easy-Medium** | Stable JSON, limited rule set compared to Semgrep. Same pattern as Bandit/Gosec. ~1 day if you've done either of those.                                                                                                                                                                                                                      |
|               | Feroxbuster     | Content Discovery | JSON             | **Easy**        | Simple JSON with URL + status code + metadata. One template (`sensitive_paths_discovered`). ~wafw00f complexity. The harder part is deciding *what* constitutes a reportable finding from content discovery data.                                                                                                                            |
|               | DNSRecon        | DNS Enum          | JSON/XML         | **Easy-Medium** | JSON output with DNS records. 2-3 templates (zone transfer allowed, DNSSEC missing, informational DNS records). The parser is simple; the template wording for DNS issues takes some thought.                                                                                                                                                |
|               | Kube-hunter     | K8s Pentesting    | JSON             | **Easy-Medium** | JSON with limited finding types. 3-5 templates for common K8s issues. Straightforward.                                                                                                                                                                                                                                                       |
|               | Kube-bench      | K8s Compliance    | JSON             | **Easy-Medium** | JSON with CIS benchmark checks. A single aggregate template works, but historical JSON validity issues may require defensive parsing.                                                                                                                                                                                                        |
|               | MobSF           | Mobile SAST       | JSON (API)       | **Hard**        | API-only (not a file export), poorly documented JSON schema, historical bugs in JSON generation. You'd need to reverse-engineer the output structure from actual API responses. Fragile.                                                                                                                                                     |
|               | Acunetix        | Web DAST          | XML/JSON         | **Medium-Hard** | Multiple format versions between Acunetix classic and Acunetix 360. Many vulnerability types. XML export schema has changed over time.                                                                                                                                                                                                       |
|               | Qualys          | Vuln Scanner      | XML/JSON (API)   | **Hard**        | Multiple product modules (VM, WAS, Cloud Security) with completely different formats. API-gated access. Would effectively be 2-3 separate parsers.                                                                                                                                                                                           |
|               | Snyk CLI        | Multi SCA/SAST    | JSON/SARIF       | **Medium**      | Clean JSON, but covers multiple scan types (open source, code, container, IaC) with varying schemas. Requires auth even for testing.                                                                                                                                                                                                         |

**Difficulty scale reference:**

| Rating          | Time Estimate            | Comparable Existing Parser |
| --------------- | ------------------------ | -------------------------- |
| **Easy**        | An evening / a few hours | wafw00f, hydra             |
| **Easy-Medium** | Half a day to a day      | graphqlcop, shortname      |
| **Medium**      | 1-2 days                 | nikto, sslscan             |
| **Medium-Hard** | 2-3 days                 | burp (in development)      |
| **Hard**        | 3-5+ days                | nessus                     |

---

# TODO

Pending work items tracked across the codebase. If you want to help me finish pending work rather than adding entirely new features, here's where I need a hand:

---

## Parser Maturity

The following parsers are not yet at production status:

| Parser      | Status      | Metadata file                           |
| ----------- | ----------- | --------------------------------------- |
| Burp        | development | `parsers/burp/burp.json5`               |
| GraphQL Cop | development | `parsers/graphqlcop/graphqlcop.json5`   |
| Nessus      | development | `parsers/nessus/nessus.json5`           |
| Bandit      | development | `parsers/bandit/bandit.json5`           |
| AttackForge | testing     | `parsers/attackforge/attackforge.json5` |
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

### Nessus — Generic Fallback Handlers

Many vulnerability-specific handlers simply delegate to `do_generic_nessus_vulnerability()` instead of producing tailored output:

- `parsers/nessus/nessus.py` (lines 139, 143, 187, 191, 195, 199, 203, 321, 325, 420, 449, 453)

The CPE field also needs conversion to a human-readable string:

- `parsers/nessus/nessus.py` (line 389)

A hardcoded CPE value for jQuery needs a proper fix:

- `parsers/nessus/nessus.py` (line 331)

### Burp — Logic Bug and Missing Features

Request/response handling is incorrect when a single issue contains more than one request/response pair:

- `parsers/burp/burp.py` (lines 305–306)

The "Vulnerable JavaScript dependency" handler needs work to report on known vulnerabilities:

- `parsers/burp/burp.py` (lines 446–448)

Latest software version discovery is missing (may require online access):

- `parsers/burp/burp.py` (lines 428–429)

SQL injection mapping is commented out:

- `parsers/burp/burp.py` (line 105)

### SSLScan — Unfinished Handling

SSL compression support is unimplemented:

- `parsers/sslscan/sslscan.py` (line 166)

Uncertain field mapping for client renegotiation:

- `parsers/sslscan/sslscan.py` (line 155)

CWE taxonomy values should be more specific than the generic CWE-310:

- `parsers/sslscan/sslscan.py` (line 190)

### Nikto — Severity Enrichment from CVEs

Issue severity should be derived from CVE data:

- `parsers/nikto/nikto.py` (line 15)

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

### Burp Templates

`missing_security_headers.json5` — richer per-header descriptions, per-header recommendations, and additional references are pending:

- `templates/burp/missing_security_headers.json5` (lines 6–7, 10–11, 18)

`mixed_content.json5` (and its `.es.json5` translation) needs improvement:

- `templates/burp/mixed_content.json5` (line 10)
- `templates/burp/mixed_content.es.json5` (line 10)

`outdated_javascript_library_found.json5` — HTTP responses could be added as evidence when available:

- `templates/burp/outdated_javascript_library_found.json5` (line 10)

### Bearer Templates

Translation support for generated templates is pending:

- `templates/bearer/generator/bearer-template-generator.py` (line 3)
