# testssl.sh JSON output — format history & magenta compatibility notes

A research document mapping testssl.sh's finding-ID surface across the 3.0 stable era through the current 3.3dev snapshot, with annotations for where the magenta parser ([testssl.py](testssl.py)) and templates ([../../templates/multiple_ssl_issues.json5](../../templates/multiple_ssl_issues.json5), [../../templates/multiple_ssl_issues.es.json5](../../templates/multiple_ssl_issues.es.json5)) are out of step with one or more testssl versions.

Not a spec — testssl ships no formal one. Sourced by parsing every `jsonID="..."` assignment and `fileout` call in `testssl.sh` at each tag.

## Tags surveyed

| Era | Representative tags | Released |
|---|---|---|
| 3.0 stable | `v3.0`, `v3.0.10` | 2019-07 → 2023-09 |
| 3.2 | `v3.2.0`, `v3.2.3` | 2024-12 → 2025-05 |
| 3.3dev | `v3.3dev-snapshot-2602` (plus `HEAD` delta) | 2025-12 |

Pre-3.0 (v2.x) intentionally not covered — JSON output was experimental and is unlikely to be encountered in practice.

## Inventory scale

| Tag | Unique resolved IDs | `fileout` call sites |
|---|---|---|
| v3.0 | 117 | 527 |
| v3.0.10 | 120 | 539 |
| v3.2.0 | 166 | 613 |
| v3.2.3 | 166 | 615 |
| v3.3dev-snapshot-2602 | ~170 (4 added since v3.2.3) | ~625 |

## Breaking renames (3.0 → 3.2)

These four ID renames landed between the end of the 3.0 era and the start of the 3.2 era. Any magenta deployment that ingests scans from a mixed-version testssl fleet needs to handle both names.

| Old ID (3.0.x) | New ID (3.2+) | Source commit | Notes |
|---|---|---|---|
| `PFS` | `FS` | testssl rename of "Perfect Forward Secrecy" → "Forward Secrecy" | All `PFS_*` IDs also renamed to `FS_*` (e.g., `PFS_ECDHE_curves` → `FS_ECDHE_curves`, `PFS_ciphers` → `FS_ciphers`) |
| `cipherlist_AVERAGE` | `cipherlist_OBSOLETED` | `6f881dc7` *"Rename 3 jsonIDs in run_cipherlists(): breaking change"* (2023-02-05, first in v3.2.0) | testssl commit message is explicit: "breaking change" |
| `cipherlist_GOOD` | `cipherlist_STRONG_NOFS` | `6f881dc7` | "Good" became "strong but no forward secrecy" |
| `cipherlist_STRONG` | `cipherlist_STRONG_FS` | `6f881dc7` | "Strong" became "strong with forward secrecy" |

## Removed IDs (3.0 → 3.2)

Findings that the 3.0 era emitted but 3.2+ does not.

| ID | Removed in | Source commit |
|---|---|---|
| `cipher_negotiated` | v3.2.0 | `1842b9ee` *"Remove Negotiated cipher / protocol in server preferences"* |
| `protocol_negotiated` | v3.2.0 | `1842b9ee` |

Maintainer rationale (per the commit message and [PR #2235](https://github.com/drwetter/testssl.sh/pull/2235)): these two findings just reported whatever the *default* openssl-client/server negotiation produced on a single connection. They reflect the test harness's configuration, not a security property of the server — duplicated by `cipher_order`, the cipherlist findings, and the per-protocol checks.

Magenta follows the same judgment: [parsers/testssl/testssl.py](testssl.py) explicitly skips both IDs even when scanning older v3.0.x output, and the template paragraphs have been removed.

## Added IDs (3.0 → 3.2)

Net new findings introduced during the 3.2 era. Magenta needs paragraphs for these to render anything meaningful when scanning with 3.2+.

### Vulnerabilities / security findings
- `starttls_injection` *(commit `6c966a5a`)* — STARTTLS injection for SMTP
- `winshock` *(commit `a511da4c`)* — MS14-066 RCE in Microsoft SChannel
- `intermediate_cert_badOCSP` *(commit `903eeec9`)* — Hanno's bad-OCSP intermediate CA detector
- `cert_trust<n>_wildcard` — flagged when SNI trust is via wildcard cert

### Server-defaults expansion
- `clientAuth`, `clientAuth_CA_list`, `clientAuth_CA_list #<i>` *(commit `9dbb6291`)*
- `cert_compression`, `certificate_compression` *(commit `fa1ccdb5`)* — RFC 8879
- `early_data` — added even later (3.3dev), see next section
- `TLS_misses_extension_23` — same (3.3dev)

### Cipher-order / preference refactor
- `cipher_order-<proto>`, `prioritize_chacha_<proto>`, `supportedciphers_<proto>` *(commits `fa5d13eb`, `5c889bde`)*

### Rating subsystem (first emitted in 3.2 — scaffolding present but unused in 3.0.x)
- `overall_grade`
- `rating_spec`, `rating_doc`
- `grade_cap_reason_<n>`, `grade_cap_warning_<n>`
- `final_score`
- `key_exchange_score`, `key_exchange_score_weighted`
- `cipher_strength_score`, `cipher_strength_score_weighted`
- `protocol_support_score`, `protocol_support_score_weighted`

### Forward-secrecy expansion
- `FS_KEMs` — post-quantum KEMs (LOW when none offered)
- `FS_TLS12_sig_algs`, `FS_TLS13_sig_algs` — signature algorithm offerings (can reach HIGH)
- `DH_groups` — severity is computed via a shell variable (`$quality_str`) in the testssl source rather than being a literal. The JSON output the parser sees is unchanged in shape; this is a non-issue for downstream parsers.

### Intermediate certificate detail
- `intermediate_cert <#<i>><n>`
- `intermediate_cert_chain <#<i>><n>`
- `intermediate_cert_expiration <#<i>><n>`
- `intermediate_cert_fingerprintSHA256 <#<i>><n>`
- `intermediate_cert_notAfter <#<i>><n>`
- `intermediate_cert_notBefore <#<i>><n>`

### Other
- `HSTS_multiple` *(via `match_httpheader_key`'s `_multiple` suffix mechanism)*
- `scanTime`, `HTTP_headerTime`
- `cert_extlifeSpan<n>`

## Added IDs (3.2.3 → 3.3dev-snapshot-2602)

Four new IDs since the last 3.2 stable. All four are entirely new and not currently handled by magenta.

| ID | Function | Severities | Note |
|---|---|---|---|
| `QUIC` | `sub_quic` | INFO, OK, WARN | QUIC protocol detection |
| `TLS_misses_extension_23` | `run_server_defaults` | INFO, MEDIUM, WARN | Missing extended master secret extension (RFC 7627/9325) |
| `early_data` | `run_server_defaults` | HIGH, INFO, OK, WARN | TLS 1.3 0-RTT early data support |
| `opossum` | `run_opossum` | CRITICAL, INFO, OK, WARN | OpOSSum vulnerability (CVE pending — see testssl.sh source for current refs) |

## Intra-era changes

### v3.0 → v3.0.10
- **Added**: `HTTP_headerAge`, `cert_serialNumberLen<n>`, `optimal_proto`
- **Removed**: none
- **Severity-set changes**:
  - `BREACH`: lost HIGH+INFO, gained MEDIUM
  - `SSLv2`: lost INFO
  - `protocol_negotiated`: swapped INFO for LOW

### v3.2.0 → v3.2.3
- **Added**: none
- **Removed**: none
- **Severity-set changes**:
  - `FS_KEMs`: added LOW (new "No KEMs offered" branch)
  - `HTTP_headerAge`: added LOW (new "not a non-negative integer" branch)
  - `pwnedkeys<n>`: "not in database" branch downgraded INFO → OK

### v3.3dev-snapshot-2602 → HEAD (uncommitted-to-tag work)
- `TLS_misses_extension_23`: added new LOW branch for misconfigured TLS 1.3-only extension presence
- `cert_signatureAlgorithm<n>`: SM2/SM3 INFO branch added
- Text refinements only on a handful of WARN messages

## Latent bugs in testssl that affect parsing

These aren't format changes — they're parsing landmines that have persisted across versions. Worth knowing about.

1. **`run_sweet32` emits with an unresolved `$jsonID`** *(present in v3.0, v3.0.10, v3.2.0, v3.2.3, v3.3dev-snapshot-2602)*
   - The function calls `fileout "$jsonID" "OK" "not vulnerable"` for the TLS-1.3-only branch but never assigns `jsonID` locally. The emitted JSON key is whatever the previous function left in the shell-global variable — effectively unpredictable.
   - Impact for magenta: an unexpected ID may appear with severity OK and the finding text "not vulnerable" — currently passes through to `problems` if severity is LOW+ (which it isn't, so silently filtered).

2. **`cert_keySize<n>` has a malformed fileout** *(present across the full 3.0+ range)*
   - One branch calls `fileout "$jsonID" "cannot be determined"` with only two args — the would-be severity slot contains a literal English string.
   - Impact for magenta: parser's `item["severity"] in ratings` check will fail for that one item (it's not OK/LOW/MEDIUM/HIGH/CRITICAL), so it gets dropped on the floor. Behavior is correct but for the wrong reason.

3. **`run_crime` unresolved `$jsonID`** *(v3.0 only — fixed in v3.0.10 by `5793bc26`)*
   - Same shape of bug as run_sweet32; only affects v3.0 scan files.

4. **`rated_output` function defined but never called** *(v3.2+)*
   - Dead code; its `fileout` calls never fire. Not a parser concern but flagged for completeness.

## Compatibility matrix for magenta-relevant IDs

Limited to IDs that the magenta template currently has paragraphs for, or that the parser populates `bad_ciphers`/`problems` from, or that were considered and intentionally dropped. ✓ = emitted, ✗ = not emitted, ↔ = renamed (see Breaking renames section). The "Magenta status" column describes current behavior — "intentionally skipped" entries are dropped on purpose; "not surfaced (informational)" entries can never reach LOW+ severity and so wouldn't be reported even if wired up.

| ID (or template paragraph name) | v3.0 | v3.0.10 | v3.2.x | v3.3dev | Magenta status |
|---|:-:|:-:|:-:|:-:|---|
| `PFS` | ✓ | ✓ | ↔ FS | ↔ FS | Aliased to `FS` in parser; template renders `FS` paragraph |
| `FS` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `PFS_ECDHE_curves` | ✓ | ✓ | ↔ FS_ECDHE_curves | ↔ FS_ECDHE_curves | Aliased to `FS_ECDHE_curves` |
| `PFS_ciphers` | ✓ | ✓ | ↔ FS_ciphers | ↔ FS_ciphers | Aliased to `FS_ciphers` (informational, not surfaced) |
| `cipherlist_AVERAGE` | ✓ | ✓ | ↔ OBSOLETED | ↔ OBSOLETED | Aliased to `cipherlist_OBSOLETED` |
| `cipherlist_GOOD` | ✓ | ✓ | ↔ STRONG_NOFS | ↔ STRONG_NOFS | Aliased to `cipherlist_STRONG_NOFS`; paragraph added |
| `cipherlist_STRONG` | ✓ | ✓ | ↔ STRONG_FS | ↔ STRONG_FS | Aliased to `cipherlist_STRONG_FS` |
| `cipher_negotiated` | ✓ | ✓ | ✗ | ✗ | Intentionally skipped (see Removed IDs section) |
| `protocol_negotiated` | ✓ | ✓ | ✗ | ✗ | Intentionally skipped (see Removed IDs section) |
| `cipher_order` | ✓ | ✓ | ✓ | ✓ | Template handles; per-protocol variants normalized in parser |
| `cert_chain_of_trust<n>` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `cert_trust<n>` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `cert_trust<n>_wildcard` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `cert_extlifeSpan<n>` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `cert_serialNumberLen<n>` | ✗ | ✓ | ✓ | ✓ | Template handles |
| `cert_signatureAlgorithm<n>` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `BEAST` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `BEAST_CBC_<PROTO>` | ✓ | ✓ | ✓ | ✓ | Consumed by parser into `bad_ciphers` |
| `winshock` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `secure_client_renego` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `LOGJAM` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `LOGJAM-common_primes` | ✓ | ✓ | ✓ | ✓ | Template handles |
| `starttls_injection` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `intermediate_cert_badOCSP<n>` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `TLS_misses_extension_23` | ✗ | ✗ | ✗ | ✓ | Template handles |
| `early_data` | ✗ | ✗ | ✗ | ✓ | Template handles |
| `opossum` | ✗ | ✗ | ✗ | ✓ | Template handles |
| `FS_KEMs` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `FS_TLS12_sig_algs`, `FS_TLS13_sig_algs` | ✗ | ✗ | ✓ | ✓ | Template handles |
| `clientAuth`, `clientAuth_CA_list` | ✗ | ✗ | ✓ | ✓ | Not surfaced (informational; INFO only) |
| `certificate_compression`, `cert_compression` | ✗ | ✗ | ✓ | ✓ | Not surfaced (informational; INFO only) |
| `intermediate_cert <#<i>><n>` (and chain/expiration/fingerprint variants) | ✗ | ✗ | ✓ | ✓ | Not surfaced (informational; INFO/$expok only) |
| `HSTS_multiple`, `HSTS_preload`, `HSTS_subdomains`, `HSTS_time` | ✓ | ✓ | ✓ | ✓ | Not surfaced (only base `HSTS` is wired up; sub-findings are LOW/INFO HTTP-header detail) |
| `HTTP_*`, `insecure_redirect`, `ipv4_in_header`, `cookie_*`, `security_headers` | ✓ | ✓ | ✓ | ✓ | Not surfaced (HTTP-header tooling, out of scope for magenta's SSL/TLS focus) |
| `overall_grade`, `rating_spec`, `grade_cap_reason_<n>` | ✗ | ✗ | ✓ | ✓ | Parser treats as special cases; grade paragraph renders them |
| `final_score`, `key_exchange_score*`, `cipher_strength_score*`, `protocol_support_score*` | ✗ | ✗ | ✓ | ✓ | Not surfaced (informational rating subcomponents) |
| `QUIC` | ✗ | ✗ | ✗ | ✓ | Not surfaced (informational; INFO/OK/WARN only) |

## Severity trust

testssl assigns severities based on context (OpenSSL flags used, what other findings were observed, etc.) that isn't always preserved in the JSON output. Magenta trusts the severity testssl assigns and does not attempt to re-rate findings. The intra-era severity-set changes documented above (e.g., `BREACH` losing HIGH+INFO between v3.0 and v3.0.10, `pwnedkeys` "not in database" going from INFO to OK in v3.2.3) reflect testssl maintainers' judgment; reports generated against older scan files will reflect the older judgments, and that's by design.

## Status of actionable gaps

The high- and medium-impact gaps identified in earlier revisions of this document have been addressed:

- **3.0 → 3.2 renames** (`PFS`, `PFS_ECDHE_curves`, `PFS_ciphers`, `cipherlist_AVERAGE`, `cipherlist_GOOD`, `cipherlist_STRONG`) are now aliased in the parser via [`LEGACY_ID_RENAMES`](testssl.py). The merger ([../../templates/multiple_ssl_issues.py](../../templates/multiple_ssl_issues.py)) keeps a synced copy of the same map and sanitizes these tags as a cross-parser safety net: if *any* parser emits a known legacy tag, the merger rewrites it and prints a loud `stderr` warning so the parser bug gets noticed rather than silently masked. Unknown tags are deliberately left untouched (they may be findings from a newer, not-yet-supported testssl version).
- **`cipherlist_STRONG_NOFS` paragraph** added to both templates.
- **New finding paragraphs** wired up: `early_data` (HIGH), `TLS_misses_extension_23` (MEDIUM), `opossum` (CRITICAL), `LOGJAM-common_primes` (HIGH ceiling), `starttls_injection` (HIGH), `intermediate_cert_badOCSP` (MEDIUM), `cert_trust_wildcard` (LOW), `FS_KEMs` (LOW), `FS_TLS12_sig_algs` / `FS_TLS13_sig_algs` (HIGH).
- **`cert_keySize` malformed-fileout** explicitly guarded in the parser.

Items intentionally left unhandled:
- `clientAuth*`, `certificate_compression`, intermediate cert chain detail, rating subcomponents (`final_score`, `*_score_weighted` etc.), `QUIC` — all INFO-only; below magenta's surfacing threshold.
- `HSTS_*` sub-findings, `HTTP_*`, `insecure_redirect`, `ipv4_in_header`, `cookie_*`, `security_headers` — HTTP-header tooling, outside magenta's TLS scope.

### Maintenance notes

- The parser's `additional_references` and `additional_taxonomies` dicts in [testssl.py](testssl.py) should grow entries for any future finding that gets a template paragraph.
- `LEGACY_ID_RENAMES` is intentionally duplicated in [testssl.py](testssl.py) and [../../templates/multiple_ssl_issues.py](../../templates/multiple_ssl_issues.py) (parser normalizes at parse time; merger sanitizes + warns as a safety net). The two copies MUST be kept in sync — both files carry a comment saying so. A longer-term fix would replace the testssl-specific tag vocabulary with a tool-agnostic SSL/TLS finding schema, retiring both copies.
- testssl's `<json_postfix>` mechanism (empty string for single-cert hosts, ` <hostCert#N>` for every cert on multi-cert hosts — note the leading space) is handled by the parser. The marker is stripped wherever it appears (including mid-string, as in `cert_trust <hostCert#2>_wildcard`) before the `if " " in id: tag = id.split(" ", 1)[0]` collapse, so per-cert findings merge into a single tag and trailing suffixes like `_wildcard` are preserved. This intentionally collapses all certs' findings of a given type into one tag — magenta does not report per-certificate.
- `match_httpheader_key` dynamically constructs `<header_name>_multiple` IDs from a 21-entry header list in `run_security_headers`. Magenta intentionally doesn't surface any of those (HTTP-header tooling, out of scope); if it ever wants to, the full list is enumerable from `run_security_headers` source at any tag.
