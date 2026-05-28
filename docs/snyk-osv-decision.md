# Vulnerability ID Map: Snyk vs OSV.dev (Decision Notes)

Reference notes from a design conversation (2026-05) about how to build a cross-database advisory-ID map (CVE ↔ CWE ↔ GHSA ↔ ecosystem-specific IDs) for use inside magenta's reporting layer.

## Goal

A canonical mapping table of vulnerability advisory IDs across taxonomies, including CWE tags and other lightweight metadata, but **not** the full advisory text. At most a 1-line excerpt suitable for a report table.

The map should let reports either:
- Expand any given ID to all of its known equivalents/tags, or
- Pick a preferred taxonomy (e.g. CVE + CWE) and translate everything to it where possible.

## Options considered

### Option 1 — Scrape Snyk by known CVEs

For every CVE we already know, fetch `https://security.snyk.io/vuln/<CVE>` (or the Snyk-ID-resolving equivalent), parse the page, store the cross-references.

- Pros: parallelizable, polite-ish (one request per known ID), easy to resume, no full DB walk.
- Cons: silently misses every Snyk advisory that has no CVE (notably npm/pip ecosystem-only entries).

### Option 2 — Paginate the Snyk vuln listing

Walk `https://security.snyk.io/vuln/<page>?tab=vulnerabilities` from page 1 to N.

- Pros: complete coverage.
- Cons: almost certain to hit rate limits or an IP block; sync issues if entries are added/removed during the walk.

### Option 3 — Pagination split by ecosystem / OS

Approach 2, but partitioned by application ecosystem or OS distro so each shard is small enough to run from a different egress IP.

- Pros: completeness with less per-IP load.
- Cons: significantly more coordination; still scraping a site that doesn't want to be scraped.

## What we found out about Snyk

Before committing to any scraping approach, we checked whether Snyk offers a canonical bulk path. Findings:

- **No public bulk API.** On [snyk/snyk#1651](https://github.com/snyk/snyk/issues/1651), Snyk's official answer was: *"No, sorry, we don't make this data available in bulk."*
- The old community mirror `lirantal/vulndb` is **gone** (404). Not usable as a fallback.
- Snyk's bulk data is sold as two commercial products — "Application Feed" and "Operating System Feed" — licensed separately.
- The Snyk REST/V1 API is project-scoped (scan-a-thing endpoints), not advisory-dump endpoints.

In other words: there is no polite, supported way to mirror the Snyk DB. Any of options 1–3 would be operating against Snyk's stated position.

## What we found out about OSV.dev

- OSV.dev is Google's open vulnerability database, covering ~30 ecosystems and ~870k records (as of 2026-05).
- Snyk itself **consumes** OSV data — most of Snyk's coverage in the open-source ecosystem space ultimately derives from the same upstream sources OSV aggregates (GHSA, RustSec, PyPA, GoVulnDB, Linux distro advisories, NVD, etc.).
- The entire corpus is published as a single zip at `gs://osv-vulnerabilities/all.zip`, plus per-ecosystem zips at `gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`, plus individual records at `gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json`.
- No auth, no rate limits, no scraping, refreshed continuously. See [Data sources | OSV](https://google.github.io/osv.dev/data/).
- Cross-references between IDs (CVE ↔ GHSA ↔ ecosystem ID) are already baked into the OSV records; CWE tags propagate from upstream sources.

## Decision

**Pivot to OSV.dev. Ignore Snyk for now.**

Plan:

1. Mirror `gs://osv-vulnerabilities/all.zip` (or selected per-ecosystem zips) on a daily refresh.
2. Build the ID ↔ CWE ↔ short-excerpt map directly from OSV records.
3. Treat OSV as the canonical source for cross-taxonomy translation in magenta.

### What we explicitly give up

- We will not have `SNYK-*` IDs in the map. For magenta's report-generation use case, this is acceptable: SNYK-IDs are mostly redundant with CVE/GHSA, which OSV does have.
- Snyk's analyst-curated *narrative* content (exploitability examples, remediation prose) is not in OSV. We don't want that anyway — the stated goal was IDs + tags + a 1-line excerpt, not advisory bodies.

### When (if ever) to revisit Snyk

Worth coming back only if:
- We find we actually need SNYK-only advisories (i.e. a non-trivial set of advisories that exist in Snyk and have no CVE/GHSA/ecosystem-ID equivalent in OSV), **and**
- The use case justifies operating against Snyk's stated bulk-access policy or paying for the licensed feed.

Until then: **option 1 (CVE-driven Snyk lookup) remains the cheapest fallback** if we ever need to enrich a specific advisory on demand, but is not the bulk-map strategy.

## References

- [Snyk issue #1651 — no bulk API answer](https://github.com/snyk/snyk/issues/1651)
- [OSV.dev data sources & GCS bucket layout](https://google.github.io/osv.dev/data/)
- [Snyk Vulnerability Database docs](https://docs.snyk.io/scan-with-snyk/snyk-open-source/manage-vulnerabilities/snyk-vulnerability-database)
- [Dependency-Track OSV integration (example of a daily-refresh mirror)](https://docs.dependencytrack.org/datasources/osv/)
