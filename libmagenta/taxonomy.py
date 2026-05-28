#!/usr/bin/python3

# The following taxonomies are supported:
#
#   * General vulnerability databases:
#     - MITRE Common Vulnerabilities and Exposures (CVE)
#     - MITRE Common Weakness Enumeration (CWE)
#     - MITRE Common Attack Pattern Enumeration and Classification (CAPEC)
#     - Chinese National Vulnerability Database (CNVD)
#     - Japanese Vulnerability Database (JVNDB / JVN)
#     - Russian Federation Data Bank of Information Security Threats (BDU)
#     - French CERT advisories, alerts, bulletins, CTI and IOC reports (CERTFR)
#
#   * Vendor-specific advisories:
#     - Ubuntu Security Notices (USN)
#     - Red Hat Security Announcements (RHSA)
#     - Debian Security Announcements (DSA)
#     - Microsoft Knowledge Base (KB)
#     - Microsoft Security Bulletins (MS)
#     - Mozilla Foundation Security Advisories (MFSA)
#     - WPScan Wordpress Vulnerability Database (WPVDB)
#     - Rust Security Advisory Database (RUSTSEC)
#
#   * Exploit databases:
#     - Exploit DB (EDB-ID)
#     - 1337 Day DB (1337DAY-ID)
#
#   * Aggregator databases:
#     - Synk Vulnerability Database (SYNK)
#     - Open Source Vulnerabilities (OSV, including PYSEC)
#     - GitHub Security Advisories (GHSA)
#     - Vulners Security Database (namespaces: GITHUBEXPLOIT, PACKETSTORM,
#       PATCHSTACK, SECURITYVULNS:DOC, WPEX-ID)
#     - Open Bug Bounty Reports (OBB)
#
#   * Misc:
#     - IETF Request For Comments (RFC)
#
# Additionally, tag_from_url recognizes the following CVE-mirror URL sources
# and collapses each one to the canonical CVE-XXXX-NNNN tag (no separate tag
# prefix is produced):
#
#   - cve.org (canonical CVE Program site, replaced cve.mitre.org in 2024)
#   - cve.mitre.org (legacy MITRE host, still resolves)
#   - National cybersecurity agencies:
#       * NVD (US NIST — enrichment layer over cve.org)
#       * INCIBE (Spain's national cybersecurity institute)
#   - Vendor trackers: SUSE, Red Hat, Ubuntu, Debian
#   - Third-party DBs: OpenCVE, SentinelOne, Tenable, GCVE, Aqua, Vulners,
#     Feedly, Vulmon, RedPacketSecurity

import re
import urllib.parse

# Optional trailing query string / fragment / slash. Forward url_from_tag never
# emits these, but real-world references often carry them, so the inverse tolerates.
URL_TAIL = r"/?(?:[?#].*)?$"

# CERT-FR routes documents by the infix in the tag id (CERTFR-YYYY-<INFIX>-NNNN)
# onto distinct URL path segments. Shared between url_from_tag and tag_from_url.
CERTFR_PATHS = {
    "AVI": "avis",  # Avis de sécurité (security advisories)
    "ALE": "alerte",  # Alertes (active alerts)
    "ACT": "actualite",  # Bulletins d'actualité (weekly bulletins)
    "CTI": "cti",  # Cyber threat intelligence
    "IOC": "ioc",  # Indicators of compromise
}

# Vendor-prefixed CVE aliases that carry no information beyond the bare CVE id.
# normalize_tag() collapses these so deduplication can merge them with plain CVE-*.
CVE_PREFIX_ALIASES = ("UBUNTU-CVE-", "DEBIAN-CVE-")

# Compiled once at import. Order matters: more-specific URLs first
# (jvndb.jvn.jp before jvn.jp; docs.microsoft.com bulletins before support.microsoft.com/kb).
#
# CVE mirror entries (cve.org, NVD, vendor advisories, third-party DBs) all
# collapse to the same canonical CVE-XXXX-NNNN tag. Forward url_from_tag emits
# the cve.org form; the inverse recognizes cve.mitre.org as legacy plus a
# curated allowlist of mirror domains, each as its own pattern.
TAG_FROM_URL_PATTERNS = [
    # Canonical CVE Program site (cve.org replaced cve.mitre.org in 2024).
    (
        re.compile(
            r"^https?://(?:www\.)?cve\.org/CVERecord\?id=(CVE-\d{4}-\d{4,})(?:[&#].*)?$",
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    # Legacy MITRE host. Still resolves; older exports point here.
    (
        re.compile(
            r"^https?://cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=(CVE-\d{4}-\d{4,})(?:[&#].*)?$",
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    # NVD: enrichment layer (CVSS/CWE/CPE) over cve.org.
    (
        re.compile(
            r"^https?://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    # Vendor security trackers that publish per-CVE pages.
    (
        re.compile(
            r"^https?://(?:www\.)?suse\.com/security/cve/(CVE-\d{4}-\d{4,})\.html"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://access\.redhat\.com/security/cve/(cve-\d{4}-\d{4,})" + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://ubuntu\.com/security/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://security-tracker\.debian\.org/tracker/(CVE-\d{4}-\d{4,})"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?incibe\.es/index\.php/incibe-cert/alerta-temprana/vulnerabilidades/(cve-\d{4}-\d{4,})"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    # Third-party CVE databases / SaaS.
    (
        re.compile(
            r"^https?://app\.opencve\.io/cve/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?sentinelone\.com/vulnerability-database/(cve-\d{4}-\d{4,})"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?tenable\.com/cve/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://db\.gcve\.eu/vuln/(cve-\d{4}-\d{4,})" + URL_TAIL, re.I),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://avd\.aquasec\.com/nvd/\d{4}/(cve-\d{4}-\d{4,})" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://vulners\.com/cve/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://feedly\.com/cve/(CVE-\d{4}-\d{4,})" + URL_TAIL, re.I),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://vulmon\.com/vulnerabilitydetails\?qid=(CVE-\d{4}-\d{4,})(?:[&#].*)?$",
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?redpacketsecurity\.com/cve_alert_(cve-\d{4}-\d{4,})"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://cwe\.mitre\.org/data/definitions/(\d+)\.html" + URL_TAIL, re.I
        ),
        lambda m: "CWE-" + m.group(1),
    ),
    (
        re.compile(
            r"^https?://capec\.mitre\.org/data/definitions/(\d+)\.html" + URL_TAIL, re.I
        ),
        lambda m: "CAPEC-" + m.group(1),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?cnvd\.org\.cn/flaw/show/(CNVD-[\w\-]+)" + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://jvndb\.jvn\.jp/\w+/contents/\d{4}/(JVNDB-[\w\-]+)\.html"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://jvn\.jp/jp/(JVN[\w\-]+)/index\.html" + URL_TAIL, re.I),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://bdu\.fstec\.ru/vul/([\w\-]+?)" + URL_TAIL, re.I),
        lambda m: "BDU:" + m.group(1),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?cert\.ssi\.gouv\.fr/(?:"
            + "|".join(CERTFR_PATHS.values())
            + r")/(CERTFR-[\w\-]+)"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://ubuntu\.com/security/notices/(\d[\w\-]*?)" + URL_TAIL, re.I
        ),
        lambda m: "USN-" + m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://access\.redhat\.com/errata/(RHSA-[\w:\-]+?)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?debian\.org/security/(dsa-[\w\-]+?)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://docs\.microsoft\.com/en-us/security-updates/securitybulletins/\d{4}/(ms\d{2}-\d+)"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://support\.microsoft\.com/kb/(\d+)" + URL_TAIL, re.I),
        lambda m: "KB" + m.group(1),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?mozilla\.org/en-US/security/advisories/(mfsa[\w\-]+)"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://wpscan\.com/vulnerability/([\w\-]+)" + URL_TAIL, re.I),
        lambda m: "WPVDB-ID:" + m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://rustsec\.org/advisories/(RUSTSEC-[\w\-]+)\.html" + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://osv\.dev/vulnerability/(PYSEC-[\w\-]+?)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?exploit-db\.com/exploits/(\d+)" + URL_TAIL, re.I
        ),
        lambda m: "EDB-ID:" + m.group(1),
    ),
    (
        re.compile(r"^https?://0day\.today/exploit/(\d+)" + URL_TAIL, re.I),
        lambda m: "1337DAY-ID-" + m.group(1),
    ),
    (
        re.compile(r"^https?://vulners\.com/githubexploit/([^/?#]+)" + URL_TAIL, re.I),
        lambda m: "GITHUBEXPLOIT:" + m.group(1),
    ),
    (
        re.compile(r"^https?://vulners\.com/osv/(OSV:[^/?#]+)" + URL_TAIL, re.I),
        lambda m: m.group(1),
    ),
    (
        re.compile(
            r"^https?://vulners\.com/packetstorm/(PACKETSTORM:[^/?#]+)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1),
    ),
    (
        re.compile(
            r"^https?://vulners\.com/patchstack/(PATCHSTACK:[^/?#]+)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1),
    ),
    (
        re.compile(
            r"^https?://vulners\.com/securityvulns/(SECURITYVULNS:DOC:[^/?#]+)"
            + URL_TAIL,
            re.I,
        ),
        lambda m: m.group(1),
    ),
    (
        re.compile(
            r"^https?://vulners\.com/wpexploit/(WPEX-ID:[^/?#]+)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1),
    ),
    (
        re.compile(
            r"^https?://security\.snyk\.io/vuln/(SYNK-[\w\-]+?)" + URL_TAIL, re.I
        ),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(r"^https?://github\.com/advisories/(GHSA-[\w\-]+)" + URL_TAIL, re.I),
        lambda m: m.group(1).upper(),
    ),
    (
        re.compile(
            r"^https?://(?:www\.)?openbugbounty\.org/reports/(\d+)" + URL_TAIL, re.I
        ),
        lambda m: "OBB-" + m.group(1),
    ),
    (
        re.compile(
            r"^https?://datatracker\.ietf\.org/doc/html/rfc(\d+)" + URL_TAIL, re.I
        ),
        lambda m: "RFC " + m.group(1),
    ),
]


# Collapse vendor-prefixed CVE aliases to their bare CVE form so deduplication
# in validate_issue() merges them with any plain CVE-* tags already present.
def normalize_tag(tag):
    for alias in CVE_PREFIX_ALIASES:
        if tag.startswith(alias):
            return "CVE-" + tag[len(alias) :]
    return tag


# Try to generate a URL for a taxonomy tag. Returns None if not known.
def url_from_tag(tag):
    assert tag == tag.upper()

    # Implementation note: one might be tempted to change this into anything
    # that's more elegant than this spaghetti of "if" statements.
    #
    # HOWEVER.
    #
    # Upon reflection you'll realize that anything more "elegant" than this
    # is also more complex and harder to maintain and debug. So this is the
    # correct solution.
    #
    # You may not like it but his is what peak code looks like. #dealwithit

    url = None
    if tag.startswith("CVE-"):
        url = "https://www.cve.org/CVERecord?id=" + tag
    elif tag.startswith("CWE-"):
        url = "https://cwe.mitre.org/data/definitions/" + tag[4:] + ".html"
    elif tag.startswith("CAPEC-"):
        url = "https://capec.mitre.org/data/definitions/" + tag[6:] + ".html"
    elif tag.startswith("CNVD-"):
        url = "https://www.cnvd.org.cn/flaw/show/" + tag
    elif tag.startswith("JVNDB-"):
        url = "https://jvndb.jvn.jp/ja/contents/" + tag[6:10] + "/" + tag + ".html"
    elif tag.startswith("JVN"):
        url = "https://jvn.jp/jp/" + tag + "/index.html"
    elif tag.startswith("BDU:"):
        url = "https://bdu.fstec.ru/vul/" + tag[4:]
    elif tag.startswith("CERTFR-"):
        # Tag form: CERTFR-YYYY-<INFIX>-NNNN. Infix selects the path segment.
        parts = tag.split("-")
        path = CERTFR_PATHS.get(parts[2]) if len(parts) >= 3 else None
        if path:
            url = "https://www.cert.ssi.gouv.fr/" + path + "/" + tag + "/"
    elif tag.startswith("USN-"):
        url = "https://ubuntu.com/security/notices/" + tag[4:]
    elif tag.startswith("RHSA-"):
        url = "https://access.redhat.com/errata/" + tag
    elif tag.startswith("DSA-"):
        url = "https://www.debian.org/security/" + tag.lower()
    elif tag.startswith("KB"):
        url = "https://support.microsoft.com/kb/" + tag[2:]
    elif tag.startswith("MS"):
        url = (
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/20"
            + tag[2:4]
            + "/"
            + tag.lower()
        )
    elif tag.startswith("MFSA"):
        url = "https://www.mozilla.org/en-US/security/advisories/" + tag.lower() + "/"
    elif tag.startswith("WPVDB-ID:"):
        url = "https://wpscan.com/vulnerability/" + tag[9:].lower() + "/"
    elif tag.startswith("RUSTSEC-"):
        url = "https://rustsec.org/advisories/" + tag + ".html"
    elif tag.startswith("PYSEC-"):
        url = "https://osv.dev/vulnerability/" + tag
    elif tag.startswith("EDB-ID:"):
        url = "https://www.exploit-db.com/exploits/" + tag[7:]
    elif tag.startswith("1337DAY-ID-"):
        url = "https://0day.today/exploit/" + tag[11:]
    elif tag.startswith("GITHUBEXPLOIT:"):
        url = "https://vulners.com/githubexploit/" + tag[14:]
    elif tag.startswith("OSV:"):
        url = "https://vulners.com/osv/" + tag
    elif tag.startswith("PACKETSTORM:"):
        url = "https://vulners.com/packetstorm/" + tag
    elif tag.startswith("PATCHSTACK:"):
        url = "https://vulners.com/patchstack/" + tag
    elif tag.startswith("SECURITYVULNS:DOC:"):
        url = "https://vulners.com/securityvulns/" + tag
    elif tag.startswith("WPEX-ID:"):
        url = "https://vulners.com/wpexploit/" + tag
    elif tag.startswith("SYNK-"):
        url = "https://security.snyk.io/vuln/" + tag
    elif tag.startswith("GHSA-"):
        url = "https://github.com/advisories/" + tag
    elif tag.startswith("OBB-"):
        url = "https://www.openbugbounty.org/reports/" + tag[4:] + "/"
    elif tag.startswith("RFC "):
        url = "https://datatracker.ietf.org/doc/html/" + tag[:3].lower() + tag[4:]
    if url:
        try:
            urllib.parse.urlparse(url)
        except Exception:
            raise AssertionError("Malformed reference URL: '%s'" % url)
    return url


# Inverse of url_from_tag. Returns the taxonomy tag encoded by a known
# reference URL, or None if the URL isn't a recognized taxonomy reference.
#
# Note: forward mapping is lossy for vendor-prefixed CVEs (UBUNTU-CVE-*,
# DEBIAN-CVE-*) — they share a URL with the bare CVE form, so this returns
# the bare CVE tag for all three.
def tag_from_url(url):
    for pattern, formatter in TAG_FROM_URL_PATTERNS:
        m = pattern.match(url)
        if m:
            return formatter(m)
    return None
