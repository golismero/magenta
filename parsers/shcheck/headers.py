#!/usr/bin/python3

"""Portable HTTP security header analysis.

Reports *what* is wrong with a header value, never *how bad* it is: severity is
policy and belongs to the caller. Findings are facts, and so are the header
tables: which headers exist and what a value means is knowledge, how much any
of it matters is not.

Keep this module stdlib-only, free of I/O, and free of any consuming
application's presentation and policy, so it remains liftable as a single file.
"""

import collections

Finding = collections.namedtuple("Finding", "header code message")

# Fetch directives fall back to default-src when they are absent.
# https://www.w3.org/TR/CSP3/#directives-fetch
FETCH_DIRECTIVES = frozenset(
    [
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "worker-src",
    ]
)

# Six months, the floor recommended for a policy that is meant to stick.
HSTS_MIN_MAX_AGE = 15768000

REFERRER_TOKENS = frozenset(
    [
        "",
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ]
)
COEP_VALUES = frozenset(["unsafe-none", "require-corp", "credentialless"])
CORP_VALUES = frozenset(["same-site", "same-origin", "cross-origin"])

# The header does not grant cross-domain access itself; it decides how much
# authority a cross-domain policy file is allowed to have. These are the values
# Adobe's specification defines, none-this-response being header-only.
XPCDP_VALUES = frozenset(
    [
        "all",
        "by-content-type",
        "by-ftp-filename",
        "master-only",
        "none",
        "none-this-response",
    ]
)

# Security headers that should be enabled.
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
)

# Security headers that are obsolete: their absence is the desired state, so
# they are never reported missing, only reported on when a response carries one.
DEPRECATED_HEADERS = (
    "Expect-CT",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
)

# Potential information disclosure headers.
INFORMATION_HEADERS = (
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Powered-By",
)

# Cache control headers.
CACHE_HEADERS = (
    "Cache-Control",
    "ETag",
    "Expires",
    "Last-Modified",
    "Pragma",
)


def parse_csp(value):
    """Parse a CSP header into an ordered {directive: [source, ...]} mapping.

    Directive names are lowercased. Source expressions keep their case, because
    host sources are case-sensitive in their path component. Repeated
    directives are ignored after the first, which is what the spec requires of
    user agents.
    """
    directives = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives:
            continue
        directives[name] = parts[1:]
    return directives


def _sources(directives, name):
    """Effective sources for a fetch directive, honouring the default-src fallback.

    Returns None when the directive is neither set nor inherited.
    """
    if name in directives:
        return directives[name]
    if name in FETCH_DIRECTIVES and "default-src" in directives:
        return directives["default-src"]
    return None


def _has_keyword(sources, keyword):
    return sources is not None and any(s.lower() == keyword for s in sources)


def _analyze_csp(value):
    findings = []
    directives = parse_csp(value)

    inline_in = [
        name
        for name in ("script-src", "style-src")
        if _has_keyword(_sources(directives, name), "'unsafe-inline'")
    ]
    if inline_in:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-inline",
                "present but allows unsafe-inline in %s, defeating most of the "
                "cross-site scripting protection a policy provides"
                % " and ".join(inline_in),
            )
        )

    if _has_keyword(_sources(directives, "script-src"), "'unsafe-eval'"):
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-eval",
                "present but allows unsafe-eval in script-src, permitting "
                "strings to be executed as code",
            )
        )

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-default-src",
                "present but sets neither default-src nor script-src, so script "
                "loading is left unrestricted",
            )
        )

    wildcarded = sorted(
        name
        for name, sources in directives.items()
        if name in FETCH_DIRECTIVES and any(s == "*" for s in sources)
    )
    if wildcarded:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-wildcard",
                "present but uses a wildcard source (*) in %s, allowing content "
                "from any origin" % ", ".join(wildcarded),
            )
        )

    frame_ancestors = directives.get("frame-ancestors")
    if frame_ancestors is None:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-frame-ancestors",
                "present but sets no frame-ancestors directive, so the page can "
                "be framed by any origin",
            )
        )
    elif "*" in frame_ancestors:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-frame-ancestors-wildcard",
                "present but sets frame-ancestors to *, so the page can be framed "
                "by any origin, exactly as if the directive were absent",
            )
        )

    if "object-src" not in directives and "default-src" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-object-src",
                "present but sets neither object-src nor default-src, so plugin "
                "content is left unrestricted",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-base-uri",
                "present but sets no base-uri directive, so an injected <base> "
                "tag can redirect every relative URL on the page",
            )
        )

    return findings


def _parse_directives(value):
    """Parse a semicolon-separated `key[=value]` header into a lowercased mapping.

    Valueless directives map to None. Values are unquoted.
    """
    directives = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, sep, val = chunk.partition("=")
        directives[key.strip().lower()] = val.strip().strip('"') if sep else None
    return directives


def _analyze_hsts(value):
    directives = _parse_directives(value)

    if directives.get("max-age") is None:
        return [
            Finding(
                "Strict-Transport-Security",
                "hsts-malformed",
                "present but specifies no max-age, so browsers ignore the policy "
                "entirely",
            )
        ]
    try:
        max_age = int(directives["max-age"])
    except ValueError:
        return [
            Finding(
                "Strict-Transport-Security",
                "hsts-malformed",
                "present but its max-age is not a number (%s), so browsers ignore "
                "the policy entirely" % directives["max-age"],
            )
        ]

    findings = []
    if max_age == 0:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-max-age-zero",
                "present but set to max-age=0, which tells browsers to forget the "
                "policy and permits plaintext connections again",
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-max-age-short",
                "present but its max-age is only %d seconds, below the "
                "recommended minimum of %d (six months)" % (max_age, HSTS_MIN_MAX_AGE),
            )
        )

    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-no-include-subdomains",
                "present but does not set includeSubDomains, leaving subdomains "
                "reachable over plaintext HTTP",
            )
        )

    return findings


def _analyze_xfo(value):
    normalized = value.strip().upper()
    if normalized.startswith("ALLOW-FROM"):
        return [
            Finding(
                "X-Frame-Options",
                "xfo-deprecated",
                "present but uses ALLOW-FROM, which no current browser supports; "
                "a CSP frame-ancestors directive is the replacement",
            )
        ]
    if normalized not in ("DENY", "SAMEORIGIN"):
        return [
            Finding(
                "X-Frame-Options",
                "xfo-invalid",
                "present but has an unrecognised value (%s), so browsers ignore it "
                "and the page stays framable" % value.strip(),
            )
        ]
    return []


def _analyze_xcto(value):
    if value.strip().lower() != "nosniff":
        return [
            Finding(
                "X-Content-Type-Options",
                "xcto-invalid",
                "present but set to %s rather than nosniff, so MIME type sniffing "
                "stays enabled" % value.strip(),
            )
        ]
    return []


def _analyze_rp(value):
    tokens = [t.strip().lower() for t in value.split(",")]
    if any(t == "unsafe-url" for t in tokens):
        return [
            Finding(
                "Referrer-Policy",
                "rp-unsafe-url",
                "present but set to unsafe-url, which leaks the full URL, query "
                "string included, to third-party origins",
            )
        ]
    if not any(t in REFERRER_TOKENS for t in tokens):
        return [
            Finding(
                "Referrer-Policy",
                "rp-invalid",
                "present but carries no recognised policy token (%s), so the "
                "browser default applies instead" % value.strip(),
            )
        ]
    return []


def parse_permissions_policy(value):
    """Parse a Permissions-Policy header into a {feature: [allowlist item, ...]} mapping.

    Feature names are lowercased; allowlist items keep their case, because
    origins are compared as written. An empty allowlist `()` yields [], and `*`
    yields ["*"]. Repeated features keep the last one, which is what the
    structured field syntax the header is built on requires of parsers.
    Chunks that are not `feature=allowlist` are skipped: call analyze() to learn
    that the header is malformed.
    """
    policy = {}
    for chunk in value.split(","):
        name, sep, allowlist = chunk.partition("=")
        name = name.strip().lower()
        if not sep or not name:
            continue
        allowlist = allowlist.strip()
        if allowlist.startswith("(") and allowlist.endswith(")"):
            allowlist = allowlist[1:-1]
        policy[name] = [item.strip('"') for item in allowlist.split()]
    return policy


def _analyze_pp(value):
    stripped = value.strip()

    # Structured field parsing is all-or-nothing: one unparseable member and the
    # browser drops the whole header, so a syntax error is never partial.
    items = [chunk.strip() for chunk in stripped.split(",")]
    malformed = [item for item in items if item and "=" not in item]
    if malformed:
        # Feature-Policy, the predecessor, separated features with semicolons
        # and quoted its allowlist keywords. That spelling still turns up in
        # Permissions-Policy headers, where it parses as nothing at all.
        if ";" in stripped or "'" in stripped:
            return [
                Finding(
                    "Permissions-Policy",
                    "pp-legacy-syntax",
                    "present but written in the older Feature-Policy syntax (%s), "
                    "which browsers cannot parse, so the whole header is ignored"
                    % stripped,
                )
            ]
        return [
            Finding(
                "Permissions-Policy",
                "pp-invalid",
                "present but %s is not a feature=allowlist pair, so browsers "
                "ignore the whole header" % malformed[0],
            )
        ]

    policy = parse_permissions_policy(stripped)
    if not policy:
        return [
            Finding(
                "Permissions-Policy",
                "pp-empty",
                "present but sets no feature, so it restricts nothing",
            )
        ]

    wildcarded = sorted(name for name, allowlist in policy.items() if "*" in allowlist)
    if wildcarded:
        return [
            Finding(
                "Permissions-Policy",
                "pp-wildcard",
                "present but allows %s in every origin (*), including third party "
                "frames the page embeds" % ", ".join(wildcarded),
            )
        ]

    return []


def _analyze_coop(value):
    # Browsers fall back to unsafe-none for unrecognised values, so an invalid
    # value and an explicit unsafe-none are the same defect.
    if value.strip().lower() not in ("same-origin", "same-origin-allow-popups"):
        return [
            Finding(
                "Cross-Origin-Opener-Policy",
                "coop-unsafe-none",
                "present but effectively unsafe-none (%s), which provides no "
                "cross-origin isolation" % value.strip(),
            )
        ]
    return []


def _analyze_coep(value):
    if value.strip().lower() not in COEP_VALUES:
        return [
            Finding(
                "Cross-Origin-Embedder-Policy",
                "coep-invalid",
                "present but has an unrecognised value (%s); expected unsafe-none, "
                "require-corp or credentialless" % value.strip(),
            )
        ]
    return []


def _analyze_corp(value):
    if value.strip().lower() not in CORP_VALUES:
        return [
            Finding(
                "Cross-Origin-Resource-Policy",
                "corp-invalid",
                "present but has an unrecognised value (%s); expected same-site, "
                "same-origin or cross-origin" % value.strip(),
            )
        ]
    return []


def _analyze_ect(value):
    # No need to parse the actual policy since no browser uses it anyway.
    return [
        Finding("Expect-CT", "ect-deprecated", "present but deprecated since June 2021")
    ]


def _analyze_xpcdp(value):
    normalized = value.strip().lower()

    # none-this-response withholds the policy file from this one response, which
    # is the same answer as none for the response being analyzed.
    if normalized in ("none", "none-this-response"):
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-deprecated",
                "present but permits no cross-domain policy file, which is the "
                "restrictive setting; only Flash and Acrobat clients ever read it",
            )
        ]

    if normalized == "all":
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-all",
                "present but set to all, so any file on the server can serve as a "
                "cross-domain policy, including whatever a user can upload",
            )
        ]

    # The remaining values narrow which files count as a policy without saying
    # what those files permit, so the answer is in crossdomain.xml, not here.
    if normalized in XPCDP_VALUES:
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-policy-file",
                "present and set to %s, which leaves cross-domain access to the "
                "policy file; check crossdomain.xml" % normalized,
            )
        ]

    return [
        Finding(
            "X-Permitted-Cross-Domain-Policies",
            "xpcdp-invalid",
            "present but has an unrecognised value (%s), so clients fall back to "
            "their default policy" % value.strip(),
        )
    ]


def _analyze_xxp(value):
    normalized = value.strip().lower().replace(" ", "")
    if normalized == "0":
        return [Finding("X-XSS-Protection", "xxp-deprecated", "present but disabled")]
    elif normalized == "1":
        return [
            Finding(
                "X-XSS-Protection",
                "xxp-enabled",
                "present and enabled, which in some cases can create XSS vulnerabilities in otherwise safe websites",
            )
        ]
    elif normalized == "1;mode=block":
        return [
            Finding(
                "X-XSS-Protection",
                "xxp-blocked",
                "present and enabled in blocked mode, which may lead to side channel attacks on iframe embeddable websites",
            )
        ]
    return [
        Finding(
            "X-XSS-Protection",
            "xxp-invalid",
            "present but has an unrecognised value (%s), expected '0', '1' or '1; mode=block'"
            % value.strip(),
        )
    ]


_ANALYZERS = {
    "content-security-policy": _analyze_csp,
    "cross-origin-embedder-policy": _analyze_coep,
    "cross-origin-opener-policy": _analyze_coop,
    "cross-origin-resource-policy": _analyze_corp,
    "expect-ct": _analyze_ect,
    "referrer-policy": _analyze_rp,
    "permissions-policy": _analyze_pp,
    "strict-transport-security": _analyze_hsts,
    "x-content-type-options": _analyze_xcto,
    "x-frame-options": _analyze_xfo,
    "x-permitted-cross-domain-policies": _analyze_xpcdp,
    "x-xss-protection": _analyze_xxp,
}


def analyze(name, value):
    """Findings for one header in isolation.

    Unknown header names and None values yield no findings.
    """
    if value is None:
        return []
    analyzer = _ANALYZERS.get(name.strip().lower())
    if analyzer is None:
        return []
    return analyzer(value)


def _missing_tag(name):
    if name == "Strict-Transport-Security":
        return "hsts-missing"
    return "".join(x for x in name if x.isupper()).lower() + "-missing"


def _report_missing(present, secure=True):
    """Reports missing security headers as findings.

    Over a plaintext connection browsers ignore HSTS entirely, so its absence
    there is not a defect and is not reported.
    """
    findings = []
    for name in SECURITY_HEADERS:
        if name.lower() in present:
            continue
        if not secure and name == "Strict-Transport-Security":
            continue
        findings.append(Finding(name, _missing_tag(name), "missing"))
    return findings


def _lookup(present, name):
    """The raw value of `name`, or None when the response does not carry it."""
    wanted = name.lower()
    for header, value in present.items():
        if header.strip().lower() == wanted:
            return value
    return None


def _restricts_framing(present):
    """Whether the CSP's frame-ancestors directive actually constrains framing.

    A directive listing `*` permits every origin, which is the state it would be
    reported for lacking, so it does not count as covering anything.
    """
    value = _lookup(present, "Content-Security-Policy")
    if value is None:
        return False
    sources = parse_csp(value).get("frame-ancestors")
    return bool(sources) and "*" not in sources


def _protects_framing(present):
    """Whether X-Frame-Options is present and browsers will act on it."""
    value = _lookup(present, "X-Frame-Options")
    return value is not None and not _analyze_xfo(value)


def _suppress_redundant(findings, present):
    """Drop findings a sibling header has already made moot.

    X-Frame-Options and the CSP frame-ancestors directive govern the same thing,
    so a page covered by one has no gap in the other: that is one finding, not
    two. Only an effective header earns the suppression -- an X-Frame-Options
    browsers ignore protects nothing, and neither does `frame-ancestors *`.
    """
    suppressed = set()
    if _protects_framing(present):
        suppressed.add("csp-no-frame-ancestors")
    if _restricts_framing(present):
        suppressed.add("xfo-missing")
    if not suppressed:
        return findings
    return [f for f in findings if f.code not in suppressed]


def analyze_all(present, secure=True):
    """analyze() across every present header, plus the missing ones and any
    cross-header suppressions.

    `present` maps header names to their raw values. `secure` tells whether the
    response arrived over TLS, which decides whether a missing HSTS header means
    anything. This is the entry point callers should use; analyze() is public
    for unit testing.
    """
    findings = _report_missing(present, secure)
    for name, value in present.items():
        findings.extend(analyze(name, value))
    return _suppress_redundant(findings, present)


def _filter_headers(present, wanted):
    filtered = {}
    for name in wanted:
        normalized = name.lower()
        if normalized in present:
            filtered[name] = present[normalized]
    return filtered


def find_cache_headers(present):
    """Return only the headers that implement cache related features.

    Note that the values of these headers are NOT analyzed."""
    return _filter_headers(present, CACHE_HEADERS)


def find_information_headers(present):
    """Return only the headers that are commonly associated with information leaks.

    Note that the values of these headers are NOT analyzed."""
    return _filter_headers(present, INFORMATION_HEADERS)


def find_deprecated_headers(present):
    """Return only the obsolete security headers the response carries.

    Unlike the other two, the values of these headers ARE analyzed: see
    analyze()."""
    return _filter_headers(present, DEPRECATED_HEADERS)
