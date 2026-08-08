#!/usr/bin/python3

"""Portable HTTP security header analysis.

Reports *what* is wrong with a header value, never *how bad* it is: severity is
policy and belongs to the caller. Findings are facts.

Keep this module stdlib-only, free of I/O, and free of any consuming application's
concepts, so it remains liftable as a single file.
"""

import collections

Finding = collections.namedtuple("Finding", "header code message")

CSP = "Content-Security-Policy"

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

HSTS = "Strict-Transport-Security"
XFO = "X-Frame-Options"
XCTO = "X-Content-Type-Options"
REFERRER = "Referrer-Policy"
COOP = "Cross-Origin-Opener-Policy"
COEP = "Cross-Origin-Embedder-Policy"
CORP = "Cross-Origin-Resource-Policy"

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
                CSP,
                "csp-unsafe-inline",
                "present but allows unsafe-inline in %s, defeating most of the "
                "cross-site scripting protection a policy provides"
                % " and ".join(inline_in),
            )
        )

    if _has_keyword(_sources(directives, "script-src"), "'unsafe-eval'"):
        findings.append(
            Finding(
                CSP,
                "csp-unsafe-eval",
                "present but allows unsafe-eval in script-src, permitting "
                "strings to be executed as code",
            )
        )

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(
            Finding(
                CSP,
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
                CSP,
                "csp-wildcard",
                "present but uses a wildcard source (*) in %s, allowing content "
                "from any origin" % ", ".join(wildcarded),
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-frame-ancestors",
                "present but sets no frame-ancestors directive, so the page can "
                "be framed by any origin",
            )
        )

    if "object-src" not in directives and "default-src" not in directives:
        findings.append(
            Finding(
                CSP,
                "csp-no-object-src",
                "present but sets neither object-src nor default-src, so plugin "
                "content is left unrestricted",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                CSP,
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
                HSTS,
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
                HSTS,
                "hsts-malformed",
                "present but its max-age is not a number (%s), so browsers ignore "
                "the policy entirely" % directives["max-age"],
            )
        ]

    findings = []
    if max_age == 0:
        findings.append(
            Finding(
                HSTS,
                "hsts-max-age-zero",
                "present but set to max-age=0, which tells browsers to forget the "
                "policy and permits plaintext connections again",
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            Finding(
                HSTS,
                "hsts-max-age-short",
                "present but its max-age is only %d seconds, below the "
                "recommended minimum of %d (six months)" % (max_age, HSTS_MIN_MAX_AGE),
            )
        )

    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                HSTS,
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
                XFO,
                "xfo-allow-from",
                "present but uses ALLOW-FROM, which no current browser supports; "
                "a CSP frame-ancestors directive is the replacement",
            )
        ]
    if normalized not in ("DENY", "SAMEORIGIN"):
        return [
            Finding(
                XFO,
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
                XCTO,
                "xcto-invalid",
                "present but set to %s rather than nosniff, so MIME type sniffing "
                "stays enabled" % value.strip(),
            )
        ]
    return []


def _analyze_referrer(value):
    tokens = [t.strip().lower() for t in value.split(",")]
    if any(t == "unsafe-url" for t in tokens):
        return [
            Finding(
                REFERRER,
                "referrer-unsafe-url",
                "present but set to unsafe-url, which leaks the full URL, query "
                "string included, to third-party origins",
            )
        ]
    if not any(t in REFERRER_TOKENS for t in tokens):
        return [
            Finding(
                REFERRER,
                "referrer-invalid",
                "present but carries no recognised policy token (%s), so the "
                "browser default applies instead" % value.strip(),
            )
        ]
    return []


def _analyze_coop(value):
    # Browsers fall back to unsafe-none for unrecognised values, so an invalid
    # value and an explicit unsafe-none are the same defect.
    if value.strip().lower() not in ("same-origin", "same-origin-allow-popups"):
        return [
            Finding(
                COOP,
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
                COEP,
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
                CORP,
                "corp-invalid",
                "present but has an unrecognised value (%s); expected same-site, "
                "same-origin or cross-origin" % value.strip(),
            )
        ]
    return []


_ANALYZERS = {
    "content-security-policy": _analyze_csp,
    "cross-origin-embedder-policy": _analyze_coep,
    "cross-origin-opener-policy": _analyze_coop,
    "cross-origin-resource-policy": _analyze_corp,
    "referrer-policy": _analyze_referrer,
    "strict-transport-security": _analyze_hsts,
    "x-content-type-options": _analyze_xcto,
    "x-frame-options": _analyze_xfo,
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


def _suppress_redundant(findings, present):
    """Drop findings a sibling header has already made moot.

    csp-no-frame-ancestors and a missing X-Frame-Options describe one gap, not
    two. The opposite direction is already handled upstream: a scanner that sees
    frame-ancestors in the CSP does not report X-Frame-Options as missing. An
    invalid X-Frame-Options protects nothing, so it does not earn the
    suppression.
    """
    for name, value in present.items():
        if name.strip().lower() != "x-frame-options" or value is None:
            continue
        if not _analyze_xfo(value):
            return [f for f in findings if f.code != "csp-no-frame-ancestors"]
    return findings


def analyze_all(present):
    """analyze() across every present header, plus cross-header suppressions.

    `present` maps header names to their raw values. This is the entry point
    callers should use; analyze() is public for unit testing and for reuse in a
    per-header display loop.
    """
    findings = []
    for name, value in present.items():
        findings.extend(analyze(name, value))
    return _suppress_redundant(findings, present)
