#!/usr/bin/python3

"""Magenta parser for shcheck, in both its original and forked form.

Handles four input shapes -- JSON and console text, from santoru/shcheck and
from MarioVilas/shcheck -- by converging them on one normalized per-URL record
before any analysis happens. Nothing downstream of normalize_* knows which
variant produced the data.
"""

import base64
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import headers as hdr

# Headers the original tool still lists in sec_headers, so it reports them as
# *missing*. Browsers dropped all three years ago; a report must never advise
# adding one. The fork already models them as deprecated-when-present.
DEPRECATED_HEADER_NAMES = (
    "Expect-CT",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
)


def new_record(url):
    """An empty normalized record.

    info_disclosure starts as None, meaning "the -i check never ran". An empty
    dict means it ran and found nothing; the two must not be conflated or the
    report will claim a clean result for a scan that never looked.
    """
    return {
        "url": url,
        "present": {},
        "missing": [],
        "unsafe": {},
        "deprecated": {},
        "info_disclosure": None,
        "request": None,
        "response": None,
    }


def _rewrite_deprecated_headers(record):
    """Move the original variant's obsolete headers out of missing[]/present{}

    and into deprecated{}, in place. A no-op on fork data, which never puts
    these in present or missing to begin with. Shared by both the JSON and
    text normalization paths so they cannot drift apart -- this branch's
    Critical finding was exactly that class of JSON/text divergence.
    """
    for name in DEPRECATED_HEADER_NAMES:
        while name in record["missing"]:
            record["missing"].remove(name)
        if name in record["present"]:
            record["deprecated"][name] = record["present"].pop(name)


def _decode_evidence(entry, url, warnings):
    decoded = {}
    for key in ("request", "response"):
        blob = entry.get(key)
        if not blob:
            decoded[key] = None
            continue
        try:
            decoded[key] = base64.b64decode(blob, validate=True)
        except Exception:
            warnings.append(
                "could not decode the base64 %s for %s; evidence dropped" % (key, url)
            )
            decoded[key] = None
    return decoded


def _normalize_json_entry(url, entry, warnings):
    record = new_record(url)
    record["present"] = dict(entry.get("present") or {})

    missing = entry.get("missing")
    if missing is None:
        missing = []
    if not isinstance(missing, list):
        # e.g. "missing": "X-Frame-Options" -- list(...) would silently
        # explode a string into one bogus "missing" entry per character.
        # Treat a wrong-typed field the same as any other malformed entry.
        raise ValueError("'missing' must be a list, got %s" % type(missing).__name__)
    record["missing"] = list(missing)

    record["unsafe"] = dict(entry.get("unsafe") or {})
    record["deprecated"] = dict(entry.get("deprecated") or {})

    # Rewrite the original variant's deprecated headers into the fork's model.
    _rewrite_deprecated_headers(record)

    # Absent key means the check never ran; both variants agree on this.
    if "information_disclosure" in entry:
        record["info_disclosure"] = dict(entry["information_disclosure"] or {})

    record.update(_decode_evidence(entry, url, warnings))
    return record


def normalize_json(data, warnings):
    """Normalize either variant's JSON into records, in input order.

    A malformed entry costs its own URL and nothing more: partial results beat
    discarding a whole file over one bad host.
    """
    records = []
    for url, entry in data.items():
        if not isinstance(entry, dict):
            warnings.append("skipped malformed entry for %s" % url)
            continue
        try:
            records.append(_normalize_json_entry(url, entry, warnings))
        except Exception as error:
            warnings.append("skipped malformed entry for %s (%s)" % (url, error))
    return records


ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# Lines both variants emit. The fork drops "Effective URL" unless a redirect
# occurred, so the target line is the fallback.
RE_TARGET = re.compile(r"^\[\*\] Analyzing headers of (\S+)")
RE_EFFECTIVE = re.compile(r"^\[\*\] Effective URL: (\S+)")
RE_PRESENT = re.compile(r"^\[\*\] Header (\S+) is present! \(Value: (.*)\)$")
RE_PRESENT_NO_VALUE = re.compile(r"^\[\*\] Header (\S+) is present!$")
RE_INSECURE = re.compile(r"^\[!\] Insecure header (\S+) is set! \(Value: (.*)\)$")
RE_UNSAFE_POLICY = re.compile(
    r"^\[!\] Header (\S+) is present but potentially unsafe!$"
)
RE_MISSING = re.compile(r"^\[!\] Security header missing: (\S+)")
RE_DEPRECATED = re.compile(
    r"^\[!\] Deprecated security header (\S+) is present! \(Value: (.*)\)$"
)
RE_DISCLOSURE = re.compile(
    r"^\[!\] Possible information disclosure: header (\S+) is present! \(Value: (.*)\)$"
)
RE_NO_DISCLOSURE = re.compile(r"^\[\*\] No information disclosure headers detected")
RE_DISCLOSURE_TALLY = re.compile(r"^\[-\] \d+ potential information disclosure header")

# Lines that are real output but carry nothing we report on.
RE_IGNORED = re.compile(
    r"^(\[!\] Cache control header |\[\*\] No caching headers detected|"
    r"\[\+\] \d+ security header|\[-\] \d+ (security|deprecated)|"
    r"\[!\] (Analyzing headers for|Headers analysis results for)|"
    r"[-=]{3,}|\s*>|\s*Simple tool|\s*$)"
)


def strip_ansi(text):
    return ANSI_RE.sub("", text)


def _flush(record, records):
    if record is not None:
        _rewrite_deprecated_headers(record)
        records.append(record)


def _strip_directive_colon(part):
    """Drop a colon glued to the leading directive name, e.g. "default-src:".

    The two tools pretty-print a policy directive differently: the fork
    writes "default-src 'self'", the original writes "default-src: 'self'".
    Fed to headers.parse_csp verbatim, the original's colon becomes part of
    the directive name ("default-src:"), which matches nothing -- the real
    finding is missed and the "directive absent" findings fire falsely. Only
    the first whitespace-delimited token is touched, so a colon that is part
    of the *value* (a https:// scheme, a report-uri target) survives intact.
    """
    head, sep, rest = part.partition(" ")
    if head.endswith(":"):
        part = head[:-1] + sep + rest
    return part


def _collect_indented(lines, index):
    """Consume a tab-indented `Value:` block, returning (text, next_index).

    Both variants pretty-print policy headers across several lines, splitting on
    ';' and re-joining. Whitespace does not survive the round trip; the
    directives do.
    """
    parts = []
    while index < len(lines) and lines[index].startswith("\t"):
        part = _strip_directive_colon(lines[index].strip().rstrip(";"))
        if part:
            parts.append(part)
        index += 1
    return "; ".join(parts), index


def _collect_raw_block(lines, index):
    """Consume a fork `-r` HTTP block, returning (bytes, next_index)."""
    parts = []
    while index < len(lines) and (
        lines[index].startswith("\t") or not lines[index].strip()
    ):
        if not lines[index].strip() and not lines[index].startswith("\t"):
            break
        parts.append(lines[index][1:] if lines[index].startswith("\t") else "")
        index += 1
    return ("\r\n".join(parts).rstrip("\r\n") + "\r\n\r\n").encode("utf-8"), index


def normalize_text(text, warnings):
    """Normalize either variant's console output into records, in output order."""
    lines = strip_ansi(text).splitlines()
    records = []
    record = None
    unrecognised = 0
    index = 0

    while index < len(lines):
        line = lines[index]
        index += 1

        match = RE_TARGET.match(line)
        if match:
            _flush(record, records)
            record = new_record(match.group(1))
            continue

        if record is None:
            if not RE_IGNORED.match(line):
                unrecognised += 1
            continue

        match = RE_EFFECTIVE.match(line)
        if match:
            record["url"] = match.group(1)
            continue

        match = RE_PRESENT.match(line)
        if match:
            record["present"][match.group(1)] = match.group(2)
            continue

        match = RE_INSECURE.match(line)
        if match:
            record["present"][match.group(1)] = match.group(2)
            record["unsafe"][match.group(1)] = match.group(2)
            continue

        match = RE_DEPRECATED.match(line)
        if match:
            record["deprecated"][match.group(1)] = match.group(2)
            continue

        match = RE_MISSING.match(line)
        if match:
            record["missing"].append(match.group(1))
            continue

        match = RE_DISCLOSURE.match(line)
        if match:
            if record["info_disclosure"] is None:
                record["info_disclosure"] = {}
            record["info_disclosure"][match.group(1)] = match.group(2)
            continue

        if RE_NO_DISCLOSURE.match(line) or RE_DISCLOSURE_TALLY.match(line):
            if record["info_disclosure"] is None:
                record["info_disclosure"] = {}
            continue

        # A policy header printed across an indented block. The fork announces
        # it as unsafe; the original just prints the value.
        match = RE_UNSAFE_POLICY.match(line) or RE_PRESENT_NO_VALUE.match(line)
        if match:
            name = match.group(1)
            unsafe = bool(RE_UNSAFE_POLICY.match(line))
            if index < len(lines) and lines[index].strip() == "Value:":
                index += 1
            value, index = _collect_indented(lines, index)
            record["present"][name] = value
            if unsafe:
                record["unsafe"][name] = value
            continue

        if line.strip() == "HTTP Request:":
            record["request"], index = _collect_raw_block(lines, index)
            continue

        if line.strip() == "HTTP Response:":
            record["response"], index = _collect_raw_block(lines, index)
            continue

        if not RE_IGNORED.match(line):
            unrecognised += 1

    _flush(record, records)

    if unrecognised:
        warnings.append(
            "ignored %d unrecognised line(s) in text output; the tool version may "
            "be newer than this parser" % unrecognised
        )
    return records


SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")
DEFAULT_SEVERITY = "low"

# Everything is low by default. A partial control must never rate worse than a
# missing one, or the report rewards deleting headers. max-age=0 is different
# in kind: it tears down protection the browser had already cached.
SEVERITY_BY_CODE = {
    "hsts-max-age-zero": "medium",
}


def _worst(severities):
    return max(severities, key=SEVERITY_ORDER.index)


def split_url(url):
    """Split a URL into the (host, path) pair the templates expect.

    The templates render `host + path`, so the two must recombine exactly.
    """
    parts = urllib.parse.urlsplit(url)
    host = "%s://%s" % (parts.scheme, parts.netloc)
    path = parts.path or "/"
    if parts.query:
        path = "%s?%s" % (path, parts.query)
    return host, path


def _evidence(record):
    evidence = {}
    if record["request"]:
        evidence["request"] = base64.b64encode(record["request"]).decode("ascii")
    if record["response"]:
        evidence["response"] = base64.b64encode(record["response"]).decode("ascii")
    return evidence


def _note_disagreements(record, findings, warnings):
    """Note where shcheck flagged a header our analysis cleared.

    Suppressed when 'self' was the only trigger: shcheck flags any policy header
    containing the substring "unsafe" or "self", so `script-src 'self'` -- good
    practice -- trips it on nearly every well-configured site.
    """
    flagged = {f.header.lower() for f in findings}
    for name, value in record["unsafe"].items():
        if name.lower() in flagged:
            continue
        lowered = (value or "").lower()
        if "self" in lowered and "unsafe" not in lowered:
            continue
        warnings.append(
            "shcheck flagged %s as unsafe but our analysis found nothing wrong "
            "with it (value: %s)" % (name, value)
        )


def build_issues(record, warnings):
    """Turn one normalized record into zero or more Magenta issues."""
    issues = []
    host, path = split_url(record["url"])
    evidence = _evidence(record)

    details = []
    severities = []

    for name in record["missing"]:
        details.append("%s - missing" % name)
        severities.append(DEFAULT_SEVERITY)

    for name, value in record["deprecated"].items():
        details.append(
            "%s - deprecated header present (value: %s); it should be removed "
            "rather than corrected" % (name, value)
        )
        severities.append(DEFAULT_SEVERITY)

    findings = hdr.analyze_all(record["present"])
    for finding in findings:
        details.append("%s - %s" % (finding.header, finding.message))
        severities.append(SEVERITY_BY_CODE.get(finding.code, DEFAULT_SEVERITY))

    _note_disagreements(record, findings, warnings)

    if details:
        entry = {"host": host, "path": path, "details": sorted(set(details))}
        entry.update(evidence)
        issues.append(
            {
                "template": "missing_security_headers",
                "tools": ["shcheck"],
                "severity": _worst(severities),
                "affects": [record["url"]],
                "issues": [entry],
            }
        )

    if record["info_disclosure"]:
        entry = {"host": host, "path": path, "headers": dict(record["info_disclosure"])}
        entry.update(evidence)
        issues.append(
            {
                "template": "information_disclosure_headers",
                "tools": ["shcheck"],
                "severity": DEFAULT_SEVERITY,
                "affects": [record["url"]],
                "issues": [entry],
            }
        )

    return issues


def sniff(raw):
    """Decide whether the input is shcheck JSON or shcheck console text.

    Raises ValueError when it is neither.
    """
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            raise ValueError("input starts like JSON but does not parse") from None
        if not isinstance(data, dict) or not all(
            isinstance(v, dict) for v in data.values()
        ):
            raise ValueError("JSON input is not an object of per-URL objects")
        return "json"
    text = strip_ansi(raw)
    for marker in (
        "[!] Headers analysis results for",
        "[!] Analyzing headers for",
        "[*] Analyzing headers of",
    ):
        if marker in text:
            return "text"
    raise ValueError("input does not look like shcheck output")


def main():
    raw = sys.stdin.read()
    warnings = []

    try:
        kind = sniff(raw)
    except ValueError as error:
        sys.stderr.write("ERROR: %s, ignoring input file.\n" % error)
        return 1

    if kind == "json":
        records = normalize_json(json.loads(raw), warnings)
    else:
        records = normalize_text(raw, warnings)

    issues = []
    for record in records:
        issues.extend(build_issues(record, warnings))

    for warning in warnings:
        sys.stderr.write("WARNING: %s\n" % warning)
    if not issues:
        sys.stderr.write(
            "WARNING: no findings in input file. Are you sure this is the right file?\n"
        )

    json.dump(issues, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
