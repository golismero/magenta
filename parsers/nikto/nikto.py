#!/usr/bin/python3

import io
import re
import csv
import sys
import json
import os.path
import traceback
from collections import namedtuple

from lxml import etree
from lxml.objectify import deannotate

# Set to True to include informational findings (those with no specific
# vulnerability tag) in the report. Mirrors the old OSVDB-0 behaviour.
INCLUDE_INFO = False

# Load the OSVDB to CVE map. Keys are colon-form: "OSVDB:<n>".
osvdb2cve = {}
try:
    with open(os.path.join(os.path.dirname(__file__), "osvdb2cve.json")) as fd:
        osvdb2cve = json.load(fd)
    del fd
except Exception:
    traceback.print_exc()

# A normalized finding produced by every format reader.
Finding = namedtuple(
    "Finding", ["host_url", "path", "method", "refs_str", "nikto_id", "msg"]
)

# --- reference token patterns -------------------------------------------------
# Specific-vulnerability identifiers (go in the per-finding "cve" column).
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
_MS_RE = re.compile(r"^MS\d{2}-\d+$")  # Microsoft bulletins, e.g. MS00-078
_CNVD_RE = re.compile(r"^CNVD(?:-C)?-\d{4}-\d+$")  # incl. the -C- sub-series
_OSVDB_RE = re.compile(r"^OSVDB-(\d+)$", re.I)
# General-concept / other taxonomy (go in issue-level taxonomy only).
_CWE_RE = re.compile(r"^CWE-\d+$")
_CAPEC_RE = re.compile(r"^CAPEC-\d+$")
_RFC_RE = re.compile(r"^RFC-(\d+)$", re.I)
_MSKB_RE = re.compile(r"^MSKB:Q?(\d+)$", re.I)
_BID_RE = re.compile(r"^BID-\d+$", re.I)
_URL_RE = re.compile(r"^https?://", re.I)

# Token-keyed overrides for known-bad upstream references. Each maps a token to
# (cve, taxonomy, references) contributions. Keyed on the token (not nikto_id),
# because CSV output carries no id column. Each token is unique to its test.
_TOKEN_OVERRIDES = {
    # Phorum 3.3.2a admin GLOBALS[message] XSS. main corrupted OSVDB-11144 into
    # OSVCVE-2011-339244 and mis-tagged the companion test with CVE-2011-3392
    # (a different, later Phorum 5.2.17 vuln). Correct CVE for both: CVE-2002-0764.
    "OSVCVE-2011-339244": (["CVE-2002-0764"], [], []),
    "CVE-2011-3392": (["CVE-2002-0764"], [], []),
}
# Concept-only hardcodes (no specific CVE exists).
# CA-2000-02 is the 2000 CERT advisory that introduced XSS as a concept; the only
# tests using it (000767/768/769) are ASP/ASP.NET reflected XSS -> CWE-79.
_CONCEPT_HARDCODE = {"CA-2000-02": "CWE-79"}
# Known DB-bug junk tokens: token -> the only nikto_id it legitimately appears on.
_KNOWN_JUNK = {"WS_FTP.LOG": "001353"}

# OSVDB lookup hit-rate counters (drift guard). Reset per run in main().
_osvdb_stats = {"mapped": 0, "unmapped": 0}


def reset_osvdb_stats():
    _osvdb_stats["mapped"] = 0
    _osvdb_stats["unmapped"] = 0


def _resolve_osvdb(num):
    # OSVDB-0 is Nikto's "no specific vulnerability" marker (informational),
    # not a real id. Drop it so the finding is treated as untagged.
    if num == "0":
        return []
    mapped = osvdb2cve.get("OSVDB:" + num)
    if mapped:
        _osvdb_stats["mapped"] += 1
        return list(mapped)
    _osvdb_stats["unmapped"] += 1
    return ["OSVDB-" + num]


def osvdb_hitrate_warning():
    total = _osvdb_stats["mapped"] + _osvdb_stats["unmapped"]
    if total >= 10 and _osvdb_stats["mapped"] == 0:
        sys.stderr.write(
            "WARNING: %d OSVDB ids seen but none mapped to a CVE; the "
            "osvdb2cve.json key format may have drifted (expected 'OSVDB:<n>').\n"
            % total
        )


def _dedup(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# https://stackoverflow.com/a/71886208/426293
def remove_namespaces(root):
    for elem in root.getiterator():
        if not (
            isinstance(elem, etree._Comment)
            or isinstance(elem, etree._ProcessingInstruction)
            or isinstance(elem, etree._Entity)
        ):
            localname = etree.QName(elem).localname
            if elem.tag != localname:
                elem.tag = etree.QName(elem).localname
            for attr_name in elem.attrib:
                local_attr_name = etree.QName(attr_name).localname
                if attr_name != local_attr_name:
                    attr_value = elem.attrib[attr_name]
                    del elem.attrib[attr_name]
                    elem.attrib[local_attr_name] = attr_value
    deannotate(root, cleanup_namespaces=True)


def classify_references(refs_str, nikto_id=None):
    """Split a Nikto references string into:
      - cve:        specific-vulnerability ids (CVE, MS bulletin, CNVD, OSVDB->CVE)
      - taxonomy:   general-concept tags (CWE, CAPEC, RFC, KB)
      - references: external URLs
    Tokens are split on whitespace and commas. Unknown tokens warn loudly."""
    cve, taxonomy, references = [], [], []
    if refs_str:
        for raw in re.split(r"[\s,]+", refs_str.strip()):
            tok = raw.strip().strip("\"'")
            if tok:
                _classify_token(tok, nikto_id, cve, taxonomy, references)
    return {
        "cve": _dedup(cve),
        "taxonomy": _dedup(taxonomy),
        "references": _dedup(references),
    }


def _classify_token(tok, nikto_id, cve, taxonomy, references):
    # URLs first — never strip trailing punctuation from a URL.
    if _URL_RE.match(tok):
        references.append(tok)
        return

    # Strip trailing sentence punctuation before any matching, so that e.g.
    # "CVE-2011-3392." still hits the overrides below and "CA-2000-02:" the
    # hardcodes. (None of the known special tokens end in . ; or :.)
    tok = tok.rstrip(".;:")
    if not tok:
        return

    # Token-keyed overrides for known-bad upstream references.
    if tok in _TOKEN_OVERRIDES:
        c, t, r = _TOKEN_OVERRIDES[tok]
        cve.extend(c)
        taxonomy.extend(t)
        references.extend(r)
        return

    # Known DB-bug junk tokens. Silent on the test that legitimately carries
    # them; loud anywhere else (we may have a new bug).
    if tok in _KNOWN_JUNK:
        expected = _KNOWN_JUNK[tok]
        if nikto_id is not None and nikto_id != expected:
            sys.stderr.write(
                "WARNING: junk reference token %r on unexpected nikto_id=%s; dropping.\n"
                % (tok, nikto_id)
            )
        return

    # Concept-only hardcodes (e.g. CA-2000-02 -> CWE-79).
    if tok in _CONCEPT_HARDCODE:
        taxonomy.append(_CONCEPT_HARDCODE[tok])
        return

    if _CVE_RE.match(tok) or _MS_RE.match(tok) or _CNVD_RE.match(tok):
        cve.append(tok)
        return
    if _CWE_RE.match(tok) or _CAPEC_RE.match(tok):
        taxonomy.append(tok)
        return
    m = _OSVDB_RE.match(tok)
    if m:
        cve.extend(_resolve_osvdb(m.group(1)))
        return
    m = _RFC_RE.match(tok)
    if m:
        taxonomy.append("RFC " + m.group(1))  # normalize dash->space for url_from_tag
        return
    m = _MSKB_RE.match(tok)
    if m:
        taxonomy.append("KB" + m.group(1))  # normalize MSKB:Q<n> -> KB<n>
        return
    if _BID_RE.match(tok):
        return  # dead taxonomy, no shipped map; drop (known class)

    # Anything else: do not guess. Warn loudly (future-version safety).
    sys.stderr.write(
        "WARNING: unrecognized Nikto reference token %r (nikto_id=%s); dropping.\n"
        % (tok, nikto_id)
    )


def build_issues(findings):
    by_host = {}  # host_url -> list[ {path, cve, msg} ]
    all_taxonomy = []
    all_references = []
    affects = []
    for f in findings:
        cls = classify_references(f.refs_str, f.nikto_id)
        tags = cls["cve"] + cls["taxonomy"]
        # Inclusion rule: report only findings carrying >=1 taxonomy tag.
        # Untagged findings are informational (old OSVDB-0 behaviour).
        if not tags and not INCLUDE_INFO:
            continue
        entry = {"path": f.path, "cve": cls["cve"], "msg": f.msg}
        host_list = by_host.setdefault(f.host_url, [])
        if entry not in host_list:
            host_list.append(entry)
        affects.append(f.host_url + f.path)
        all_taxonomy.extend(tags)
        all_references.extend(cls["references"])
    if not by_host:
        return []
    issue = {
        "tools": ["nikto"],
        "template": "multiple_nikto_issues",
        "severity": "high",
        "affects": sorted(set(affects)),
        "taxonomy": sorted(set(all_taxonomy)),
        "references": sorted(set(all_references)),
        "issues": by_host,
    }
    if not issue["taxonomy"]:
        del issue["taxonomy"]
    if not issue["references"]:
        del issue["references"]
    return [issue]


# Hardened parser for untrusted tool output: no external entity resolution,
# no network access, no DTD loading, no unbounded tree growth (XXE and
# billion-laughs guards).
_XML_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False
)


def _to_xml_bytes(input_data):
    return input_data.encode("utf-8") if isinstance(input_data, str) else input_data


def _parse_xml_tolerant(input_data):
    """Parse Nikto XML, tolerating its historically not-well-formed output.

    Returns the root element, or None if the input cannot be parsed even after
    the wrapping workaround (the caller treats None as 'no findings')."""
    try:
        return etree.fromstring(_to_xml_bytes(input_data), _XML_PARSER)
    except etree.XMLSyntaxError:
        # Strip the XML declaration and wrap the remainder in a single root.
        body = re.sub(r"^\s*<\?xml[^>]*\?>", "", input_data, count=1).strip()
        wrapped = "<niktontwrap>%s</niktontwrap>" % body
        try:
            return etree.fromstring(_to_xml_bytes(wrapped), _XML_PARSER)
        except etree.XMLSyntaxError:
            sys.stderr.write(
                "WARNING: could not parse Nikto XML (malformed even after the "
                "wrapping workaround); skipping.\n"
            )
            return None


def _text(elem, tag):
    child = elem.find(tag)
    return child.text if child is not None and child.text is not None else None


def read_xml(input_data):
    root = _parse_xml_tolerant(input_data)
    if root is None:
        return []
    remove_namespaces(root)
    findings = []
    # Iterate every <scandetails> regardless of niktoscan/niktoscans nesting
    # (handles single root, plural wrapper, and the doubled-niktoscan quirk).
    scandetails_list = list(root.iter("scandetails"))
    if root.tag == "scandetails":
        scandetails_list = [root]
    for sd in scandetails_list:
        host_url = _host_url(
            sd.attrib.get("targethostname"),
            sd.attrib.get("targetip"),
            sd.attrib.get("targetport") or "80",
        )
        for item in sd.iter("item"):
            uri = _text(item, "uri")
            if uri is None:
                continue  # informational scanner message (no uri); not a finding
            # References: <references> child (2.5.0+) or osvdblink attr (old).
            refs_str = _text(item, "references")
            if not refs_str:
                link = item.attrib.get("osvdblink")
                if link:
                    num = link.rstrip("/").rsplit("/", 1)[-1]
                    refs_str = "OSVDB-" + num
                else:
                    refs_str = ""
            findings.append(
                Finding(
                    host_url=host_url,
                    path=uri,
                    method=item.attrib.get("method", ""),
                    refs_str=refs_str,
                    nikto_id=item.attrib.get("id"),
                    msg=_text(item, "description") or "",
                )
            )
    return findings


def _host_url(hostname, ip, port):
    host = hostname or ip
    use_ssl = str(port) == "443"
    scheme = "https" if use_ssl else "http"
    return "%s://%s:%s" % (scheme, host, port)


def _strip_csv_injection(cell):
    # Nikto prefixes a "'" to cells starting with = + @ - (CSV-injection guard).
    if cell[:1] == "'" and cell[1:2] in ("=", "+", "@", "-"):
        return cell[1:]
    return cell


def read_csv(input_data):
    fd = io.StringIO(input_data)
    fd.readline()  # discard the '"Nikto - v..."' header line
    findings = []
    for row in csv.reader(fd):
        if len(row) < 7:
            continue  # blank/short line
        hostname, ip, port, col4, method, uri, msg = (
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
        )
        # Host-start rows have empty method+uri (banner sits in col7). Skip.
        if not method and not uri:
            continue
        col4 = _strip_csv_injection(col4)
        # SSL-info rows (2.6.0+) use the pseudo test id 000137 in col4. Skip.
        if col4 == "000137":
            continue
        findings.append(
            Finding(
                host_url=_host_url(hostname, ip, port),
                path=uri,
                method=method,
                refs_str=col4,
                nikto_id=None,  # CSV has no id column
                msg=msg,
            )
        )
    return findings


def _path_from_url(url, host_url):
    if url and url.startswith(host_url):
        return url[len(host_url) :] or "/"
    return url or "/"


def _findings_from_json_hosts(hosts):
    findings = []
    for host in hosts:
        host_url = _host_url(host.get("host"), host.get("ip"), host.get("port") or "80")
        for v in host.get("vulnerabilities", []):
            url = v.get("url", "")
            findings.append(
                Finding(
                    host_url=host_url,
                    path=_path_from_url(url, host_url),
                    method=v.get("method", ""),
                    refs_str=v.get("references", "") or "",
                    nikto_id=v.get("id"),
                    msg=v.get("msg", "") or "",
                )
            )
    return findings


def read_json(input_data):
    data = None
    try:
        data = json.loads(input_data)
    except ValueError:
        # 2.5.0 emitted concatenated per-host objects (invalid for >1 host).
        # Repair: insert commas between adjacent objects and wrap in an array.
        repaired = input_data.strip().replace("}{", "},{")
        if not repaired.startswith("["):
            repaired = "[" + repaired + "]"
        try:
            data = json.loads(repaired)
        except ValueError:
            sys.stderr.write(
                "WARNING: could not parse Nikto JSON (and 2.5.0 fragment repair "
                "failed); skipping.\n"
            )
            return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        sys.stderr.write("WARNING: unexpected Nikto JSON shape; skipping.\n")
        return []
    return _findings_from_json_hosts(data)


def main():
    input_data = sys.stdin.read()

    if not input_data.strip():
        sys.stderr.write("Empty file received, surely this is an error?\n")
        json.dump([], sys.stdout)
        return

    reset_osvdb_stats()
    stripped = input_data.lstrip()

    if stripped.startswith("<?xml") or stripped.startswith("<niktoscan"):
        findings = read_xml(input_data)
    elif stripped[:1] in ("[", "{"):
        findings = read_json(input_data)
    elif re.match(r'"Nikto - v.*"', stripped):
        findings = read_csv(input_data)
    else:
        sys.stderr.write(
            "Invalid file type, are you sure this was generated by nikto.pl?\n"
        )
        json.dump([], sys.stdout)
        return

    output = build_issues(findings)
    osvdb_hitrate_warning()
    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
