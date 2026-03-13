#!/usr/bin/python3

import base64
import io
import json
import re
import sys
import traceback

from lxml import etree
from lxml.objectify import deannotate

# https://stackoverflow.com/a/71886208/426293
def remove_namespaces(root):
    for elem in root.getiterator():
        if not (
                isinstance(elem, etree._Comment)
                or isinstance(elem, etree._ProcessingInstruction)
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

# Some extensions mangle the HTTP header names by making them lowercase.
# This function attempts to fix that.
def fix_header_name(header):
    parts = header.split("-")
    parts = [x.capitalize() for x in parts]
    header = "-".join(parts)
    return header

# Use LXML to parse HTML too.
# Very hacky but it saves us from having to add another dependency.
def parse_html(text):
    parser = etree.HTMLParser(
        recover=True,
        no_network=True,
        remove_blank_text=True,
        remove_comments=True,
        remove_pis=True,
        strip_cdata=True,
        compact=True,
        default_doctype=True,
        collect_ids=True,
        huge_tree=False
    )
    fd = io.StringIO(text)
    tree = etree.parse(fd, parser=parser)
    return tree.getroot()

# This maps the issues from Burp to our templates based on their titles.
# We cannot use the issue type from Burp because it lumps all of the
# extension generated issues together, which is quite useless TBH.
#
# If you're reading this and you see an issue title not in this dictionary,
# please let me know and I'll try to add it! :)
#
TEMPLATES = {
    "Base64-encoded data in parameter": None,
    "Browser cross-site scripting filter disabled": "missing_security_headers",
    "Browser cross-site scripting filter misconfiguration": "missing_security_headers",
    "Cacheable HTTPS response": "missing_security_headers",
    "Content Sniffing not disabled": "missing_security_headers",
    "Content type is not specified": None,
    "Cookie scoped to parent domain": None,
    "Cookie with SameSite set to None": "insecure_cookies_found",
    "Cookie without HttpOnly flag set": "insecure_cookies_found",
    "Cookie without SameSite flag set": "insecure_cookies_found",
    "Credit card numbers disclosed": None,
    "Cross-domain Referer leakage": None,
    "Cross-domain script include": None,
    "Detailed Error Messages Revealed": "information_exposure_in_error_messages",
    "Duplicate cookies set": None,
    "Email addresses disclosed": None,
    "File upload functionality": None,
    "Frameable response (potential Clickjacking)": "missing_security_headers",
    "HTML does not specify charset": None,
    "HTML5 concern: client storage": None,
    "HTML5 concern: geolocation": None,
    "HTML5 concern: insecure web sockets": None,
    "HTML uses unrecognized charset": None,
    "Interesting Header(s)": None,
    "Lack or Misconfiguration of Security Header(s)": "missing_security_headers",
    "Long redirection response": None,  # not usually a real bug
    "Mixed content": "mixed_content",
    "Password field with autocomplete enabled": "password_field_with_autocomplete_enabled",
    "Password submitted using GET method": None,    # sadly generates too many fp
    "Robots.txt file": "robots_txt_file",
    "Session token in URL": "information_exposure_in_url",
    "Software Version Numbers Revealed": None, #"information_exposure_in_http_headers", # I gave up on this bs
    "Source code disclosure": None, # may be salvaged by checking the file extension maybe?
    "Strict Transport Security Misconfiguration": "missing_security_headers",
    "Strict transport security not enforced": "missing_security_headers",
    #"SQL statement in request parameter": "sql_injection", # XXX TODO
    "TLS certificate": None,
    "TLS cookie without secure flag set": "insecure_cookies_found",
    "Vulnerable JavaScript dependency": "outdated_javascript_library_found",
    "[Vulners] Software detected": None,
    "[Vulners] Vulnerable Software detected": "outdated_server_software_found",
}

# Flat out ignore the issue detail items for these and hardcode the info we need.
DETAILS_DICT = {

    # HTTP headers
    "Browser cross-site scripting filter disabled": "X-XSS-Protection",
    "Browser cross-site scripting filter misconfiguration": "X-XSS-Protection",
    "Cacheable HTTPS response": ("Cache-Control", "Pragma"),
    "Content Sniffing not disabled": "X-Content-Type-Options",
    "Strict Transport Security Misconfiguration": "Strict-Transport-Security",
    "Strict transport security not enforced": "Strict-Transport-Security",

    # Cookies
    "Cookie with SameSite set to None": "SameSite",
    "Cookie without HttpOnly flag set": "HttpOnly",
    "Cookie without SameSite flag set": "SameSite",
    "TLS cookie without secure flag set": "Secure",

    # Others
    "Vulnerable JavaScript dependency": None,
}

def main():

    # Cannot parse straight out of stdin because it's not a byte file.
    # Python 3 sucks sometimes.
    # Also LXML has a size limitation that we need to override here.
    # I need to look for a better parser because this might, in theory,
    # cause integer overflows in the underlying C library.
    parser = etree.XMLParser(
        load_dtd=False,
        dtd_validation=False,
        recover=True,
        remove_comments=True,
        remove_pis=True,
        resolve_entities=False,
        huge_tree=True,
        strip_cdata=False
    )
    fd = io.StringIO(sys.stdin.read())
    tree = etree.parse(fd, parser=parser)
    root = tree.getroot()
    remove_namespaces(root)
    assert root.tag == "issues", root.tag
    assert "burpVersion" in root.attrib, root.attrib

    # Since this is already going to be quite memory intensive,
    # let's spit out each data object individually.
    doComma = False
    sys.stdout.write("[")
    for issue in root:
        try:

            # Convert Burp's <issue> into our JSON issue format.
            data = {"tools": ["burp"], "issues": [{}]}
            assert issue.tag == "issue", issue.tag
            name = ""
            confidence = ""
            for element in issue:

                if element.tag == "name":
                    name = element.text.strip()
                    details = []

                    if name.startswith("Vulnerable version of the library"):
                        template_name = "outdated_software_found"
                        assert "'" in name, "Malformed issue: '%s'" % name
                        p = name.find("'")
                        q = name.find("'", p+1)
                        assert "details" not in data["issues"][0], "Malformed issue: '%s'" % name
                        data["issues"][0]["details"] = [name[p+1:q]]

                    elif name.startswith("[JS Miner]"):
                        template_name = None

                    elif name in TEMPLATES:
                        template_name = TEMPLATES[name]
                        if name in DETAILS_DICT:
                            value = DETAILS_DICT[name]
                            if value is not None:
                                if isinstance(value, str):
                                    details.append(value)
                                else:
                                    details.extend(value)

                    else:
                        sys.stderr.write("Skipping unsupported Burp issue: '%s'\n" % element.text)
                        template_name = None

                    if not template_name:
                        data = {}
                        break
                    assert "template" not in data, "Duplicated <%s> tag" % element.tag
                    data["template"] = template_name
                    if details:
                        assert "details" not in data["issues"][0], "Malformed issue: '%s'" % name
                        data["issues"][0]["details"] = details

                elif element.tag in ("type", "serialNumber",
                        "issueBackground", "remediationBackground", "remediationDetail"):
                    continue

                # Certain: The issue is definitely present.
                # Firm: The issue is probably present,
                #     but this could be a false positive.
                # Tentative: The issue is potentially present
                #     but there is a high chance that this
                #     could be a false positive.
                elif element.tag == "confidence":
                    confidence = element.text
                    if confidence == "Tentative" and name != "Vulnerable JavaScript dependency":
                        sys.stderr.write("Skipped likely false positive: '%s'\n" % name)
                        data = {}
                        break

                elif element.tag in ("path", "location"):
                    assert element.tag not in data["issues"][0], "Duplicated <%s> tag" % element.tag
                    data["issues"][0][element.tag] = element.text

                elif element.tag == "host":
                    assert "host" not in data["issues"][0], "Duplicated <%s> tag" % element.tag
                    data["issues"][0]["host"] = element.text
                    #if "ip" in element.attrib and element.attrib["ip"]:
                    #    data["ip"] = element.attrib["ip"]

                elif element.tag == "severity":
                    if element.text == "False positive":
                        #sys.stderr.write("Skipped confirmed false positive for: '%s'\n" % name)
                        data = {}
                        break
                    assert "severity" not in data, "Duplicated <%s> tag" % element.tag
                    severity = element.text.lower()
                    if severity == "information":
                        severity = "none"
                    data["severity"] = severity

                elif element.tag == "references":
                    if "references" not in data:
                        data["references"] = []
                    for link in parse_html(element.text).findall(".//a"):
                        data["references"].append(link.attrib["href"])

                elif element.tag == "vulnerabilityClassifications":
                    if "taxonomy" not in data:
                        data["taxonomy"] = []
                    for link in parse_html(element.text).findall(".//a"):
                        taxonomy = link.text[:link.text.find(":")].strip().upper()
                        if re.match("^A[0-9][0-9]?$", taxonomy):
                            if "references" not in data:
                                data["references"] = []
                            data["references"].append(link.attrib["href"])
                        else:
                            data["taxonomy"].append(taxonomy)

                elif element.tag == "requestresponse":
                    method = None
                    request = None
                    response = None
                    redirected = None
                    child = element.find("request")
                    if child is not None:
                        method = child.attrib.get("method", "GET")
                        if child.attrib.get("base64", "false") == "true":
                            request = child.text
                        else:
                            request = base64.b64encode(child.text.encode("utf-8")).decode("utf-8")
                    child = element.find("response")
                    if child is not None:
                        if child.attrib.get("base64", "false") == "true":
                            response = child.text
                        else:
                            response = base64.b64encode(child.text.encode("utf-8")).decode("utf-8")
                    child = element.find("responseRedirected")
                    if child is not None:
                        redirected = child.text == "true"

                    # XXX FIXME this logic is wrong, we can have more than one req/resp in a single issue
                    # R0VUIC9wYWdlYWQvanMvcjIwMjQwMzExL3IyMDExMDkxNC9jbGllbnQvd2luZG93X2ZvY3VzX2Z5MjAyMS5qcyBIVFRQLzEuMQ0KSG9zdDogcGFnZWFkMi5nb29nbGVzeW5kaWNhdGlvbi5jb20NClNlYy1DaC1VYTogIk5vdChBOkJyYW5kIjt2PSIyNCIsICJDaHJvbWl1bSI7dj0iMTIyIg0KU2VjLUNoLVVhLU1vYmlsZTogPzANClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMjIuMC42MjYxLjExMiBTYWZhcmkvNTM3LjM2DQpTZWMtQ2gtVWEtUGxhdGZvcm06ICJtYWNPUyINCkFjY2VwdDogKi8qDQpYLUNsaWVudC1EYXRhOiBDTFNFeXdFPQ0KU2VjLUZldGNoLVNpdGU6IGNyb3NzLXNpdGUNClNlYy1GZXRjaC1Nb2RlOiBuby1jb3JzDQpTZWMtRmV0Y2gtRGVzdDogc2NyaXB0DQpSZWZlcmVyOiBodHRwczovL2FtZXJpY2FuZmFybWhvdXNlc3R5bGUuY29tLw0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlLCBicg0KQWNjZXB0LUxhbmd1YWdlOiBlbi1HQixlbi1VUztxPTAuOSxlbjtxPTAuOA0KUHJpb3JpdHk6IA0KQ29ubmVjdGlvbjogY2xvc2UNCg0K

                    if method:
                        assert "method" not in data["issues"][0], \
                                "Duplicated <%s> tag, processing issue '%s'" % (element.tag, name)
                        data["issues"][0]["method"] = method
                    if request:
                        assert "request" not in data["issues"][0], \
                                "Duplicated <%s> tag, processing issue '%s'" % (element.tag, name)
                        data["issues"][0]["request"] = request
                    if response:
                        assert "response" not in data["issues"][0], \
                                "Duplicated <%s> tag, processing issue '%s'" % (element.tag, name)
                        data["issues"][0]["response"] = response
                    if redirected:
                        assert "redirected" not in data["issues"][0], \
                                "Duplicated <%s> tag, processing issue '%s'" % (element.tag, name)
                        data["issues"][0]["redirected"] = redirected

                    # The plugin that reports this more often that not marks its own issues as "certain".
                    # I haven't checked why it does this, I'm just choosing to ignore it. I've half a mind
                    # to remove the issue entirely to be honest, it's almost never correct.
                    if name == "Detailed Error Messages Revealed" and response: # and confidence != "Certain":
                        headers = base64.b64decode(response).decode("utf-8")
                        headers = headers.split("\r\n\r\n", 1)[0]
                        headers = headers.split("\r\n")
                        status = headers[0].split(" ", 2)[1]
                        if status == "200":
                            headers = headers[1:]
                            headers = [h.split(":", 1) for h in headers]
                            headers = dict([(h[0].lower().strip(), h[1].lower().strip()) for h in headers])
                            if "content-type" in headers:
                                if headers["content-type"].startswith("application/javascript") or \
                                        headers["content-type"].startswith("text/javascript"):
                                    sys.stderr.write(
                                            "Skipped known false positive, 'Detailed Error Messages Revealed'" \
                                            " in JavaScript source code\n")
                                    data = {}
                                    break
                            else:
                                path = data["issues"][0].get("path", data["issues"][0].get("location", ""))
                                if "?" in path:
                                    path = path.split("?", 1)[0]
                                if path.endswith(".js") or path.endswith(".mjs"):
                                    sys.stderr.write(
                                            "Skipped known false positive, 'Detailed Error Messages Revealed'" \
                                            " in JavaScript source code\n")
                                    data = {}
                                    break

                elif element.tag == "issueDetailItems":
                    if name in DETAILS_DICT:
                        continue
                    assert "details" not in data["issues"][0], "Malformed issue: '%s'" % name
                    if name == "Mixed content":
                        data["issues"][0]["details"] = sorted(set(
                                child.text[child.text.find("http://"):].strip()
                                for child in element.findall("issueDetailItem")))
                    else:
                        data["issues"][0]["details"] = sorted(set(
                                child.text.strip() for child in element.findall("issueDetailItem")))

                elif element.tag == "issueDetail":
                    assert name, "Missing <name> tag in issue"
                    details = []

                    if name == "Detailed Error Messages Revealed":
                        assert element.text.startswith(
                            "The application displays detailed error messages when unhandled "), \
                            "Malformed issue: '%s'" % name
                        assert " exceptions occur." in element.text, "Malformed issue: '%s'" % name
                        assert "<li>" in element.text, "Malformed issue: '%s'" % name
                        p = len("The application displays detailed error messages when unhandled ")
                        q = element.text.find(" exceptions occur.", p)
                        exc_type = element.text[p:q]
                        html = parse_html(element.text)
                        for li in html.findall(".//li"):
                            details.append("%s - %s" % (exc_type, li.text.strip()))

                    elif name == "Lack or Misconfiguration of Security Header(s)":
                        html = parse_html(element.text)
                        for li in html.findall(".//li"):
                            assert li.text.startswith("Header name:")
                            details.append(fix_header_name(li.find(".//b").text.strip()))

                    # XXX TODO Tt would be nice to find out what the latest version is.
                    # Since this may require online access, I'm not sure where to put it.
                    elif name == "[Vulners] Vulnerable Software detected":
                        result, taxonomy, references = parse_vulners_plugin(element.text)
                        if "vulnerabilities" not in data["issues"][0]:
                            data["issues"][0]["vulnerabilities"] = []
                        data["issues"][0]["vulnerabilities"].append(result)
                        if taxonomy:
                            if "taxonomy" not in data:
                                data["taxonomy"] = []
                            data["taxonomy"].extend(taxonomy)
                        if references:
                            if "references" not in data:
                                data["references"] = []
                            data["references"].extend(references)

                    # XXX FIXME This needs a bit more love, we should report on the known vulns.
                    # Then again I have seen the plugin make egregious mustakes with this.
                    # It may be safer to get the info from elsewhere.
                    elif name == "Vulnerable JavaScript dependency":
                        html = parse_html(element.text)
                        library, version = html.findall(".//strong")
                        library = library.text.strip().replace("-", "_")
                        version = version.text.strip()
                        details.append(library + " - " + version)
                        if "references" not in data:
                            data["references"] = []
                        for link in html.findall(".//a"):
                            data["references"].append(link.attrib["href"])

                    if details:
                        assert "details" not in data["issues"][0], "Malformed issue: '%s'" % name
                        data["issues"][0]["details"] = details

                else:
                    assert False, "Unknown tag: <%s>" % element.tag

            if not data:
                continue

            if "references" in data:
                data["references"] = sorted(set(data["references"]))
            if "taxonomy" in data:
                data["taxonomy"] = sorted(set(data["taxonomy"]))

            assert data["issues"], "Error parsing issue: '%s'" % name
            assert data["issues"][0], "Error parsing issue: '%s'" % name
            assert data["issues"][0]["host"], "Error parsing issue: '%s'" % name

            issue = data["issues"][0]
            if "details" in issue:
                if issue["details"]:
                    issue["details"] = sorted(set(issue["details"]))
                else:
                    del issue["details"]
            if "vulnerabilities" in issue:
                if issue["vulnerabilities"]:
                    issue["vulnerabilities"] = sorted(
                            issue["vulnerabilities"], key=lambda k:k["software"]+"-"+k["version"])
                else:
                    del issue["vulnerabilities"]
            if "path" in issue and "location" in issue and issue["path"] == issue["location"]:
                del issue["location"]
            url = issue["host"]
            if "path" in issue:
                url += issue["path"]
            elif "location" in issue:
                url += issue["location"]
            data["affects"] = [url]

            if doComma:
                sys.stdout.write(", ")
            doComma = True
            json.dump(data, sys.stdout)

        except Exception:
            traceback.print_exc()

    sys.stdout.write("]")

# Here's my second attempt at parsing the absolute horrid mess
# that the Vulners plugin for Burp produces. I can't guarantee
# success since this garbage barely readable by humans...
RE_VULNERS = re.compile("The following vulnerabilities for software <b>([^ ]+) - ([^<]+)</b> found:")
def parse_vulners_plugin(text):
    software, version = RE_VULNERS.search(text).groups()
    assert software and version and version != "null"
    swlist = {
        "taxonomy": [
            "CVE-",
            "CWE-",
            "CAPEC-",
            "CNVD-",
            "JVNDB-",
            "JVN",
            "BDU:",
            "USN-",
            "RHSA-",
            "DSA-",
            "KB",
            "MS",
            "MFSA",
            "WPVDB-ID:",
            "OSV:",
            "PACKETSTORM:",
            "SECURITYVULNS:DOC:",
            "OBB-",
        ],
        "patches": [
            "PATCHSTACK:",
        ],
        "exploits": [
            "EDB-ID:",
            "1337DAY-ID-",
            "GITHUBEXPLOIT:",
            "WPEX-ID:",
        ],
    }
    result = {
        "software": software,
        "version": version,
        "taxonomy": [],
        "patches": [],
        "exploits": [],
    }
    taxonomy = []
    references = []
    html = parse_html(text)
    for a in html.findall(".//a"):
        href = a.attrib.get("href", "").strip()
        if href.startswith("https://vulners.com/"):
            if href.startswith("https://vulners.com/githubexploit/"):
                tax = "GITHUBEXPLOIT:" + href[34:].strip()  # whyyyyy
            else:
                tax = href[href.find("/",21)+1:].strip()
                if tax.startswith("PRION:CVE-"):            # ~quiet whimper~
                    tax = tax[6:]
            if tax:
                found = None
                for tagtype in swlist:
                    for sw in swlist[tagtype]:
                        if tax.startswith(sw):
                            found = tagtype
                            break
                    if found:
                        break
                if found:
                    result[found].append(tax)
                    taxonomy.append(tax)
                else:
                    sys.stderr.write("Unknown taxonomy tag used by Vulners plugin: '%s'\n" % tax)
                    references.append(href)
            else:
                sys.stderr.write("Unknown Vulners link used by Vulners plugin: '%s'\n" % href)
                references.append(href)
        else:
            references.append(href)
    for propname in swlist:
        if result[propname]:
            result[propname] = sorted(set(result[propname]))
        else:
            del result[propname]
    return result, taxonomy, references

if __name__ == "__main__":
    main()
