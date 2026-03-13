#!/usr/bin/python3

import csv
import json
import io
import os.path
import sys
import traceback

from lxml import etree

def tag_to_str(element):
    source = "<" + element.tag
    for key, value in element.attrib.items():
        source += " %s=%r" % (key, value)
    if element.text:
        source += ">" + element.text + "</" + element.tag + ">"
    else:
        source += "/>"
    return source

def main():

    # Load the input data as XML. For now (and the foreseeable future) this will be the only supported format.
    # Parsing the text output would be way too complicated and I don't really see a good use case for it.
    parser = etree.XMLParser(
        load_dtd=False,
        dtd_validation=False,
        recover=True,
        remove_comments=True,
        remove_pis=True,
        resolve_entities=False,
        huge_tree=False,
        strip_cdata=False
    )
    fd = io.BytesIO(sys.stdin.read().encode("utf-8"))
    tree = etree.parse(fd, parser=parser)
    root = tree.getroot()
    assert root.attrib.get("title", "") == "SSLScan Results", "Invalid file format"
    version = int(root.attrib["version"][0])
    assert version in (1, 2), "Invalid file format version"

    # Parse the input data. Fortunately, the data is easy to parse.
    # Unfortunately, the data itself is hot garbage. It does produce
    # the results but refuses to tell me if they're good or bad, so
    # I have to re-implement all of the logic to determine what the
    # vulnerabilities are inside the parser, which I more or less
    # refuse to do for the time being. I'll just add the most obvious
    # stuff and maybe, if I feel like it, will keep adding more later.
    hosts = []
    for ssltest in root.findall("./ssltest"):
        host = ssltest.attrib["host"]
        port = int(ssltest.attrib["port"])
        severity = "low"
        bad_ciphers = []
        problems = {
            "TLS1_2": "",   # assume is missing until seen
            "TLS1_3": "",   # assume is missing until seen
        }
        for child in ssltest.getchildren():
            sslversion = child.attrib.get("sslversion", None)
            tag = child.tag

            # Skip the client ciphers, they are completely pointless.
            if tag == "client-cipher":
                continue

            # Skip the protocol tags, since we're deducing that information anyway.
            # The tag doesn't exist in v1 of the file format.
            if tag == "protocol":
                continue

            # I have literally no idea what this tag is supposed to be about.
            if tag == "group":
                continue

            # This is the main use of the tool, since it's mostly focused around
            # listing ciphers rather than testing for vulnerabilities.
            if tag == "cipher":

                # Version 1.x:
                #   We need to add some logic here to determine whather or not each cipher
                #   is vulnerable, and that should hopefully come from a file rather than
                #   adding a kludge of if statements here... for now we just ignore the
                #   list of ciphers for these old versions.
                #
                # Version 2.x:
                #   This version supports the "strength" attribute, so we can at least use that.
                #
                if child.attrib.get("strength", "acceptable") not in ("strong", "acceptable"):
                    obj = {
                        "cipher": child.attrib["cipher"],
                        "version": sslversion,
                        "openssl_id": child.attrib["id"],
                        "cipher_bits": int(child.attrib["bits"]),
                        "severity": "low",
                        "status": child.attrib["status"],
                    }
                    if "ecdhebits" in child.attrib:
                        obj["hash_bits"] = int(child.attrib["ecdhebits"])
                    elif "dhebits" in child.attrib:
                        obj["hash_bits"] = int(child.attrib["dhebits"])
                    bad_ciphers.append(obj)

                # We will use the "sslversion" attribute to deduce whether each
                # protocol version is implemented or not.
                if sslversion == "SSLv2":
                    problems["SSLv2"] = ""
                    if severity == "low":
                        severity = "medium"
                elif sslversion == "SSLv3":
                    problems["SSLv3"] = ""
                    if severity == "low":
                        severity = "medium"
                elif sslversion == "TLSv1.0":
                    problems["TLS1"] = ""
                elif sslversion == "TLSv1.1":
                    problems["TLS1_1"] = ""
                elif sslversion == "TLSv1.2":
                    if "TLS1_2" in problems:
                        del problems["TLS1_2"]
                elif sslversion == "TLSv1.3":
                    if "TLS1_3" in problems:
                        del problems["TLS1_3"]

            # Very very basic parsing of the certificate data to get the most obvious problems.
            # No idea how to deduce anything else without basically reimplementing half the tool.
            elif tag == "certificate" or tag == "certificates":
                if tag == "certificate":
                    grandchildren = child.getchildren()
                else:
                    grandchildren = child.findall(".//certificate/*")
                for grandchild in grandchildren:
                    subtag = grandchild.tag
                    if subtag == "self-signed":
                        if grandchild.text == "true":
                            problems["cert_caIssuers"] = ""
                            if severity == "low":
                                severity = "medium"
                    elif subtag == "expired":
                        if grandchild.text == "true":
                            problems["cert_expirationStatus"] = ""
                            if severity == "low":
                                severity = "medium"
                    elif subtag == "pk":
                        if grandchild.attrib["error"] == "true":    # who the hell knows what this is supposed to mean
                            problems["cert_chain_of_trust"] = ""
                            if severity == "low":
                                severity = "medium"
            elif tag == "renegotiation":
                if child.attrib["secure"] == "0":
                    problems["secure_renego"] = ""      # not sure, may be secure_client_renego
                    if severity in ("low", "medium"):
                        severity = "high"
            elif tag == "heartbleed":
                if child.attrib["vulnerable"] == "":
                    problems["heartbleed"] = sslversion
                    if severity in ("low", "medium"):
                        severity = "high"
            elif tag == "compression":
                if child.attrib["supported"] == "1":
                    pass    # no idea what the hell I'm supposed to do here
            elif tag == "fallback":
                if child.attrib["supported"] == "0":
                    problems["fallback_SCSV"] = ""
            else:
                sys.stderr.write("Warning, unknown tag found: %s\n" % tag_to_str(child))

        # Add the host data to the list.
        if problems or bad_ciphers:
            obj = {
                "host": "%s:%d" % (host, port),
            }
            if bad_ciphers:
                obj["bad_ciphers"] = bad_ciphers
            if problems:
                obj["problems"] = problems
            hosts.append(obj)

    # Send the output back to Magenta.
    obj = {
        "template": "multiple_ssl_issues",
        "tools": ["sslscan"],
        "severity": severity,
        "affects": sorted(set(h["host"] for h in hosts)),
        "taxonomy": ["CWE-310"],    # XXX TODO use more specific CWE values
        "hosts": hosts,
    }
    json.dump([obj], sys.stdout)

if __name__ == "__main__":
    main()
