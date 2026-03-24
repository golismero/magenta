#!/usr/bin/python3

import html
import json
import re
import sys
import urllib.parse
import traceback

from lxml import etree

# This maps Nessus plugin IDs to our templates.
#
# If you're reading this and you see plugin not in this dictionary,
# please let me know and I'll try to add it! :)
#
TEMPLATES = {
    66334: "missing_security_patches",  # Patch Report
    # These are missing the CVE information and must be routed manually.
    # Surely more will be added, because Nessus plugins are a bit chaotic.
    10539: "outdated_server_software_found",  # DNS Server Recursive Query Cache Poisoning Weakness
    34460: "outdated_server_software_found",  # Unsupported Web Server Detection
    35450: "outdated_server_software_found",  # DNS Server Spoofed Request Amplification DDoS
    73756: "outdated_server_software_found",  # Microsoft SQL Server Unsupported Version Detection (remote check)
    109345: "outdated_server_software_found",  # Oracle WebLogic Unsupported Version Detection
    149348: "outdated_server_software_found",  # PHP 7.4.x < 7.4.18 / 8.x < 8.0.5 Integer Overflow
    158094: "outdated_server_software_found",  # Apache Solr Unauthenticated Access Information Disclosure
    # Client and server software should be separate issues.
    # This may be a problem since they will have CVEs too.
    # More research into the Nessus plugins is needed.
    136929: "outdated_javascript_library_found",  # JQuery 1.2 < 3.5.0 Multiple XSS
    18405: "misconfigured_terminal_services",  # Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness
    30218: "misconfigured_terminal_services",  # Terminal Services Encryption Level is not FIPS-140 Compliant
    58453: "misconfigured_terminal_services",  # Terminal Services Doesn't Use Network Level Authentication (NLA) Only
    57690: "misconfigured_terminal_services",  # Terminal Services Encryption Level is Medium or Low
    85582: "missing_security_headers",  # Web Application Potentially Vulnerable to Clickjacking
    142960: "missing_security_headers",  # HSTS Missing From HTTPS Server (RFC 6797)
    42057: "password_field_with_autocomplete_enabled",  # Web Server Allows Password Auto-Completion
    15901: "multiple_ssl_issues",  # SSL Certificate Expiry
    20007: "multiple_ssl_issues",  # SSL Version 2 and 3 Protocol Detection
    26928: "multiple_ssl_issues",  # SSL Weak Cipher Suites Supported
    31705: "multiple_ssl_issues",  # SSL Anonymous Cipher Suites Supported
    35291: "multiple_ssl_issues",  # SSL Certificate Signed Using Weak Hashing Algorithm
    42053: "multiple_ssl_issues",  # SSL Certificate Null Character Spoofing Weakness
    42873: "multiple_ssl_issues",  # SSL Medium Strength Cipher Suites Supported (SWEET32)
    42880: "multiple_ssl_issues",  # SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection
    45411: "multiple_ssl_issues",  # SSL Certificate with Wrong Hostname
    51192: "multiple_ssl_issues",  # SSL Certificate Cannot Be Trusted
    51356: "multiple_ssl_issues",  # Well-known SSL Certificate Used in Remote Device
    51892: "multiple_ssl_issues",  # OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Session Resume Ciphersuite Downgrade
    51893: "multiple_ssl_issues",  # OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Ciphersuite Disabled Cipher Issue
    52963: "multiple_ssl_issues",  # Blacklisted SSL Certificate
    56043: "multiple_ssl_issues",  # SSL Certificate Signed with the Revoked DigiNotar Certificate Authority
    56284: "multiple_ssl_issues",  # SSL Certificate Fails to Adhere to Basic Constraints / Key Usage Extensions
    57582: "multiple_ssl_issues",  # SSL Self-Signed Certificate
    58751: "multiple_ssl_issues",  # SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)
    60016: "multiple_ssl_issues",  # Vulnerability in TLS Could Allow Information Disclosure (2655992)
    60108: "multiple_ssl_issues",  # SSL Certificate Chain Contains Weak RSA Keys
    61447: "multiple_ssl_issues",  # SSL Certificate Signed with the Publicly Known Cyberoam Key
    62565: "multiple_ssl_issues",  # Transport Layer Security (TLS) Protocol CRIME Vulnerability
    62566: "multiple_ssl_issues",  # RuggedCom RuggedOS Known Hardcoded SSL RSA Private Key
    62969: "multiple_ssl_issues",  # SSL Certificate Signed with the Compromised FortiGate Key
    63398: "multiple_ssl_issues",  # SSL Certificate Chain Contains Illegitimate TURKTRUST Intermediate CA
    64688: "multiple_ssl_issues",  # APT1-Related SSL Certificate Detected
    65821: "multiple_ssl_issues",  # SSL RC4 Cipher Suites Supported (Bar Mitzvah)
    66848: "multiple_ssl_issues",  # SSL Null Cipher Suites Supported
    69551: "multiple_ssl_issues",  # SSL Certificate Chain Contains RSA Keys Less Than 2048 bits
    71534: "multiple_ssl_issues",  # SuperMicro Device Uses Default SSL Certificate
    73459: "multiple_ssl_issues",  # SSL Certificate Chain Contains RSA Keys Less Than 2048 bits (PCI DSS)
    78479: "multiple_ssl_issues",  # SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)
    80035: "multiple_ssl_issues",  # TLS Padding Oracle Information Disclosure Vulnerability (TLS POODLE)
    80399: "multiple_ssl_issues",  # PolarSSL Weak Signature Algorithm Negotiation
    81606: "multiple_ssl_issues",  # SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)
    83875: "multiple_ssl_issues",  # SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)
    91572: "multiple_ssl_issues",  # OpenSSL AES-NI Padding Oracle MitM Information Disclosure
    94437: "multiple_ssl_issues",  # SSL 64-bit Block Size Cipher Suites Supported (SWEET32)
    97191: "multiple_ssl_issues",  # F5 TLS Session Ticket Implementation Remote Memory Disclosure (Ticketbleed)
    103864: "multiple_ssl_issues",  # SSL Certificate Contains Weak RSA Key (Infineon TPM / ROCA)
    104743: "multiple_ssl_issues",  # TLS Version 1.0 Protocol Detection
    105415: "multiple_ssl_issues",  # Return Of Bleichenbacher's Oracle Threat (ROBOT) Information Disclosure
    106457: "multiple_ssl_issues",  # Anonymous Key Exchanges Supported (PCI DSS)
    106458: "multiple_ssl_issues",  # SSL/TLS Services Support RC4 (PCI DSS)
    106459: "multiple_ssl_issues",  # Weak DH Key Exchange Supported (PCI DSS)
    121009: "multiple_ssl_issues",  # SSL Certificate Validity - Duration
    124410: "multiple_ssl_issues",  # SSL Root Certification Authority Distrusted
    132675: "multiple_ssl_issues",  # SSL/TLS Deprecated Ciphers Unsupported
    132676: "multiple_ssl_issues",  # SSLv2-Only Open Ports Unsupported
    157288: "multiple_ssl_issues",  # TLS Version 1.1 Protocol Deprecated
    159543: "multiple_ssl_issues",  # SSL/TLS Recommended Cipher Suites (PCI DSS)
    10268: "multiple_ssh_issues",  # SSH CBC/CFB Data Stream Injection
    10882: "multiple_ssh_issues",  # SSH Protocol Version 1 Session Key Retrieval
    57620: "multiple_ssh_issues",  # Small SSH RSA Key
    70658: "multiple_ssh_issues",  # SSH Server CBC Mode Ciphers Enabled
    71049: "multiple_ssh_issues",  # SSH Weak MAC Algorithms Enabled
    86328: "multiple_ssh_issues",  # SSH Diffie-Hellman Modulus <= 1024 Bits (Logjam)
    90317: "multiple_ssh_issues",  # SSH Weak Algorithms Supported
    153953: "multiple_ssh_issues",  # SSH Weak Key Exchange Algorithms Enabled
    153954: "multiple_ssh_issues",  # SSH Host Keys < 2048 Bits Considered Weak
    10756: "sensitive_file_exposed",  # Apple Mac OS X Find-By-Content .DS_Store Web Directory Listing
    11229: "sensitive_file_exposed",  # Web Server info.php / phpinfo.php Detection
    11411: "sensitive_file_exposed",  # Backup Files Disclosure
    121479: "sensitive_file_exposed",  # web.config File Information Disclosure
    40984: "directory_listing_enabled",  # Browsable Web Directories
    10498: "insecure_http_methods_allowed",  # Web Server HTTP Dangerous Method Detection
    11213: "insecure_http_methods_allowed",  # HTTP TRACE / TRACK Methods Allowed
    33270: "insecure_http_methods_allowed",  # ASP.NET DEBUG Method Enabled
    10759: "information_exposure_in_http_headers",  # Web Server HTTP Header Internal IP Disclosure
    12085: "default_web_server_files",  # Apache Tomcat Default Files
    26194: "credentials_sent_over_unencrypted_connection",  # Web Server Transmits Cleartext Credentials
    34850: "credentials_sent_over_unencrypted_connection",  # Web Server Uses Basic Authentication Without HTTPS
    54582: "credentials_sent_over_unencrypted_connection",  # SMTP Service Cleartext Login Permitted
    42054: "server_side_include",  # CGI Generic SSI Injection
    42423: "server_side_include",  # CGI Generic SSI Injection (HTTP headers)
    10815: "cross_site_scripting",  # Web Server Generic XSS
    47831: "cross_site_scripting",  # CGI Generic XSS (comprehensive test)
    49067: "cross_site_scripting",  # CGI Generic HTML Injections (quick test)
    42263: "cleartext_open_ports",  # Unencrypted Telnet Server
}


def do_generic_nessus_vulnerability(obj):
    vuln = {
        "host": obj["host"],
        "plugin_id": obj["plugin_id"],
        "plugin_name": obj["plugin_name"],
    }
    if "port" in obj and obj["port"]:
        vuln["port"] = obj["port"]
    if "plugin_output" in obj:
        vuln["plugin_output"] = html.unescape(obj["plugin_output"].strip())
    if "description" in obj:
        vuln["description"] = html.unescape(obj["description"].strip())
    if "solution" in obj:
        vuln["solution"] = html.unescape(obj["solution"].strip())
    return {"template": "generic_nessus_vulnerability", "nessus": [vuln]}


def do_credentials_sent_over_unencrypted_connection(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_cross_site_scripting(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


re_default_password = re.compile(
    r"^Default Password \('([^']+)'\) for '(^']+)' Account$"
)
re_unpassworded = re.compile(r"^Unpassworded '(^']+)' Account$")


def do_default_credentials_detected(obj):
    plugin_id = obj["plugin_id"]
    plugin_name = obj["plugin_name"]
    if plugin_id == 87601:
        username = "netscreen"
        password = "<<< %s(un='%s') = %u"
    elif plugin_id == 94358:
        username = "admin"
        password = ""
    else:
        m = re_default_password.search(plugin_name)
        if m:
            username = m.group(1)
            password = m.group(2)
        else:
            m = re_unpassworded.search(plugin_name)
            if m:
                username = m.group(1)
                password = ""
            else:
                do_generic_nessus_vulnerability(obj)
    return {
        "credentials": [
            {
                "host": obj["host"],
                "port": obj["port"],
                "service": obj["svc_name"],
                "login": username,
                "password": password,
            }
        ]
    }


def do_default_web_server_files(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_directory_listing_enabled(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_information_exposure_in_http_headers(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_insecure_http_methods_allowed(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_misconfigured_terminal_services(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


re_missing_security_patches = re.compile(r"^\[.*\]$")


def do_missing_security_patches(obj):
    host = obj["host"]
    port = obj["port"]
    if port:
        host = host + ":" + str(port)
    patches = []
    if "plugin_output" in obj:
        for line in obj["plugin_output"].split("\n"):
            m = re_missing_security_patches.search(line)
            if m:
                patches.append(m.group(1).strip())
    else:
        return do_generic_nessus_vulnerability(obj)
    if patches:
        return {"issues": [{"host": host, "patches": patches}]}
    return do_generic_nessus_vulnerability(obj)


def do_missing_security_headers(obj):
    host = obj["host"]
    port = obj["port"]
    if port:
        host = host + ":" + str(port)
    if obj["plugin_id"] == 85582:
        header = "X-Frame-Options"
    elif obj["plugin_id"] == 142960:
        header = "Strict-Transport-Security"
    else:
        assert False, "Internal error"
    return {
        "issues": [
            {
                "host": host,
                "path": "/",
                "method": "GET",
                "details": [header],
            }
        ]
    }


nessus2testssl = {
    15901: "cert_expirationStatus",  # SSL Certificate Expiry
    20007: ("SSLv2", "SSLv3"),  # SSL Version 2 and 3 Protocol Detection
    26928: "",  # SSL Weak Cipher Suites Supported
    31705: "",  # SSL Anonymous Cipher Suites Supported
    35291: "",  # SSL Certificate Signed Using Weak Hashing Algorithm
    42053: "",  # SSL Certificate Null Character Spoofing Weakness
    42873: "SWEET32",  # SSL Medium Strength Cipher Suites Supported (SWEET32)
    42880: "secure_renego",  # SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection
    45411: "cert_chain_of_trust",  # SSL Certificate with Wrong Hostname
    51192: "cert_chain_of_trust",  # SSL Certificate Cannot Be Trusted
    51356: "",  # Well-known SSL Certificate Used in Remote Device
    51892: "",  # OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Session Resume Ciphersuite Downgrade
    51893: "",  # OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Ciphersuite Disabled Cipher Issue
    52963: "",  # Blacklisted SSL Certificate
    56043: "",  # SSL Certificate Signed with the Revoked DigiNotar Certificate Authority
    56284: "",  # SSL Certificate Fails to Adhere to Basic Constraints / Key Usage Extensions
    57582: "cert_caIssuers",  # SSL Self-Signed Certificate
    58751: "BEAST",  # SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)
    60016: "",  # Vulnerability in TLS Could Allow Information Disclosure (2655992)
    60108: "",  # SSL Certificate Chain Contains Weak RSA Keys
    61447: "",  # SSL Certificate Signed with the Publicly Known Cyberoam Key
    62565: "CRIME",  # Transport Layer Security (TLS) Protocol CRIME Vulnerability
    62566: "",  # RuggedCom RuggedOS Known Hardcoded SSL RSA Private Key
    62969: "",  # SSL Certificate Signed with the Compromised FortiGate Key
    63398: "",  # SSL Certificate Chain Contains Illegitimate TURKTRUST Intermediate CA
    64688: "",  # APT1-Related SSL Certificate Detected
    65821: "RC4",  # SSL RC4 Cipher Suites Supported (Bar Mitzvah)
    66848: "cipherlist_NULL",  # SSL Null Cipher Suites Supported
    69551: "",  # SSL Certificate Chain Contains RSA Keys Less Than 2048 bits
    71534: "",  # SuperMicro Device Uses Default SSL Certificate
    73459: "",  # SSL Certificate Chain Contains RSA Keys Less Than 2048 bits (PCI DSS)
    78479: "POODLE",  # SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)
    80035: "POODLE",  # TLS Padding Oracle Information Disclosure Vulnerability (TLS POODLE)
    80399: "",  # PolarSSL Weak Signature Algorithm Negotiation
    81606: "FREAK",  # SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)
    83875: "LOGJAM",  # SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)
    91572: "",  # OpenSSL AES-NI Padding Oracle MitM Information Disclosure
    94437: "SWEET32",  # SSL 64-bit Block Size Cipher Suites Supported (SWEET32)
    97191: "ticketbleed",  # F5 TLS Session Ticket Implementation Remote Memory Disclosure (Ticketbleed)
    103864: "",  # SSL Certificate Contains Weak RSA Key (Infineon TPM / ROCA)
    104743: "TLSv1",  # TLS Version 1.0 Protocol Detection
    105415: "ROBOT",  # Return Of Bleichenbacher's Oracle Threat (ROBOT) Information Disclosure
    106457: "",  # Anonymous Key Exchanges Supported (PCI DSS)
    106458: "RC4",  # SSL/TLS Services Support RC4 (PCI DSS)
    106459: "DH_groups",  # Weak DH Key Exchange Supported (PCI DSS)
    121009: "cert_extlifeSpan",  # SSL Certificate Validity - Duration
    124410: "cert_chain_of_trust",  # SSL Root Certification Authority Distrusted
    132675: "",  # SSL/TLS Deprecated Ciphers Unsupported
    132676: "",  # SSLv2-Only Open Ports Unsupported
    157288: "TLS1_1",  # TLS Version 1.1 Protocol Deprecated
    159543: "",  # SSL/TLS Recommended Cipher Suites (PCI DSS)
}


def do_multiple_ssl_issues(obj):
    plugin_id = obj["plugin_id"]
    if plugin_id in nessus2testssl and nessus2testssl[plugin_id]:
        host = obj["host"]
        port = obj["port"]
        if port:
            host = host + ":" + str(port)
        if isinstance(nessus2testssl[plugin_id], str):
            return {
                "hosts": [{"host": host, "problems": {nessus2testssl[plugin_id]: ""}}]
            }
        return {
            "hosts": [
                {"host": host, "problems": {x: "" for x in nessus2testssl[plugin_id]}}
            ]
        }
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_multiple_ssh_issues(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_outdated_javascript_library_found(obj):
    if "cpe" not in obj:
        if "jquery" in obj["plugin_name"].lower():
            obj["cpe"] = "jQuery"  # XXX FIXME HACK
    return do_outdated_server_software_found(obj)


re_url_outdated_software = re.compile("^ *URL *: *([^ ]+)$")
re_product_outdated_software = re.compile("^ *Product *: *(.*)$")
re_server_outdated_software = re.compile("^ *Server response header *: *([^/]+)/(.+)$")
re_banner_outdated_software = re.compile("^ *Banner *: *(.*)$")
re_installed_outdated_software = re.compile("^ *Installed version *: *(.*)$")
re_reported_outdated_software = re.compile("^ *Reported version *: *(.*)$")
re_fixed_outdated_software = re.compile("^ *Fixed *: *(.*)$")


def do_outdated_server_software_found(obj):
    url = None
    software = None
    version = None
    fixed = None
    if "plugin_output" in obj:
        for line in obj["plugin_output"].split("\n"):
            if version is None:
                m = re_server_outdated_software.search(line)
                if m:
                    software = m.group(1)
                    version = m.group(2)
            if url is None:
                m = re_url_outdated_software.search(line)
                if m:
                    url = m.group(1)
                    continue
            if software is None:
                m = re_product_outdated_software.search(line)
                if m:
                    software = m.group(1)
                    continue
                m = re_banner_outdated_software.search(line)
                if m:
                    software = m.group(1)
                    continue
            if version is None:
                m = re_installed_outdated_software.search(line)
                if m:
                    version = m.group(1)
                    continue
                m = re_reported_outdated_software.search(line)
                if m:
                    version = m.group(1)
                    continue
            if fixed is None:
                m = re_fixed_outdated_software.search(line)
                if m:
                    fixed = m.group(1)
                    continue
    else:
        return do_generic_nessus_vulnerability(obj)
    if software and software.lower() == "unknown":
        software = None
    if not software:
        software = obj.get("cpe", None)  # XXX TODO convert to human readable string
    if version and version.lower() == "unknown":
        version = None
    if software and version:
        vulnerabilities = [
            {
                "software": software,
                "version": version,
            }
        ]
        if fixed:
            vulnerabilities[0]["fixed"] = fixed
        issue = {
            "vulnerabilities": vulnerabilities,
        }
        if url:
            u = urllib.parse.urlparse(url)
            issue["host"] = u.netloc
            if u.path != "/":
                issue["path"] = u.path
        else:
            host = obj["host"]
            port = obj["port"]
            if port:
                host = host + ":" + str(port)
            issue["host"] = host
        return {"issues": [issue]}
    return do_generic_nessus_vulnerability(obj)


def do_outdated_wordpress_plugin_found(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


re_password_field_with_autocomplete_enabled = re.compile("^Page : (.*)$")


def do_password_field_with_autocomplete_enabled(obj):
    host = obj["host"]
    port = obj["port"]
    if port:
        host = host + ":" + str(port)
    issues = []
    affects = []
    for line in obj["plugin_output"].split("\n"):
        m = re_password_field_with_autocomplete_enabled.search(line)
        if m is not None:
            path = m.group(1)
            affects.append(host + path)
            issue = {
                "host": host,
                "path": path,
                "method": "GET",
                "details": [],
            }
            issues.append(issue)
    return {"affects": affects, "issues": issues}


def do_sensitive_file_exposed(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def do_server_side_include(obj):
    return do_generic_nessus_vulnerability(obj)  # XXX TODO


def parse_xml():
    parser = etree.XMLParser(
        load_dtd=False,
        dtd_validation=False,
        recover=True,
        remove_comments=True,
        remove_pis=True,
        resolve_entities=False,
        huge_tree=False,
        strip_cdata=False,
    )
    tree = etree.parse(sys.stdin, parser=parser)
    root = tree.getroot()
    nessus_report = []
    for report_host in root.findall(".//ReportHost"):
        host = report_host.attrib["name"]
        ip = None
        for tag in report_host.findall("./HostProperties/tag"):
            if tag.attrib["name"] == "host-ip":
                ip = tag.text
                break
        for report_item in report_host.findall("./ReportItem"):
            name = report_item.attrib["pluginName"]
            plugin_id = 0
            try:
                plugin_id = int(report_item.attrib["pluginID"])
                family = report_item.attrib["pluginFamily"]
                severity = ["none", "low", "medium", "high", "critical"][
                    int(report_item.attrib["severity"])
                ]
                port = int(report_item.attrib["port"])
                protocol = report_item.attrib["protocol"]
                svc_name = report_item.attrib["svc_name"]
                item = {
                    "plugin_id": plugin_id,
                    "plugin_name": name,
                    "plugin_family": family,
                    "severity": severity,
                    "host": host,
                    "svc_name": svc_name,
                    "port": port,
                    "protocol": protocol,
                }
                plugin_output = report_item.find("./plugin_output")
                if plugin_output is not None:
                    item["plugin_output"] = plugin_output.text
                cpe = report_item.find("./cpe")
                if cpe is not None:
                    item["cpe"] = cpe.text
                taxonomy = []
                references = [
                    "https://www.tenable.com/plugins/nessus/" + str(plugin_id)
                ]
                cve = report_item.find("./cve")
                if cve is not None:
                    taxonomy.append(cve.text)
                description = report_item.find("./description")
                if description is not None:
                    item["description"] = description.text
                solution = report_item.find("./solution")
                if solution is not None:
                    item["solution"] = solution.text
                see_also = report_item.find("./see_also")
                if see_also is not None:
                    references.extend(see_also.text.split("\n"))
                if taxonomy:
                    item["taxonomy"] = taxonomy
                item["references"] = references
                if ip:
                    item["ip"] = ip
                nessus_report.append(item)
            except Exception:
                sys.stderr.write(
                    "Error parsing vulnerability %d: %s\n" % (plugin_id, name)
                )
                traceback.print_exc()
                sys.stderr.write("\n")
    return nessus_report


def main():
    # Parse the input .nessus file.
    nessus_report = parse_xml()

    # Go through every Nessus report item and call the corresponding handler function.
    results = []
    for report_item in nessus_report:
        severity = report_item["severity"]
        if severity == "none":
            continue
        plugin_id = report_item["plugin_id"]
        if plugin_id in TEMPLATES:
            template_name = TEMPLATES[plugin_id]
            if not template_name:
                continue
        else:
            if report_item["plugin_name"].startswith("WordPress Plugin "):
                template_name = "outdated_wordpress_plugin_found"
            elif report_item["plugin_family"] == "Default Unix Accounts":
                template_name = "default_credentials_detected"
            elif any(t.startswith("CVE-") for t in report_item.get("taxonomy", [])):
                template_name = "outdated_server_software_found"
            else:
                template_name = "generic_nessus_vulnerability"
        try:
            vuln = globals()["do_" + template_name](report_item)
        except Exception:
            traceback.print_exc()
            continue
        if vuln is not None:
            if "template" not in vuln:
                vuln["template"] = template_name
            if "tools" not in vuln:
                vuln["tools"] = ["nessus"]
            if "severity" not in vuln:
                vuln["severity"] = severity
            if "affects" not in vuln:
                vuln["affects"] = [report_item["host"] + ":" + str(report_item["port"])]
            if "references" not in vuln:
                vuln["references"] = report_item["references"]
            if "taxonomy" not in vuln and "taxonomy" in report_item:
                vuln["taxonomy"] = report_item["taxonomy"]
            results.append(vuln)

    # Output the resulting Magenta vulnerability objects.
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
