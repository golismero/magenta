#!/usr/bin/python3

import csv
import json
import os.path
import sys
import traceback

# Get the data from stdin.
raw_input = sys.stdin.read()

# If we got no data, just ignore it.
# This should not happen.
if not raw_input:
    sys.stdout.write("[]")
    exit(0)

# This dictionary collects the testssl.sh data in a unified format.
items = {}

# Parse an output generated with the -oJ switch.
if raw_input[0] == "{":
    input = json.loads(raw_input)
    cmd = input["Invocation"]
    start = int(input["startTime"])
    try:
        end = start + int(input["scanTime"])
    except Exception:
        end = start
    for result in input["scanResult"]:
        try:
            if "id" in result and result["id"] == "scanProblem":
                break
            ip = result["targetHost"] + "/" + result["ip"]
            port = result["port"]
            key = result["ip"] + ":" + result["port"]
            for section in (
                "pretest", "protocols", "grease", "ciphers", "serverPreferences",
                "fs", "serverDefaults", "vulnerabilities", "browserSimulations", "rating"
            ):
                for item in result[section]:
                    item["ip"] = ip
                    item["port"] = port
                    if key not in items:
                        items[key] = []
                    items[key].append(item)
        except Exception:
            traceback.print_exc()

# Parse an output generated with the -oj switch.
elif raw_input[0] == "[":
    cmd = None
    start = None
    end = None
    input = json.loads(raw_input)
    for item in input:
        try:
            ip = item["ip"].split("/")[1]
            port = item["port"]
            key = item["ip"] + ":" + item["port"]
            if key not in items:
                items[key] = []
            items[key].append(item)
        except Exception:
            traceback.print_exc()

# Parse an output generated with the -oC switch.
elif raw_input[0] == "\"":
    cmd = None
    start = None
    end = None
    reader = csv.reader(raw_input.split("\n")[1:])
    for row in reader:
        if not row: continue
        row = list(row)
        if len(row) < 7:
            row.extend( [""] * (7 - len(row)) )
        id, ip, port, severity, finding, cve, cwe = row[:7]
        item = {
            "id": id,
            "ip": ip,
            "port": port,
            "severity": severity,
            "finding": finding,
            "cve": cve,
            "cwe": cwe,
        }
        key = item["ip"] + ":" + item["port"]
        if key not in items:
            items[key] = []
        items[key].append(item)

# We could not recognize the file format.
else:
    raise Exception("Unsupported output type")

# Parse the client simulations file.
# If we fail to do this, simply ignore the client simulations in the resulting output.
# We will output a warning to the logs, however.
try:
    client_simulation_names = {}
    cs_txt = os.path.join(os.path.dirname(__file__), "client-simulation.txt")
    with open(cs_txt, "r") as fd:
        for line in fd:
            line = line.strip()
            if line.startswith("names+="):
                value = line[9:-2]
            elif line.startswith("short+="):
                key = line[9:-2]
                client_simulation_names[key] = value
except Exception:
    client_simulation_names = None
    traceback.print_exc()

# Additional reference links per vulnerability.
additional_references = {
    "GREASE": ["https://www.ietf.org/archive/id/draft-ietf-tls-grease-01.txt"],
    "OSCP_stapling": ["https://www.rfc-editor.org/rfc/rfc6066#section-8"],
    "DNS_CAArecord": ["https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization",
                      "https://docs.digicert.com/en/certcentral/manage-certificates/dns-caa-resource-record-check.html"],
    "cipherlist_3DES_IDEA": ["https://en.wikipedia.org/wiki/Triple_DES"],
    "cipherlist_EXPORT": ["https://www.virtuesecurity.com/kb/export-ciphers-enabled"],
    "cipher_order": ["https://crashtest-security.com/configure-ssl-cipher-order/"],
    "FS": ["https://en.wikipedia.org/wiki/Forward_secrecy"],
    "TLS_session_ticket": ["https://en.wikipedia.org/wiki/Forward_secrecy"],
    "pwnedkeys": ["https://pwnedkeys.com"],
    "heartbleed": ["https://heartbleed.com/"],
    "ticketbleed": ["https://filippo.io/Ticketbleed/"],
    "ROBOT": ["https://robotattack.org/"],
    "secure_client_renego": ["https://myakamai.force.com/customers/s/article/How-to-test-Client-TLS-Renegotiation",
                             "https://www.kali.org/tools/thc-ssl-dos/"],
    "CRIME_TLS": ["https://en.wikipedia.org/wiki/CRIME"],
    "BEAST": ["https://www.acunetix.com/blog/web-security-zone/what-is-beast-attack/",
              "https://web.archive.org/web/20140603102506/https://bug665814.bugzilla.mozilla.org/attachment.cgi?id=540839"],
    "POODLE": ["https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/"],
    "SWEET32": ["https://sweet32.info/"],
    "FREAK": ["https://www.cisa.gov/news-events/alerts/2015/03/06/freak-ssltls-vulnerability"],
    "DROWN": ["https://drownattack.com/drown-attack-paper.pdf",
              "https://censys.io/ipv4?q=5EF2F214260AB8F58E55EEA42E4AC04B0F171807D8D1185FDDD67470E9AB6096"],
    "LOGJAM": ["https://weakdh.org/"],
    "LUCKY13": ["https://web.archive.org/web/20200324101422/http://www.isg.rhul.ac.uk/tls/Lucky13.html",
                "https://en.wikipedia.org/wiki/Lucky_Thirteen_attack"],
    "RC4": ["https://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html"],
}

# Additional taxonomy tags per vulnerability.
additional_taxonomies = {
    "OSCP_stapling": ["RFC 6066"],
    "SSLv2": ["RFC 6176"],
    "SSLv3": ["RFC 7568"],
    "TLS1": ["RFC 8996"],
    "TLS1_1": ["RFC 8996"],
    "HTST": ["RFC 6797"],
    "RC4": ["RFC 7465"],
    "winshock": ["MS14-066"],
}

# These lists will be populated when parsing below.
affects = []
references = []
taxonomy = []
hosts = []

# The final severity will be the highest one found.
severity = 0

# Severity rating names in testssl.
ratings = ("LOW", "MEDIUM", "HIGH", "CRITICAL")     # must be only low and above

# This is the object containing all vulnerabilities for this host.
# Since testssl.sh detects a ton of vulnerabilities, but they're all intrinsically connected to SSL,
# it makes more sense to report them all as a single issue and put all the details together.
issue = {
    "tools": ["testssl"],
    "template": "multiple_ssl_issues",
}

# Parse the testssl.sh results and generate an issue object.
# The same issue will try to merge all of the affected hosts.
for key, results in items.items():
    affects.append(key)

    # Parse the testssl.sh data.
    # We're going to treat the vulnerable ciphers, client simulations and grade rating as special cases.
    # Everything else gets treated in a pretty generic manner.
    bad_ciphers = []
    grade = None
    grade_cap = []
    client_sims = []
    rating_spec = None
    problems = {}
    cipher_order = {}
    for item in results:

        # We'll use the testssl.sh ID as additional properties we can look up later from the templates.
        # This should work nicely since we know for a fact they cannot collide.
        id = item["id"]

        # Use the highest rating as the overall rating of the issue.
        # Evaluating this here at the top ensures we always pick up
        # all of the severity values, even if we don't have a specific
        # paragraph in the issue details later on.
        if item["severity"] in ratings:
            sev = ratings.index(item["severity"])
            if sev > severity:
                severity = sev

        # Collect the grade rating data always, regardless of the severity.
        if id == "overall_grade":
            grade = item["finding"]
            continue
        if id.startswith("grade_cap_reason_"):
            grade_cap.append(item["finding"])
            continue
        if id == "rating_spec":
            rating_spec = item["finding"]
            continue

        # Collect the client simulations data, regardless of the severity.
        if id.startswith("clientsimulation-"):
            csim_name = id[17:]
            if client_simulation_names is not None:
                csim_name = client_simulation_names.get(csim_name, csim_name)
            if item["finding"] == "No connection":
                csim = {
                    "client": csim_name,
                    "cipher": "",
                    "version": "",
                    "status": "no-connection",
                }
            else:
                version, cipher = item["finding"].split(" ")
                if version in cipher_order and cipher == cipher_order[version][0]:
                    status = "preferred"
                else:
                    status = "available"
                csim = {
                    "client": csim_name,
                    "cipher": cipher,
                    "version": version,
                    "status": status,
                }
            client_sims.append(csim)
            continue

        # Get the cipher order, regardless of the severity.
        # Sadly the cipher order is AFTER the ciphers, which sucks
        # because this would be a hell of a lot easier to parse.
        # Honestly, sslscan is SO much more sensible with its output...
        # ...too bad its outpput is vastly inferior to testssl :D
        if id.startswith("cipherorder_") or id.startswith("cipher_order_"):
            if id.startswith("cipherorder_"):
                k = id[12:]
            else:
                k = id[13:]
            k = k.replace("_", ".")
            if k == "TLSv1":
                k = "TLSv1.0"
            cipher_order[k] = [x.strip() for x in item["finding"].split(" ")]
            for obj in bad_ciphers:
                if obj["version"] == k and obj["cipher"] == cipher_order[k][0]:
                    obj["status"] = "preferred"
            for obj in client_sims:
                if obj["version"] == k and obj["cipher"] == cipher_order[k][0]:
                    obj["status"] = "preferred"
            continue

        # For every other item, ignore if not a vulnerability.
        if item["severity"] not in ratings:
            continue

        # Skip some redundant items.
        if id.startswith("BEAST_") or id.startswith("cert_notAfter"):
            continue

        # Add CVE and CWE IDs.
        cve = item.get("cve", "")
        if cve:
            taxonomy.extend(cve.split(" "))
        cwe = item.get("cwe", "")
        if cwe:
            taxonomy.extend(cwe.split(" "))

        # Add any additional reference links if we have any for this vulnerability.
        if id in additional_references:
            references.extend(additional_references[id])

        # Add any additional taxonomy tags if we have any for this vulnerability.
        if id in additional_taxonomies:
            taxonomy.extend(additional_taxonomies[id])

        # Collect vulnerable ciphers.
        if id.startswith("cipher-"):
            txt = item["finding"]
            row = [x.strip() for x in txt.split(" ") if x]
            row = [x for x in row if x]
            if row[0] == "TLSv1":
                row[0] = "TLSv1.0"
                txt = "TLSv1.0" + txt[5:]
            if row[3] == "RSA":
                row.insert(4, 256)
            obj = {
                #"text": txt,
                "version": row[0],
                "cipher": row[2],
                "openssl_id": row[1],
                "cipher_bits": int(row[4]),
                "hash_bits": int(row[6]),
                "severity": item["severity"].lower(),
            }
            if row[0] in cipher_order and row[2] == cipher_order[row[0]][0]:
                obj["status"] = "preferred"
            else:
                obj["status"] = "available"
            bad_ciphers.append(obj)
            continue

        # For every other finding we just copy the data we need.
        # The assumption here is for every testssl.sh ID we have a matching i18n template.
        # Possibly some of this data won't be used by the templates, but actually checking
        # is a bit more work than I feel is needed right now. Definitely doable though.

        # Some IDs will contain suffixes if, for example, there is more than one certificate.
        # Since parsing that is too complicated we will just append everything to a single ID.
        if " " in id:
            tag = id.split(" ", 1)[0]
        else:
            tag = id

        # Add the findings as additional properties the paragraph template can access.
        if "finding" in item and item["finding"]:
            if tag in problems:
                problems[tag] += " " + item["finding"]
            else:
                problems[tag] = item["finding"]

    # If the issue is empty, this means testssl.sh did not find anything to report on this host.
    # Usually this happens when there was an error during the scan. ;)
    if not (bad_ciphers or problems): # or client_sims or grade):
        continue

    # Create the host details object.
    host = {
        "host": key,
    }
    if bad_ciphers:
        host["bad_ciphers"] = bad_ciphers
    if problems:
        host["problems"] = problems
    if client_sims:
        host["clientsimulations"] = client_sims
    if grade:
        host["grade"] = grade
        host["grade_cap"] = grade_cap
        references.append("https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide")
    if rating_spec:
        host["rating_spec"] = rating_spec

    # Add the host to the list.
    hosts.append(host)

output_data = []

# If we have vulnerable hosts...
if hosts:

    # Sort the CVE, CWE and reference links alphabetically and remove duplicates.
    taxonomy = sorted(set(taxonomy))
    references = sorted(set(references))

    # Add the collected data to the issue.
    issue["severity"] = ("low", "medium", "high", "critical")[severity]
    assert affects, issue
    issue["affects"] = affects
    if taxonomy:
        issue["taxonomy"] = taxonomy
    if references:
        issue["references"] = references
    issue["hosts"] = hosts

    # Output the issue.
    output_data.append(issue)

# Send the object array back to the caller.
json.dump(output_data, sys.stdout)
