#!/usr/bin/python3

import re
import sys
import json

# This is the crude text output format that most people will probably use.
# It's posible to trick the parser by having a password be "password:",
# but I don't really care. Next I should implement the -b format anyway.
"""
# Hydra v9.2 run at 2023-06-30 10:33:37 on localhost ftp (hydra -l username -p password -o private/test.hydra ftp://localhost)
[21][ftp] host: localhost   login: username   password: password
"""
re_start = re.compile(
    r"^# Hydra v[0-9]+\.[0-9]+ run at ([^ ]+ [^ ]+) on ([^ ]+) ([^ ]+) \(([^\)]+)\)$"
)
re_result = re.compile(
    r"^\[([0-9]+)\]\[([^\]]+)\] host: ([^ ]+) +login: ([^ ]+) +password: (.+)$"
)
fmt_timestamp = "%Y-%m-%d %H:%M:%S"


# Importer function for text files.
def import_hydra_textfile(fd):
    did_warn_1 = False
    did_warn_2 = False
    did_warn_3 = False
    output = []
    current = None
    credentials = set()
    seen = set()
    for line in fd:
        line = line.strip()

        # Start of a new scan.
        m = re_start.match(line)
        if m:
            if current is not None and credentials:
                _finish_issue(current, credentials)
                output.append(current)
            current = {
                "template": "weak_credentials_discovered_via_bruteforce_attack",
                "tools": ["hydra"],
            }
            credentials = set()
            continue

        # Result of a scan.
        m = re_result.match(line)
        if m:
            if line.count("password: ") != 1 and not did_warn_2:
                sys.stderr.write(
                    "WARNING: parser found line(s) it could not parse, results may be missing or wrong\n"
                )
                did_warn_2 = True
            port, service, hostname, login, password = m.groups()
            t = (hostname, port, service, login, password)
            if t in seen:
                if not did_warn_3:
                    sys.stderr.write(
                        "WARNING: parser found duplicated entries, results may be missing or wrong\n"
                    )
                    did_warn_3 = True
                continue
            seen.add(t)
            credentials.add(t)
            continue

        # Error while parsing.
        if not did_warn_1:
            sys.stderr.write(
                "WARNING: parser found line(s) it could not parse, results may be missing or wrong\n"
            )
            did_warn_1 = True

    # Return the output array.
    if current is not None and current not in output and credentials:
        _finish_issue(current, credentials)
        output.append(current)
    return output


# Helper function.
def _finish_issue(current, credentials):
    affects = set()
    current["credentials"] = []
    for hostname, port, service, login, password in sorted(credentials):
        affects.add("%s:%s (%s)" % (hostname, port, service))
        cred = {
            "host": hostname,
            "port": port,
            "service": service,
            "login": login,
            "password": password,
        }
        current["credentials"].append(cred)
    current["severity"] = "critical"
    current["affects"] = sorted(affects)


# Entry point.
if __name__ == "__main__":
    # Parse the input from stdin and generate an output array.
    output = import_hydra_textfile(sys.stdin)

    # Convert the output array to JSON and send it over stdout.
    json.dump(output, sys.stdout)
