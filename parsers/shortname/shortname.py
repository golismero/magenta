#!/usr/bin/python3

import json
import sys

DEBUG = False
# DEBUG = True   # Uncomment to debug.


# Entry point.
def main():
    # We're going to preserve some of the input file for the description of the issue.
    output = []

    # Read the file line by line until we find the line where the results start.
    # Everything else before that can be ignored.
    found = False
    for line in sys.stdin:
        if DEBUG:
            sys.stderr.write("DEBUG: %s" % line)
        if line.startswith("#"):
            output.append(line)
            found = True
            break
    assert found, "ERROR: Could not find IIS Short Name Scanner results in input file!"

    # The next line should be the target.
    line = sys.stdin.readline()
    if DEBUG:
        sys.stderr.write("DEBUG: %s" % line)
    assert line.startswith("Target: "), "ERROR: Failed to parse input file"
    output.append(line)
    target = line[8:]

    # The next line should be the result of the scan.
    # Ignore the entire output if the result is negative.
    line = sys.stdin.readline()
    if DEBUG:
        sys.stderr.write("DEBUG: %s" % line)
    assert line.startswith("|_ Result: "), "ERROR: Failed to parse input file"
    if not line[11:].startswith("Vulnerable!"):
        sys.stderr.write(
            "Ignoring input file due to the target not being vulnerable.\n"
        )
        sys.stdout.write("[]")
        return
    output.append(line)

    # We'll add the rest of the output to the description as-is.
    # We don't really need to parse a lot more here, unless in a future
    # version we really want to flesh out the text in the description
    # by extracting the exact HTTP verb and URI used or something like that.
    for line in sys.stdin:
        if not line:
            break
        if DEBUG:
            sys.stderr.write("DEBUG: %s" % line)
        output.append(line)

    # Create a Magenta vulnerability object and send it over stdout.
    issue = {
        "template": "iis_short_name_8_3_disclosure",
        "tools": ["shortname"],
        "severity": "low",
        "affects": [target],
        "findings": [
            {
                "target": target,
                "output": "".join(output),
            },
        ],
    }
    json.dump([issue], sys.stdout)


if __name__ == "__main__":
    main()
