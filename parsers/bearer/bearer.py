#!/usr/bin/python3

import codecs
import csv
import json
import io
import re
import sys

import yaml

def parse_raw_input(raw_input):
    if raw_input.startswith("{"):
        return parse_json_input(raw_input)
    if raw_input.startswith("<!DOCTYPE html>"):
        return parse_html_input(raw_input)
    return parse_yaml_input(raw_input)

def parse_yaml_input(raw_input):
    return yaml.safe_load(raw_input)

def parse_json_input(raw_input):
    json_input = json.loads(raw_input)
    if "$schema" in json_input:
        if json_input["$schema"].endswith("/sarif-2.1.0.json"):
            raise NotImplementedError("SARIF format not yet supported")
        elif json_input["$schema"].endswith("/sast-report-format.json"):
            raise NotImplementedError("SAST format not yet supported")
    elif "findings" in json_input:  # v2
        converted = {}
        for obj in json_input["findings"]:
            severity = obj["severity"]
            if severity not in converted:
                converted[severity] = []
            converted[severity].append(obj)
        json_input = converted
    elif "diagnostics" in json_input:   # rdjson
        raise NotImplementedError("RDJSON format not yet supported")
    return json_input

def parse_html_input(raw_input):
    raise NotImplementedError("HTML format not yet supported")

# XXX TODO try to add the source and sink as trace.
# I'm not 100% sure how to interpret the data from the files right now,
# as it seems to include only the lines and not the file or contents...
def main():
    raw_input = sys.stdin.read()
    json_input = parse_raw_input(raw_input)
    json_output = []

    for severity, array in json_input.items():
        for obj in array:
            if "rule" in obj:
                rule = obj["rule"]
            else:
                rule = obj
            template_name = rule["id"]
            if "cwe_ids" in rule:
                taxonomy = ["CWE-%s" % cwe_id for cwe_id in rule["cwe_ids"]]
            else:
                taxonomy = []
            if "documentation_url" in rule:
                references = [rule["documentation_url"]]
            else:
                references = []
            if "filename" in obj:
                filename = obj["filename"]
            else:
                filename = obj["full_filename"]
            line = obj["line_number"]
            if "code_extract" in obj:
                code = obj["code_extract"]
            else:
                code = None
            try:
                start = obj["sink"]["location"]["column"]["start"]
                end = obj["sink"]["location"]["column"]["end"]
            except Exception:
                start = None
                end = None
            if code is not None and start is not None and end is not None:
                trace = [{
                    "file": filename,
                    "language": template_name[:template_name.find("_")],
                    "source": [{
                        "line": line,
                        "text": code,
                    }],
                    "highlight": {
                        "line": line,
                        "start": start,
                        "end": end,
                    },
                }]
            else:
                trace = None
            issue = {
                "template": template_name,
                "tools": ["bearer"],
                "severity": severity.lower(),
                "affects": ["%s:%s" % (filename, line)],
                "code": [{
                    "file": filename,
                    "line": line,
                }],
            }
            if trace:
                issue["code"][0]["trace"] = trace
            if taxonomy:
                issue["taxonomy"] = taxonomy
            if references:
                issue["references"] = references
            json_output.append(issue)

    json.dump(json_output, sys.stdout)

if __name__ == "__main__":
    main()
