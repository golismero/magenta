#!/usr/bin/python3

import codecs
import csv
import json
import io
import re
import sys

import yaml

from bs4 import BeautifulSoup
from lxml import etree

# Parse the input data in all supported formats.
def parse_raw_input(raw_input):

    # The easiest format is JSON. We will convert all of the other formats to JSON internally.
    if raw_input.startswith("{"):
        json_input = json.loads(raw_input)["results"]
    else:

        # The YAML format will give us basically the same stuff.
        # HOWEVER, the YAML parser will not understand \n and other \ escapes.
        # That means we have to painstakingly fix those instances.
        if "generated_at:" in raw_input:
            json_input = parse_bandit_yml(raw_input)
        else:

            # Ok, XML should be a bit more complicated. But not by much.
            # Let's move the code out of here though, cause it's kinda long.
            if raw_input.startswith("<?xml version='1.0' encoding='utf-8'?>"):
                json_input = parse_bandit_xml(raw_input.encode("utf-8"))
            else:

                # HTML should be kinda similar to XML.
                if raw_input.strip().startswith("<!DOCTYPE html>"):
                    json_input = parse_bandit_html(raw_input)
                else:

                    # CSV should at least be very easy to parse.
                    if raw_input.startswith(
                        "filename,test_name,test_id,issue_severity,"
                        "issue_confidence,issue_cwe,issue_text,"
                        "line_number,col_offset,end_col_offset,"
                        "line_range,more_info"
                    ):
                        json_input = parse_bandit_csv(raw_input)
                    else:

                        # Last chance or bust, this must be a text file.
                        if raw_input.startswith("Run started:"):
                            json_input = parse_bandit_txt(raw_input)
                        else:

                            # We don't know what type of file this is...
                            assert False, "Malformed file, or file format version is incompatible"

    # If everything went alright, we have enough data now to process.
    return json_input

# This should be easy to parse. Sadly it does not contain the source code snippets.
def parse_bandit_csv(raw_input):
    reader = csv.DictReader(io.StringIO(raw_input))
    results = []
    for row in reader:
        assert row["issue_cwe"].startswith("https://cwe.mitre.org/data/definitions/") and \
                row["issue_cwe"].endswith(".html"), \
                "Malformed file, or file format version is incompatible"
        assert row["line_range"].startswith("[") and row["line_range"].endswith("]"), \
                "Malformed file, or file format version is incompatible"
        obj = {k: v for k, v in row.items()}
        obj["issue_cwe"] = {
            "id": int(obj["issue_cwe"][39:-5]),
            "link": obj["issue_cwe"],
        }
        obj["line_number"] = int(obj["line_number"])
        obj["col_offset"] = int(obj["col_offset"])
        obj["end_col_offset"] = int(obj["end_col_offset"])
        obj["line_range"] = [int(x.strip()) for x in obj["line_range"][1:-1].split(",")]
        results.append(obj)
    return results

# We need to fix the bug in the YAML parser.
def parse_bandit_yml(raw_input):
    yaml_input = yaml.safe_load(raw_input)["results"]
    for item in yaml_input:
        item["code"] = decode_escapes(item["code"])
    return yaml_input

# https://stackoverflow.com/a/24519338/426293
ESCAPE_SEQUENCE_RE = re.compile(r'''
    ( \\U........      # 8-digit hex escapes
    | \\u....          # 4-digit hex escapes
    | \\x..            # 2-digit hex escapes
    | \\[0-7]{1,3}     # Octal escapes
    | \\N\{[^}]+\}     # Unicode characters by name
    | \\[\\'"abfnrtv]  # Single-character escapes
    )''', re.UNICODE | re.VERBOSE)
def decode_match(match):
    return codecs.decode(match.group(0), 'unicode-escape')
def decode_escapes(s):
    return ESCAPE_SEQUENCE_RE.sub(decode_match, s)

# Unfortunately the code samples are missing from XML files, and
# some of the stuff we have to parse as raw text for some reason.
def parse_bandit_xml(raw_input):
    root = etree.fromstring(raw_input)
    results = []
    for testcase in root.findall("./testcase"):
        filename = testcase.attrib["classname"]
        test_name = testcase.attrib["name"]
        error = testcase.find("./error")
        more_info = error.attrib["more_info"]
        issue_severity = error.attrib["type"]
        issue_text = error.attrib["message"]
        lines = error.text.split("\n")
        assert len(lines) == 4, "Malformed file, or file format version is incompatible"
        assert lines[0].startswith("Test ID: "), "Malformed file, or file format version is incompatible"
        assert ("Severity: " + issue_severity + " ") in lines[0], \
                "Malformed file, or file format version is incompatible"
        assert lines[1].startswith("CWE: CWE-"), "Malformed file, or file format version is incompatible"
        assert " (https://cwe.mitre.org" in lines[1], "Malformed file, or file format version is incompatible"
        assert lines[2] == issue_text, "Malformed file, or file format version is incompatible"
        assert lines[3].startswith("Location " + filename + ":"), \
                "Malformed file, or file format version is incompatible"
        test_id = lines[0][9:]
        test_id = test_id[:test_id.find(" ")]
        issue_confidence = lines[0][lines[0].find("Confidence: ")+12:]
        issue_cwe_id = lines[1][9:]
        issue_cwe_id = issue_cwe_id[:issue_cwe_id.find(" ")]
        issue_cwe_link = "https://cwe.mitre.org/data/definitions/" + issue_cwe_id + ".html"
        issue_cwe_id = int(issue_cwe_id)
        line_number = int(lines[3][lines[3].rfind(":")+1:])
        obj = {
            "filename": filename,
            "issue_confidence": issue_confidence,
            "issue_cwe": {
                "id": issue_cwe_id,
                "link": issue_cwe_link,
            },
            "issue_severity": issue_severity,
            "issue_text": issue_text,
            "line_number": line_number,
            "more_info": more_info,
            "test_id": test_id,
            "test_name": test_name,
        }
        results.append(obj)
    return results

# This will yield results similar to the XML format.
def parse_bandit_html(raw_input):
    soup = BeautifulSoup(raw_input, 'html.parser')
    results = []
    for div in soup.find_all("div"):
        css = div.get("class")
        if not css or "issue-block" not in css:
            continue
        children = [x.text.strip() for x in div.children if x.text.strip() and x.name != "br"]
        assert children[0].endswith(":"), "Malformed file, or file format version is incompatible"
        assert children[2] == "Test ID:", "Malformed file, or file format version is incompatible"
        assert children[4] == "Severity:", "Malformed file, or file format version is incompatible"
        assert children[6] == "Confidence:", "Malformed file, or file format version is incompatible"
        assert children[8] == "CWE:", "Malformed file, or file format version is incompatible"
        assert children[9].startswith("CWE-"), "Malformed file, or file format version is incompatible"
        assert children[10] == "File:", "Malformed file, or file format version is incompatible"
        assert children[12] == "Line number:", "Malformed file, or file format version is incompatible"
        assert children[14] == "More info:", "Malformed file, or file format version is incompatible"
        test_name = children[0][:-1].strip()
        issue_text = children[1]
        test_id = children[3]
        issue_severity = children[5]
        issue_confidence = children[7]
        issue_cwe_id = int(children[9][4:])
        issue_cwe_link = "https://cwe.mitre.org/data/definitions/" + str(issue_cwe_id) + ".html"
        filename = children[11]
        line_number = int(children[13])
        more_info = children[15]
        code = children[16]
        line_range = [
            int(x[:x.find("\t")]) if "\t" in x else int(x)
            for x in code.split("\n")
        ]
        obj = {
            "code": code,
            "filename": filename,
            "issue_confidence": issue_confidence,
            "issue_cwe": {
                "id": issue_cwe_id,
                "link": issue_cwe_link,
            },
            "issue_severity": issue_severity,
            "issue_text": issue_text,
            "line_number": line_number,
            "line_range": line_range,
            "more_info": more_info,
            "test_id": test_id,
            "test_name": test_name,
        }
        results.append(obj)
    return results

# This one is probably the flimsiet to parse...
# We're going with regex so it stands a better chance of future compatibility.
re_issue = re.compile(r"Issue: \[([^:]+):([^\]]+)\] ([^\n]+)\n")
re_severity = re.compile(r"Severity: ([^ \n]+)")
re_confidence = re.compile(r"Confidence: ([^ \n]+)")
re_cwe = re.compile(r"CWE: CWE-([0-9]+) \(([^\)]+)\)")
re_more_info = re.compile(r"More Info: ([^\n]+)\n")
re_location = re.compile(r"Location: ([^\n]+)\n")
re_code_line = re.compile(r"^([0-9]+)[ \t]?(.*)")
def parse_bandit_txt(raw_input):
    assert ">> " in raw_input, "Malformed file, or file format version is incompatible"
    results = []
    for issue in raw_input.split(">> ")[1:]:
        assert "\n\n--------------------------------------------------" in issue.strip(), \
                "Malformed file, or file format version is incompatible"
        issue = issue[:issue.find("\n\n--------------------------------------------------")]
        test_id, test_name, issue_text = re_issue.search(issue).group(1,2,3)
        issue_severity = re_severity.search(issue).group(1).upper()
        issue_confidence = re_confidence.search(issue).group(1).upper()
        issue_cwe_id, issue_cwe_link = re_cwe.search(issue).group(1,2)
        more_info = re_more_info.search(issue).group(1)
        location = re_location.search(issue).group(1)
        col_offset = int(location[location.rfind(":")+1:])
        location = location[:location.rfind(":")]
        line_number = int(location[location.rfind(":")+1:])
        filename = location[:location.rfind(":")]
        codelines = issue.split("\n")[5:]
        code = ""
        line_range = []
        for code_line in codelines:
            if not code_line: continue
            m = re_code_line.search(code_line)
            assert m is not None, "Malformed file, or file format version is incompatible"
            line_range.append(int(m.group(1)))
            code += code_line + "\n"
        obj = {
            "code": code,
            "col_offset": col_offset,
            "filename": filename,
            "issue_confidence": issue_confidence,
            "issue_cwe": {
                "id": issue_cwe_id,
                "link": issue_cwe_link,
            },
            "issue_severity": issue_severity,
            "issue_text": issue_text,
            "line_number": line_number,
            "line_range": line_range,
            "more_info": more_info,
            "test_id": test_id,
            "test_name": test_name,
        }
        results.append(obj)
    return results

# Each Bandit issue is matched up with one of our templates here.
TEMPLATES = {

    # Blacklist issues. Defined by the tool's core.
    #"B001": "blacklisted_function_in_use",
    #"B301": "python_pickle",                               # maybe all the deserialization ones can be grouped
    #"B302": "python_marshal",
    "B303": "insecure_hash_function_used",
    "B304": "insecure_cryptographic_algorithm_used",
    "B305": "insecure_cryptographic_algorithm_used",
    "B306": "insecure_temporary_file",
    #"B307": "python_eval",
    #"B308": "potential_sql_injection_django_mark_safe",    # confusing naming I know
    #"B309": "python_httpsconnection",
    #"B310": "python_urllib_urlopen",
    #"B311": "insecure_random_function_used",
    #"B312": "connections_using_cleartext_protocol",
    #"B313": "python_xml",
    #"B314": "python_xml",
    #"B315": "python_xml",
    #"B316": "python_xml",
    #"B317": "python_xml",
    #"B318": "python_xml",
    #"B319": "python_xml",
    #"B320": "python_xml",
    #"B321": "connections_using_cleartext_protocol",
    #"B322": "python_input",
    "B323": "no_certificate_validation",
    "B325": "insecure_temporary_file",
    #"B401": "connections_using_cleartext_protocol",
    #"B402": "connections_using_cleartext_protocol",
    #"B403": "python_pickle",
    #"B404": "python_subprocess",
    #"B405": "python_xml",
    #"B406": "python_xml",
    #"B407": "python_xml",
    #"B408": "python_xml",
    #"B409": "python_xml",
    #"B410": "python_xml",
    #"B411": "python_xml",
    #"B412": "python_deprecated_library",
    #"B413": "python_deprecated_library",
    #"B414": "python_deprecated_library",
    #"B415": "python_deprecated_library",

    # Plugin issues. Find the definitions here:
    # https://github.com/PyCQA/bandit/tree/main/bandit/plugins
    "B201": "flask_debug",
    "B101": "python_assert",
    "B501": "no_certificate_validation",
    "B610": "potential_sql_injection_django_extra",
    "B611": "potential_sql_injection_django_rawsql",
    "B703": "potential_sql_injection_django_mask_safe",
    "B102": "python_exec",
    "B103": "chmod_insecure_file_permissions",
    "B104": "bind_to_all_interfaces",
    "B105": "potential_hardcoded_password",
    "B108": "insecure_temporary_file",
    "B324": "insecure_hash_function_used",
    "B601": "paramiko_shell_injection",
    "B602": "python_potential_shell_injection",
    "B603": None,
    "B604": "python_potential_shell_injection",
    "B605": "python_potential_shell_injection",
    "B606": None,
    "B607": "process_launch_with_partial_path",
    "B608": "potential_sql_injection_in_code",
    "B609": "wildcard_injection",
    "B502": "insecure_tls_version_used",
    "B701": "jinja2_autoescaping_disabled",
    "B612": "insecure_python_logging_listen",
    "B702": "python_mako",
    "B113": "missing_python_requests_timeout",
    "B508": "insecure_version_of_smtp",
    "B507": "missing_ssh_host_key_validation",
    "B202": "python_tarfile_extractall",
    "B112": "python_continue_in_except_block",
    "B110": "python_pass_in_except_block",
    "B505": "insecure_cryptographic_algorithm_used",
    "B506": "python_yaml_load",
}

# We're going to parse any file and produce a JSON input,
# then go through it to try and build Magenta issues.
# We won't always have all of the information since not
# all file formats supported by Bandit contain it all.
# This will be a bit messy...
def main():
    raw_input = sys.stdin.read()
    json_input = parse_raw_input(raw_input)
    json_output = []

    # XXX DEBUG
    """
    import copy
    json_input = [copy.deepcopy(json_input[0]) for _ in range(len(TEMPLATES))]
    current_templates = sorted(TEMPLATES.keys())
    for index in range(len(json_input)):
        json_input[index]["test_id"] = current_templates[index]
    """

    for bandit_issue in json_input:
        if bandit_issue["test_id"] not in TEMPLATES:
            sys.stderr.write("Warning, unknown issue code found: '%s'.\n" % bandit_issue["test_id"])
        elif TEMPLATES[bandit_issue["test_id"]] is None:
            sys.stderr.write("Skipped known false positive: '%s'\n" % bandit_issue["test_id"])
            continue
        code = {
            "file": bandit_issue["filename"],
            "line": bandit_issue["line_number"],
        }
        if "code" in bandit_issue:
            source = []
            for codeline in bandit_issue["code"].split("\n"):
                if not codeline: continue
                m = re_code_line.match(codeline)
                assert m is not None, "Malformed file, or file format version is incompatible"
                line = int(m.group(1))
                text = m.group(2)
                if not text: continue
                source.append({
                    "line": line,
                    "text": text,
                })
            #
            # XXX TODO find the minimum indent level and shrink it,
            #          but be careful with the highlight offsets
            #
            traceitem = {
                "file": bandit_issue["filename"],
                "source": source,
                "language": "python",
            }
            if "col_offset" in bandit_issue and "end_col_offset" in bandit_issue:
                traceitem["highlight"] = {
                    "line": bandit_issue["line_number"],
                    "start": bandit_issue["col_offset"],
                    "end": bandit_issue["end_col_offset"],
                }
            code["trace"] = [traceitem]
        issue = {
            "template": TEMPLATES.get(bandit_issue["test_id"], "generic_source_code_issue"),
            "tools": ["bandit"],
            "severity": bandit_issue["issue_severity"].lower(),
            "affects": [bandit_issue["filename"] + ":" + str(bandit_issue["line_number"])],
            "taxonomy": ["CWE-" + str(bandit_issue["issue_cwe"]["id"])],
            "references": [bandit_issue["more_info"]],
            "code": [code],
            "bandit": [bandit_issue["test_id"]],
        }
        json_output.append(issue)
    json.dump(json_output, sys.stdout)

if __name__ == "__main__":
    main()
