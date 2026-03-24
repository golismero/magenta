#!/usr/bin/python3

import sys
import json
import urllib.parse

# TODO: the unhandled errors one may be best handled as a generic unhandled error vuln instead,
#       trouble is out schema wants HTTP traffic rather than a curl command

# TODO: reorganize everything to have three lists, one per consequence, so that way the report
#       can focus on that instead of repeating over and over what the consequences are

CAUSES = {
    "Alias Overloading": "alias_overloading",
    "Array-based Query Batching": "batch_queries",
    "GET Method Query Support": "get_based_queries",
    "POST based url-encoded query (possible CSRF)": "post_based_queries",
    "Trace Mode": "trace",
    "Field Duplication": "field_duplication",
    "Field Suggestions": "field_suggestions",
    "GraphQL IDE": "ide",
    "Introspection": "introspection",
    "Directive Overloading": "directives_overloading",
    "Introspection-based Circular Query": "circular_query",
    "Mutation is allowed over GET (possible CSRF)": "mutation_over_get",
    "Unhandled Errors Detection": "unhandled_errors",
}
CONSEQUENCES = {
    "Alias Overloading": "dos",
    "Array-based Query Batching": "dos",
    "GET Method Query Support": "csrf",
    "POST based url-encoded query (possible CSRF)": "csrf",
    "Trace Mode": "infoleak",
    "Field Duplication": "dos",
    "Field Suggestions": "infoleak",
    "GraphQL IDE": "infoleak",
    "Introspection": "infoleak",
    "Directive Overloading": "dos",
    "Introspection-based Circular Query": "dos",
    "Mutation is allowed over GET (possible CSRF)": "csrf",
    "Unhandled Errors Detection": "infoleak",
}
REFERENCES = {
    "Alias Overloading": [
        "https://www.acunetix.com/vulnerabilities/web/graphql-alias-overloading-allowed-potential-denial-of-service-vulnerability/",
        "https://checkmarx.com/blog/alias-and-directive-overloading-in-graphql/",
    ],
    "Array-based Query Batching": [],
    "GET Method Query Support": [],
    "POST based url-encoded query (possible CSRF)": [],
    "Trace Mode": [],
    "Field Duplication": [],
    "Field Suggestions": [],
    "GraphQL IDE": [],
    "Introspection": [
        "https://portswigger.net/kb/issues/00200512_graphql-introspection-enabled",
        "https://www.acunetix.com/vulnerabilities/web/graphql-introspection-query-enabled/",
        "https://www.tenable.com/plugins/was/112894",
    ],
    "Directive Overloading": [
        "https://checkmarx.com/blog/alias-and-directive-overloading-in-graphql/",
    ],
    "Introspection-based Circular Query": [
        "https://www.acunetix.com/vulnerabilities/web/graphql-circular-query-via-introspection-allowed-potential-dos-vulnerability/"
    ],
    "Mutation is allowed over GET (possible CSRF)": [],
    "Unhandled Errors Detection": [],
}


def main():
    # The output file is expected to be a JSON array.
    # However, the tool seems to mix its console messages with the JSON output,
    # so the trick here is to read the file line by line, testing until we get
    # an actual JSON array, ignoring everything else.
    input_array = []
    for line in sys.stdin:
        if line.startswith('[{"'):
            input_array = json.loads(line)
    if not input_array:
        sys.stderr.write(
            "WARNING: No vulnerabilities found in input file. Are you sure this is the right file?\n"
        )
        sys.stdout.write("[]")
        return

    # Each object in the input array is expected to have this format:
    #
    # {
    #     "result": true,
    #     "title": "Alias Overloading",
    #     "description": "Alias Overloading with 100+ aliases is allowed",
    #     "impact": "Denial of Service - /graphql",
    #     "severity": "HIGH",
    #     "color": "red",
    #     "curl_verify": "curl -X POST -H \"User-Agent: graphql-cop/1.13\" -H \"Accept-Encoding: gzip, deflate\" -H \"Accept: */*\" -H \"Connection: keep-alive\" -H \"Content-Length: 2163\" -H \"Content-Type: application/json\" -d '{\"query\": \"query cop { alias0:__typename \\nalias1:__typename \\nalias2:__typename \\nalias3:__typename \\nalias4:__typename \\nalias5:__typename \\nalias6:__typename \\nalias7:__typename \\nalias8:__typename \\nalias9:__typename \\nalias10:__typename \\nalias11:__typename \\nalias12:__typename \\nalias13:__typename \\nalias14:__typename \\nalias15:__typename \\nalias16:__typename \\nalias17:__typename \\nalias18:__typename \\nalias19:__typename \\nalias20:__typename \\nalias21:__typename \\nalias22:__typename \\nalias23:__typename \\nalias24:__typename \\nalias25:__typename \\nalias26:__typename \\nalias27:__typename \\nalias28:__typename \\nalias29:__typename \\nalias30:__typename \\nalias31:__typename \\nalias32:__typename \\nalias33:__typename \\nalias34:__typename \\nalias35:__typename \\nalias36:__typename \\nalias37:__typename \\nalias38:__typename \\nalias39:__typename \\nalias40:__typename \\nalias41:__typename \\nalias42:__typename \\nalias43:__typename \\nalias44:__typename \\nalias45:__typename \\nalias46:__typename \\nalias47:__typename \\nalias48:__typename \\nalias49:__typename \\nalias50:__typename \\nalias51:__typename \\nalias52:__typename \\nalias53:__typename \\nalias54:__typename \\nalias55:__typename \\nalias56:__typename \\nalias57:__typename \\nalias58:__typename \\nalias59:__typename \\nalias60:__typename \\nalias61:__typename \\nalias62:__typename \\nalias63:__typename \\nalias64:__typename \\nalias65:__typename \\nalias66:__typename \\nalias67:__typename \\nalias68:__typename \\nalias69:__typename \\nalias70:__typename \\nalias71:__typename \\nalias72:__typename \\nalias73:__typename \\nalias74:__typename \\nalias75:__typename \\nalias76:__typename \\nalias77:__typename \\nalias78:__typename \\nalias79:__typename \\nalias80:__typename \\nalias81:__typename \\nalias82:__typename \\nalias83:__typename \\nalias84:__typename \\nalias85:__typename \\nalias86:__typename \\nalias87:__typename \\nalias88:__typename \\nalias89:__typename \\nalias90:__typename \\nalias91:__typename \\nalias92:__typename \\nalias93:__typename \\nalias94:__typename \\nalias95:__typename \\nalias96:__typename \\nalias97:__typename \\nalias98:__typename \\nalias99:__typename \\nalias100:__typename \\n }\", \"operationName\": \"cop\"}' 'https://rickandmortyapi.com/graphql'"
    # }
    #
    issues = []
    THEIR_SEVERITIES = ("info", "low", "medium", "high")
    OUR_SEVERITIES = ("none", "low", "medium", "high", "critical")
    max_severity = 0
    affects = []
    references = []
    for vuln in input_array:
        # print(json.dumps(vuln))
        # print()

        # Ignore tests that were carried out but resulted in no vulnerability.
        if not vuln["result"]:
            continue

        # The title gives us the templates we need to use to report this.
        title = vuln["title"]
        cause = CAUSES[title]
        consequence = CONSEQUENCES[title]
        references.extend(REFERENCES[title])

        # The severity is very straightforward to get.
        severity_num = THEIR_SEVERITIES.index(vuln["severity"].lower())
        if severity_num > max_severity:
            max_severity = severity_num
        severity = OUR_SEVERITIES[severity_num]

        # We can extract the vulnerable endpoint from the curl command.
        curl_verify = vuln["curl_verify"]
        url = curl_verify.split(" ")[-1]
        if url.startswith("'") and url.endswith("'"):
            url = url[1:-1]
        try:
            urllib.parse.urlparse(url)
        except Exception:
            raise AssertionError("Malformed URL: '%s'" % url)
        affects.append(url)

        # Add the issue data to the list.
        issues.append(
            {
                "cause": cause,
                "consequence": consequence,
                "severity": severity,
                "url": url,
                "command": curl_verify,
            }
        )

    # Warn if no issues were found.
    if not issues:
        sys.stderr.write(
            "WARNING: No vulnerabilities found in input file. Are you sure this is the right file?\n"
        )
        sys.stdout.write("[]")
        return

    # Create a Magenta vulnerablity object.
    output = {
        "template": "multiple_graphql_vulnerabilities",
        "tools": ["graphqlcop"],
        "severity": OUR_SEVERITIES[max_severity],
        "affects": sorted(set(affects)),
        "issues": issues,
    }
    if references:
        output["references"] = sorted(set(references))

    # Convert the output array to JSON and send it over stdout.
    json.dump([output], sys.stdout)


if __name__ == "__main__":
    main()
