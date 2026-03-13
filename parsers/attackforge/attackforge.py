#!/usr/bin/python3

import csv
import json
import sys

def main():
    results = []
    reader = csv.DictReader(sys.stdin)
    for row in reader:
        if row["Status"] != "Open":
            continue
        description = row["Description"]
        if description.startswith("<p>"):
            summary = description[3:description.find("</p>")]
        elif "\n" in description:
            summary = description.split("\n", 1)[0]
        elif "<br>" in description:
            summary = description.split("<br>", 1)[0]
        else:
            summary = description
        if row["Attack Scenario"]:
            description = description.strip() + "\n\n" + row["Attack Scenario"].strip()
        affects = row["Affected Asset Name"].strip()
        if row["Affected Asset Id"]:
            affects += " [%s]" % row["Affected Asset Id"].strip()
        if row["Affected Asset Library Id"]:
            affects += " [%s]" % row["Affected Asset Library Id"].strip()
        if row["Affected Asset Library External Id"]:
            affects += " [%s]" % row["Affected Asset Library External Id"].strip()
        references = []
        taxonomy = []
        tags = row["Tags"]
        if tags:
            tags = json.loads(tags)
            for link in tags:
                if link.startswith("CWE-"):
                    taxonomy.append(link[:link.find(":")].strip())
                elif "https://" in link:
                    url = link[link.rfind("https://"):].strip()
                    references.append(url)
        severity = row["Priority"].lower()
        if severity == "info":
            severity = "none"
        issue = {
            "template": "manual",
            "tools": ["attackforge"],
            "severity": severity.strip(),
            "affects": [affects],
            "title": row["Title"].strip(),
            "summary": summary.strip(),
            "description": description.strip(),
            "recommendations": row["Recommendation"].strip(),
            "details": row["Steps To Reproduce (Proof of Concept)"].strip(),
        }
        if references:
            issue["references"] = references
        if taxonomy:
            issue["taxonomy"] = taxonomy
        results.append(issue)
    json.dump(results, sys.stdout)

if __name__ == "__main__":
    main()
