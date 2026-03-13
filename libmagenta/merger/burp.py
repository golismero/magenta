#!/usr/bin/python3

from . import *

# Issue merger for Burp Suite Pro.
# Since we have a lot of those and they are all identical, it's best to put this code here.
class BurpMerger(Merger):

    # Remove duplicates using a very generic algorithm that uses sorting keys.
    # This does not account for one specific scenario, where we have the same
    # issue with and without HTTP data, but with the same URL. This will have
    # to be dealt with by individual templates, since it may make sense in
    # some cases to preserve both, but definitely does not in some others.
    def do_issues_cleanup(self, issues):
        unique_items = {}
        for issue in issues:
            key = (
                issue["host"] + issue.get("path", ""),
                issue.get("method", "GET"),
                issue.get("request", ""),
                issue.get("response", ""),
                issue.get("redirected", False),
            )
            if key not in unique_items:
                unique_items[key] = issue
            else:
                value = unique_items[key]
                if "items" in issue:
                    if "items" in value:
                        value["items"] = sorted(set(value["items"] + issue["items"]))
                    else:
                        value["items"] = list(issue["items"])
                if "vulnerabilities" in issue:
                    if "taxonomy" in value:
                        taxonomy = []
                        for new in issue["taxonomy"]:
                            found = False
                            for orig in value["taxonomy"]:
                                if orig["software"] == new["software"] and orig["version"] == new["version"]:
                                    orig["taxonomy"] = sorted(set(orig["taxonomy"] + new["taxonomy"]))
                                    found = True
                                    break
                            if found:
                                taxonomy.append(orig)
                            else:
                                taxonomy.append(new)
                        value["taxonomy"] = taxonomy
                    elif "taxonomy" in issue:
                        value["taxonomy"] = list(issue["taxonomy"])
        sorted_keys = sorted(unique_items.keys())
        return [unique_items[key] for key in sorted_keys]
