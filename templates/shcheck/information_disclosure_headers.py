#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger.burp import BurpMerger  # noqa: E402


class InfoDisclosureMerger(BurpMerger):
    """BurpMerger, but unioning the headers map instead of dropping duplicates.

    BurpMerger keys on host+path+method+request+response and keeps only the
    first issue for a given key. That would silently discard a second scan's
    extra headers, so union them first and let BurpMerger handle the rest.
    """

    def do_issues_cleanup(self, issues):
        unioned = {}
        for issue in issues:
            key = (
                issue["host"] + issue.get("path", ""),
                issue.get("request", ""),
                issue.get("response", ""),
            )
            if key in unioned:
                unioned[key]["headers"].update(issue.get("headers", {}))
            else:
                unioned[key] = dict(issue, headers=dict(issue.get("headers", {})))
        return super().do_issues_cleanup(list(unioned.values()))


if __name__ == "__main__":
    InfoDisclosureMerger().run()
