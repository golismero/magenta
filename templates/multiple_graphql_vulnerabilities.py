#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger

class GraphQLMerger(Merger):

    def do_issues_cleanup(self, merged_issues):
        unique_issues = [
            (
                issue["cause"],
                issue["consequence"],
                issue["severity"],
                issue["url"],
                issue["command"]
            ) for issue in merged_issues
        ]
        unique_issues = sorted(set(unique_issues))
        return [
            {
                "cause": issue[0],
                "consequence": issue[1],
                "severity": issue[2],
                "url": issue[3],
                "command": issue[4],
            } for issue in unique_issues
        ]

if __name__ == "__main__":
    GraphQLMerger().run()
