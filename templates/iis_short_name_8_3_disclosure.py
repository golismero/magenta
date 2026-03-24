#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


class IISShortName(Merger):
    def do_findings_cleanup(self, merged_findings):
        findings = sorted(set([(f["target"], f["output"]) for f in merged_findings]))
        return [
            {
                "target": t[0],
                "output": t[1],
            }
            for t in findings
        ]


if __name__ == "__main__":
    IISShortName().run()
