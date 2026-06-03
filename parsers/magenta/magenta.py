#!/usr/bin/python3

import json
import sys


def main():
    results = json.load(sys.stdin)["issues"]
    for issue in results:
        # vulnid is post-merge UI metadata; re-derived after the next merge pass.
        issue.pop("vulnid", None)
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
