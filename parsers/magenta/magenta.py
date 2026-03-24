#!/usr/bin/python3

import json
import sys


def main():
    results = json.load(sys.stdin)["issues"]
    for issue in results:
        try:
            del issue["vulnid"]
        except KeyError:
            pass
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
