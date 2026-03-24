#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


class NiktoMerger(Merger):
    def do_issues_init(self):
        return {}

    def do_issues_collect(self, merged_dict, issue_dict):
        for key, value in issue_dict.items():
            if key not in merged_dict:
                merged_dict[key] = list(value)
            else:
                array = merged_dict[key]
                for item in value:
                    if item not in array:
                        array.append(item)

    def do_issues_cleanup(self, merged_dict):
        return merged_dict


if __name__ == "__main__":
    NiktoMerger().run()
