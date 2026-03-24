#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


class WAFMerger(Merger):
    def do_firewalls_init(self):
        return {}

    def do_firewalls_collect(self, merged_dict, issue_dict):
        for key, value in issue_dict.items():
            if key in merged_dict:
                merged_list = merged_dict[key]
                for item in value:
                    if item not in merged_list:
                        merged_list.append(item)
            else:
                merged_dict[key] = value
        return merged_dict

    def do_firewalls_cleanup(self, merged_dict):
        return merged_dict


if __name__ == "__main__":
    WAFMerger().run()
