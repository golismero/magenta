#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


class SSLMerger(Merger):
    def do_hosts_cleanup(self, merged_hosts):
        hostmap = {}
        for host in merged_hosts:
            key = host["host"]
            if key in hostmap and host not in hostmap[key]:
                hostmap[key].append(host)
            else:
                hostmap[key] = [host]
        hostnames = sorted(hostmap.keys())
        hostlist = []
        for key in hostnames:
            hostlist.extend(hostmap[key])
        return hostlist


if __name__ == "__main__":
    SSLMerger().run()
