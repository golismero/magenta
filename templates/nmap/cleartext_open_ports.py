#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger

# XXX FIXME
# The implementation for this one is a bit dirty... it collects the ports
# as a sorted list of tuples, then on cleanup converts the tuples to dicts.
class CleartextOpenPortsMerger(Merger):

    def do_plaintext_ports_collect(self, merged_plaintext_ports, issue_plaintext_ports):
        for x in issue_plaintext_ports:
            port, proto = x["port"].split("/")
            port = int(port)
            merged_plaintext_ports.append((x["address"], port, proto, x["service"]))
        return merged_plaintext_ports

    def do_plaintext_ports_cleanup(self, plaintext_ports):
        plaintext_ports = sorted(set(plaintext_ports))
        return [
            {
                "address": x[0],
                "port": "%s/%s" % (x[1], x[2]),
                "service": x[3],
            }
            for x in plaintext_ports
        ]

if __name__ == "__main__":
    CleartextOpenPortsMerger().run()
