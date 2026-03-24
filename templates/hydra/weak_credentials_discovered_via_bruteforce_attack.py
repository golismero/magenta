#!/usr/bin/env python3

import os.path
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


# XXX FIXME the implementation does a dirty trick
class ServiceBruteforceMerger(Merger):
    def do_credentials_collect(self, merge_credentials, issue_credentials):
        for x in issue_credentials:
            merge_credentials.append(
                (x["host"], x["port"], x["service"], x["login"], x["password"])
            )
        return merge_credentials

    def do_credentials_cleanup(self, credentials):
        return [
            {
                "host": x[0],
                "port": x[1],
                "service": x[2],
                "login": x[3],
                "password": x[4],
            }
            for x in sorted(set(credentials))
        ]


if __name__ == "__main__":
    ServiceBruteforceMerger().run()
