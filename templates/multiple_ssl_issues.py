#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger import Merger


# Known testssl tag renames (legacy name -> current name). Parsers should never
# emit the legacy names -- the testssl parser already normalizes them at parse
# time -- but if one does (a parser bug, or another tool reusing these tag
# names), we sanitize it here and warn loudly so the bug gets noticed and fixed.
# We only touch *known* legacy tags: an unknown tag might be a finding from a
# newer testssl version we don't support yet, which is not a bug.
#
# NOTE: This map is a copy of LEGACY_ID_RENAMES in parsers/testssl/testssl.py.
# The two MUST be kept in sync. See parsers/testssl/FORMAT_HISTORY.md.
LEGACY_ID_RENAMES = {
    "PFS": "FS",
    "PFS_ciphers": "FS_ciphers",
    "PFS_ECDHE_curves": "FS_ECDHE_curves",
    "cipherlist_AVERAGE": "cipherlist_OBSOLETED",
    "cipherlist_GOOD": "cipherlist_STRONG_NOFS",
    "cipherlist_STRONG": "cipherlist_STRONG_FS",
}


class SSLMerger(Merger):
    def do_hosts_cleanup(self, merged_hosts):
        # Sanitize known-legacy problem tags before deduping, so hosts that
        # differ only by an outdated tag name collapse together correctly.
        for host in merged_hosts:
            self.sanitize_legacy_tags(host)

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

    def sanitize_legacy_tags(self, host):
        problems = host.get("problems")
        if not problems:
            return
        for old, new in LEGACY_ID_RENAMES.items():
            if old not in problems:
                continue
            sys.stderr.write(
                "WARNING: merger sanitized outdated tag '%s' -> '%s' for host "
                "'%s'. A parser emitted a legacy testssl tag; it was "
                "auto-corrected, but the parser should be fixed.\n"
                % (old, new, host.get("host", "?"))
            )
            value = problems.pop(old)
            if new in problems:
                # Merge into the existing entry the same way the parser would.
                problems[new] = (problems[new] + " " + value).strip()
            else:
                problems[new] = value


if __name__ == "__main__":
    SSLMerger().run()
