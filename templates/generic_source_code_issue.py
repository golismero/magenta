#!/usr/bin/env python3

import os.path
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger.codevuln import CodeVulnMerger

if __name__ == "__main__":
    CodeVulnMerger().run()
