#!/usr/bin/python3

import os
import sys

sys.path.insert(1, os.environ["MAGENTA_HOME"])
from libmagenta.merger.burp import BurpMerger

if __name__ == "__main__":
    BurpMerger().run()
