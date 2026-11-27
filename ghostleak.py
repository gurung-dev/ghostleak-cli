#!/usr/bin/env python3
"""GhostLeak CLI entry point. Run: python3 ghostleak.py"""

from __future__ import annotations

import sys

from ghostleak.cli import main

if __name__ == "__main__":
    sys.exit(main())
