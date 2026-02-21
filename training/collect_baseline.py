#!/usr/bin/env python3
"""Collect baseline data by running CocoSentry in baseline mode.

This is a convenience wrapper — equivalent to:
    wifi_coconut | python -m cocosentry --baseline --duration 24h
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add parent to path for direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cocosentry.__main__ import main as cocosentry_main


def main():
    # Inject baseline args and forward to cocosentry
    sys.argv = [
        "cocosentry",
        "--baseline",
        *sys.argv[1:],
    ]
    cocosentry_main()


if __name__ == "__main__":
    main()
