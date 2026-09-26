#!/usr/bin/env python3
"""Entry point for the Red Team Toolkit.

Kept as a thin shim so ``python main.py <command>`` works from a clone without
installing anything. For the installed console script, use the ``rtt`` command.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from redteam_toolkit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
