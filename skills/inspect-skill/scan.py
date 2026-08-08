#!/usr/bin/env python3
"""Launcher — makes `scanner` importable from any working directory.

The skill invokes this by absolute path so cwd never matters:
    python3 <skill_dir>/scan.py <target> --json
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from scanner.__main__ import main  # noqa: E402

raise SystemExit(main())
