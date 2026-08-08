"""CLI entry point.

    python -m scanner <path> [--json] [--verbose]

Never executes, imports, sources, or network-resolves anything from the target.
Standard library only, by design: this tool gets installed with Bash access, so
it has no business pulling dependencies.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import engine, report
from .unit import collect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspector-skills",
        description="Static audit of an agent extension before installation. "
                    "Reports; never blocks.")
    parser.add_argument("path", type=Path, help="file or directory to audit")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--verbose", action="store_true", help="do not truncate finding lists")
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 2

    unit = collect(args.path)
    findings, profile = engine.scan(unit)

    if args.json:
        print(report.to_json(unit, findings, profile))
    else:
        print(report.to_text(unit, findings, profile, verbose=args.verbose))

    # Exit code is informational only. The tool has no veto (RULES.md section 1.3).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
