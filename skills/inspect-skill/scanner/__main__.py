"""CLI entry point.

    python -m scanner <path> [--json] [--verbose]
    python -m scanner diff <old-path> <new-path> [--json]

Never executes, imports, sources, or network-resolves anything from the target.
Standard library only, by design: this tool gets installed with Bash access, so
it has no business pulling dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import diff as diffmod
from . import semantic
from . import engine, report
from .unit import collect


def _scan(path: Path):
    unit = collect(path)
    findings, profile = engine.scan(unit)
    return unit, findings, profile


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        prog="inspector-skills",
        description="Static audit of an agent extension before installation. "
                    "Reports; never blocks.")
    parser.add_argument("path", type=Path, help="file or directory to audit")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--verbose", action="store_true", help="do not truncate lists")

    if argv and argv[0] == "semantic-prep":
        sparser = argparse.ArgumentParser(
            prog="inspector-skills semantic-prep",
            description="Emit quarantined chunks for the semantic pass. "
                        "Carries no scanner results: the comparison baseline is "
                        "recomputed at verify time so no judge can echo it back.")
        sparser.add_argument("path", type=Path)
        args = sparser.parse_args(argv[1:])
        if not args.path.exists():
            print(f"error: {args.path} does not exist", file=sys.stderr)
            return 2
        print(semantic.request_json(semantic.prepare(collect(args.path))))
        return 0

    if argv and argv[0] == "semantic-verify":
        vparser = argparse.ArgumentParser(
            prog="inspector-skills semantic-verify",
            description="Cross-check judge descriptions against the scanner. "
                        "Every comparison happens here, never in a context that "
                        "read the target.")
        vparser.add_argument("path", type=Path)
        vparser.add_argument("answers", type=Path, help="JSON from the judge panel")
        vparser.add_argument("--json", action="store_true")
        args = vparser.parse_args(argv[1:])
        for candidate in (args.path, args.answers):
            if not candidate.exists():
                print(f"error: {candidate} does not exist", file=sys.stderr)
                return 2

        unit, findings, profile = _scan(args.path)
        request = semantic.prepare(unit)
        try:
            raw = json.loads(args.answers.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            print(f"error: answers file is not valid JSON: {exc}", file=sys.stderr)
            return 2

        extra = semantic.verify(unit, findings, request, raw)
        combined = sorted(findings + extra, key=lambda f: f.sort_key())
        # Recompute: a profile built before the semantic pass would print
        # "Network no" in the same report where SEM-002 reports network.
        profile = engine.profile(combined, unit)
        if args.json:
            print(report.to_json(unit, combined, profile))
        else:
            print(report.to_text(unit, combined, profile, verbose=args.verbose
                                 if hasattr(args, "verbose") else False))
        return 0

    if argv and argv[0] == "diff":
        dparser = argparse.ArgumentParser(
            prog="inspector-skills diff",
            description="Compare two versions and report NEW capabilities. "
                        "The update is how supply-chain attacks arrive.")
        dparser.add_argument("old", type=Path, help="the version you already trust")
        dparser.add_argument("new", type=Path, help="the version you are being offered")
        dparser.add_argument("--json", action="store_true")
        args = dparser.parse_args(argv[1:])

        for candidate in (args.old, args.new):
            if not candidate.exists():
                print(f"error: {candidate} does not exist", file=sys.stderr)
                return 2

        delta = diffmod.compare(*_scan(args.old), *_scan(args.new))
        if args.json:
            print(json.dumps(diffmod.to_dict(delta), indent=2, ensure_ascii=False))
        else:
            print(diffmod.to_text(delta))
        return 0

    args = parser.parse_args(argv)
    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 2

    unit, findings, profile = _scan(args.path)
    if args.json:
        print(report.to_json(unit, findings, profile))
    else:
        print(report.to_text(unit, findings, profile, verbose=args.verbose))

    # Exit code is informational only. The tool has no veto (RULES.md section 1.3).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
