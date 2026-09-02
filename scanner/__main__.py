"""CLI entry point.

    python -m scanner <path> [--json] [--verbose]
    python -m scanner diff <old-path> <new-path> [--json]
    python -m scanner baseline <path> [--json]      record the approved state
    python -m scanner check <path> [--json]         compare against it
    python -m scanner --version

`diff` needs both trees; `check` needs only the one on disk, because an update
overwrites the old copy in place and you rarely still have it.

Never executes, imports, sources, or network-resolves anything from the target.
Standard library only, by design: this tool gets installed with Bash access, so
it has no business pulling dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import baseline
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
    parser.add_argument("--version", action="version", version=f"inspector-skills {__version__}")
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

    if argv and argv[0] in ("baseline", "check"):
        mode = argv[0]
        bparser = argparse.ArgumentParser(
            prog=f"inspector-skills {mode}",
            description=("Record the current state as approved."
                         if mode == "baseline" else
                         "Scan now and compare against the approved state."))
        bparser.add_argument("path", type=Path)
        bparser.add_argument("--json", action="store_true")
        args = bparser.parse_args(argv[1:])

        if not args.path.exists():
            print(f"error: {args.path} does not exist", file=sys.stderr)
            return 2

        if mode == "baseline":
            unit, findings, profile = _scan(args.path)
            existed = baseline.path_for(args.path).exists()
            stored = baseline.save(args.path, unit, findings, profile)
            if args.json:
                print(json.dumps({"stored": str(stored), "replaced": existed,
                                  "unit": unit.name,
                                  "capabilities": sorted(profile["capabilities"]),
                                  "finding_count": len(findings)},
                                 indent=2, ensure_ascii=False))
            else:
                verb = "Replaced approved state" if existed else "Approved"
                print(f"{verb} for {unit.name or args.path}")
                print(f"  stored at   {stored}")
                print(f"  capabilities {', '.join(sorted(profile['capabilities'])) or 'none'}")
                print(f"  findings     {len(findings)}")
                print("\nThis is what future `check` runs compare against. Approving "
                      "a version you have not read\nmakes every later comparison "
                      "clean by definition.")
            return 0

        # `check` — never records anything. Approving is always explicit.
        try:
            document = baseline.load(args.path)
        except baseline.BaselineError as exc:
            # Loud, not a line in a report. A baseline that cannot be trusted
            # would otherwise produce a confident "nothing changed".
            print(f"error: {exc}", file=sys.stderr)
            return 2

        unit, findings, profile = _scan(args.path)
        if document is None:
            if args.json:
                print(json.dumps({"baseline": None, "unit": unit.name,
                                  "capabilities": sorted(profile["capabilities"]),
                                  "finding_count": len(findings)},
                                 indent=2, ensure_ascii=False))
            else:
                print(f"NO APPROVED STATE for {unit.name or args.path}\n")
                print("Nothing to compare against — this unit has never been approved.")
                print("Audit it in full first, and only then record it:\n")
                print(f"    python3 -m scanner {args.path}")
                print(f"    python3 -m scanner baseline {args.path}\n")
                print("A first sighting is never recorded automatically. Blessing "
                      "whatever is on disk\nthe first time this runs would approve "
                      "a payload nobody read.")
            return 0

        old_unit, old_findings, old_profile = baseline.restore(document)
        delta = diffmod.compare(old_unit, old_findings, old_profile,
                                unit, findings, profile)
        if args.json:
            payload = diffmod.to_dict(delta)
            payload["approved_at"] = document.get("approved_at", "")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"APPROVED {document.get('approved_at', 'unknown date')}\n")
            print(diffmod.to_text(delta))
            if delta.has_change:
                print("\nIf you have read the change and accept it, record the new "
                      "state:\n"
                      f"    python3 -m scanner baseline {args.path}")
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
