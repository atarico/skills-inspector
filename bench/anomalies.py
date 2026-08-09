"""Invariant sweep across a whole corpus — QA, not detection.

The false-positive benchmark asks "is the verdict noisy". This asks a different
and cheaper question: "is the OUTPUT well-formed at all". Auditing real plugins
by hand found a string being iterated as a dict, a README banner used as a
description, and a security tool's own warning text read as live code. None of
those are detection errors; they are output defects, and each one was found by
eyeballing a report.

This checks the invariants that eyeballing would catch, over every unit at once.

    python -m bench.anomalies [corpus-root]
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.corpus import discover  # noqa: E402
from scanner import engine, report  # noqa: E402
from scanner.evidence import MAX_EVIDENCE  # noqa: E402
from scanner.unit import collect  # noqa: E402

RED, YELLOW, GREEN, DIM, RESET = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"

# Characters that must never survive sanitization.
_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​‮]")
_HARNESS = re.compile(r"(?i)<\|[^|>]*\|>|^\s*(Human|Assistant)\s*:|```")
# A list joined from a string shows up as single characters separated by commas.
_CHAR_JOINED = re.compile(r"(?:^|: )(?:\S, ){3,}\S(?:,|$)")
_HTML_LEFTOVER = re.compile(r"<(?:p|div|img|br|a|h\d|strong|em)\b")

SLOW_SECONDS = 8.0


def check(unit, findings, profile) -> list[tuple[str, str]]:
    """Return (severity, message) for every invariant violation."""
    bad: list[tuple[str, str]] = []

    # --- the report's own arithmetic ------------------------------------
    if profile["finding_count"] != len(findings):
        bad.append(("ERROR", f"finding_count {profile['finding_count']} "
                             f"!= len(findings) {len(findings)}"))
    if sum(profile["severity_counts"].values()) != len(findings):
        bad.append(("ERROR", "severity_counts do not sum to the finding total"))

    # --- description quality: disclosure is computed against it ----------
    desc = unit.description
    if _HTML_LEFTOVER.search(desc):
        bad.append(("ERROR", f"description is markup: {desc[:60]!r}"))
    elif desc and len(desc.strip()) < 15:
        bad.append(("WARN", f"description too short to compare against: {desc!r}"))
    elif not desc and any(f.relpath in ("README.md", "SKILL.md") for f in unit.files):
        bad.append(("WARN", "no description extracted though README/SKILL.md exists"))

    known = {f.relpath for f in unit.files}
    seen: Counter = Counter()

    for finding in findings:
        tag = f"{finding.id}@{finding.location}:{finding.line}"

        # --- evidence must be safe to hand to another agent --------------
        if _FORBIDDEN.search(finding.evidence):
            bad.append(("ERROR", f"{tag} evidence carries control/invisible chars"))
        if _HARNESS.search(finding.evidence):
            bad.append(("ERROR", f"{tag} evidence carries harness delimiters"))
        if len(finding.evidence) > MAX_EVIDENCE + 40:
            bad.append(("ERROR", f"{tag} evidence {len(finding.evidence)} chars, "
                                 f"over the {MAX_EVIDENCE} cap"))
        if "\n" in finding.evidence:
            bad.append(("ERROR", f"{tag} evidence is multi-line"))

        # --- `detects` is an injection channel too -----------------------
        # Structural findings interpolate target-controlled data into their
        # labels (MCP server names, git aliases, hook events). The sweep used
        # to check only `evidence`, which is how a label carrying `Human:` and
        # a harness token reached the reading agent intact.
        if _FORBIDDEN.search(finding.detects):
            bad.append(("ERROR", f"{tag} detects carries control/invisible chars"))
        if _HARNESS.search(finding.detects):
            bad.append(("ERROR", f"{tag} detects carries harness delimiters"))
        if "\n" in finding.detects or "\r" in finding.detects:
            bad.append(("ERROR", f"{tag} detects is multi-line"))

        # --- a string iterated as a collection --------------------------
        if _CHAR_JOINED.search(finding.detects):
            bad.append(("ERROR", f"{tag} detects looks character-joined: "
                                 f"{finding.detects[:60]!r}"))
        if len(finding.detects) > 200:
            bad.append(("WARN", f"{tag} detects is {len(finding.detects)} chars"))

        # --- locations must be real -------------------------------------
        if finding.location not in known:
            bad.append(("WARN", f"{tag} location is not a file in the unit"))
        if finding.line < 1:
            bad.append(("ERROR", f"{tag} line number {finding.line}"))

        # --- axes must hold to their contract ---------------------------
        if finding.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            bad.append(("ERROR", f"{tag} bad severity {finding.severity!r}"))
        if finding.confidence not in ("high", "medium", "low"):
            bad.append(("ERROR", f"{tag} bad confidence {finding.confidence!r}"))
        if finding.status not in ("active", "conditional", "dormant"):
            bad.append(("ERROR", f"{tag} bad status {finding.status!r}"))
        if finding.disclosure not in ("declared", "euphemistic", "undeclared"):
            bad.append(("ERROR", f"{tag} bad disclosure {finding.disclosure!r}"))
        if finding.id.startswith("SEM-") and finding.confidence != "low":
            bad.append(("ERROR", f"{tag} semantic finding above low confidence"))

        # --- every finding must be actionable ---------------------------
        for field in ("impact", "legitimate_use", "what_to_check"):
            if not getattr(finding, field, "").strip():
                bad.append(("WARN", f"{tag} empty {field}"))

        # --- dedup should have collapsed these --------------------------
        seen[(finding.location, finding.line, finding.id)] += 1

    for key, count in seen.items():
        if count > 1:
            bad.append(("ERROR", f"{key[2]}@{key[0]}:{key[1]} emitted {count} times"))

    # --- the JSON must survive a round trip -----------------------------
    try:
        json.loads(report.to_json(unit, findings, profile))
    except Exception as exc:
        bad.append(("ERROR", f"JSON output is not valid: {exc}"))

    return bad


def main(argv: list[str]) -> int:
    root = Path(argv[0] if argv else Path.home() / ".claude").expanduser()
    units = discover(root)
    print(f"sweeping {len(units)} units under {root}\n")

    errors = warns = crashes = 0
    slow: list[tuple[float, str]] = []
    by_message: Counter = Counter()
    sample: dict[str, str] = {}

    for path in units:
        started = time.monotonic()
        try:
            unit = collect(path)
            findings, profile = engine.scan(unit)
        except Exception as exc:
            crashes += 1
            print(f"{RED}CRASH{RESET} {path.name}: {type(exc).__name__}: {exc}")
            continue
        elapsed = time.monotonic() - started
        if elapsed > SLOW_SECONDS:
            slow.append((elapsed, unit.name or path.name))

        for level, message in check(unit, findings, profile):
            if level == "ERROR":
                errors += 1
                print(f"{RED}ERROR{RESET} {unit.name or path.name}: {message}")
            else:
                warns += 1
                # Group by the message TEXT, not the finding tag. Keying on the
                # tag collapsed every warning into its rule id and threw away
                # the only part that says what went wrong.
                shape = re.sub(r"^\S+@\S+\s+", "", message)
                shape = re.sub(r"['\"].*", "", shape).strip()[:56]
                by_message[shape] += 1
                sample.setdefault(shape, f"{unit.name or path.name}: {message}")

    print(f"\ncrashes {crashes}   errors {errors}   warnings {warns}")
    if by_message:
        print("\nwarning shapes:")
        for shape, count in by_message.most_common(8):
            print(f"  {count:>4}  {shape}")
            print(f"        {DIM}e.g. {sample[shape][:96]}{RESET}")
    if slow:
        print(f"\nslow units (> {SLOW_SECONDS}s):")
        for elapsed, name in sorted(slow, reverse=True)[:5]:
            print(f"  {elapsed:5.1f}s  {name}")
    if not (crashes or errors):
        print(f"\n{GREEN}no hard invariant violations{RESET}")
    return 1 if (crashes or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
