"""True-positive harness.

Measures the other half of quality: does the scanner catch the attack? Each
fixture is scanned as its own unit (so section-3 position stays active), then
checked against its EXPECT.json.

    python -m tests.truepos
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import engine  # noqa: E402
from scanner.unit import collect  # noqa: E402
from scanner.engine import headline  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
ROOT = PROJECT / "fixtures"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def detected_ids(findings) -> set:
    """A rule collapsed into related_rules by dedup is still detected."""
    ids = set()
    for f in findings:
        ids.add(f.id)
        ids.update(f.related_rules)
    return ids


def main() -> int:
    fixtures = sorted(p.parent for p in ROOT.rglob("EXPECT.json"))
    if not fixtures:
        print("no fixtures — run: python -m tests.make_fixtures")
        return 1

    passed = failed = 0
    fn_confirmed = 0

    for base in fixtures:
        expect = json.loads((base / "EXPECT.json").read_text())
        category = expect.get("category", "?")
        unit = collect(base)
        findings, _ = engine.scan(unit)
        ids = detected_ids(findings)
        head_ids = {f.id for f in headline(findings)}
        head_ids |= {r for f in headline(findings) for r in f.related_rules}
        label = f"{category}/{base.name}"

        if category == "malicious":
            must = set(expect.get("must_detect", []))
            missing = must - ids
            not_headlined = must - head_ids
            if missing:
                print(f"{RED}MISS{RESET}  {label:<28} expected {sorted(must)}, "
                      f"missing {sorted(missing)}")
                failed += 1
            elif not_headlined:
                print(f"{YELLOW}WEAK{RESET}  {label:<28} detected but not in headline: "
                      f"{sorted(not_headlined)}")
                passed += 1
            else:
                extra = ", ".join(sorted(set(expect.get("also_expect", [])) & ids))
                print(f"{GREEN}OK{RESET}    {label:<28} {sorted(must)}"
                      + (f"  {DIM}(+{extra}){RESET}" if extra else ""))
                passed += 1

        elif category == "benign":
            cap = expect.get("max_headline", 0)
            hl = headline(findings)
            if len(hl) > cap:
                print(f"{RED}FP{RESET}    {label:<28} {len(hl)} headline findings "
                      f"(max {cap}): {sorted(head_ids)}")
                failed += 1
            else:
                print(f"{GREEN}OK{RESET}    {label:<28} clean headline  {DIM}"
                      f"({expect.get('note','')}){RESET}")
                passed += 1

        elif category == "known-miss":
            should_miss = set(expect.get("known_miss", []))
            leaked = should_miss & ids
            if leaked:
                print(f"{YELLOW}SURPRISE{RESET} {label:<24} unexpectedly detected "
                      f"{sorted(leaked)} — update EXPECT.json")
            else:
                print(f"{DIM}FN-OK {label:<28} confirmed blind spot: "
                      f"{sorted(should_miss)}  ({expect.get('note','')}){RESET}")
                fn_confirmed += 1

    # Diff mode: the attack is only visible in the delta between two versions.
    v1, v2 = ROOT / "update" / "telemetry-v1", ROOT / "update" / "telemetry-v2"
    if v1.exists() and v2.exists():
        from scanner import diff as diffmod
        old = collect(v1)
        new = collect(v2)
        delta = diffmod.compare(old, *engine.scan(old), new, *engine.scan(new))
        silent = delta.silent_escalation
        if silent and not delta.description_changed:
            print(f"{GREEN}OK{RESET}    diff/telemetry-v1..v2        "
                  f"{len(silent)} silent escalation(s), description unchanged")
            passed += 1
        else:
            print(f"{RED}MISS{RESET}  diff/telemetry-v1..v2        "
                  f"expected a silent escalation, got {len(silent)}")
            failed += 1

    total = passed + failed
    print(f"\n{passed}/{total} detection checks passed"
          f"   {fn_confirmed} known blind spots confirmed")

    # Section-3 property: when these same attack files sit inside a real unit's
    # fixtures/ tree, their path contains "fixtures" and they are demoted. Scan
    # from the project root so the relpath is fixtures/... exactly as it would be
    # for an audited skill that ships samples.
    tree = collect(PROJECT)
    tree_findings, _ = engine.scan(tree)
    fx = [f for f in tree_findings if f.location.startswith("fixtures/")]
    fx_head = [f for f in headline(fx)]
    fx_active = [f for f in fx if f.position == "active"]
    ok = not fx_head and not fx_active
    mark = f"{GREEN}OK{RESET}" if ok else f"{RED}LEAK{RESET}"
    print(f"\nsection-3 self-check ({mark}): attack files under a real unit's fixtures/ ->")
    print(f"  {len(fx_head)} headline, {len(fx_active)} active-position of {len(fx)} "
          f"fixture matches (both must be 0 — they are illustrative by location)")

    return 1 if (failed or not ok) else 0


if __name__ == "__main__":
    raise SystemExit(main())
