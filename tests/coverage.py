"""Exact per-fixture expectations, and the coverage measurement behind them.

`tests/truepos.py` asks one question: did the attack get caught. It cannot
answer two others, and four defects in a row lived in that gap.

  - **Did a rule that used to fire stop firing?** `must_detect` is a subset
    check, so every id a fixture does not name is unobserved. A change that
    narrowed a scan class silently stopped detecting five attack spellings and
    passed the whole suite, because the attack table only held characters that
    were still inside the new class.
  - **Is a rule family covered at all?** Nothing ever counted implemented rules
    against the fixtures that exercise them, so a family with zero fixtures read
    exactly like a family that passes.

This module answers both.

1. It pins the EXACT id set every fixture produces. A MISSING id means a rule
   stopped firing; an EXTRA id means a rule started over-firing. Both fail.
   Benign fixtures are pinned by the same mechanism with (near-)empty sets, so
   precision is measured rather than asserted.
2. It aggregates those results per rule-id family — the families come from
   RULES.md, never from a list typed here — and prints coverage, recall and
   precision per family, plus the count of documented blind spots so that
   number cannot drift upward unnoticed.

The manifest is `fixtures/EXPECTED.json`: ONE file keyed by fixture path, not a
sibling of each fixture. Three reasons.

  - `EXPECT.json` beside each fixture is *intent*, hand-written in
    `tests/make_fixtures.py` and rewritten wholesale by `make fixtures`. The
    exact sets are *observation* — recorded scanner output. Keeping the two in
    separate files keeps the generator from having to ask the thing under test
    what the right answer is.
  - Adding a rule is the diff that has to stay readable. A new rule firing on
    twelve fixtures is twelve sorted one-line additions in one hunk of one file.
    The same change spread over twelve sibling files is twelve file headers and
    no way to see the shape at a glance.
  - Exact sets are a golden. Goldens regenerate with one command against one
    file, and the regeneration has to be visible in review.

    python -m tests.coverage             check against fixtures/EXPECTED.json
    python -m tests.coverage --update     re-record the manifest
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import engine  # noqa: E402
from scanner import rules as R  # noqa: E402
from scanner.engine import headline  # noqa: E402
from scanner.unit import collect  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
ROOT = PROJECT / "fixtures"
MANIFEST = ROOT / "EXPECTED.json"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

MANIFEST_NOTE = (
    "Recorded scanner output, one entry per fixture. `findings` is every rule id "
    "the scan produces including ids collapsed into related_rules; `headline` is "
    "the primary id of every finding that leads the report; `status` is those "
    "same ids paired with the reachability status they were reported under "
    "(`id:active`, `id:dormant`, `id:conditional`). Exact match on all three: a "
    "missing entry is a rule that stopped firing, an extra one is a rule that "
    "started over-firing. Regenerate with: python -m tests.coverage --update"
)

# Axes compared exactly, in both directions. Listed once so adding a fourth is
# one edit rather than three that have to agree.
AXES = ("findings", "headline", "status")


# ----------------------------------------------------------------- rule families
# The family list is READ from RULES.md. Typing it here would reintroduce the
# exact failure this module exists to catch: a list that looks like coverage and
# is really just what somebody remembered.

def _expand(row: str) -> set[str]:
    """Rule ids in a table row, expanding `X-001`…`X-004` range notation."""
    found: set[str] = set()
    for low, high in re.findall(r"`([A-Z]{3}-\d{3})`(?:…`([A-Z]{3}-\d{3})`)?", row):
        found.add(low)
        if high:
            prefix, start = low.rsplit("-", 1)
            found.update(f"{prefix}-{n:03d}" for n in
                         range(int(start), int(high.rsplit("-", 1)[1]) + 1))
    return found


def catalogue() -> tuple[dict[str, set[str]], dict[str, str]]:
    """({family: documented ids}, {family: RULES.md section title}).

    The section title comes from the lettered catalogue headings (`### A. …`),
    and only from the id in a row's LEADING cell — the rule that row is about.
    Ids mentioned inside a prose cell are cross-references: `AGT-011`'s row
    names `BND-003` and `EXE-001`'s row names `CHN-002`, which filed Bundle
    structure under Instruction surface and Derived findings under Code
    execution. A family that never leads a row under a lettered heading gets
    `-` rather than a title borrowed from whatever heading happened to be open —
    an invented label is the same lie as an invented rule list.
    """
    doc = (PROJECT / "RULES.md").read_text(encoding="utf-8")

    documented: set[str] = set()
    for row in re.findall(r"^\|\s*(`[A-Z]{3}-\d{3}`[^|]*)", doc, re.M):
        documented |= _expand(row)

    section: dict[str, str] = {}
    current = ""
    for line in doc.splitlines():
        heading = re.match(r"^### ([A-L])\. (.+)$", line)
        if heading:
            current = heading.group(2).strip()
            continue
        if line.startswith("### ") or line.startswith("## "):
            current = ""
            continue
        lead = re.match(r"^\|\s*(`[A-Z]{3}-\d{3}`(?:…`[A-Z]{3}-\d{3}`)?)\s*\|", line)
        if current and lead:
            for rule_id in _expand(lead.group(1)):
                section.setdefault(rule_id.split("-")[0], current)

    families: dict[str, set[str]] = {}
    for rule_id in documented:
        families.setdefault(rule_id.split("-")[0], set()).add(rule_id)
    return families, section


def implemented_ids() -> set[str]:
    """Every rule id the scanner can actually emit."""
    ids = {rule.id for rule in R.RULES}
    for module in ("structural", "engine", "taint", "semantic", "reachability"):
        text = (PROJECT / "scanner" / f"{module}.py").read_text(encoding="utf-8")
        ids |= set(re.findall(r'"([A-Z]{3}-\d{3})"', text))
    return ids


def unexercised_ids(live: set[str], fixture_ids: set[str]) -> list[str]:
    """Implemented rules that no fixture exercises AND no test module names.

    The table above counts fixtures, and for HOK and SEM that reads far lower
    than the truth: structural and semantic rules are pinned by case tables in
    tests/unit_test.py and tests/semantic_test.py, which a fixture count cannot
    see. Reading `cover` as a testing total is a live mistake — it has already
    produced one wrong claim in a published release and one wrong plan.

    So this reports the strictly worse thing the table could never say: a rule
    that NOTHING names. That is the dead-code risk `_EXEC_SINK` was — a pattern
    that could not match at all, found only when something finally ran it.

    Naming is the honest bound, not proof of a test: an id inside a comment
    counts as named here. The set is therefore a floor on what is untested,
    never a ceiling, and it is deliberately the cheap half of the question.
    """
    named: set[str] = set()
    for module in ("unit_test", "semantic_test", "truepos", "fuzz"):
        path = PROJECT / "tests" / f"{module}.py"
        if path.exists():
            named |= set(re.findall(r"\b([A-Z]{3}-\d{3})\b",
                                    path.read_text(encoding="utf-8")))
    return sorted(live - fixture_ids - named)


# ----------------------------------------------------------------- scanning

def observe(base: Path) -> dict:
    """The three id sets a fixture must reproduce.

    `findings` folds in `related_rules` because dedup (RULES.md section 7)
    collapses a rule into another finding without meaning it stopped matching —
    the same reason `truepos.detected_ids` does it. `headline` deliberately does
    NOT: it records which rule LEADS the report, and a rule absorbed into
    another finding's `related_rules` is not leading anything.

    `status` is the reachability axis (RULES.md section 2.3), and it exists
    because the first two are blind to it. Nothing here recorded whether a
    finding was reported `active`, `dormant` or `conditional`, so rewiring the
    corpus — which is what the fixtures were rebuilt to do — moved no axis a
    check reads, and the skew could come back without failing anything. A file
    that is reachable only through a sample directory is the sharpest case:
    `_reachability_findings` skips those outright, so its status can flip in
    either direction while `findings` and `headline` stay byte-identical.

    It is recorded as `id:status` pairs so it stays in the same vocabulary as
    the axes beside it and stays a strict refinement of `findings`: every id
    there appears here exactly once per status it was reported under. A rule
    collapsed into `related_rules` shares the winning finding's location, and
    therefore its status, so it is recorded with it rather than dropped.
    """
    unit = collect(base)
    findings, _ = engine.scan(unit)
    ids: set[str] = set()
    status: set[str] = set()
    for finding in findings:
        ids.add(finding.id)
        ids.update(finding.related_rules)
        for rule_id in (finding.id, *finding.related_rules):
            status.add(f"{rule_id}:{finding.status}")
    return {
        "findings": sorted(ids),
        "headline": sorted({f.id for f in headline(findings)}),
        "status": sorted(status),
    }


def fixtures() -> list[tuple[str, Path, dict]]:
    """(key, path, EXPECT.json) for every fixture, sorted by key."""
    out = []
    for expect_path in sorted(ROOT.rglob("EXPECT.json")):
        base = expect_path.parent
        key = base.relative_to(ROOT).as_posix()
        out.append((key, base, json.loads(expect_path.read_text(encoding="utf-8"))))
    return sorted(out, key=lambda row: row[0])


def build() -> dict:
    entries = {key: observe(base) for key, base, _ in fixtures()}
    blind = sum(len(expect.get("known_miss", [])) for _, _, expect in fixtures())
    return {
        "_": MANIFEST_NOTE,
        "totals": {"fixtures": len(entries), "known_miss": blind},
        "fixtures": entries,
    }


# ----------------------------------------------------------------- the report

def measure(rows: list[tuple[str, dict, dict]]) -> dict[str, dict]:
    """Per-family tallies.

    `rows` is (category, EXPECT.json, observed).

    - `expected` counts (fixture, rule id) pairs the corpus declares a malicious
      fixture must produce — `must_detect` plus `also_expect`. `found` is how
      many of those actually appeared. Recall is found/expected.
    - `blind` counts pairs declared in `known_miss`. They are NOT folded into
      recall in either direction: a documented blind spot is neither a pass nor
      a silent failure, it is its own number.
    - `tp` / `fp` count headline rule ids on malicious / benign fixtures. A
      headline finding on a unit that is malicious is correct whether or not the
      fixture thought to name it; a headline finding on a benign unit is not.
      Precision is tp/(tp+fp).
    """
    stats: dict[str, dict] = {}

    def bucket(rule_id: str) -> dict:
        return stats.setdefault(rule_id.split("-")[0], {
            "expected": 0, "found": 0, "blind": 0, "tp": 0, "fp": 0, "exercised": set()})

    for category, expect, observed in rows:
        detected = set(observed["findings"])
        if category == "malicious":
            for rule_id in expect.get("must_detect", []) + expect.get("also_expect", []):
                cell = bucket(rule_id)
                cell["expected"] += 1
                cell["exercised"].add(rule_id)
                if rule_id in detected:
                    cell["found"] += 1
            for rule_id in observed["headline"]:
                bucket(rule_id)["tp"] += 1
        elif category == "benign":
            for rule_id in observed["headline"]:
                bucket(rule_id)["fp"] += 1
        elif category == "known-miss":
            for rule_id in expect.get("known_miss", []):
                cell = bucket(rule_id)
                cell["blind"] += 1
                cell["exercised"].add(rule_id)
    return stats


def _ratio(num: int, den: int) -> str:
    return f"{100 * num // den:>3}%" if den else "  -"


def print_table(rows: list[tuple[str, dict, dict]]) -> int:
    """Print the per-family table. Returns the number of uncovered families."""
    families, section = catalogue()
    live = implemented_ids()
    stats = measure(rows)

    print("\nper-family coverage, recall and precision")
    print(f"{DIM}  impl   implemented rules in the family (RULES.md minus rules.DEFERRED)")
    print("  exer   implemented rules at least one fixture declares it exercises")
    print("  cover  exer/impl — FIXTURES ONLY. A structural family reads low here")
    print("         while its rules are covered by case tables in tests/; see below")
    print("  recall (fixture, id) pairs declared must-detect that actually fired")
    print("  blind  pairs declared known_miss: documented, counted, never a pass")
    print(f"  prec   headline ids on malicious units / (that + headline ids on benign){RESET}\n")

    header = (f"  {'fam':<5} {'impl':>4} {'exer':>4} {'cover':>6}  "
              f"{'recall':>9} {'':>5}  {'blind':>5} {'fp':>3} {'prec':>5}  section")
    print(header)
    print(f"  {'-' * (len(header) - 2)}")

    uncovered = 0
    for family in sorted(families):
        impl = sorted(families[family] & live)
        cell = stats.get(family, {"expected": 0, "found": 0, "blind": 0,
                                  "tp": 0, "fp": 0, "exercised": set()})
        exercised = cell["exercised"] & set(impl)
        if impl and not exercised:
            uncovered += 1
        colour = RED if (impl and not exercised) else ""
        reset = RESET if colour else ""
        recall = (f"{cell['found']:>4}/{cell['expected']:<4}" if cell["expected"]
                  else f"{'-':>4} {'':<4}")
        print(f"  {colour}{family:<5} {len(impl):>4} {len(exercised):>4} "
              f"{_ratio(len(exercised), len(impl)):>6}  "
              f"{recall} {_ratio(cell['found'], cell['expected'])}  "
              f"{cell['blind']:>5} {cell['fp']:>3} "
              f"{_ratio(cell['tp'], cell['tp'] + cell['fp']):>5}  "
              f"{section.get(family, '-')}{reset}")

    blind_total = sum(cell["blind"] for cell in stats.values())
    fp_total = sum(cell["fp"] for cell in stats.values())
    tp_total = sum(cell["tp"] for cell in stats.values())
    exp_total = sum(cell["expected"] for cell in stats.values())
    found_total = sum(cell["found"] for cell in stats.values())
    print(f"  {'-' * (len(header) - 2)}")
    print(f"  {'all':<5} {len(live):>4} "
          f"{len({r for c in stats.values() for r in c['exercised']} & live):>4} "
          f"{_ratio(len({r for c in stats.values() for r in c['exercised']} & live), len(live)):>6}  "
          f"{found_total:>4}/{exp_total:<4} {_ratio(found_total, exp_total)}  "
          f"{blind_total:>5} {fp_total:>3} {_ratio(tp_total, tp_total + fp_total):>5}")

    return uncovered


def main(argv: list[str]) -> int:
    if "--update" in argv:
        manifest = build()
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"recorded {len(manifest['fixtures'])} fixtures "
              f"({manifest['totals']['known_miss']} known miss) -> "
              f"{MANIFEST.relative_to(PROJECT)}")
        return 0

    if not MANIFEST.exists():
        print("no manifest — run: python -m tests.coverage --update")
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded: dict[str, dict] = manifest.get("fixtures", {})

    passed = failed = 0
    rows: list[tuple[str, dict, dict]] = []
    benign_headline: list[tuple[str, list[str]]] = []
    seen: set[str] = set()

    for key, base, expect in fixtures():
        seen.add(key)
        category = expect.get("category", "?")
        observed = observe(base)
        rows.append((category, expect, observed))
        if category == "benign" and observed["headline"]:
            benign_headline.append((key, observed["headline"]))

        if key not in recorded:
            print(f"{RED}NEW{RESET}   {key:<32} unrecorded fixture: "
                  f"{observed['findings']} — run --update and review the diff")
            failed += 1
            continue

        want = recorded[key]
        broken = []
        for axis in AXES:
            missing = sorted(set(want.get(axis, [])) - set(observed[axis]))
            extra = sorted(set(observed[axis]) - set(want.get(axis, [])))
            if missing:
                broken.append(f"{axis} missing {missing}")
            if extra:
                broken.append(f"{axis} extra {extra}")
        if broken:
            print(f"{RED}DRIFT{RESET} {key:<32} " + "; ".join(broken))
            failed += 1
        else:
            passed += 1

    for key in sorted(set(recorded) - seen):
        print(f"{RED}STALE{RESET} {key:<32} recorded but no such fixture on disk")
        failed += 1

    print(f"\n{passed}/{passed + failed} fixtures match their exact expected findings")

    # The blind-spot count is pinned in the manifest on purpose. Adding a
    # known-miss fixture is a decision to ship a documented gap, and it has to
    # cost an explicit edit here rather than sliding in as one more green line.
    blind = sum(len(expect.get("known_miss", [])) for _, _, expect in fixtures())
    pinned = manifest.get("totals", {}).get("known_miss")
    if pinned is None or blind != pinned:
        direction = "grew" if pinned is not None and blind > pinned else "changed"
        print(f"{RED}BLIND{RESET} documented blind spots {direction}: "
              f"{blind} on disk, {pinned} pinned in the manifest")
        failed += 1
    else:
        print(f"{YELLOW}known misses{RESET}: {blind} documented blind spot(s), "
              f"pinned — they are counted, never passed")

    uncovered = print_table(rows)

    if benign_headline:
        print(f"\n{DIM}benign fixtures that still lead the report (counted as fp above; "
              f"each is inside its own EXPECT.json max_headline budget):{RESET}")
        for key, ids in benign_headline:
            print(f"  {key:<32} {ids}")

    if uncovered:
        print(f"\n{YELLOW}{uncovered} implemented rule famil"
              f"{'y is' if uncovered == 1 else 'ies are'} exercised by no fixture{RESET}"
              " — reported, not failed: the corpus is the thing to grow, not this check")

    fixture_ids: set[str] = set()
    for cell in measure(rows).values():
        fixture_ids |= cell["exercised"]
    nowhere = unexercised_ids(implemented_ids(), fixture_ids)
    if nowhere:
        print(f"\n{YELLOW}{len(nowhere)} implemented rule"
              f"{'' if len(nowhere) == 1 else 's'} named by no fixture and by no "
              f"test module{RESET} — the dead-code risk, and the one number above "
              f"that a fixture count cannot show:")
        print(f"  {' '.join(nowhere)}")
    else:
        print(f"\n{DIM}every implemented rule is named by a fixture or a test "
              f"module{RESET}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
