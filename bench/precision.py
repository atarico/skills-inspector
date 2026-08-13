"""Freeze the false-positive benchmark, then diff against it.

`make falsepos` measures the number that decides whether this tool is usable:
how much noise it makes against extensions that are known to be fine. It prints
that number and forgets it. Nothing compared today's report to yesterday's, so a
rule that started firing on real, trusted software showed up as a slightly
larger number in a scrolling report and nobody had to justify it.

This freezes the report and fails on any NEW finding.

    python -m bench.precision --freeze [corpus]   record bench/precision-baseline.json
    python -m bench.precision [corpus]            diff current against the frozen file

WHAT THE FROZEN FILE CONTAINS, and what it must never contain
-------------------------------------------------------------
It is committed to a public repository and it describes software the user
installed on their own machine, so it carries AGGREGATE COUNTS AND RULE IDS
ONLY:

  discovered                              units found — the size of the corpus
  units                                   of those, the ones that scanned at all
  clean_units, clean_pct, median, mean, p90, max          distribution shape
  crashes                                 units that raised; a count, never a message
  headline_total                                          sum over the corpus
  rule_headline_counts   {rule id: units it leads on}     ids from RULES.md only
  unit_histogram         {finding count: how many units}  the shape, unnamed

Deliberately excluded, because each one leaks:

  the corpus root path            absolute path and the username inside it
  unit names ("worst units")      the list of extensions the user has installed
  crash text                      exception messages carry paths and file content
  any finding evidence            by construction: nothing below rule-id level

Normalised for stability: every mapping is written sorted by key, so a rerun
produces byte-identical output; `mean` is rounded to two places, since an
unrounded float turns a no-op rerun into a diff.

CORPUS-BOUND ON PURPOSE
-----------------------
The counts only mean something against the corpus they were frozen on. If the
corpus is missing (CI, a fresh clone) or a different number of units is
DISCOVERED (an extension was installed or removed), this exits 2 — "did not
run" — rather than 0. A precision check that reports success when it measured
nothing is the exact shape of defect this whole benchmark exists to catch.

Discovered and scanned are separate facts on purpose. A unit that raises is
still discovered — the corpus did not change, the scanner broke — so it is a
REGRESSION, never "did not run". One count for both made that unreachable: the
crash shrank the corpus, tripped the guard above, and reported the loudest
failure this benchmark can see as an inability to measure it.

  exit 0   measured, no new findings
  exit 1   measured, a precision regression a human has to justify
  exit 2   did not measure — corpus absent, empty, or a different size
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.corpus import discover  # noqa: E402
from scanner import engine  # noqa: E402
from scanner.unit import collect  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
BASELINE = PROJECT / "bench" / "precision-baseline.json"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

SCHEMA = 2

DID_NOT_RUN = 2

# What compare() reads. A baseline missing any of them is truncated, not zero.
REQUIRED = ("discovered", "units", "clean_units", "clean_pct", "median", "mean",
            "p90", "max", "crashes", "headline_total", "rule_headline_counts")


def collect_report(root: Path) -> dict | None:
    """Scan the corpus and reduce it to the publishable aggregate.

    Returns None when the corpus holds nothing at all. A unit that raises is
    still counted in `discovered`: it is the scanner that broke, not the corpus
    that changed, and the two have to stay separable downstream.

    Note what never enters the dict: no path, no unit name, no exception text.
    The reduction happens here rather than at write time so there is one place
    to audit for a leak.
    """
    units = discover(root)
    if not units:
        return None

    rule_counts: collections.Counter = collections.Counter()
    histogram: collections.Counter = collections.Counter()
    crashes = 0
    clean = 0
    counts: list[int] = []

    for path in units:
        try:
            unit = collect(path)
            findings, _ = engine.scan(unit)
        except Exception:
            # The message names a file on this machine. The count is the finding.
            crashes += 1
            continue
        head = engine.headline(findings)
        counts.append(len(head))
        histogram[len(head)] += 1
        for finding in head:
            rule_counts[finding.id] += 1
        if not head:
            clean += 1

    counts.sort()
    total = len(counts) or 1
    return {
        "schema": SCHEMA,
        "discovered": len(units),
        "units": len(counts),
        "clean_units": clean,
        "clean_pct": 100 * clean // total,
        "median": counts[len(counts) // 2] if counts else 0,
        "mean": round(sum(counts) / total, 2),
        "p90": counts[int(total * 0.9) - 1] if counts else 0,
        "max": max(counts) if counts else 0,
        "crashes": crashes,
        "headline_total": sum(counts),
        "rule_headline_counts": dict(sorted(rule_counts.items())),
        "unit_histogram": {str(k): histogram[k] for k in sorted(histogram)},
    }


def _summary(report: dict) -> str:
    return (f"{report['discovered']} discovered   {report['units']} scanned   "
            f"clean {report['clean_units']} "
            f"({report['clean_pct']}%)   median {report['median']}   "
            f"mean {report['mean']}   p90 {report['p90']}   max {report['max']}   "
            f"crashes {report['crashes']}")


def compare(base: dict, now: dict) -> int:
    """Print the diff. Returns the number of regressions — crashes included."""
    print(f"  frozen  {_summary(base)}")
    print(f"  current {_summary(now)}\n")

    regressions = 0
    # A crash is not a precision fact, it is the scanner failing on software the
    # user actually installed — so it is reported first, in its own words. Note
    # that units + crashes == discovered, so a drop in scanned units IS this
    # crash; counting it again would be counting one event twice.
    crashed = now["crashes"] - base["crashes"]
    if crashed > 0:
        print(f"  {RED}CRASH{RESET} {'crashes':<10} {base['crashes']:>4} -> "
              f"{now['crashes']:<4} (+{crashed}) the scanner now raises on "
              f"{crashed} unit(s) it used to scan.\n"
              f"        Fix the crash — re-freezing bakes it into the baseline.")
        regressions += 1

    before = base.get("rule_headline_counts", {})
    after = now.get("rule_headline_counts", {})

    for rule_id in sorted(set(before) | set(after)):
        was, is_ = before.get(rule_id, 0), after.get(rule_id, 0)
        if was == is_:
            continue
        if is_ > was:
            tag = f"{RED}NEW{RESET}  " if not was else f"{RED}UP{RESET}   "
            print(f"  {tag} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"(+{is_ - was}) leads on real, trusted extensions")
            regressions += 1
        else:
            note = ("— fewer units were scanned, so this proves nothing"
                    if crashed > 0 else "— an improvement; re-freeze to lock it in")
            print(f"  {GREEN}DOWN{RESET} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"({is_ - was}) {note}")

    # Increases stay regressions whatever else happened: firing MORE while
    # scanning fewer units cannot be explained away by the crash.
    for field, worse in (("headline_total", "more"), ("max", "higher")):
        if now[field] > base[field]:
            print(f"  {RED}UP{RESET}   {field:<10} {base[field]:>4} -> {now[field]:<4} "
                  f"({worse} than the frozen corpus)")
            regressions += 1
    # A crash can cost at most `crashed` clean units. Anything beyond that is a
    # rule that started firing on a unit which used to scan clean.
    if now["clean_units"] < base["clean_units"] - max(crashed, 0):
        print(f"  {RED}DOWN{RESET} {'clean_units':<10} {base['clean_units']:>4} -> "
              f"{now['clean_units']:<4} (units that used to scan clean no longer do)")
        regressions += 1
    return regressions


def read_baseline(path: Path) -> dict | None:
    """The frozen file, or None with the reason printed.

    A file that cannot be parsed is not a file that says zero. Unguarded, a
    truncated or hand-edited baseline either raised out of the run or came back
    without the keys compare() reads — and absent counts read as a measured
    regression, which is the same lie in the other direction.
    """
    if not path.exists():
        print(f"  no frozen baseline at {path.name} — record one with: "
              f"make falsepos-freeze")
        return None
    try:
        base = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  the frozen baseline cannot be read ({type(exc).__name__}) — "
              f"restore it from git, or re-record it: make falsepos-freeze")
        return None
    if not isinstance(base, dict) or base.get("schema") != SCHEMA:
        got = base.get("schema") if isinstance(base, dict) else "not an object"
        print(f"  the frozen baseline is schema {got}, this build reads {SCHEMA}.")
        return None
    missing = [key for key in REQUIRED if key not in base]
    if missing:
        print(f"  the frozen baseline is missing {missing} — truncated or "
              f"hand-edited, so there is nothing to compare against.")
        return None
    return base


def freeze_report(report: dict, path: Path) -> int:
    """Record the baseline — unless there is no measurement to record."""
    if not report["units"]:
        print(f"{YELLOW}DID NOT RUN{RESET}  all {report['discovered']} discovered "
              f"unit(s) crashed the scanner.\n  Nothing was measured, so nothing "
              f"was frozen: a baseline of zero successful scans would make every "
              f"later run look clean.")
        return DID_NOT_RUN
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"froze {report['units']} scanned of {report['discovered']} discovered "
          f"units -> {path.name}")
    print(f"  {_summary(report)}")
    print(f"  {len(report['rule_headline_counts'])} rule ids carry a headline "
          f"finding somewhere in the corpus")
    if report["crashes"]:
        print(f"  {RED}warning{RESET}: {report['crashes']} crash(es) just became "
              f"the frozen normal. Fix them first unless you meant that.")
    return 0


def verdict(base: dict | None, now: dict) -> int:
    """The whole decision: 0 measured clean, 1 measured regression, 2 unmeasured.

    Three outcomes, never two. Only ONE fact sends a run to "did not measure":
    there is no comparable baseline, or the corpus itself is a different one.
    Everything the scanner does to a corpus that DID stay the same — including
    crashing on it — is a measurement, and gets measured.
    """
    if base is None:
        print(f"{YELLOW}DID NOT RUN{RESET}  no usable baseline; nothing was compared.")
        print(f"  current {_summary(now)}")
        return DID_NOT_RUN

    if base["discovered"] != now["discovered"]:
        print(f"{YELLOW}DID NOT RUN{RESET}  the corpus is not the one this baseline "
              f"was frozen on:\n  {base['discovered']} units frozen, "
              f"{now['discovered']} discovered.")
        print(f"  frozen  {_summary(base)}")
        print(f"  current {_summary(now)}")
        print(f"  Per-rule counts are only comparable against the same corpus, so "
              f"nothing was compared.\n  If an extension really was installed or "
              f"removed, re-freeze: make falsepos-freeze")
        return DID_NOT_RUN

    regressions = compare(base, now)
    if regressions:
        print(f"\n{RED}{regressions} regression(s){RESET} — a new finding above is "
              f"on software that is known to be fine; a crash is the scanner "
              f"failing on it.\nJustify or fix each one. Re-freeze only after "
              f"that: make falsepos-freeze")
        return 1
    print(f"\n{GREEN}no new findings on the real corpus{RESET}")
    return 0


def main(argv: list[str]) -> int:
    freeze = "--freeze" in argv
    positional = [a for a in argv if not a.startswith("--")]
    root = Path(positional[0] if positional else Path.home() / ".claude").expanduser()

    if not root.exists():
        print(f"{YELLOW}DID NOT RUN{RESET}  no corpus at the requested root.\n"
              f"  This check needs a directory of extensions you already trust; it "
              f"defaults to\n  Claude Code's, and CI does not have one. Pass "
              f"CORPUS=<dir>, or accept that\n  precision was NOT measured on this "
              f"run — it is deliberately not reported as a pass.")
        return DID_NOT_RUN

    report = collect_report(root)
    if report is None:
        print(f"{YELLOW}DID NOT RUN{RESET}  the corpus root exists but holds no "
              f"installation units.\n  Nothing was measured; this is not a pass.")
        return DID_NOT_RUN

    if freeze:
        return freeze_report(report, BASELINE)

    print(f"precision baseline: {BASELINE.relative_to(PROJECT)}\n")
    return verdict(read_baseline(BASELINE), report)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
