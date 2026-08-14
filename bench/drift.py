"""Freeze the real-corpus report, then diff against it — in BOTH directions.

`make falsepos` measures the number that decides whether this tool is usable:
how much noise it makes against extensions that are known to be fine. It prints
that number and forgets it. Nothing compared today's report to yesterday's, so a
rule that started firing on real, trusted software showed up as a slightly
larger number in a scrolling report and nobody had to justify it.

This freezes the report and fails on drift either way:

  MORE findings than frozen   precision: a rule started firing on trusted software
  FEWER findings than frozen  recall: a rule stopped firing on real software

    python -m bench.drift --freeze [corpus]   record bench/drift-baseline.json
    python -m bench.drift [corpus]            diff current against the frozen file

WHY THE SECOND DIRECTION EXISTS
-------------------------------
The first version of this file guarded precision only, and a decrease printed as
"an improvement; re-freeze to lock it in". So a change that dropped one token
from AGT-002's object alternation to kill a false positive also removed a real
detection on an installed extension, and this benchmark exited 0.

The obvious fix does not work. The frozen numbers reduced the corpus to what
LEADS a report, and that AGT-002 was reported at low confidence — `headline()`
excludes low confidence, so it was never in `rule_headline_counts` and no guard
built on those counts could have seen it go. On this machine that is not an edge
case: 39 of the 58 rules that fire on the corpus fire ONLY outside the headline,
1415 findings against 125 headline ones. The recall guard therefore needs a
census of EVERY reported finding — `headline()` decides what leads, never what
is reported — which is what `rule_finding_counts` is.

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
  rule_headline_counts   {rule id: headline findings}     ids from RULES.md only
  finding_total          every finding reported, headline or not
  rule_finding_counts    {rule id: findings reported}     the recall census
  unit_histogram         {finding count: how many units}  the shape, unnamed

Deliberately excluded, because each one leaks:

  the corpus root path            absolute path and the username inside it
  unit names ("worst units")      the list of extensions the user has installed
  crash text                      exception messages carry paths and file content
  any finding evidence            by construction: nothing below rule-id level

That privacy floor is also this guard's blind spot, and it is worth naming: with
counts alone, a change that loses a finding on one unit and gains one on another
nets to zero and passes. Seeing that would need per-unit identity, which is the
one thing this file may never carry. `make coverage` holds the per-unit version
of that question against fixtures, where names are ours to publish.

Normalised for stability: every mapping is written sorted by key, so a rerun
produces byte-identical output; `mean` is rounded to two places, since an
unrounded float turns a no-op rerun into a diff.

CORPUS-BOUND ON PURPOSE
-----------------------
The counts only mean something against the corpus they were frozen on. If the
corpus is missing (CI, a fresh clone) or a different number of units is
DISCOVERED (an extension was installed or removed), this exits 2 — "did not
run" — rather than 0. A check that reports success when it measured nothing is
the exact shape of defect this whole benchmark exists to catch.

Discovered and scanned are separate facts on purpose. A unit that raises is
still discovered — the corpus did not change, the scanner broke — so it is a
REGRESSION, never "did not run". One count for both made that unreachable: the
crash shrank the corpus, tripped the guard above, and reported the loudest
failure this benchmark can see as an inability to measure it.

  exit 0   measured, no drift
  exit 1   measured, a regression a human has to justify — new findings on
           trusted software, lost findings on real software, or a crash
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
BASELINE = PROJECT / "bench" / "drift-baseline.json"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

# 3 added the recall census (finding_total, rule_finding_counts). The bump is
# load-bearing: read as schema 3, a schema-2 file has no census at all, and an
# absent census is not a census of zero — it would read as every rule on the
# corpus having stopped firing at once. read_baseline() refuses it instead, and
# the run degrades to "did not measure" until a human re-freezes.
SCHEMA = 3

DID_NOT_RUN = 2

# What compare() reads. A baseline missing any of them is truncated, not zero.
REQUIRED = ("discovered", "units", "clean_units", "clean_pct", "median", "mean",
            "p90", "max", "crashes", "headline_total", "rule_headline_counts",
            "finding_total", "rule_finding_counts")

# Every key that may be written to the public baseline. Enumerated rather than
# implied so adding a field to collect_report() is a decision somebody makes
# on purpose: this is the list a privacy review reads, and a test asserts the
# frozen report carries nothing outside it.
FROZEN_KEYS = ("schema", "discovered", "units", "clean_units", "clean_pct",
               "median", "mean", "p90", "max", "crashes", "headline_total",
               "rule_headline_counts", "finding_total", "rule_finding_counts",
               "unit_histogram")


def collect_report(root: Path) -> dict | None:
    """Scan the corpus and reduce it to the publishable aggregate.

    Returns None when the corpus holds nothing at all. A unit that raises is
    still counted in `discovered`: it is the scanner that broke, not the corpus
    that changed, and the two have to stay separable downstream.

    TWO per-rule counters, and the difference between them is the whole point.
    `rule_headline_counts` counts what LEADS a report — the precision number, the
    noise a human pays for. `rule_finding_counts` counts what is REPORTED, lead
    or not — the recall census, because a finding that drops out of the headline
    is still on the page while a finding that stops being produced is gone. Only
    the second one can see a detection disappear at low confidence, which is
    exactly how one disappeared unnoticed.

    Note what never enters the dict: no path, no unit name, no exception text.
    The reduction happens here rather than at write time so there is one place
    to audit for a leak.
    """
    units = discover(root)
    if not units:
        return None

    rule_counts: collections.Counter = collections.Counter()
    census: collections.Counter = collections.Counter()
    histogram: collections.Counter = collections.Counter()
    crashes = 0
    clean = 0
    counts: list[int] = []
    findings_seen = 0

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
        # Every finding the report carries, headline or body, high confidence or
        # low. `findings` is what report.to_json publishes verbatim, so this
        # census is a census of what the user is actually told.
        findings_seen += len(findings)
        for finding in findings:
            census[finding.id] += 1
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
        "finding_total": findings_seen,
        "rule_finding_counts": dict(sorted(census.items())),
        "unit_histogram": {str(k): histogram[k] for k in sorted(histogram)},
    }


def _summary(report: dict) -> str:
    return (f"{report['discovered']} discovered   {report['units']} scanned   "
            f"clean {report['clean_units']} "
            f"({report['clean_pct']}%)   median {report['median']}   "
            f"mean {report['mean']}   p90 {report['p90']}   max {report['max']}   "
            f"crashes {report['crashes']}   "
            f"reported {report['finding_total']}")


def _compare_census(base: dict, now: dict, crashed: int) -> int:
    """The recall half: every finding reported, not only the ones that lead.

    A DECREASE here is a regression, symmetric to a new finding above, and for a
    worse reason. A new finding is noise a human sees and argues with; a lost
    finding is silence, and silence is what a pre-install audit cannot recover
    from — nobody re-reads a report that said nothing.

    So a decrease is never announced as an improvement. The one honest way to
    make a count go DOWN is for the finding to have been a false positive, and
    that is a claim about specific evidence in specific units, which a number
    cannot make. A human makes it and re-freezes.

    THE CRASH INTERACTION, stated exactly. When more units raise than when the
    baseline was frozen, every decrease below is printed `UNPROVEN` and adds no
    regression: a unit that did not scan reports nothing, so its findings are
    missing for a reason that is not a rule change, and this file cannot tell the
    two apart with counts alone. That suppression can never turn a lost detection
    into a pass, because the crash itself already counted as a regression in
    compare() — the run exits 1 either way, and the message says the recall
    question was NOT answered rather than answering it wrongly. Nothing is
    tolerated silently: it is the crash that has to be fixed before the recall
    number means anything again. Increases are never suppressed, since scanning
    fewer units cannot explain finding more.
    """
    before = base.get("rule_finding_counts", {})
    after = now.get("rule_finding_counts", {})
    regressions = 0

    print(f"  {DIM}census — every finding reported, headline or not{RESET}")
    for rule_id in sorted(set(before) | set(after)):
        was, is_ = before.get(rule_id, 0), after.get(rule_id, 0)
        if was == is_:
            continue
        if is_ > was:
            tag = f"{RED}NEW{RESET}  " if not was else f"{RED}MORE{RESET} "
            print(f"  {tag} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"(+{is_ - was}) reported on real, trusted extensions")
            regressions += 1
        elif crashed > 0:
            print(f"  {YELLOW}UNPROVEN{RESET} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"({is_ - was}) fewer units were scanned, so whether this "
                  f"detection\n           was LOST cannot be told from here — "
                  f"fix the crash and re-run")
        else:
            tag = f"{RED}LOST{RESET}" if not is_ else f"{RED}DOWN{RESET}"
            gone = ("stopped firing on the corpus entirely" if not is_
                    else "is reported fewer times than it was")
            print(f"  {tag} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"({is_ - was}) {gone}")
            regressions += 1
    return regressions


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

    print(f"  {DIM}headline — what leads a report{RESET}")
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
            # NOT a regression, and not counted as one: a finding demoted out of
            # the headline is still in the report, so this is the noise going
            # down. The census below is what decides whether it is still there
            # at all — if it went with the headline, that loop fails the run.
            note = ("— fewer units were scanned, so this proves nothing"
                    if crashed > 0 else "— it no longer leads; the census below "
                    "says whether it is still reported")
            print(f"  {GREEN}DOWN{RESET} {rule_id:<10} {was:>4} -> {is_:<4} "
                  f"({is_ - was}) {note}")

    regressions += _compare_census(base, now, crashed)

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
              f"make drift-freeze")
        return None
    try:
        base = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  the frozen baseline cannot be read ({type(exc).__name__}) — "
              f"restore it from git, or re-record it: make drift-freeze")
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
    """Record the baseline — unless there is no measurement to record.

    The key filter is a privacy gate, not a schema nicety. This file is
    committed to a public repository and describes the software one person
    installed, so the write fails closed on any key nobody reviewed: adding a
    field upstream must not publish it here by accident.
    """
    if not report["units"]:
        print(f"{YELLOW}DID NOT RUN{RESET}  all {report['discovered']} discovered "
              f"unit(s) crashed the scanner.\n  Nothing was measured, so nothing "
              f"was frozen: a baseline of zero successful scans would make every "
              f"later run look clean.")
        return DID_NOT_RUN
    unknown = sorted(set(report) - set(FROZEN_KEYS))
    if unknown:
        print(f"{YELLOW}DID NOT RUN{RESET}  the report carries key(s) this file "
              f"has never published: {unknown}.\n  Nothing was written. The "
              f"baseline is public and describes installed software, so a new "
              f"field\n  gets reviewed for what it leaks and added to "
              f"FROZEN_KEYS on purpose.")
        return DID_NOT_RUN
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"froze {report['units']} scanned of {report['discovered']} discovered "
          f"units -> {path.name}")
    print(f"  {_summary(report)}")
    print(f"  {len(report['rule_headline_counts'])} rule ids lead a report "
          f"somewhere in the corpus; {len(report['rule_finding_counts'])} are "
          f"reported at all")
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
              f"removed, re-freeze: make drift-freeze")
        return DID_NOT_RUN

    regressions = compare(base, now)
    if regressions:
        print(f"\n{RED}{regressions} regression(s){RESET} — a new finding above is "
              f"on software that is known to be fine; a LOST one is a detection "
              f"this\ntool no longer makes on real software; a crash is the "
              f"scanner failing on it.\nJustify or fix each one. Re-freeze only "
              f"after that: make drift-freeze")
        return 1
    print(f"\n{GREEN}no drift on the real corpus{RESET} — nothing new, nothing lost")
    return 0


def main(argv: list[str]) -> int:
    freeze = "--freeze" in argv
    positional = [a for a in argv if not a.startswith("--")]
    root = Path(positional[0] if positional else Path.home() / ".claude").expanduser()

    if not root.exists():
        print(f"{YELLOW}DID NOT RUN{RESET}  no corpus at the requested root.\n"
              f"  This check needs a directory of extensions you already trust; it "
              f"defaults to\n  Claude Code's, and CI does not have one. Pass "
              f"CORPUS=<dir>, or accept that\n  neither precision nor recall was "
              f"measured on this run — it is deliberately not\n  reported as a "
              f"pass.")
        return DID_NOT_RUN

    report = collect_report(root)
    if report is None:
        print(f"{YELLOW}DID NOT RUN{RESET}  the corpus root exists but holds no "
              f"installation units.\n  Nothing was measured; this is not a pass.")
        return DID_NOT_RUN

    if freeze:
        return freeze_report(report, BASELINE)

    print(f"frozen corpus report: {BASELINE.relative_to(PROJECT)}\n")
    return verdict(read_baseline(BASELINE), report)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
