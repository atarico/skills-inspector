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
one thing THIS FILE may never carry — it exists instead, gitignored, never
committed, in LOCAL_KEYS below. `make coverage` holds the per-unit version of
that question against fixtures, where names are ours to publish.

Normalised for stability: every mapping is written sorted by key, so a rerun
produces byte-identical output; `mean` is rounded to two places, since an
unrounded float turns a no-op rerun into a diff.

CORPUS-BOUND ON PURPOSE
-----------------------
The counts only mean something against the corpus they were frozen on. If the
corpus is missing entirely (CI, a fresh clone), this exits 2 — "did not run" —
rather than 0. A check that reports success when it measured nothing is the
exact shape of defect this whole benchmark exists to catch.

A DIFFERENT NUMBER OF UNITS DISCOVERED (an extension was installed or removed)
used to mean the same blind refusal, unconditionally, and that was wrong: it
went blind exactly when a regression is likeliest to surface, and it died this
way twice in one week — once measuring nothing for 24 commits. `--freeze` now
also records a per-unit fingerprint map, keyed by the content signature from
`bench.corpus.signature`, into a GITIGNORED sidecar next to the baseline
(UNITS_SIDECAR, `bench/.drift-units.json`) — never the public file, see
LOCAL_KEYS below. When discovery disagrees, `verdict()` intersects that
sidecar against the CURRENT run's own per-unit map, restricts BOTH sides to
the units present in both, and runs the exact same compare() on the
restriction; a unit that appeared or disappeared is printed as information,
never silently folded into "did not measure". Losing the sidecar — a fresh
clone, a machine that has never frozen, a corrupted or wrong-schema file, or
an intersection of zero units — falls back to the old all-or-nothing refusal
exactly as it read before: the per-unit path is an optimisation over the
aggregate guard, and the guard must keep working without it.

Discovered and scanned are separate facts on purpose. A unit that raises is
still discovered — the corpus did not change, the scanner broke — so it is a
REGRESSION, never "did not run". One count for both made that unreachable: the
crash shrank the corpus, tripped the guard above, and reported the loudest
failure this benchmark can see as an inability to measure it.

  exit 0   measured, no drift
  exit 1   measured, a regression a human has to justify — new findings on
           trusted software, lost findings on real software, or a crash
  exit 2   did not measure — corpus absent or empty, or a different size with
           no usable per-unit sidecar, or no unit in common with one
"""

from __future__ import annotations

import collections
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.corpus import discover, signature  # noqa: E402
from scanner import engine  # noqa: E402
from scanner.unit import collect  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
BASELINE = PROJECT / "bench" / "drift-baseline.json"
UNITS_SIDECAR = PROJECT / "bench" / ".drift-units.json"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

# 3 added the recall census (finding_total, rule_finding_counts). The bump is
# load-bearing: read as schema 3, a schema-2 file has no census at all, and an
# absent census is not a census of zero — it would read as every rule on the
# corpus having stopped firing at once. read_baseline() refuses it instead, and
# the run degrades to "did not measure" until a human re-freezes.
SCHEMA = 3

# The sidecar's own schema, independent of the public baseline's. It has never
# been published and never needs to stay compatible with an old baseline, so
# it gets its own number rather than borrowing SCHEMA and coupling two files
# that are allowed to evolve separately.
UNITS_SCHEMA = 1

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

# Keys collect_report() computes but freeze_report() must NEVER write to
# BASELINE — the second reviewed list, alongside FROZEN_KEYS above.
# `unit_fingerprints` maps a content signature (bench.corpus.signature) to a
# per-unit finding record, and a signature is a confirmable fingerprint of
# software one specific person installed on one specific machine: exactly the
# per-unit identity the module docstring's privacy section says the public
# file may never carry. It is written instead to the gitignored UNITS_SIDECAR.
LOCAL_KEYS = ("unit_fingerprints",)


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

    ALSO RETURNS `unit_fingerprints`, in LOCAL_KEYS and never written to
    BASELINE (see freeze_report()). It maps each unit's content signature —
    the same `bench.corpus.signature` `discover()` already dedupes on — to a
    small record: whether the unit crashed, the rule id of every headline
    finding (with repeats, since rule_headline_counts counts findings, not
    distinct rules), and the rule id of every reported finding the same way.
    That is exactly enough to rebuild every aggregate field below for any
    SUBSET of units — see restrict_report() — without re-scanning anything.
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
    unit_fingerprints: dict[str, dict] = {}

    for path in units:
        sig = signature(path)
        try:
            unit = collect(path)
            findings, _ = engine.scan(unit)
        except Exception:
            # The message names a file on this machine. The count is the finding.
            crashes += 1
            unit_fingerprints[sig] = {"crashed": True, "headline_ids": [],
                                       "finding_ids": []}
            continue
        head = engine.headline(findings)
        counts.append(len(head))
        histogram[len(head)] += 1
        headline_ids = [finding.id for finding in head]
        for rule_id in headline_ids:
            rule_counts[rule_id] += 1
        # Every finding the report carries, headline or body, high confidence or
        # low. `findings` is what report.to_json publishes verbatim, so this
        # census is a census of what the user is actually told.
        finding_ids = [finding.id for finding in findings]
        findings_seen += len(finding_ids)
        for rule_id in finding_ids:
            census[rule_id] += 1
        if not head:
            clean += 1
        unit_fingerprints[sig] = {"crashed": False, "headline_ids": headline_ids,
                                   "finding_ids": finding_ids}

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
        "unit_fingerprints": unit_fingerprints,
    }


def restrict_report(report: dict, signatures) -> dict:
    """Rebuild the aggregate as if the corpus held only these units.

    This is what lets verdict() compare two runs whose DISCOVERED counts
    disagree: restrict both the frozen sidecar and the current run's own
    `unit_fingerprints` to the signatures they have in common, then run the
    exact same compare() the same-corpus path already uses. The result must
    be indistinguishable from a report collect_report() would have produced
    directly over that subset — which is why every field below is computed
    with the identical arithmetic collect_report() uses, `round(..., 2)` for
    `mean` and the `int(total * 0.9) - 1` index for `p90` included. Diverging
    by even one rounding rule would make a restricted comparison disagree
    with an unrestricted one for a reason that has nothing to do with drift.

    `report["unit_fingerprints"]` must already contain every signature in
    `signatures` — the caller (verdict()) computes the intersection first, so
    this never has to guess what a missing signature means.
    """
    fingerprints = report["unit_fingerprints"]
    rule_counts: collections.Counter = collections.Counter()
    census: collections.Counter = collections.Counter()
    histogram: collections.Counter = collections.Counter()
    crashes = 0
    clean = 0
    counts: list[int] = []
    findings_seen = 0

    for sig in signatures:
        record = fingerprints[sig]
        if record["crashed"]:
            crashes += 1
            continue
        headline_ids = record["headline_ids"]
        counts.append(len(headline_ids))
        histogram[len(headline_ids)] += 1
        for rule_id in headline_ids:
            rule_counts[rule_id] += 1
        finding_ids = record["finding_ids"]
        findings_seen += len(finding_ids)
        for rule_id in finding_ids:
            census[rule_id] += 1
        if not headline_ids:
            clean += 1

    counts.sort()
    total = len(counts) or 1
    return {
        "schema": report.get("schema", SCHEMA),
        "discovered": len(signatures),
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


def path_name(path: Path) -> str:
    """Just the file name. The baseline is public; this message is not
    the place a home directory starts appearing in terminal output."""
    return path.name


def baseline_digest(report: dict) -> str:
    """Which freeze a sidecar belongs to, in one field.

    The per-unit path takes its BEFORE numbers from the sidecar rather than
    from the public baseline, which is correct only while the two are the same
    freeze. Nothing made them say so, and they come apart in the way
    read_baseline() itself recommends out loud — "restore it from git". An
    older baseline restored beside a newer local sidecar compared against the
    sidecar and reported a rule that had stopped firing entirely as clean.

    LOCAL_KEYS are stripped and the keys are sorted, so the digest of a
    baseline is the digest of that same baseline after a json round trip. A
    guard that broke on key order would fire on files nobody edited, and a
    guard that cries wolf gets deleted.
    """
    published = {key: value for key, value in report.items()
                 if key not in LOCAL_KEYS}
    payload = json.dumps(published, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def freeze_report(report: dict, path: Path, units_path: Path = UNITS_SIDECAR) -> int:
    """Record the baseline — unless there is no measurement to record.

    The key filter is a privacy gate, not a schema nicety. This file is
    committed to a public repository and describes the software one person
    installed, so the write fails closed on any key nobody reviewed: adding a
    field upstream must not publish it here by accident.

    LOCAL_KEYS is stripped BEFORE that filter runs, not after — `report` may
    legitimately carry `unit_fingerprints` (collect_report() always adds it
    now), and it must never be able to trip "the report carries key(s) this
    file has never published" for a field this file itself computes. Once
    stripped, what remains is written to `path` exactly as before; the
    stripped-off local data is written separately to `units_path`, which is
    gitignored and gets its own schema (UNITS_SCHEMA) because nothing commits
    it to compatibility with an old public baseline.

    A sidecar write failure is reported, never fatal: `path` is the contract
    `make drift-freeze` exists to keep, and `units_path` is an optimisation
    over `verdict()`'s aggregate fallback. Losing write access to a gitignored
    file (a read-only checkout, a full disk) must not stop the real freeze.
    """
    if not report["units"]:
        print(f"{YELLOW}DID NOT RUN{RESET}  all {report['discovered']} discovered "
              f"unit(s) crashed the scanner.\n  Nothing was measured, so nothing "
              f"was frozen: a baseline of zero successful scans would make every "
              f"later run look clean.")
        return DID_NOT_RUN
    local = {key: report[key] for key in LOCAL_KEYS if key in report}
    published = {key: value for key, value in report.items() if key not in local}
    unknown = sorted(set(published) - set(FROZEN_KEYS))
    if unknown:
        print(f"{YELLOW}DID NOT RUN{RESET}  the report carries key(s) this file "
              f"has never published: {unknown}.\n  Nothing was written. The "
              f"baseline is public and describes installed software, so a new "
              f"field\n  gets reviewed for what it leaks and added to "
              f"FROZEN_KEYS on purpose.")
        return DID_NOT_RUN
    path.write_text(json.dumps(published, indent=2) + "\n", encoding="utf-8")
    print(f"froze {published['units']} scanned of {published['discovered']} "
          f"discovered units -> {path.name}")
    print(f"  {_summary(published)}")
    print(f"  {len(published['rule_headline_counts'])} rule ids lead a report "
          f"somewhere in the corpus; {len(published['rule_finding_counts'])} are "
          f"reported at all")
    if published["crashes"]:
        print(f"  {RED}warning{RESET}: {published['crashes']} crash(es) just "
              f"became the frozen normal. Fix them first unless you meant that.")
    if "unit_fingerprints" in local:
        try:
            units_path.write_text(
                json.dumps({"schema": UNITS_SCHEMA,
                            "baseline_digest": baseline_digest(published),
                            "unit_fingerprints": local["unit_fingerprints"]},
                           indent=2) + "\n", encoding="utf-8")
            print(f"  {len(local['unit_fingerprints'])} per-unit fingerprint(s) "
                  f"-> {units_path.name} (gitignored — verdict() falls back to "
                  f"comparing the whole corpus when the size changes and this "
                  f"file is missing or stale)")
        except OSError as exc:
            print(f"  {YELLOW}warning{RESET}: could not write {units_path.name} "
                  f"({type(exc).__name__}) — the public baseline above is still "
                  f"the frozen contract; only the per-unit fallback for a "
                  f"changed corpus size is unavailable until this is fixed.")
    return 0


def _load_units_sidecar(path: Path) -> dict | None:
    """The frozen per-unit fingerprint map, or None with nothing printed.

    Silent on failure on purpose: every caller treats None as "fall back to
    the aggregate-only comparison", which already explains itself, so an
    extra message here would either repeat that one or contradict it. A file
    that is missing, unreadable, not an object, or stamped with a schema this
    build does not read is the SAME situation as never having frozen at all —
    a fresh clone must land here exactly as a stale or corrupt sidecar does.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != UNITS_SCHEMA:
        return None
    fingerprints = payload.get("unit_fingerprints")
    return payload if isinstance(fingerprints, dict) else None


def verdict(base: dict | None, now: dict, units_path: Path = UNITS_SIDECAR) -> int:
    """The whole decision: 0 measured clean, 1 measured regression, 2 unmeasured.

    Three outcomes, never two. Only ONE fact sends a run to "did not measure":
    there is no comparable baseline, or the corpus itself is a different one
    with no per-unit way to narrow the comparison. Everything the scanner does
    to a corpus that DID stay the same — including crashing on it — is a
    measurement, and gets measured.

    WHEN DISCOVERY DISAGREES, this used to stop here unconditionally — see the
    module docstring's CORPUS-BOUND section for why that is exactly the wrong
    moment to go blind. Before giving up, it now tries the per-unit path:
    load UNITS_SIDECAR (the fingerprint map `--freeze` wrote for `base`),
    intersect its signatures with `now`'s own `unit_fingerprints`, and if
    anything survives, restrict BOTH sides to that intersection and run the
    exact same compare() the same-corpus path uses. Appeared and disappeared
    units are printed as information — never silently dropped, and never
    folded into a regression count they had nothing to do with.

    Any reason the per-unit path cannot run — no sidecar, a wrong schema, a
    `now` with no `unit_fingerprints` (a caller that built one by hand,
    matching REQUIRED but not this), or an intersection of zero units — falls
    through to the ORIGINAL message below, unchanged, because that path has
    to keep working on a fresh clone where the sidecar has never existed.
    """
    if base is None:
        print(f"{YELLOW}DID NOT RUN{RESET}  no usable baseline; nothing was compared.")
        print(f"  current {_summary(now)}")
        return DID_NOT_RUN

    if base["discovered"] != now["discovered"]:
        now_fingerprints = now.get("unit_fingerprints")
        payload = _load_units_sidecar(units_path)
        if payload is not None and payload.get("baseline_digest") != baseline_digest(base):
            # NOT reported as an ordinary corpus mismatch, because that message
            # ends in "re-freeze" and re-freezing is the one action that
            # destroys the evidence of which freeze this sidecar came from.
            print(f"{YELLOW}DID NOT RUN{RESET}  the per-unit fingerprints in "
                  f"{units_path.name} were written beside a different freeze "
                  f"than\n  {path_name(BASELINE)}, so they cannot say what "
                  f"these units reported before.")
            print(f"  frozen  {_summary(base)}")
            print(f"  current {_summary(now)}")
            print(f"  Nothing was compared. This happens when the baseline is "
                  f"restored from git while the\n  gitignored sidecar stays "
                  f"local. Re-freeze ONLY if the restored baseline is the one "
                  f"you\n  meant to keep: make drift-freeze")
            return DID_NOT_RUN
        sidecar = payload.get("unit_fingerprints") if payload else None
        if sidecar and isinstance(now_fingerprints, dict):
            shared = set(sidecar) & set(now_fingerprints)
            if shared:
                appeared = len(now_fingerprints) - len(shared)
                gone = len(sidecar) - len(shared)
                print(f"  {YELLOW}corpus size changed{RESET} — comparing units "
                      f"present in both: {len(shared)} shared, {appeared} new, "
                      f"{gone} gone.\n")
                restricted_base = restrict_report({"unit_fingerprints": sidecar},
                                                   shared)
                restricted_now = restrict_report(now, shared)
                regressions = compare(restricted_base, restricted_now)
                if regressions:
                    print(f"\n{RED}{regressions} regression(s){RESET} among the "
                          f"{len(shared)} shared unit(s) — a new finding above is "
                          f"on software that is known to be fine; a LOST one is a "
                          f"detection this\ntool no longer makes on real "
                          f"software; a crash is the scanner failing on it.\n"
                          f"Justify or fix each one. Re-freeze only after that: "
                          f"make drift-freeze")
                    return 1
                print(f"\n{GREEN}no drift on the {len(shared)} shared unit(s)"
                      f"{RESET} — nothing new, nothing lost. {appeared} new "
                      f"unit(s) and {gone} removed unit(s) were not compared; "
                      f"re-freeze to fold them into the baseline: "
                      f"make drift-freeze")
                return 0
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
