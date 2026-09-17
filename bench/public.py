"""False-positive benchmark against a public, reproducible corpus.

`bench.corpus` and `bench.drift` answer the question that decides whether
this tool is usable — how much noise it makes against extensions that are
known to be fine — but only against `$HOME/.claude`. The Makefile has said so
since `falsepos` was written: it reads a machine-specific directory CI does
not have, and its output names the operator's own installed extensions, so
the report cannot be published either. `openclaw/clawscan` issue #53 asks for
benchmark evidence a third party can check; a number nobody else can
reproduce is not evidence.

This is the second corpus: `bench/public-corpus.json`, 253 plugins pinned by
exact git sha out of Anthropic's `claude-plugins-official` marketplace
manifest, vendored and committed so this benchmark needs nothing but network
access to reproduce. Fetching happens here, one unit at a time, from the
GitHub codeload tarball for the pinned sha; measurement reuses
`bench.corpus.report_for_units` — the exact arithmetic `bench.drift` freezes
— rather than a second copy of it.

    python -m bench.public --limit 5            fetch, measure, print
    python -m bench.public --limit 5 --freeze    record bench/public-baseline.json
    python -m bench.public                       the full 253-unit corpus (network-heavy)

THE GOVERNING PRINCIPLE, and it is why `bench/public-corpus.json` has two
top-level lists instead of one. This benchmark refuses to measure what it
cannot pin: 52 of the 305 marketplace entries carry no sha at all (a plain
relative path into the marketplace repository itself, not an external git
reference), so there is nothing immutable to fetch and compare against
tomorrow. They are EXCLUDED, and the exclusion is RECORDED — see
`bench/public-corpus.json`'s `excluded` list, one reason per entry — never
silently dropped from a percentage. A benchmark that quietly measures 253 of
305 units and reports it as "the corpus" is the exact defect class this
repository has fixed three times over: a climb that stops and calls its last
answer the whole search, a scope that never widened counted as a scope that
was searched, a pruned directory the report never admitted to skipping.

THREE OUTCOMES, matching the convention `bench.drift` documents, because a
check that reports success when it measured nothing is the failure mode this
whole file exists to catch:

  exit 0   measured — and, when a frozen baseline exists for the same unit
           set, consistent with it. No baseline yet is not a failure; it is
           what every corpus looks like before its first `--freeze`.
  exit 1   measured, and a regression against the frozen baseline a human
           has to justify — same shape as `bench.drift`: a new finding on
           trusted software, a lost one, or a crash.
  exit 2   did not run — the cache was empty and the network unreachable, a
           unit failed to fetch (a 404, an archived or renamed repository, a
           timeout), or fewer units were fetched than this run requested.
           Every fetch failure is counted and named above this line, never
           folded into a clean-looking smaller corpus.

WHY THIS NEVER JOINS `make check`. It needs network, exactly like
`falsepos`/`drift`, and it downloads from GitHub on every invocation unless
the cache already holds the sha — unsuitable for a target that has to pass
offline and fast in CI.

WHAT THE FROZEN FILE MAY CARRY, and why the answer is more here than in
`bench/drift-baseline.json`. That file's corpus is software one person
installed, so it is scrubbed down to aggregate counts and rule ids — no unit
names, no paths. This corpus is a public marketplace manifest: the unit
names are already published in `bench/public-corpus.json`, so
`bench/public-baseline.json` records them too, as `unit_names`. That is what
lets a corpus-size mismatch be detected EXACTLY, by the set of names that
were measured, rather than by count alone — `bench.drift` cannot do this
without a gitignored, privacy-sensitive sidecar; this file does not need one.
"""

from __future__ import annotations

import json
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.corpus import report_for_units  # noqa: E402
from bench.drift import compare  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
CORPUS = PROJECT / "bench" / "public-corpus.json"
BASELINE = PROJECT / "bench" / "public-baseline.json"
DEFAULT_CACHE = PROJECT / "bench" / ".public-cache"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

SCHEMA = 1
DID_NOT_RUN = 2
FETCH_TIMEOUT = 30

CODELOAD = "https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}"

# What compare()/_summary() read, plus `unit_names` — the extra field this
# benchmark's comparability check needs that bench.drift cannot publish (see
# module docstring). A baseline missing any of these is truncated, not zero.
REQUIRED = ("discovered", "units", "clean_units", "clean_pct", "median", "mean",
            "p90", "max", "crashes", "headline_total", "rule_headline_counts",
            "finding_total", "rule_finding_counts", "unit_names")

# Every key that may be written to bench/public-baseline.json. Enumerated
# rather than implied, exactly as bench.drift.FROZEN_KEYS is: a new field on
# the report is a decision somebody makes on purpose, not something that
# reaches a committed file because nobody subtracted it out.
FROZEN_KEYS = ("schema", "limit", "marketplace_json_sha256", "unit_names",
               "discovered", "units", "clean_units", "clean_pct", "median",
               "mean", "p90", "max", "crashes", "headline_total",
               "rule_headline_counts", "finding_total", "rule_finding_counts",
               "unit_histogram")

# report_for_units() also returns `unit_fingerprints` — headline/finding ids
# per unit NAME. Unlike bench.drift's content-signature fingerprints, a name
# here is already public (bench/public-corpus.json says so), so keeping it
# out of FROZEN_KEYS is not a privacy decision; it is just unneeded for the
# name-set comparability check this file actually does, and every published
# key stays reviewed rather than growing by accident.
LOCAL_KEYS = ("unit_fingerprints",)

# How many rows each census in `_breakdown` prints before it stops. Twelve is
# `bench.corpus`'s number, kept so the two benchmarks read the same way; the
# difference is that this one names what it left out.
BREAKDOWN_ROWS = 12


def load_corpus(path: Path = CORPUS) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def select(corpus: dict, limit: int | None) -> list[dict]:
    """The units this run measures: the first `limit` by name, or all of
    them. Sorted explicitly rather than trusting the file's own order, so a
    hand-edited or regenerated corpus.json cannot silently change which
    units a fixed `--limit` picks."""
    units = sorted(corpus["units"], key=lambda u: u["name"])
    return units[:limit] if limit else units


def _owner_repo(url: str) -> tuple[str, str]:
    """https://github.com/OWNER/REPO.git -> (OWNER, REPO)."""
    path = urlparse(url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    owner, _, repo = path.partition("/")
    return owner, repo


def fetch_unit(unit: dict, cache_dir: Path,
                timeout: int = FETCH_TIMEOUT) -> tuple[Path | None, str]:
    """Fetch one pinned unit's exact sha into the cache.

    Keyed `<sha>/<path>` (path "" for the 153 pinned units that are a whole
    repository, not a subdirectory) — a cached unit is never re-downloaded,
    and a changed sha is a different key, never a silent overwrite of one
    that scanned differently.

    The whole-repository tarball is fetched (codeload has no endpoint for a
    single subtree), then only the entries under `path` are extracted and
    everything else is discarded — cheaper than a full clone, which would
    also carry the git history and every other subdirectory this benchmark
    never reads.

    Returns (root, reason). `root` is the extracted directory on success, or
    None with `reason` naming why the fetch failed — a 404, an archived
    repository, a timeout, a corrupt tarball, or the pinned `path` being
    absent from that sha's tree. Extraction lands in a temp directory first
    and is moved into place only once every entry has been written, so a
    fetch that fails partway never leaves a directory a later run mistakes
    for a cache hit.
    """
    sha, path = unit["sha"], unit["path"]
    dest = cache_dir / sha / path if path else cache_dir / sha
    if dest.is_dir() and any(dest.iterdir()):
        return dest, "cached"

    owner, repo = _owner_repo(unit["url"])
    if not owner or not repo:
        return None, f"unparseable repository url: {unit['url']!r}"

    # NOT nested under `dest` (or under `cache_dir / sha`, dest's parent when
    # `path` is "") — the cleanup below removes any stale `dest` before the
    # final move, and a tmp dir living inside the thing it is about to
    # delete would delete itself out from under the extraction in progress.
    tmp = cache_dir / f".fetch-{sha[:12]}-{uuid.uuid4().hex[:12]}"
    tmp.mkdir(parents=True, exist_ok=True)
    extracted_any = False
    try:
        url = CODELOAD.format(owner=owner, repo=repo, sha=sha)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            with tarfile.open(fileobj=resp, mode="r|gz") as tar:
                prefix = None
                for member in tar:
                    if prefix is None:
                        # codeload's top-level directory name varies with the
                        # ref shape (tag, branch, sha); read it from the
                        # archive instead of assuming one.
                        top = member.name.split("/", 1)[0]
                        prefix = f"{top}/{path}/" if path else f"{top}/"
                    if not member.name.startswith(prefix):
                        continue
                    if member.issym() or member.islnk():
                        # A symlink escaping the unit is a finding the
                        # scanner itself reports (FSW-008) once the unit is
                        # collected; following one here, before that check
                        # runs, could write outside `tmp`.
                        continue
                    rel = member.name[len(prefix):]
                    if not rel:
                        continue
                    target = tmp / rel
                    if not target.resolve().is_relative_to(tmp.resolve()):
                        continue
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        fh = tar.extractfile(member)
                        if fh is None:
                            continue
                        target.write_bytes(fh.read())
                        if member.mode & 0o111:
                            target.chmod(target.stat().st_mode | 0o111)
                        extracted_any = True
    except urllib.error.HTTPError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"HTTP {exc.code} fetching {sha[:12]}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"{type(exc).__name__} fetching {sha[:12]}"
    except tarfile.TarError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"corrupt tarball ({type(exc).__name__})"

    if not extracted_any:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"{path or '(repository root)'} not present at {sha[:12]}"

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(tmp), str(dest))
    return dest, "fetched"


def _summary(report: dict) -> str:
    return (f"{report['discovered']} discovered   {report['units']} scanned   "
            f"clean {report['clean_units']} ({report['clean_pct']}%)   "
            f"median {report['median']}   mean {report['mean']}   "
            f"p90 {report['p90']}   max {report['max']}   "
            f"crashes {report['crashes']}   reported {report['finding_total']}")


def _breakdown(report: dict) -> None:
    """Print the per-rule and per-unit censuses behind the summary line.

    NOTHING HERE IS COMPUTED. `rule_headline_counts` and `unit_fingerprints`
    come straight out of `bench.corpus.report_for_units` — the same function
    `bench.drift` freezes — and this only orders and prints them. That is the
    point: a breakdown doing its own arithmetic could disagree with the
    aggregate it sits under, and a report whose halves contradict each other
    is the defect class this whole benchmark exists to refuse.

    WHY IT EXISTS. Issue #53 asks for benchmark evidence a third party can
    check, and `_summary`'s single line cannot be checked — it says
    `clean 47 (20%)` and hands the reader nothing to look at when they doubt
    it. The rules that lead, and the units they lead on, are what turn a
    percentage into a claim somebody else can go verify against the same
    pinned shas.

    WHY IT MAY NAME UNITS, when `bench.drift` may not: this corpus is a
    public marketplace manifest and every name here is already published in
    `bench/public-corpus.json`. See `bench.corpus.report_for_units` for the
    half of this that stays anonymous and why.

    ORDER IS COUNT DESCENDING, ties broken by rule id and by unit name —
    never by the order a Counter happened to see them. A table that
    reshuffles between two runs over the same corpus is not reproducible
    evidence, whatever the numbers in it say.

    BOTH LISTS CUT AT `BREAKDOWN_ROWS`, AND BOTH SAY SO, with what they cut
    accounted for rather than implied. `bench.corpus` prints a flat twelve
    rows with no sign that a thirteenth rule fired; that is the same shape as
    a climb that stopped and called its last answer the whole search, a scope
    that never widened counted as a scope that was searched, and a pruned
    directory the report never admitted to skipping. Three fixes in the
    scanner, and the benchmark that publishes its number should not reopen it.
    """
    rules = report.get("rule_headline_counts", {})
    fingerprints = report.get("unit_fingerprints", {})
    scanned = report["units"]

    print(f"\nnoisiest rules (headline hits across {scanned} scanned unit(s)):")
    if not rules:
        print("  none — no scanned unit produced a headline finding")
    else:
        ranked = sorted(rules.items(), key=lambda row: (-row[1], row[0]))
        for rule_id, hits in ranked[:BREAKDOWN_ROWS]:
            print(f"  {rule_id:<10} {hits:>4}")
        print(f"  {DIM}listed {min(len(ranked), BREAKDOWN_ROWS)} of "
              f"{len(ranked)} rule(s) that fired; --freeze records the "
              f"complete census{RESET}")

    # A crashed unit has no findings to rank, and ranking it at zero would put
    # it among the quiet ones — a unit that never ran reading as evidence of
    # quiet. It gets its own section below instead.
    noisy = [(len(row["headline_ids"]), name, row["headline_ids"])
             for name, row in fingerprints.items()
             if not row["crashed"] and row["headline_ids"]]

    print("\nworst units (headline findings, and the rules that fired):")
    if not noisy:
        print(f"  none — all {scanned} scanned unit(s) are clean")
    else:
        for hits, name, ids in sorted(noisy, key=lambda row: (-row[0], row[1]))[:BREAKDOWN_ROWS]:
            print(f"  {hits:>4}  {name:<34} {DIM}{' '.join(sorted(set(ids)))}{RESET}")
        print(f"  {DIM}listed {min(len(noisy), BREAKDOWN_ROWS)} of "
              f"{len(noisy)} unit(s) with a headline finding; the other "
              f"{report['clean_units']} scanned unit(s) are clean{RESET}")

    # Names only, and deliberately no exception text: it would name a path
    # inside the local cache directory, which is the one thing about this
    # report that is not reproducible anywhere else. `report_for_units` drops
    # it at the source for the same reason; reproduce a crash by scanning the
    # named unit out of bench/.public-cache directly.
    crashed = sorted(name for name, row in fingerprints.items() if row["crashed"])
    if crashed:
        print(f"\ncrashed ({len(crashed)} unit(s) — counted above, and in "
              f"none of the numbers):")
        for name in crashed[:BREAKDOWN_ROWS]:
            print(f"  {name}")
        if len(crashed) > BREAKDOWN_ROWS:
            print(f"  {DIM}listed {BREAKDOWN_ROWS} of {len(crashed)}{RESET}")


def read_baseline(path: Path) -> dict | None:
    """The frozen public report, or None with the reason printed.

    Same discipline as `bench.drift.read_baseline` — a truncated or
    hand-edited baseline must never read as zero regressions."""
    if not path.exists():
        return None
    try:
        base = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  the frozen public baseline cannot be read "
              f"({type(exc).__name__}) — restore it from git, or re-record "
              f"it: make bench-public-freeze")
        return None
    if not isinstance(base, dict) or base.get("schema") != SCHEMA:
        got = base.get("schema") if isinstance(base, dict) else "not an object"
        print(f"  the frozen public baseline is schema {got}, this build "
              f"reads {SCHEMA}.")
        return None
    missing = [key for key in REQUIRED if key not in base]
    if missing:
        print(f"  the frozen public baseline is missing {missing} — "
              f"truncated or hand-edited, nothing to compare against.")
        return None
    return base


def freeze_report(report: dict) -> int:
    """Record bench/public-baseline.json — unless nothing was measured.

    Fails closed on any key this file has never reviewed, exactly like
    `bench.drift.freeze_report` — adding a field upstream must be a decision
    someone makes here on purpose, not a silent addition to a committed
    file."""
    if not report["units"]:
        print(f"{YELLOW}DID NOT RUN{RESET}  all {report['discovered']} "
              f"fetched unit(s) crashed the scanner.\n  Nothing was frozen: "
              f"a baseline of zero successful scans would make every later "
              f"run look clean.")
        return DID_NOT_RUN

    local = {key: report[key] for key in LOCAL_KEYS if key in report}
    published = {key: value for key, value in report.items() if key not in local}
    unknown = sorted(set(published) - set(FROZEN_KEYS))
    if unknown:
        print(f"{YELLOW}DID NOT RUN{RESET}  the report carries key(s) this "
              f"file has never published: {unknown}.\n  Nothing was "
              f"written — a new field gets reviewed for what it says and "
              f"added to FROZEN_KEYS on purpose.")
        return DID_NOT_RUN

    published = {key: published[key] for key in FROZEN_KEYS}
    BASELINE.write_text(json.dumps(published, indent=2) + "\n", encoding="utf-8")
    print(f"\nfroze {published['units']} scanned of {published['discovered']} "
          f"requested unit(s) -> {BASELINE.name}")
    print(f"  {_summary(published)}")
    if published["crashes"]:
        print(f"  {RED}warning{RESET}: {published['crashes']} crash(es) "
              f"just became the frozen normal. Fix them first unless you "
              f"meant that.")
    return 0


def main(argv: list[str]) -> int:
    freeze = False
    limit: int | None = None
    cache_dir = DEFAULT_CACHE
    timeout = FETCH_TIMEOUT

    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--freeze":
            freeze = True
        elif arg == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 1
        elif arg == "--cache" and i + 1 < len(args):
            cache_dir = Path(args[i + 1]).expanduser()
            i += 1
        elif arg == "--timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 1
        i += 1

    try:
        corpus = load_corpus()
    except (OSError, ValueError) as exc:
        print(f"{YELLOW}DID NOT RUN{RESET}  bench/public-corpus.json could "
              f"not be read ({type(exc).__name__}).")
        return DID_NOT_RUN

    requested = select(corpus, limit)
    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched: list[tuple[str, Path]] = []
    fetch_failures: list[tuple[str, str]] = []
    for unit in requested:
        root, reason = fetch_unit(unit, cache_dir, timeout)
        if root is None:
            fetch_failures.append((unit["name"], reason))
        else:
            fetched.append((unit["name"], root))

    print(f"public corpus: {len(requested)} unit(s) requested "
          f"({corpus['provenance']['pinned']} pinned in {CORPUS.name}"
          f"{f', limit={limit}' if limit else ''})")
    print(f"  fetched {len(fetched)}/{len(requested)}" +
          (f", {len(fetch_failures)} failure(s) below" if fetch_failures else ""))
    for name, reason in fetch_failures:
        print(f"    FAILED  {name}: {reason}")

    if len(fetched) < len(requested):
        print(f"\n{YELLOW}DID NOT RUN{RESET}  {len(fetch_failures)} of "
              f"{len(requested)} requested unit(s) could not be fetched.\n"
              f"  A benchmark that reports a clean pass over an incomplete "
              f"corpus is the exact defect this repository exists to "
              f"catch;\n  every fetch failure above is counted and named, "
              f"never silently dropped from the measurement.")
        return DID_NOT_RUN

    report = report_for_units(fetched)
    if report is None:
        print(f"\n{YELLOW}DID NOT RUN{RESET}  nothing was measured.")
        return DID_NOT_RUN

    report["schema"] = SCHEMA
    report["limit"] = limit
    report["marketplace_json_sha256"] = corpus["provenance"]["marketplace_json_sha256"]
    report["unit_names"] = sorted(name for name, _ in fetched)

    print(f"\n{_summary(report)}")
    _breakdown(report)

    if freeze:
        return freeze_report(report)

    baseline = read_baseline(BASELINE)
    if baseline is None:
        print(f"\n  no frozen public baseline yet — nothing to compare. "
              f"Record one with: make bench-public-freeze")
        return 0

    if baseline["unit_names"] != report["unit_names"]:
        gone = sorted(set(baseline["unit_names"]) - set(report["unit_names"]))
        new = sorted(set(report["unit_names"]) - set(baseline["unit_names"]))
        print(f"\n{YELLOW}DID NOT RUN{RESET}  this run's unit set does not "
              f"match the frozen baseline's — not comparable by exact "
              f"name, unlike bench.drift this never has to guess: "
              f"{len(gone)} missing, {len(new)} new.\n"
              f"  Use the same --limit the baseline was frozen with, or "
              f"re-freeze: make bench-public-freeze")
        return DID_NOT_RUN

    print()
    regressions = compare(baseline, report)
    if regressions:
        print(f"\n{RED}{regressions} regression(s){RESET} against the "
              f"public baseline — reproducible by anyone who runs this "
              f"file. Justify or fix each one. Re-freeze only after that: "
              f"make bench-public-freeze")
        return 1
    print(f"\n{GREEN}no drift against the public baseline{RESET} — "
          f"nothing new, nothing lost")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
