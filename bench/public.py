"""False-positive benchmark against a public, reproducible corpus.

`bench.corpus` and `bench.drift` answer the question that decides whether
this tool is usable — how much noise it makes against extensions that are
known to be fine — but only against `$HOME/.claude`. The Makefile has said so
since `falsepos` was written: it reads a machine-specific directory CI does
not have, and its output names the operator's own installed extensions, so
the report cannot be published either. `openclaw/clawscan` issue #53 asks for
benchmark evidence a third party can check; a number nobody else can
reproduce is not evidence.

This is the second corpus: `bench/public-corpus.json`, 253 marketplace
entries pinned by exact git sha out of Anthropic's `claude-plugins-official`
manifest, vendored and committed so this benchmark needs nothing but network
access to reproduce. Those 253 entries resolve to 248 distinct trees — the
marketplace publishes some of them under more than one name, and `select`
folds each group down to one before anything is fetched, so `discovered`
counts trees and `listings` remembers how many names folded into them. Fetching happens here, one unit at a time, from the
GitHub codeload tarball for the pinned sha; measurement uses
`bench.corpus.report_for_units`, a reduction kept deliberately identical to
`bench.drift.collect_report()` and `bench.drift.restrict_report()` — three
parallel copies of the same arithmetic, not one shared function, so a change
to one must be mirrored in the other two by hand.

    python -m bench.public --limit 5            fetch, measure, print
    python -m bench.public --limit 5 --freeze    record bench/public-baseline.json
    python -m bench.public                       all 248 trees of the corpus (network-heavy)

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

It also carries `link_drops_total`/`link_drops_units` and
`escape_drops_total`/`escape_drops_units` — the aggregate counts of link
entries and containment escapes discarded before extraction (see
`fetch_unit`), across how many units each kind of drop touched. These are
published because the measurement they describe is otherwise invisible: a
member never extracted is a member the scanner never sees, so `clean 31
(12%)` is a claim about the tree this file fetched, not the tree the pinned
shas actually contain, unless the gap between the two is on the record too.
`freeze_report` refuses to write these fields at all when any unit's drops
are unknown (a cache entry from a build that predates this registry) — a
partial total published as the total would understate every comparison run
against it forever after.

It also carries `listings`, next to `discovered`. `bench/public-corpus.json`
lists the same byte-identical tree — same `sha` + `path` — under several
marketplace names (see `select`), and scanning it once per name reported the
same findings again: 911 of 37310, 2.4%, were copies, and the per-rule census
carried that inflation rule by rule. The clean rate is what did NOT move, and
the reason is worth keeping: none of the duplicated trees was clean, so the
duplication had been making the measured ecosystem look WORSE than it is.
`select` folds a group down to one tree before anything is fetched, so
`discovered` counts distinct TREES and `listings` remembers how many
marketplace LISTINGS folded into them — without it, "clean 31 of 248" reads
as a number somebody typed, not one this file derived from
`bench/public-corpus.json`'s own 253 rows.
"""

from __future__ import annotations

import http.client
import json
import os
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
# OUTSIDE THE REPOSITORY, and that is not a preference. This cache is a full
# checkout of every pinned third-party subtree — a gigabyte of other people's
# plugins — and `make selftest` and `make schema` scan `.` to prove the
# scanner stays quiet on its own source. With the cache inside the tree those
# targets scan the corpus instead: the self-scan went from 8.8 seconds and 14
# headline findings to a 60-second timeout and 578, and `make check` stopped
# being green depending on whether somebody had run the network benchmark.
# An offline check must not depend on that.
#
# The scanner is right to report what is on disk — silently skipping a
# directory is the defect this repository has already fixed. So the fix is to
# stop putting foreign code in the scanned tree, not to teach the scan to look
# away from it.
_XDG_CACHE = os.environ.get("XDG_CACHE_HOME")
DEFAULT_CACHE = (Path(_XDG_CACHE) if _XDG_CACHE else Path.home() / ".cache") \
    / "skills-inspector" / "public-corpus"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

SCHEMA = 1
DID_NOT_RUN = 2
FETCH_TIMEOUT = 30

CODELOAD = "https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}"

# What compare()/_summary() read, plus `unit_names` — the extra field this
# benchmark's comparability check needs that bench.drift cannot publish (see
# module docstring) — the four drop totals, missing which a baseline is
# truncated, not a corpus with nothing dropped: a hand-edited or pre-registry
# file that simply lacks the field must never read as zero drops — and
# `listings`, added deliberately alongside `discovered` so a baseline frozen
# before the alias collapse (see `select`) reads as truncated rather than as
# a corpus that always had 248 trees and no marketplace duplication at all.
REQUIRED = ("discovered", "listings", "units", "clean_units", "clean_pct",
            "median", "mean", "p90", "max", "crashes", "headline_total",
            "rule_headline_counts", "finding_total", "rule_finding_counts",
            "unit_names", "link_drops_total", "link_drops_units",
            "escape_drops_total", "escape_drops_units")

# Every key that may be written to bench/public-baseline.json. Enumerated
# rather than implied, exactly as bench.drift.FROZEN_KEYS is: a new field on
# the report is a decision somebody makes on purpose, not something that
# reaches a committed file because nobody subtracted it out.
FROZEN_KEYS = ("schema", "limit", "marketplace_json_sha256", "unit_names",
               "discovered", "listings", "units", "clean_units", "clean_pct",
               "median", "mean", "p90", "max", "crashes", "headline_total",
               "rule_headline_counts", "finding_total", "rule_finding_counts",
               "unit_histogram", "link_drops_total", "link_drops_units",
               "escape_drops_total", "escape_drops_units")

# report_for_units() also returns `unit_fingerprints` — headline/finding ids
# per unit NAME. Unlike bench.drift's content-signature fingerprints, a name
# here is already public (bench/public-corpus.json says so), so keeping it
# out of FROZEN_KEYS is not a privacy decision; it is just unneeded for the
# name-set comparability check this file actually does, and every published
# key stays reviewed rather than growing by accident.
#
# `unknown_drop_units` joins it for a different reason: it counts units whose
# drops this run could not determine (see fetch_unit / _read_drop_record),
# and it exists only so freeze_report can refuse to publish a partial total —
# publishing the count itself would be publishing a number about this one
# run's cache, not about the corpus, and the next run's cache state would
# make it drift for no reason a diff could explain.
#
# `collapsed_aliases` joins them for a narrower reason: it is `select()`'s
# alias map (see its docstring), carried on the report only so
# `freeze_report`'s anti-narrowing guard can tell a name lost because its
# tree collapsed into its group's canonical entry from a name lost because
# it is actually gone. It is not a fact about the corpus a third party needs
# to check — `bench/public-corpus.json` already publishes every name and
# sha, so the mapping is always reconstructible from that file — and keeping
# it out of the frozen baseline keeps FROZEN_KEYS meaning "what this file
# publishes", not "everything `main` happened to compute".
LOCAL_KEYS = ("unit_fingerprints", "unknown_drop_units", "collapsed_aliases")

# How many rows each census in `_breakdown` prints before it stops. Twelve is
# `bench.corpus`'s number, kept so the two benchmarks read the same way; the
# difference is that this one names what it left out.
BREAKDOWN_ROWS = 12


def load_corpus(path: Path = CORPUS) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def select(corpus: dict, limit: int | None) -> tuple[list[dict], dict[str, str]]:
    """The distinct trees this run measures, plus the alias map naming
    every listing the collapse folded away: the first `limit` distinct
    trees by name, or all of them.

    Sorted explicitly rather than trusting the file's own order, so a
    hand-edited or regenerated corpus.json cannot silently change which
    units a fixed `--limit` picks.

    COLLAPSE BEFORE LIMIT. `bench/public-corpus.json` publishes what the
    marketplace publishes, and the marketplace lists the same byte-identical
    tree — same `sha` + `path`, the identity `_drop_key` already keys the
    drop registry on — under several `name`s. Scanning that tree twice under
    two names is not two units measured; it is one unit measured twice and
    counted twice, on the flattering side of both the numerator and the
    denominator. Folding groups AFTER truncating to `limit` would let a
    duplicate inside the cut silently hand back fewer than `limit` distinct
    trees; folding first is the only order where `--limit N` always means
    "N distinct trees", not "N listings, some of which are the same tree".

    The canonical survivor of a group is its alphabetically-first name — the
    same ordering this function already sorts by — so which listing a group
    collapses TO is deterministic, never the order the corpus file happens
    to list them in.
    """
    units = sorted(corpus["units"], key=lambda u: u["name"])
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for unit in units:
        key = _drop_key(unit["sha"], unit["path"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(unit)

    keys = order[:limit] if limit else order
    selected: list[dict] = []
    aliases: dict[str, str] = {}
    for key in keys:
        members = groups[key]
        canonical = members[0]  # alphabetically first: `units` was sorted above
        selected.append(canonical)
        for extra in members[1:]:
            aliases[extra["name"]] = canonical["name"]
    return selected, dict(sorted(aliases.items()))


def _owner_repo(url: str) -> tuple[str, str]:
    """https://github.com/OWNER/REPO.git -> (OWNER, REPO)."""
    path = urlparse(url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    owner, _, repo = path.partition("/")
    return owner, repo


def _drop_registry_path(cache_dir: Path) -> Path:
    """`drops.json`'s path, at the cache ROOT — never inside a unit's own
    tree. `make selftest`/`make schema` scan `.`, and the whole reason the
    fetch cache lives outside the repository (see DEFAULT_CACHE above) is
    that a scan must never walk what it is trying to measure; a registry
    file dropped inside `cache_dir / sha / path` would be exactly that
    mistake in miniature, sitting in every extracted unit's own directory
    and entering the FSW-008 census it exists to make honest."""
    return cache_dir / "drops.json"


def _drop_key(sha: str, path: str) -> str:
    """The registry's key for one unit — the same `<sha>/<path>` shape
    `fetch_unit` already uses for its cache directory, so a registry entry
    and its cached unit are always found by, and always disagree with, the
    same identity."""
    return f"{sha}/{path}" if path else sha


def _read_drop_registry(cache_dir: Path) -> dict | None:
    """The whole drop registry, or None when it cannot be trusted.

    None means the file exists and could not be parsed; `{}` means it is
    not there yet, which a cache nothing has extracted into since this file
    started writing one legitimately is.

    BOTH ALREADY READ AS UNKNOWN downstream, and saying so is the point of
    this paragraph. `_read_drop_record` funnels the two through
    `registry.get(key)`, which answers None for a missing key just as it
    does for a registry that was never readable, so returning `{}` here on
    a parse failure would not change one published number today. The
    distinction is kept because it is the honest return type, not because
    it is load-bearing: a later caller that iterates the registry instead
    of indexing it would see an empty mapping and conclude every unit
    dropped nothing, and that caller is the one this signature refuses to
    mislead. Mutation-checking found the claim that used to sit here —
    that substituting `{}` would publish known-zero — asserting a
    protection the `.get()` below was already providing. `_record_drops`
    used to be exactly that caller, and now refuses instead, for the
    same reason.
    """
    path = _drop_registry_path(cache_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_drop_record(cache_dir: Path, sha: str, path: str) -> dict | None:
    """This unit's `{"links": N, "escapes": M}`, or None when UNKNOWN.

    Unknown covers two cases a caller must never tell apart, because both
    mean the same thing to a total that must never publish a floor as a
    fact: the registry itself could not be read, or it parsed fine but has
    no entry for this unit — a cache populated before this registry
    existed, which is every unit in a cache built by an older version of
    this file. Neither one is "zero drops"; both are "this run cannot say".
    """
    registry = _read_drop_registry(cache_dir)
    if registry is None:
        return None
    return registry.get(_drop_key(sha, path))


def _record_drops(cache_dir: Path, sha: str, path: str,
                   links: int, escapes: int) -> bool:
    """Write one unit's drop counts into the registry. True on success.

    Called BEFORE `fetch_unit`'s `shutil.move` commits the extraction, not
    after, so the only reachable disagreement is a record with no tree —
    which the next run heals on its own, since a missing tree is a cache
    miss that re-extracts and rewrites the record. The old ordering left
    the other disagreement reachable instead (a tree with no record), and
    that one is unrecoverable: a cache hit never re-reads to fix it.

    Returns False, touching nothing, when the registry cannot be trusted:
    an unparseable file is left as-is rather than replaced with `{}`,
    which used to discard every peer's record on one corrupt write. The
    write itself goes through a temp file and `os.replace` — atomic on
    the same filesystem — so a kill or ENOSPC mid-write leaves the
    untouched previous registry, never a truncated one.

    Read-modify-write, no locking: `main()` calls `fetch_unit` once per
    unit, sequentially, so there is never a second writer racing this
    write.
    """
    registry = _read_drop_registry(cache_dir)
    if registry is None:
        return False
    registry[_drop_key(sha, path)] = {"links": links, "escapes": escapes}
    dest = _drop_registry_path(cache_dir)
    tmp = dest.with_name(f"{dest.name}.tmp-{uuid.uuid4().hex[:12]}")
    try:
        tmp.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
        os.replace(str(tmp), str(dest))
    except OSError:
        tmp.unlink(missing_ok=True)
        return False
    return True


def fetch_unit(unit: dict, cache_dir: Path,
                timeout: int = FETCH_TIMEOUT,
                drops: list | None = None) -> tuple[Path | None, str]:
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

    `drops`, when given, collects `(name, counts)` for every unit this call
    resolves — fetched fresh or already cached — where `counts` is
    `{"links": N, "escapes": M}` when known, or None when UNKNOWN (see
    `_read_drop_record`). A cache hit is never re-read to recount its drops
    — that would cost as much as fetching it again — so its counts come from
    `drops.json` at the cache root, written when the unit was first
    extracted (see `_record_drops`); an entry that registry does not have is
    unknown, never zero, because zero here is a claim that nothing was
    dropped and a cache hit has no way to back that claim up.

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
        if drops is not None:
            drops.append((unit["name"], _read_drop_record(cache_dir, sha, path)))
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
    links = 0
    escapes = 0
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
                        # DROPPED, AND THE SCAN NEVER SEES IT. Following a link
                        # could write outside `tmp`, so it is not extracted —
                        # which also means it never reaches the cache, and
                        # FSW-008 cannot fire on what is not there. The comment
                        # this replaces claimed the scanner covered the case
                        # downstream; this line is what removes it from
                        # coverage, so the drops are counted, not implied.
                        links += 1
                        continue
                    rel = member.name[len(prefix):]
                    if not rel:
                        continue
                    target = tmp / rel
                    if not target.resolve().is_relative_to(tmp.resolve()):
                        # DROPPED, AND UNTIL NOW UNCOUNTED. A member whose own
                        # path climbs out of `tmp` (see the `..`-in-name test)
                        # never reaches `dest`, so FSW-008 cannot fire on it —
                        # the same story as the link filter above, and it was
                        # missing the same fix: a bare `continue` here made
                        # this the one drop the module's own governing
                        # principle did not apply to. Counted before
                        # discarded, exactly like `links`.
                        escapes += 1
                        continue
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        fh = tar.extractfile(member)
                        if fh is None:
                            continue
                        data = fh.read()
                        if len(data) != member.size:
                            # A cut connection makes this `read()` come back
                            # short with no exception: `_Stream._read()` breaks
                            # on an empty underlying read instead of raising,
                            # because it drives raw deflate through
                            # `zlib.decompressobj` rather than gzip's checked
                            # reader. Everything after a short member is
                            # unreliable too, so the whole fetch is abandoned
                            # rather than just this one member.
                            shutil.rmtree(tmp, ignore_errors=True)
                            return None, (f"truncated member {member.name!r} "
                                          f"({len(data)}/{member.size} bytes)")
                        target.write_bytes(data)
                        if member.mode & 0o111:
                            target.chmod(target.stat().st_mode | 0o111)
                        extracted_any = True
            # The member loop above cannot see a cut body at a HEADER
            # boundary: `TarFile.next()` treats a short header past offset 0
            # as a clean end of archive, so every member still looks
            # complete. Draining what is left is the only place that checks
            # it — on a chunked or Content-Length body cut early this raises
            # IncompleteRead; a body framed only by connection-close still
            # slips through, since HTTP gives it no length to fail against.
            resp.read()
    except urllib.error.HTTPError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"HTTP {exc.code} fetching {sha[:12]}"
    except http.client.IncompleteRead as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"truncated response ({len(exc.partial)} bytes) fetching {sha[:12]}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"{type(exc).__name__} fetching {sha[:12]}"
    except tarfile.TarError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"corrupt tarball ({type(exc).__name__})"

    if not extracted_any:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, f"{path or '(repository root)'} not present at {sha[:12]}"

    # Written BEFORE the tree is committed — see _record_drops. An
    # unrecordable count stops the commit as an ordinary fetch failure.
    if not _record_drops(cache_dir, sha, path, links, escapes):
        shutil.rmtree(tmp, ignore_errors=True)
        return None, "drop registry could not be written; unit not cached"

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(tmp), str(dest))
    if drops is not None:
        drops.append((unit["name"], {"links": links, "escapes": escapes}))
    return dest, "fetched"


def _drop_totals(drops: list[tuple[str, dict | None]]) -> dict:
    """Reduce fetch_unit's per-unit `(name, counts)` records to the four
    totals this file publishes, plus how many units this run could not
    price.

    Kept separate from main()'s loop so the arithmetic behind
    link_drops_total/escape_drops_total is one function a test can call
    directly, rather than something only provable by driving the whole CLI.
    `*_units` counts units with a NONZERO known count — a unit whose
    registry entry is `{"links": 0, "escapes": 0}` contributed nothing and
    should not inflate "how many units this affected", the same way
    `link_drops`'s old callers never recorded a unit that dropped nothing.
    """
    link_drops_total = link_drops_units = 0
    escape_drops_total = escape_drops_units = 0
    unknown_drop_units = 0
    for _, counts in drops:
        if counts is None:
            unknown_drop_units += 1
            continue
        if counts["links"]:
            link_drops_total += counts["links"]
            link_drops_units += 1
        if counts["escapes"]:
            escape_drops_total += counts["escapes"]
            escape_drops_units += 1
    return {
        "link_drops_total": link_drops_total,
        "link_drops_units": link_drops_units,
        "escape_drops_total": escape_drops_total,
        "escape_drops_units": escape_drops_units,
        "unknown_drop_units": unknown_drop_units,
    }


def _summary(report: dict) -> str:
    return (f"{report['discovered']} discovered   {report['units']} scanned   "
            f"clean {report['clean_units']} ({report['clean_pct']}%)   "
            f"median {report['median']}   mean {report['mean']}   "
            f"p90 {report['p90']}   max {report['max']}   "
            f"crashes {report['crashes']}   reported {report['finding_total']}")


def _breakdown(report: dict) -> None:
    """Print the per-rule and per-unit censuses behind the summary line.

    NOTHING HERE IS COMPUTED. `rule_headline_counts` and `unit_fingerprints`
    come straight out of `bench.corpus.report_for_units` — kept deliberately
    identical to, but not shared with, the arithmetic `bench.drift` freezes
    in its own `collect_report()`/`restrict_report()` — and this only orders
    and prints them. That is the point: a breakdown doing its own arithmetic
    could disagree with the aggregate it sits under, and a report whose
    halves contradict each other is the defect class this whole benchmark
    exists to refuse.

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
    # named unit out of the fetch cache directly (see DEFAULT_CACHE).
    crashed = sorted(name for name, row in fingerprints.items() if row["crashed"])
    if crashed:
        print(f"\ncrashed ({len(crashed)} unit(s) — counted above, and in "
              f"none of the numbers):")
        for name in crashed[:BREAKDOWN_ROWS]:
            print(f"  {name}")
        if len(crashed) > BREAKDOWN_ROWS:
            print(f"  {DIM}listed {BREAKDOWN_ROWS} of {len(crashed)}{RESET}")


def read_baseline(path: Path) -> tuple[dict | None, str]:
    """The frozen public report, or None with the reason printed.

    Same discipline as `bench.drift.read_baseline` — a truncated or
    hand-edited baseline must never read as zero regressions, and a bare
    `None` meaning BOTH absence and damage is what let one read as the
    other: the caller printed "no baseline yet", named a cause that was not
    the cause, and exited 0. Returns `(baseline, status)` — present, absent
    or damaged — and damaged is a DID NOT RUN, never a pass."""
    if not path.exists():
        return None, "absent"
    try:
        base = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  the frozen public baseline cannot be read "
              f"({type(exc).__name__}) — restore it from git, or re-record "
              f"it: make bench-public-freeze")
        return None, "damaged"
    if not isinstance(base, dict) or base.get("schema") != SCHEMA:
        got = base.get("schema") if isinstance(base, dict) else "not an object"
        print(f"  the frozen public baseline is schema {got}, this build "
              f"reads {SCHEMA}.")
        return None, "damaged"
    missing = [key for key in REQUIRED if key not in base]
    if missing:
        print(f"  the frozen public baseline is missing {missing} — "
              f"truncated or hand-edited, nothing to compare against.")
        return None, "damaged"
    return base, "present"


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

    # A partial total is not a total: `unknown_drop_units` counts units this
    # run could not price (a cache hit with no drops.json entry — every unit
    # in a cache built before this registry existed). Freezing anyway would
    # publish link_drops_total/escape_drops_total as though they covered the
    # whole corpus, when they are really a floor over however much of it
    # happened to have a record — the exact "clean 31 (12%)" problem this
    # field exists to fix, reintroduced one level down.
    if report.get("unknown_drop_units"):
        print(f"{YELLOW}DID NOT RUN{RESET}  {report['unknown_drop_units']} "
              f"unit(s) came from cache entries with no drop record, so "
              f"their link/containment-escape counts are unknown, not "
              f"zero.\n  Nothing was frozen: a drop total that is partly "
              f"unknown would publish a floor as if it were the number.\n"
              f"  Fetch into a fresh --cache so every unit's drops get "
              f"recorded, then re-freeze.")
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

    # A NARROWING RE-FREEZE IS A DELETION, not an update: `LIMIT=5 make
    # bench-public-freeze` forwards the measuring target's --limit, and that
    # replaced a 253-unit baseline with a five-unit one that still parsed.
    existing, status = read_baseline(BASELINE)
    if status == "damaged":
        # read_baseline() already printed why. A damaged file still exists —
        # this is not the fresh-freeze case ("absent") — so falling through
        # to an unconditional overwrite below would destroy whatever the
        # existing file recorded without ever checking it for narrowing.
        # The guard cannot prove the new report is not narrower than a
        # baseline it cannot read, so it refuses rather than assumes.
        print(f"{YELLOW}DID NOT RUN{RESET}  nothing was written — a damaged "
              f"baseline cannot be checked for narrowing, so overwriting it "
              f"could silently delete units the same way a bad --limit "
              f"would.")
        return DID_NOT_RUN
    if status == "present":
        lost = sorted(set(existing["unit_names"]) - set(report["unit_names"]))
        # A name in `lost` is not always a deletion: `select()`'s alias
        # collapse (see its docstring) can make a previously-frozen name
        # disappear because its tree is now measured under its group's
        # canonical name instead — a row rename, not the corpus shrinking.
        # Only exempt it when the canonical name it folded into is actually
        # in THIS run's unit_names; a report's alias map is never trusted to
        # excuse a loss it does not itself explain.
        aliases = report.get("collapsed_aliases", {})
        measured = set(report["unit_names"])
        renamed = sorted(name for name in lost if aliases.get(name) in measured)
        lost = sorted(set(lost) - set(renamed))
        if lost:
            print(f"{YELLOW}DID NOT RUN{RESET}  the frozen baseline covers "
                  f"{len(existing['unit_names'])} unit(s); this run measured "
                  f"{len(report['unit_names'])} and would drop {len(lost)}. "
                  f"Nothing was written — re-run without --limit, or remove "
                  f"{BASELINE.name} first if starting over is the intent.")
            return DID_NOT_RUN
        if renamed:
            print(f"  {len(renamed)} previously-frozen name(s) folded into "
                  f"their canonical entry, not lost:")
            for name in renamed:
                print(f"    {name} -> {aliases[name]}")

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
            try:
                limit = int(args[i + 1])
            except ValueError:
                print(f"{YELLOW}DID NOT RUN{RESET}  --limit expects an "
                      f"integer, got {args[i + 1]!r}.")
                return DID_NOT_RUN
            i += 1
        elif arg == "--cache" and i + 1 < len(args):
            cache_dir = Path(args[i + 1]).expanduser()
            i += 1
        elif arg == "--timeout" and i + 1 < len(args):
            try:
                timeout = int(args[i + 1])
            except ValueError:
                print(f"{YELLOW}DID NOT RUN{RESET}  --timeout expects an "
                      f"integer, got {args[i + 1]!r}.")
                return DID_NOT_RUN
            i += 1
        i += 1

    try:
        corpus = load_corpus()
    except (OSError, ValueError) as exc:
        print(f"{YELLOW}DID NOT RUN{RESET}  bench/public-corpus.json could "
              f"not be read ({type(exc).__name__}).")
        return DID_NOT_RUN

    # Neither of these is a detection regression: `select()` reading a
    # corpus shaped wrong (a missing/malformed 'units' list) and the cache
    # directory failing to come into existence are both environment/input
    # failures, not the scanner finding something new. Exit 1 is reserved
    # for compare()'s own verdict below.
    try:
        requested, aliases = select(corpus, limit)
        cache_dir.mkdir(parents=True, exist_ok=True)
    except (KeyError, TypeError, OSError) as exc:
        print(f"{YELLOW}DID NOT RUN{RESET}  could not prepare the run "
              f"({type(exc).__name__}: {exc}).")
        return DID_NOT_RUN

    fetched: list[tuple[str, Path]] = []
    fetch_failures: list[tuple[str, str]] = []
    drops: list[tuple[str, dict | None]] = []
    for unit in requested:
        # fetch_unit's own try/except does not cover its heaviest I/O — the
        # temp mkdir, the cache-hit stat/iterdir, and the destination
        # mkdir/rmtree/move — so an ENOSPC, a lost-permission cache
        # directory, or an EDQUOT/NotADirectoryError on the final rename is
        # not a detection regression either: it is the same environment
        # failure fetch_unit's internal handler already turns into a named
        # fetch failure, just raised one call frame earlier.
        try:
            root, reason = fetch_unit(unit, cache_dir, timeout, drops)
        except OSError as exc:
            root, reason = None, f"{type(exc).__name__}: {exc}"
        if root is None:
            fetch_failures.append((unit["name"], reason))
        else:
            fetched.append((unit["name"], root))

    totals = _drop_totals(drops)

    print(f"public corpus: {len(requested)} unit(s) requested "
          f"({corpus['provenance']['pinned']} pinned in {CORPUS.name}"
          f"{f', limit={limit}' if limit else ''})")
    if aliases:
        print(f"    {len(aliases)} listing(s) collapsed into their "
              f"canonical entry — same sha + path published under another "
              f"marketplace name, never scanned twice:")
        for alias, canonical in aliases.items():
            print(f"      {alias} -> {canonical}")
    print(f"  fetched {len(fetched)}/{len(requested)}" +
          (f", {len(fetch_failures)} failure(s) below" if fetch_failures else ""))
    for name, reason in fetch_failures:
        print(f"    FAILED  {name}: {reason}")
    if totals["link_drops_units"]:
        print(f"    {totals['link_drops_total']} link entr(ies) dropped "
              f"before extraction across {totals['link_drops_units']} "
              f"unit(s), never scanned")
    if totals["escape_drops_units"]:
        print(f"    {totals['escape_drops_total']} containment escape(s) "
              f"dropped before extraction across "
              f"{totals['escape_drops_units']} unit(s), never scanned")
    if totals["unknown_drop_units"]:
        print(f"    {totals['unknown_drop_units']} cached unit(s) have no "
              f"drop record (fetched by a build before this one tracked "
              f"them) — their link/containment drops are unknown, not zero")

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

    # `report_for_units` returns None only for an EMPTY list; when every unit
    # CRASHES it returns units=0 carrying the zeroes of an empty sequence, and
    # that reached the exit-0 branch below. `freeze_report` already refused it.
    if not report["units"]:
        print(f"\n{YELLOW}DID NOT RUN{RESET}  all {report['discovered']} "
              f"fetched unit(s) crashed the scanner; nothing was measured.")
        return DID_NOT_RUN

    report["schema"] = SCHEMA
    report["limit"] = limit
    report["marketplace_json_sha256"] = corpus["provenance"]["marketplace_json_sha256"]
    report["unit_names"] = sorted(name for name, _ in fetched)
    report.update(totals)
    # `requested` is post-collapse; `aliases` names every listing that
    # collapsed into one of its members. Their sum is the raw marketplace
    # listing count behind this run's `unit_names` — `listings` next to
    # `discovered`, never implied by subtracting one frozen file from another.
    report["listings"] = len(requested) + len(aliases)
    report["collapsed_aliases"] = aliases

    print(f"\n{_summary(report)}")
    _breakdown(report)

    if freeze:
        return freeze_report(report)

    baseline, status = read_baseline(BASELINE)
    if status == "damaged":
        print(f"\n{YELLOW}DID NOT RUN{RESET}  the baseline named above could "
              f"not be read, so nothing was compared — a gate that cannot see "
              f"its own reference reports neither a pass nor a regression.")
        return DID_NOT_RUN
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
