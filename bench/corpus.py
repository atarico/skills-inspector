"""False-positive benchmark against a corpus of known-good installed extensions.

The measurement that decides whether this tool is usable is not "does it catch
the payload" — any regex does that. It is how much noise it produces against
extensions that are known to be fine.

    python -m bench.corpus ~/.claude
"""

from __future__ import annotations

import collections
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import engine  # noqa: E402
from scanner.unit import collect  # noqa: E402


SKIP = {"projects", "file-history", "paste-cache", "backups", "todos",
        "shell-snapshots", "statsig", ".git", "node_modules"}


def signature(root: Path) -> str:
    """Content hash of a unit: every path, every byte, and the executable bit.

    CONTENT, NOT LAYOUT, and that choice is the whole point. The duplicates
    this exists to collapse live under `plugins/cache/<marketplace>/<plugin>/`,
    one directory per revision ever fetched, and keying on that path shape
    would couple this benchmark to a directory convention it does not own —
    the same defect class as `reachability._ENTRY_NAMES` drifting away from the
    structural checks it was supposed to mirror. Identical bytes produce
    identical findings by construction, wherever they sit.

    The mode bit is in the hash because it is an input to the scan: BND-001
    reports an unreferenced file differently when it is ready to run.
    """
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP)
        rel_dir = Path(dirpath).relative_to(root)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            digest.update(str(rel_dir / name).encode("utf-8", "surrogateescape"))
            try:
                digest.update(b"\x01" if path.stat().st_mode & 0o111 else b"\x00")
                digest.update(path.read_bytes())
            except OSError:
                # An unreadable file is part of the unit's identity too, and a
                # scan reports it. Two copies that differ only in what cannot
                # be read are still two different units.
                digest.update(b"<unreadable>")
    return digest.hexdigest()


def discover(root: Path) -> list[Path]:
    """Every installation unit under `root`, deduplicated by CONTENT.

    Two deduplications, and they answer different questions.

    By RESOLVED root, because deduplicating candidates instead re-scans a
    shared plugin tree once per skill inside it — quadratic, and it hangs on a
    real machine.

    By CONTENT, because a bundle really can be installed at two paths, and a
    second copy carries no information.

    MEASURE WHAT THIS DOES AND DOES NOT BUY, because the first version of this
    docstring claimed more than the measurement supported. The plugin cache
    keeps every revision it has ever fetched, and on the machine this was
    written against `context7`, `github` and `playwright` each held ELEVEN
    revision directories that all SCAN IDENTICALLY. It does not follow that
    they are copies: all 33 have DISTINCT byte signatures. They are different
    revisions the scanner happens to read the same way. Content deduplication
    collapses 2 units on that machine, 103 to 101 — not 30.

    Deduplicating by scan RESULT instead would collapse all 30, and it must not
    be done. `bench.drift` exists to detect the scan result changing; keying
    the corpus on the scan result means a scanner change silently resizes the
    corpus, and a resized corpus is exactly what the gate refuses to compare.
    The dedup key has to be an input to the scan, never an output of it.

    So this does NOT fix the DID NOT RUN outage. A rotated cache revision has
    new bytes, `discovered` moves, and the gate still refuses. That is a
    separate decision about whether a cache of historical revisions belongs in
    a corpus of installed software at all.

    The survivor is the lexicographically first path, so the choice is stable
    across runs and `worst units` does not name a different directory each time.
    """
    from scanner.unit import resolve

    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        if "SKILL.md" in filenames:
            candidates.append(Path(dirpath))
        if "plugin.json" in filenames and Path(dirpath).name == ".claude-plugin":
            candidates.append(Path(dirpath).parent)

    resolved: dict[Path, None] = {}
    for path in candidates:
        root_path, _kind, _widened, _scope_search, _scope_levels = resolve(path)
        resolved.setdefault(root_path, None)

    by_content: dict[str, Path] = {}
    for root_path in sorted(resolved):
        by_content.setdefault(signature(root_path), root_path)
    return sorted(by_content.values())


def report_for_units(units: list[tuple[str, Path]]) -> dict | None:
    """Reduce an explicit, already-resolved unit list to the aggregate shape
    `bench.drift` freezes: clean/median/mean/p90/max, the precision and
    recall per-rule censuses, and the crash count.

    `bench.drift.collect_report()` computes the same arithmetic starting from
    `discover(root)` — a filesystem walk over a machine-specific directory.
    `bench.public` cannot start there: its units are fetched by exact git sha
    into a cache, one at a time, and never share a single scannable root. This
    is the smallest cut that lets both corpora reduce through one function
    instead of two copies of the same math drifting apart — the caller
    supplies the `(name, root)` pairs, this function never calls `discover()`
    or walks a filesystem on its own.

    Unlike `bench.drift`, the per-unit identity here is the caller-supplied
    NAME, not a content signature. `bench.drift`'s corpus is software one
    person installed, so a content hash is the only identity its frozen file
    may carry — see that module's docstring. `bench.public`'s corpus is a
    public marketplace manifest; the names in it are already published, so
    naming a unit in this benchmark's output leaks nothing that
    `bench/public-corpus.json` does not already say.

    Returns None when `units` is empty — the caller (a fetch stage with zero
    successes) already knows that story and tells it without guessing at
    counts from an empty aggregate.
    """
    if not units:
        return None

    rule_headline: collections.Counter = collections.Counter()
    rule_finding: collections.Counter = collections.Counter()
    histogram: collections.Counter = collections.Counter()
    crashes = 0
    clean = 0
    counts: list[int] = []
    findings_seen = 0
    fingerprints: dict[str, dict] = {}

    for name, path in units:
        try:
            unit = collect(path)
            findings, _ = engine.scan(unit)
        except Exception:
            # No exception text: it names a path inside the local cache
            # directory, and this report is the one meant to be published.
            crashes += 1
            fingerprints[name] = {"crashed": True, "headline_ids": [],
                                   "finding_ids": []}
            continue
        head = engine.headline(findings)
        counts.append(len(head))
        histogram[len(head)] += 1
        headline_ids = [f.id for f in head]
        for rule_id in headline_ids:
            rule_headline[rule_id] += 1
        finding_ids = [f.id for f in findings]
        findings_seen += len(finding_ids)
        for rule_id in finding_ids:
            rule_finding[rule_id] += 1
        if not head:
            clean += 1
        fingerprints[name] = {"crashed": False, "headline_ids": headline_ids,
                               "finding_ids": finding_ids}

    counts.sort()
    total = len(counts) or 1
    return {
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
        "rule_headline_counts": dict(sorted(rule_headline.items())),
        "finding_total": findings_seen,
        "rule_finding_counts": dict(sorted(rule_finding.items())),
        "unit_histogram": {str(k): histogram[k] for k in sorted(histogram)},
        "unit_fingerprints": fingerprints,
    }


def main(argv: list[str]) -> int:
    root = Path(argv[0] if argv else Path.home() / ".claude").expanduser()
    units = discover(root)
    print(f"corpus: {len(units)} units under {root}\n")

    headline_totals: list[tuple[int, str]] = []
    rule_noise: collections.Counter = collections.Counter()
    clean = 0
    failures: list[str] = []

    for path in units:
        try:
            unit = collect(path)
            findings, _ = engine.scan(unit)
        except Exception as exc:  # a scanner that crashes on real input is useless
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue

        head = engine.headline(findings)
        headline_totals.append((len(head), unit.name or path.name))
        for f in head:
            rule_noise[f.id] += 1
        if not head:
            clean += 1

    counts = [n for n, _ in headline_totals]
    counts.sort()
    total = len(counts) or 1
    print(f"clean (0 headline findings) : {clean}/{len(counts)}  "
          f"({100 * clean // total}%)")
    print(f"median headline findings    : {counts[len(counts) // 2] if counts else 0}")
    print(f"mean                        : {sum(counts) / total:.1f}")
    print(f"p90                         : {counts[int(total * 0.9) - 1] if counts else 0}")
    print(f"max                         : {max(counts) if counts else 0}")
    if failures:
        print(f"\ncrashes: {len(failures)}")
        for line in failures[:10]:
            print("  ", line)

    print("\nnoisiest rules (headline hits across the corpus):")
    for rule_id, n in rule_noise.most_common(12):
        print(f"  {rule_id:<10} {n:>4}")

    print("\nworst units:")
    for n, name in sorted(headline_totals, reverse=True)[:12]:
        print(f"  {n:>4}  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
