"""False-positive benchmark against a corpus of known-good installed extensions.

The measurement that decides whether this tool is usable is not "does it catch
the payload" — any regex does that. It is how much noise it produces against
extensions that are known to be fine.

    python -m bench.corpus ~/.claude
"""

from __future__ import annotations

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import engine  # noqa: E402
from scanner.unit import collect  # noqa: E402


SKIP = {"projects", "file-history", "paste-cache", "backups", "todos",
        "shell-snapshots", "statsig", ".git", "node_modules"}


def discover(root: Path) -> list[Path]:
    """Every installation unit under `root`, deduplicated by RESOLVED root.

    Deduplicating candidates instead of resolved roots re-scans a shared plugin
    tree once per skill inside it — quadratic, and it hangs on a real machine.
    """
    from scanner.unit import resolve

    candidates: list[Path] = []
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        if "SKILL.md" in filenames:
            candidates.append(Path(dirpath))
        if "plugin.json" in filenames and Path(dirpath).name == ".claude-plugin":
            candidates.append(Path(dirpath).parent)

    resolved: dict[Path, None] = {}
    for path in candidates:
        root_path, _kind, _widened = resolve(path)
        resolved.setdefault(root_path, None)
    return sorted(resolved)


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
