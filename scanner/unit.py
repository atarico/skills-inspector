"""Unit resolution and file walk — RULES.md section 0.

The audit target is the installation unit, not a single file. Auditing SKILL.md
alone misses the entire control plane.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Per-file read cap. Deliberately generous, because the old 512 KB limit was a
# one-line evasion: a file over the cap was given `text=None` and the engine
# skipped it outright, so padding a payload script past the limit produced a scan
# with ZERO findings and a single NOT ANALYZED line. Cost to the attacker: one
# `print("x" * 600000)`.
#
# The real bound on work is MAX_TOTAL_LINES below, which is per-unit and cannot
# be evaded by splitting or padding a single file. This cap now only decides when
# a file is too big to hold in memory, and anything hitting it is reported as
# partially read AND escalated if something in the bundle runs it.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 2000
# Total lines the rule pass will read across a unit. A real third-party bundle
# turned out to ship a 1.7M-line JSON knowledge base; 68 patterns over that is
# minutes of work for data that is not code. What gets dropped is reported, and
# files are ordered so the drop lands on bulk data rather than on scripts.
MAX_TOTAL_LINES = 200_000

# Scanned first, so a budget cut removes the least interesting tail.
_PRIORITY_NAMES = {
    "SKILL.md": 0, "plugin.json": 0, "marketplace.json": 0, ".mcp.json": 0,
    "settings.json": 0, "settings.local.json": 0, "opencode.json": 0,
    "package.json": 0, ".envrc": 0, "config.toml": 0, "AGENTS.md": 0,
    "CLAUDE.md": 0, "README.md": 1,
}
_PRIORITY_SUFFIXES = {
    ".sh": 1, ".bash": 1, ".zsh": 1, ".ps1": 1, ".py": 1, ".js": 1, ".mjs": 1,
    ".cjs": 1, ".ts": 1, ".rb": 1, ".pl": 1,
    ".md": 2, ".toml": 2, ".yaml": 2, ".yml": 2, ".json": 3,
}


def scan_priority(entry) -> tuple[int, int]:
    """Lower sorts first: entry points, then code, then docs, then bulk data."""
    from pathlib import PurePosixPath
    name = PurePosixPath(entry.relpath).name
    rank = _PRIORITY_NAMES.get(name)
    if rank is None:
        rank = _PRIORITY_SUFFIXES.get(PurePosixPath(entry.relpath).suffix.lower(), 4)
    return (rank, entry.size)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".next", "target", ".ruff_cache"}

BINARY_MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary"),
    (b"PK\x03\x04", "zip archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\xfd7zXZ", "xz archive"),
    (b"ustar", "tar archive"),
]

UNIT_MARKERS = [
    (".claude-plugin/marketplace.json", "claude marketplace"),
    (".claude-plugin/plugin.json", "claude plugin"),
    ("opencode.json", "opencode project"),
    ("SKILL.md", "skill"),
]


@dataclass
class FileEntry:
    relpath: str
    size: int
    is_binary: bool
    binary_kind: str = ""
    executable: bool = False
    text: str | None = None
    symlink_target: str = ""  # set only when the link escapes the unit root
    truncated: bool = False   # read only in part; anything past the cap is unseen


# The five ways the upward search for an enclosing unit can end. Only the first
# three are conclusive: the search actually saw enough of the ancestor chain to
# trust its answer. `depth_limit` and `unreadable_ancestor` mean the search
# stopped without ruling out a stronger marker further up — see resolve()'s
# docstring for why that distinction has to survive into the report.
SCOPE_SEARCH_VALUES = (
    "widened", "marker_at_target", "reached_filesystem_root",
    "depth_limit", "unreadable_ancestor",
)


@dataclass
class Unit:
    root: Path
    kind: str
    requested: Path
    widened: bool
    scope_search: str
    scope_levels: int
    files: list[FileEntry] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    description: str = ""
    declared_tools: list[str] = field(default_factory=list)
    name: str = ""


def resolve(target: Path) -> tuple[Path, str, bool, str, int]:
    """Widen the scope to the installation unit if a marker sits above the target.

    A skill audited without its plugin manifest produces a false clean.

    Returns (root, kind, widened, scope_search, scope_levels).

    `scope_search` names HOW the upward walk ended and `scope_levels` says how
    far it got. Before this, the only signal was `widened` (now derived from
    the same result, kept for compatibility) — and a `False` value meant two
    different things with nothing to tell them apart: "climbed all the way to
    '/' and there is genuinely no marker above" and "gave up two steps in
    because that is where the mount, the depth budget, or a permission error
    ended the search". Both looked identical in the old report. A sandbox that
    mounts only the target directory reaches `reached_filesystem_root` in two
    steps against a filesystem that is not the user's — that is ClawScan's
    issue #53 objection — and only `scope_levels` lets a consumer see that two
    steps is not the same claim as forty.

    The value names how the ENCLOSING-UNIT search ended, not what was found.
    Those are different questions, and conflating them re-creates the defect
    in a new place. `widened` is conclusive because the climb stopped on the
    answer itself. `marker_at_target` is conclusive ONLY when the climb went
    on to run out of tree without finding anything stronger — that is what
    proves nothing encloses the target. A climb that instead ran out of budget
    or hit an unreadable directory reports `depth_limit` /
    `unreadable_ancestor` even though a marker sits at the target: the unit is
    known, what encloses it is not, and a plugin manifest one level past the
    budget is exactly the false clean named above. Claiming
    `marker_at_target` there would assert a search that never happened, which
    is worse than the bare boolean this replaced — that one claimed nothing.
    """
    target = target.resolve()
    start = target if target.is_dir() else target.parent

    # A non-skill marker (plugin, marketplace, opencode project) always wins:
    # that is the widening this function exists for. Between two SKILL.md files
    # the INNERMOST one wins — it is the unit the caller asked about. Letting an
    # ancestor overwrite it took the name and description from the wrong unit,
    # which marks every real capability of the target `undeclared` (or, worse,
    # `declared` against a sibling's description) and poisons the whole
    # disclosure axis. Pinned by tests/unit_test.py::resolve.
    best: tuple[Path, str] | None = None
    current = start
    levels = 0
    termination = "depth_limit"  # overwritten below unless the for-loop runs dry
    for _ in range(8):
        # Read permission is required to trust "no marker here" — a directory
        # this process cannot list is not evidence of an empty one. Checked
        # BEFORE the marker probe below, because (dir / marker).exists() alone
        # cannot make this distinction: stat'ing a KNOWN filename only needs
        # execute (search) permission on its parent, not read, so it would
        # silently report "no marker" for a directory that was never actually
        # examined.
        if not os.access(current, os.R_OK):
            termination = "unreadable_ancestor"
            break
        levels += 1
        for marker, kind in UNIT_MARKERS:
            if (current / marker).exists():
                if best is None or kind != "skill":
                    best = (current, kind)
                break
        if best and best[1] != "skill":
            break
        parent = current.parent
        if parent == current:
            termination = "reached_filesystem_root"
            break
        current = parent
    else:
        termination = "depth_limit"

    if best is None:
        return start, "directory", False, termination, levels
    root, kind = best
    widened = root != start
    if widened:
        # The climb stopped because it FOUND the enclosing unit. That is an
        # answer, not a truncated search.
        return root, kind, True, "widened", levels
    # A marker at the target settles what the unit IS. It does not settle
    # whether something ENCLOSES it, and that is the question this field
    # exists to answer. Only a climb that ran out of tree
    # (`reached_filesystem_root`) proves nothing encloses the target; one that
    # ran out of budget, or hit a directory it could not read, leaves an
    # enclosing plugin possible and unseen. Reporting `marker_at_target` there
    # would assert a search that never happened — worse than the bare boolean
    # this replaced, which at least claimed nothing. It is also precisely the
    # false clean named at the top of this function.
    search = "marker_at_target" if termination == "reached_filesystem_root" else termination
    return root, kind, False, search, levels


def _read_head(path: Path, n: int = 512) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _detect_binary(head: bytes) -> str:
    for magic, kind in BINARY_MAGIC:
        if magic == b"ustar":
            continue
        if head.startswith(magic):
            return kind
    if b"ustar" in head[:300]:
        return "tar archive"
    if b"\x00" in head:
        return "binary (null bytes)"
    return ""


def _skip_dir_reason(name: str) -> str:
    """Why a SKIP_DIRS name is pruned, derived from the name — not written by
    hand at the one call site, so a new entry added to SKIP_DIRS cannot ship
    without a reason.

    `.git` is not the same kind of skip as `dist/`: version-control metadata
    can carry a hook or config that RUNS on its own (a `post-checkout` script,
    a `.git/config` core.hooksPath override), with nothing in the bundle ever
    referencing it. Everything else in SKIP_DIRS is build output or a vendored
    dependency — inert data, unreviewed, but not an execution vector on its own.
    """
    if name == ".git":
        return ("version control metadata is never scanned — a hook or config "
                "placed here can run on its own, with nothing in the bundle "
                "referencing it")
    return ("build output or a vendored dependency, skipped by default — "
            "contents unreviewed")


def collect(target: Path) -> Unit:
    root, kind, widened, scope_search, scope_levels = resolve(target)
    unit = Unit(root=root, kind=kind, requested=target.resolve(), widened=widened,
                scope_search=scope_search, scope_levels=scope_levels, name=root.name)

    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Every OTHER exclusion path below appends to unit.skipped (file limit,
        # symlink escape, unreadable, binary, size) — this pruning step used to
        # be the one silent exception. One entry per pruned DIRECTORY, recorded
        # before the prune, never one per file it happens to contain.
        for pruned in sorted(d for d in dirnames if d in SKIP_DIRS):
            rel = str((Path(dirpath) / pruned).relative_to(root))
            unit.skipped.append((rel, _skip_dir_reason(pruned)))
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            rel = str(full.relative_to(root))
            count += 1
            if count > MAX_FILES:
                unit.skipped.append((rel, "file limit reached"))
                continue
            # A symlink escaping the unit is both an attack (the bundle reaches
            # outside its own directory) and a correctness trap: following it
            # would attribute someone else's file content to this bundle.
            if full.is_symlink():
                try:
                    resolved = full.resolve()
                    escapes = not resolved.is_relative_to(root)
                except (OSError, RuntimeError):
                    resolved, escapes = full, True
                if escapes:
                    unit.files.append(FileEntry(
                        rel, 0, False, "", False, None, str(resolved)))
                    unit.skipped.append((rel, f"symlink escaping the unit -> {resolved}"))
                    continue

            try:
                stat = full.stat()
            except OSError:
                unit.skipped.append((rel, "unreadable"))
                continue

            executable = bool(stat.st_mode & 0o111) and not full.is_dir()
            head = _read_head(full)
            binary_kind = _detect_binary(head)

            if binary_kind:
                unit.files.append(FileEntry(rel, stat.st_size, True, binary_kind, executable))
                unit.skipped.append((rel, f"{binary_kind}, contents unreviewable"))
                continue

            # Over the cap the file is read PARTIALLY, never dropped. Handing the
            # engine `text=None` was the evasion; a partial read still carries
            # line numbers that are correct for everything it contains, and the
            # truncation is both reported and escalated downstream.
            truncated = stat.st_size > MAX_FILE_BYTES
            try:
                if truncated:
                    with full.open("r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read(MAX_FILE_BYTES)
                    unit.skipped.append((
                        rel, f"{stat.st_size // 1024} KB, read the first "
                             f"{MAX_FILE_BYTES // 1024} KB only"))
                else:
                    text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                unit.skipped.append((rel, "unreadable"))
                continue

            unit.files.append(FileEntry(rel, stat.st_size, False, "", executable,
                                        text, "", truncated))

    _read_manifest(unit)
    unit.files.sort(key=scan_priority)
    return unit


# Badge rows, raw HTML wrappers, and image lines are not a description. Taking
# one anyway poisons the `disclosure` axis: every capability then reads as
# undeclared, because the text it is compared against says nothing.
_HTML_TAG = __import__("re").compile(r"<[^>]+>")
_NOISE_LINE = __import__("re").compile(
    r"^\s*(?:!\[|\[!\[|<img|<p\b|</p>|<div|</div>|<br|<a\b|</a>|<h\d|-{3,}|={3,}|\|)")


def _readme_summary(raw: str) -> str:
    """First line of actual prose, HTML stripped."""
    import re as _re
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _NOISE_LINE.match(stripped) and "<strong>" not in stripped \
                and "<em>" not in stripped:
            continue
        text = _HTML_TAG.sub(" ", stripped)
        text = _re.sub(r"\s+", " ", text).strip(" *_`")
        # A line that was only markup, or is too short to describe anything.
        if len(text) < 20:
            continue
        return text[:400]
    return ""


def _yaml_scalar(block: str, key: str) -> str:
    """Read a frontmatter value, including block scalars.

    `description: |` puts the text on the following indented lines, so reading
    the rest of the key's line yields just "|". That is not cosmetic: it is the
    text the `disclosure` axis compares against, so a unit using block style
    would have every capability marked undeclared.
    """
    import re as _re

    lines = block.splitlines()
    for idx, line in enumerate(lines):
        match = _re.match(rf"^{_re.escape(key)}:\s*(.*)$", line)
        if not match:
            continue
        inline = match.group(1).strip()
        if inline and inline not in ("|", ">", "|-", ">-", "|+", ">+"):
            return inline.strip("\"'")
        # Block scalar: take the indented run that follows.
        body: list[str] = []
        for follow in lines[idx + 1:]:
            if follow.strip() and not follow.startswith((" ", "\t")):
                break
            body.append(follow.strip())
        folded = " ".join(part for part in body if part)
        return _re.sub(r"\s+", " ", folded).strip()
    return ""


def _yaml_list(block: str, key: str) -> list[str]:
    """Read a frontmatter value that may be inline CSV or a YAML sequence."""
    import re as _re

    lines = block.splitlines()
    for idx, line in enumerate(lines):
        match = _re.match(rf"^{_re.escape(key)}:\s*(.*)$", line)
        if not match:
            continue
        inline = match.group(1).strip()
        if inline:
            return [t.strip().strip("\"'") for t in inline.split(",") if t.strip()]
        items: list[str] = []
        for follow in lines[idx + 1:]:
            if follow.strip() and not follow.startswith((" ", "\t")):
                break
            entry = follow.strip()
            if entry.startswith("- "):
                items.append(entry[2:].strip().strip("\"'"))
        return items
    return []


def _read_manifest(unit: Unit) -> None:
    """Pull the declared description — the basis of the disclosure axis."""
    import json
    import re

    for candidate in ("SKILL.md", ".claude-plugin/plugin.json", "README.md"):
        path = unit.root / candidate
        if not path.exists():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if candidate.endswith(".json"):
            try:
                data = json.loads(raw)
                unit.description = unit.description or str(data.get("description", ""))
                unit.name = data.get("name") or unit.name
            except Exception:
                pass
            continue

        match = re.match(r"^---\s*\n(.*?)\n---\s*\n", raw, re.DOTALL)
        if match:
            block = match.group(1)
            if not unit.description:
                unit.description = _yaml_scalar(block, "description")
            name = re.search(r"^name:\s*(.+?)\s*$", block, re.MULTILINE)
            if name:
                unit.name = name.group(1).strip().strip("\"'")
            unit.declared_tools = _yaml_list(block, "allowed-tools")
        elif candidate == "README.md" and not unit.description:
            unit.description = _readme_summary(raw)
