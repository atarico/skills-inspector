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


@dataclass
class Unit:
    root: Path
    kind: str
    requested: Path
    widened: bool
    files: list[FileEntry] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    description: str = ""
    declared_tools: list[str] = field(default_factory=list)
    name: str = ""


def resolve(target: Path) -> tuple[Path, str, bool]:
    """Widen the scope to the installation unit if a marker sits above the target.

    A skill audited without its plugin manifest produces a false clean.
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
    for _ in range(8):
        for marker, kind in UNIT_MARKERS:
            if (current / marker).exists():
                if best is None or kind != "skill":
                    best = (current, kind)
                break
        if best and best[1] != "skill":
            break
        parent = current.parent
        if parent == current:
            break
        current = parent

    if best is None:
        return start, "directory", False
    root, kind = best
    return root, kind, root != start


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


def collect(target: Path) -> Unit:
    root, kind, widened = resolve(target)
    unit = Unit(root=root, kind=kind, requested=target.resolve(), widened=widened,
                name=root.name)

    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
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
