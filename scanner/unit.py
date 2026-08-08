"""Unit resolution and file walk — RULES.md section 0.

The audit target is the installation unit, not a single file. Auditing SKILL.md
alone misses the entire control plane.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 2000

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

    best: tuple[Path, str] | None = None
    current = start
    for _ in range(8):
        for marker, kind in UNIT_MARKERS:
            if (current / marker).exists():
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

            if stat.st_size > MAX_FILE_BYTES:
                unit.files.append(FileEntry(rel, stat.st_size, False, "", executable))
                unit.skipped.append((rel, f"{stat.st_size // 1024} KB, over size limit"))
                continue

            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                unit.skipped.append((rel, "unreadable"))
                continue

            unit.files.append(FileEntry(rel, stat.st_size, False, "", executable, text))

    _read_manifest(unit)
    return unit


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
            desc = re.search(r"^description:\s*(.+?)\s*$", block, re.MULTILINE)
            if desc and not unit.description:
                unit.description = desc.group(1).strip().strip("\"'")
            name = re.search(r"^name:\s*(.+?)\s*$", block, re.MULTILINE)
            if name:
                unit.name = name.group(1).strip().strip("\"'")
            tools = re.search(r"^allowed-tools:\s*(.+?)\s*$", block, re.MULTILINE)
            if tools:
                unit.declared_tools = [t.strip() for t in tools.group(1).split(",") if t.strip()]
        elif candidate == "README.md" and not unit.description:
            body = [ln.strip() for ln in raw.splitlines()
                    if ln.strip() and not ln.startswith("#")]
            if body:
                unit.description = body[0][:400]
