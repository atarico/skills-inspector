"""Unit resolution and file walk — RULES.md section 0.

The audit target is the installation unit, not a single file. Auditing SKILL.md
alone misses the entire control plane.
"""

from __future__ import annotations

import json
import os
import re
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


# The six ways the upward search for an enclosing unit can end. Only the first
# three are conclusive: the search actually saw enough of the ancestor chain to
# trust its answer. `depth_limit`, `unreadable_ancestor`, and
# `stopped_at_unit_marker` mean the search stopped without ruling out a
# stronger marker further up — see resolve()'s docstring for why that
# distinction has to survive into the report.
SCOPE_SEARCH_VALUES = (
    "widened", "marker_at_target", "reached_filesystem_root",
    "depth_limit", "unreadable_ancestor", "stopped_at_unit_marker",
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
    # Non-empty only when this unit's marketplace.json could NOT be trusted to
    # narrow the audit to one declared plugin source (RULES.md section 0.1) —
    # names the specific reason. Empty when there was nothing to narrow (no
    # marketplace marker), narrowing succeeded, or narrowing simply found no
    # single matching source (not a trust failure, just not narrowable).
    marketplace_narrowing: str = ""


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
    # No default value on purpose: every exit below (unreadable ancestor,
    # non-skill marker, filesystem root, budget run-dry) assigns its own
    # reason. A bare annotation means an exit that forgot to assign one fails
    # loudly with NameError instead of silently reporting whatever sentinel
    # was left here — which is exactly how the non-skill-marker break used to
    # leak `depth_limit` for a search that ran one iteration, not eight.
    termination: str
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
            # This is the widening marker itself, found at `current`. When
            # `current` is still `start` (the target), this is the same
            # false-clean shape the docstring above names: the marker settles
            # what the unit IS, but a marketplace could enclose THIS plugin
            # and the break means it is never looked for. `stopped_at_unit_marker`
            # names that truthfully; only `widened` (below) claims the search
            # is done.
            termination = "stopped_at_unit_marker"
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


# A plain scheme prefix ("http://", "git://", "ssh://", ...) or an scp-style
# git remote ("git@host:org/repo"). Either means the source is not a path on
# this filesystem at all, so treating it as one would be the shrinking defect
# this whole check exists to prevent.
_SOURCE_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


def _valid_relative_source(source: object) -> bool:
    """A `source` this audit will trust enough to even ATTEMPT to resolve.

    Only a plain relative string survives: not absolute, not a URL, not the
    `{"source": "github", ...}` object form a real marketplace.json may use.
    RULES.md section 0.1 — this is the first half of "fail wide, never narrow"
    for an untrustworthy manifest; the second half, catching a `..`-escape or a
    symlink that gets past this, is `_resolve_plugin_source`'s realpath check.
    """
    if not isinstance(source, str) or not source:
        return False
    if os.path.isabs(source):
        return False
    if _SOURCE_SCHEME_RE.match(source):
        return False
    if source.startswith("git@"):
        return False
    return True


def _resolve_plugin_source(marketplace_root: Path, source: object) -> Path | None:
    """Resolve one plugin's declared `source` to a real directory, or None if
    it cannot be trusted — an invalid shape, or a resolved realpath (`..` or a
    symlink) that escapes the marketplace directory. `marketplace_root` is
    already a real, resolved path (it came out of resolve()'s climb), so the
    only thing left to resolve is `source` itself.
    """
    if not _valid_relative_source(source):
        return None
    try:
        resolved = (marketplace_root / source).resolve()
    except (OSError, RuntimeError):
        return None
    if not resolved.is_relative_to(marketplace_root):
        return None
    return resolved


def _outside_siblings(marketplace_root: Path, plugin_root: Path) -> list[tuple[str, str]]:
    """One NOT ANALYZED entry per sibling the narrowed unit excludes, at every
    level between the marketplace root and the plugin source directory —
    mirroring SKIP_DIRS pruning in `collect()`: one entry per excluded
    directory or file, never one per file inside it, and never walked into.
    Paths are reported relative to `plugin_root` (the new unit root), like
    every other NOT ANALYZED entry, so a "../" prefix is what says "outside".

    `marketplace_root/.claude-plugin` is NEVER one of these entries. Claude
    Code lets a marketplace entry declare a plugin's hooks/mcpServers/commands
    inline (`"strict": false`), so that directory is control plane for every
    plugin the manifest lists, not a sibling's private tree — excluding it
    would be exactly the false clean RULES.md section 0 widens to prevent, now
    reintroduced by narrowing. `collect()` walks it back into the unit
    separately; this function's only job here is to never mark it excluded.
    """
    if plugin_root == marketplace_root:
        return []
    rel_parts = plugin_root.relative_to(marketplace_root).parts
    out: list[tuple[str, str]] = []
    current = marketplace_root
    for part in rel_parts:
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            break
        for entry in entries:
            if entry.name == part:
                continue
            if current == marketplace_root and entry.name == ".claude-plugin":
                continue
            rel = os.path.relpath(str(entry), str(plugin_root))
            out.append((rel, "outside every declared plugin source"))
        current = current / part
    return out


def _narrow_marketplace(marketplace_root: Path, target: Path) -> tuple[Path, str, list[tuple[str, str]]]:
    """RULES.md section 0.1: when the target sits inside exactly one plugin's
    declared `source`, narrow the unit to that directory instead of the whole
    marketplace. Returns (root, narrowing_failure_reason, outside_siblings).

    FAIL WIDE, never narrow, whenever the manifest cannot be trusted: missing,
    malformed, or unreadable marketplace.json; a `plugins` field that is not a
    list; or ANY plugin entry whose `source` this audit will not resolve —
    absolute, `..`-escaping, a URL, a git/github object form, or a symlink
    whose realpath escapes the marketplace directory. One untrustworthy entry
    taints the whole manifest, even if the target would have matched a
    different, valid one: a manifest must never be able to shrink its own
    audit, and a scanner that narrows around the one entry it distrusts is
    exactly that shrinking, just spelled differently.

    `target` matching zero or more-than-one declared source (including the
    target being the marketplace root itself, matched by no strict
    subdirectory) is not a trust failure — it is simply not narrowable, so the
    unit stays the marketplace directory with an EMPTY reason: there was
    nothing wrong with the manifest, just nothing to narrow into.
    """
    manifest_path = marketplace_root / ".claude-plugin" / "marketplace.json"
    try:
        raw = manifest_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except (OSError, ValueError):
        return marketplace_root, "marketplace.json is malformed or unreadable", []

    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        return (marketplace_root,
                "marketplace.json's plugins field is missing or not a list", [])

    sources: list[Path] = []
    for entry in plugins:
        source = entry.get("source") if isinstance(entry, dict) else None
        resolved = _resolve_plugin_source(marketplace_root, source)
        if resolved is None:
            name = entry.get("name", "?") if isinstance(entry, dict) else "?"
            return (marketplace_root,
                    f"plugin '{name}' declares a source this audit will not "
                    f"trust to narrow into ({source!r})", [])
        sources.append(resolved)

    matches = sorted({s for s in sources if target.is_relative_to(s)}, key=str)
    if len(matches) != 1:
        return marketplace_root, "", []

    plugin_root = matches[0]
    return plugin_root, "", _outside_siblings(marketplace_root, plugin_root)


def _walk_into(walk_root: Path, root: Path, unit: Unit, count: int) -> int:
    """Walk `walk_root`, recording every file into `unit` with its path
    reported relative to `root`.

    `walk_root` and `root` differ exactly once: `collect()` re-includes a
    narrowed marketplace unit's `.claude-plugin` directory, which sits ABOVE
    `root`, by calling this a second time with `walk_root` pointed at it and
    `root` left at the narrowed directory — the relpaths that come out carry a
    leading `../`, same as every other NOT-under-root path this scanner
    already reports (RULES.md section 0.1). `count` and `MAX_FILES` are shared
    across both calls so a bloated manifest cannot buy a bigger budget.
    """
    for dirpath, dirnames, filenames in os.walk(walk_root):
        # Every OTHER exclusion path below appends to unit.skipped (file limit,
        # symlink escape, unreadable, binary, size) — this pruning step used to
        # be the one silent exception. One entry per pruned DIRECTORY, recorded
        # before the prune, never one per file it happens to contain.
        for pruned in sorted(d for d in dirnames if d in SKIP_DIRS):
            rel = os.path.relpath(Path(dirpath) / pruned, root)
            unit.skipped.append((rel, _skip_dir_reason(pruned)))
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            rel = os.path.relpath(full, root)
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
    return count


def collect(target: Path) -> Unit:
    root, kind, widened, scope_search, scope_levels = resolve(target)
    target_resolved = target.resolve()
    marketplace_narrowing = ""
    outside: list[tuple[str, str]] = []
    manifest_dir: Path | None = None
    if kind == "claude marketplace":
        marketplace_root = root
        narrowed_root, marketplace_narrowing, outside = _narrow_marketplace(
            marketplace_root, target_resolved)
        if narrowed_root != root:
            root = narrowed_root
            start = target_resolved if target_resolved.is_dir() else target_resolved.parent
            widened = root != start
            # RULES.md section 0.1: the marketplace's OWN manifest directory is
            # control plane for every plugin it lists (a marketplace entry can
            # declare hooks/mcpServers/commands inline, "strict": false) — it
            # stays inside the unit even though narrowing moved root below it.
            candidate = marketplace_root / ".claude-plugin"
            if candidate.is_dir():
                manifest_dir = candidate

    unit = Unit(root=root, kind=kind, requested=target_resolved, widened=widened,
                scope_search=scope_search, scope_levels=scope_levels, name=root.name,
                marketplace_narrowing=marketplace_narrowing)
    for rel, reason in outside:
        unit.skipped.append((rel, reason))

    count = _walk_into(root, root, unit, 0)
    if manifest_dir is not None:
        count = _walk_into(manifest_dir, root, unit, count)

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
