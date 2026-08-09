"""Reachability graph — RULES.md section 5.

The skill-native "below the fold" is not scrolling. It is a clean 120-line
SKILL.md that says *"for advanced cases, read `references/advanced.md`"*. The
human reviews the entry point; the model loads the other file on a trigger. That
is where the payload goes, and reading the entry point never finds it.

Produces `status` (RULES.md section 2.3), which annotates findings but NEVER
lowers severity. A dormant CRITICAL is still CRITICAL — code nobody wired up is
code waiting to be wired up, and nobody ships it by accident.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

ENTRY = "entry"
ACTIVE = "active"
CONDITIONAL = "conditional"
DORMANT = "dormant"

# Files a harness or user opens directly; nobody has to reference them.
_ENTRY_NAMES = {
    "SKILL.md", "README.md", "AGENTS.md", "CLAUDE.md",
    "plugin.json", "marketplace.json", ".mcp.json",
    "settings.json", "settings.local.json", "opencode.json",
    "package.json", ".envrc", "config.toml",
}
_ENTRY_DIRS = {".claude/commands", ".claude/agents", ".codex/prompts",
               ".opencode/command", ".opencode/agent", ".opencode/plugin"}

# Paths mentioned in prose, code, or config.
_REF_PATTERNS = [
    re.compile(r"!?\[[^\]]*\]\(\s*<?([^)>\s#]+)"),                 # markdown link
    re.compile(r"`([^`\n]{2,120}?\.[A-Za-z0-9]{1,6})`"),           # `path.ext` in backticks
    re.compile(r"""["']([^"'\n]{2,120}?\.[A-Za-z0-9]{1,6})["']"""),  # quoted path
    re.compile(r"(?:source|\.|bash|sh|zsh|python3?|node|ruby|perl)\s+"
               r"([A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,6})"),            # invocation
    re.compile(r"(?:from|require|import)\s*\(?\s*['\"]([^'\"\n]+)['\"]"),
    re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/([A-Za-z0-9_./-]+)"),
    re.compile(r"(?<![\w/])((?:references|scripts|assets|lib|src|bin|hooks|"
               r"commands|agents|templates)/[A-Za-z0-9_./-]+)"),     # bare bundle path
]

# Only these shapes are *structural* references — something the machine follows.
# A bare or backticked path in prose is documentation naming a path, not loading
# it: tutorials are full of `agents/your-agent.md`. Using the loose patterns for
# dangling detection produced 66 false positives across the corpus, every one of
# them a doc describing a path rather than referencing a file.
_STRICT_REF_PATTERNS = [
    _REF_PATTERNS[0],  # markdown link
    _REF_PATTERNS[3],  # invocation: bash/python/source path
    _REF_PATTERNS[4],  # import / require
    _REF_PATTERNS[5],  # ${CLAUDE_PLUGIN_ROOT}/path
]

# A reference guarded by a runtime condition: loaded only sometimes.
_CONDITIONAL = re.compile(
    r"(?i)\b(if|when|whenever|should|in case|only\s+(?:if|when|for)|for\s+"
    r"(?:advanced|complex|deeper|further|edge)|as\s+needed|optionally|"
    r"unless|otherwise|for more|si\b|cuando)\b")

# Extensions worth reporting as dormant. A stray LICENSE is not a finding;
# an unreferenced shell script is.
_INTERESTING = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts",
                ".rb", ".pl", ".ps1", ".md", ".json", ".toml", ".yaml", ".yml"}


@dataclass
class Graph:
    status: dict[str, str] = field(default_factory=dict)
    conditional_from: dict[str, str] = field(default_factory=dict)
    dangling: list[tuple[str, str, int]] = field(default_factory=list)


def _is_entry(relpath: str) -> bool:
    p = PurePosixPath(relpath)
    if p.name in _ENTRY_NAMES:
        return True
    parent = str(p.parent).replace("\\", "/")
    return any(parent.endswith(d) for d in _ENTRY_DIRS)


def _basename_index(known: set[str]) -> dict[str, list[str]]:
    """basename -> paths. Built once; the fallback lookup below is O(files)
    otherwise, and on a 429-file marketplace that alone cost 13 seconds."""
    index: dict[str, list[str]] = {}
    for path in known:
        index.setdefault(PurePosixPath(path).name, []).append(path)
    return index


def _candidates(ref: str, source: str, known: set[str],
                index: dict[str, list[str]] | None = None) -> str | None:
    """Resolve a raw reference against the bundle's real file list."""
    ref = ref.strip().lstrip("./").split("#")[0].split("?")[0]
    if not ref or ref.startswith(("http://", "https://", "mailto:", "data:")):
        return None
    if ref in known:
        return ref
    # relative to the referencing file's directory
    parent = PurePosixPath(source).parent
    joined = str((parent / ref)) if str(parent) != "." else ref
    try:
        normalized = str(PurePosixPath(joined))
    except ValueError:
        return None
    if normalized in known:
        return normalized
    # last resort: unique basename match
    base = PurePosixPath(ref).name
    matches = (index.get(base, []) if index is not None
               else [k for k in known if PurePosixPath(k).name == base])
    return matches[0] if len(matches) == 1 else None


def _extract(text: str, relpath: str, known: set[str], index=None) -> list[tuple[str, bool, int, str]]:
    """(target, is_conditional, line, raw_ref) for each resolvable reference."""
    out = []
    seen: set[tuple[str, int]] = set()
    for idx, line in enumerate(text.splitlines(), start=1):
        conditional = bool(_CONDITIONAL.search(line))
        for pattern in _REF_PATTERNS:
            for match in pattern.finditer(line):
                raw = match.group(1)
                target = _candidates(raw, relpath, known, index)
                if target and target != relpath and (target, idx) not in seen:
                    seen.add((target, idx))
                    out.append((target, conditional, idx, raw))
    return out


def _config_refs(text: str, relpath: str, known: set[str], index=None) -> list[tuple[str, bool, int, str]]:
    """JSON config: any string value that resolves to a bundle file."""
    try:
        data = json.loads(text)
    except Exception:
        return []
    found: list[tuple[str, bool, int, str]] = []

    # Depth-capped: a bundle can ship JSON nested thousands of levels deep, and
    # an unbounded walk blows the Python stack. Nothing at that depth is a
    # reference anyone resolves, so stopping early loses no signal — where an
    # exception handler here would have silently discarded the whole file.
    def walk(node, depth=0):
        if depth > 40:
            return
        if isinstance(node, str):
            for token in re.findall(r"[A-Za-z0-9_./${}-]+\.[A-Za-z0-9]{1,6}", node):
                target = _candidates(token.replace("${CLAUDE_PLUGIN_ROOT}/", ""),
                                     relpath, known, index)
                if target and target != relpath:
                    found.append((target, False, 1, token))
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, depth + 1)

    walk(data)
    return found


def build(files: list) -> Graph:
    """files: FileEntry list. Returns per-file status plus dangling references."""
    known = {f.relpath for f in files}
    known_dirs = {str(PurePosixPath(k).parent) for k in known} - {"."}
    index = _basename_index(known)
    texts = {f.relpath: f.text for f in files if f.text is not None}
    graph = Graph()

    edges: dict[str, list[tuple[str, bool]]] = {}
    referenced_raw: dict[str, set[str]] = {}

    for relpath, text in texts.items():
        refs = _extract(text, relpath, known, index)
        if relpath.endswith((".json",)):
            refs += _config_refs(text, relpath, known, index)
        edges[relpath] = [(target, cond) for target, cond, _l, _r in refs]

        # dangling: a STRUCTURAL reference that resolves to nothing
        for idx, line in enumerate(text.splitlines(), start=1):
            for pattern in _STRICT_REF_PATTERNS:
                for match in pattern.finditer(line):
                    raw = match.group(1).strip()
                    if raw.startswith(("http://", "https://", "mailto:", "#")):
                        continue
                    # must look like a bundle-relative file, not a package name
                    if "/" not in raw or not PurePosixPath(raw).suffix:
                        continue
                    if raw.startswith(("@", "~", "/")) or raw.endswith("."):
                        continue
                    if _candidates(raw, relpath, known, index) is not None:
                        continue
                    # Most references in a real skill point at the USER's project
                    # (./CLAUDE.md, dist/server.js, config/settings.json), which
                    # the scanner cannot see, so "missing" is the normal case.
                    # Only flag when the bundle itself owns the parent directory:
                    # then the file belongs here and is genuinely absent.
                    parent = str(PurePosixPath(raw).parent)
                    if parent in ("", ".") or parent not in known_dirs:
                        continue
                    referenced_raw.setdefault(raw, set()).add(f"{relpath}:{idx}")

    entries = [f.relpath for f in files if _is_entry(f.relpath)]
    for relpath in known:
        graph.status[relpath] = DORMANT
    for relpath in entries:
        graph.status[relpath] = ENTRY

    # BFS: unconditional edges win over conditional ones.
    frontier = [(e, False) for e in entries]
    visited: set[str] = set()
    while frontier:
        current, inherited_cond = frontier.pop()
        key = (current, inherited_cond)
        if key in visited:
            continue
        visited.add(key)
        for target, cond in edges.get(current, []):
            conditional = inherited_cond or cond
            existing = graph.status.get(target)
            if existing == ENTRY:
                continue
            if conditional:
                if existing == DORMANT:
                    graph.status[target] = CONDITIONAL
                    graph.conditional_from[target] = current
            else:
                graph.status[target] = ACTIVE
                graph.conditional_from.pop(target, None)
            frontier.append((target, conditional))

    for raw, locations in referenced_raw.items():
        location = sorted(locations)[0]
        path, _, line = location.rpartition(":")
        graph.dangling.append((raw, path, int(line)))

    return graph


def is_interesting(relpath: str) -> bool:
    return PurePosixPath(relpath).suffix.lower() in _INTERESTING
