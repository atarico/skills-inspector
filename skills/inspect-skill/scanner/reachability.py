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

from . import position

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

# A Claude Code PLUGIN auto-discovers these at its own root, with no `.claude/`
# prefix and nothing in the bundle referencing them: `commands/deploy.md` is the
# `/deploy` command, `agents/reviewer.md` is a subagent. RULES.md section 5
# already calls "every registered command file" and "every subagent definition"
# an entry point; only the plugin-root spelling was missing, and it accounted
# for 31 of the 92 BND-001 findings across the 76 installed extensions.
#
# THREE NARROWINGS, and each one is what keeps this from being a way out of
# `dormant` rather than a fix.
#
# Only under a plugin root. These names are ordinary English, and a skill
# bundle's `commands/` is loaded by nobody. Without the manifest requirement,
# "rename the directory to commands/" is a one-word laundering of any payload.
# On this corpus every unit with a root-level `commands/`, `agents/` or `hooks/`
# is a plugin, so the requirement costs nothing and bounds the claim.
#
# Only the extensions the harness registers. Commands and subagents are Markdown;
# a `commands/helper.sh` sitting beside them is registered by nothing and is
# exactly the dormant payload this axis exists to report.
#
# Only `hooks/hooks.json` by name. The harness loads that one file; the scripts
# it wires are reached THROUGH it, as config references, which is already how
# `_config_refs` works. Treating all of `hooks/` as entry would have skipped the
# question of whether the hook config actually names the script.
_PLUGIN_MANIFEST = ".claude-plugin/plugin.json"
_PLUGIN_ENTRY_DIRS = {"commands": {".md"}, "agents": {".md"}}
_PLUGIN_ENTRY_FILES = {("hooks", "hooks.json")}

# Paths mentioned in prose, code, or config.
_REF_PATTERNS = [
    re.compile(r"!?\[[^\]]*\]\(\s*<?([^)>\s#]+)"),                 # markdown link
    re.compile(r"`([^`\n]{2,120}?\.[A-Za-z0-9]{1,6})`"),           # `path.ext` in backticks
    re.compile(r"""["']([^"'\n]{2,120}?\.[A-Za-z0-9]{1,6})["']"""),  # quoted path
    # The lookbehind is load-bearing. Without it the `sh` alternative matched the
    # tail of any word: "The cleanup will flush scripts/cache.json" was read as
    # an invocation of scripts/cache.json and reported BND-002 HIGH. The bare `.`
    # (shell's `source` shorthand) had the same problem in reverse — it matched
    # the full stop ending a sentence whenever a path followed it.
    re.compile(r"(?<![\w./-])(?:source|bash|sh|zsh|python3?|node|ruby|perl|\.)\s+"
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
    # Files referenced from a line that is itself in ACTIVE position — an
    # instruction to run the thing, not a mention of it. This is deliberately
    # narrower than `status == ACTIVE`: "see examples/basic.sh for usage" makes a
    # file reachable, while "Run `bash examples/payload.sh`" makes it live. Only
    # the second may lift the sample-directory confidence floor.
    invoked: set[str] = field(default_factory=set)


def _plugin_roots(known: set[str]) -> set[str]:
    """Every directory in the bundle that is a Claude Code plugin root.

    Usually one — the bundle root, since `unit.resolve` widens to the manifest.
    A marketplace ships several below its own root (`plugins/<name>/`), and
    those plugins auto-discover their commands exactly the same way, so the
    answer follows the manifests rather than the bundle root.
    """
    roots = set()
    for path in known:
        if path == _PLUGIN_MANIFEST:
            roots.add("")
        elif path.endswith("/" + _PLUGIN_MANIFEST):
            roots.add(path[:-len(_PLUGIN_MANIFEST) - 1])
    return roots


def _is_plugin_entry(relpath: str, plugin_roots: set[str]) -> bool:
    for root in plugin_roots:
        prefix = f"{root}/" if root else ""
        if not relpath.startswith(prefix):
            continue
        parts = PurePosixPath(relpath[len(prefix):]).parts
        if len(parts) < 2:
            continue
        # commands/ and agents/ nest: `commands/git/commit.md` is `/git:commit`.
        suffixes = _PLUGIN_ENTRY_DIRS.get(parts[0])
        if suffixes and PurePosixPath(parts[-1]).suffix.lower() in suffixes:
            return True
        if len(parts) == 2 and (parts[0], parts[1]) in _PLUGIN_ENTRY_FILES:
            return True
    return False


def _is_entry(relpath: str, plugin_roots: set[str] = frozenset()) -> bool:
    p = PurePosixPath(relpath)
    if p.name in _ENTRY_NAMES:
        return True
    parent = str(p.parent).replace("\\", "/")
    if any(parent.endswith(d) for d in _ENTRY_DIRS):
        return True
    return _is_plugin_entry(relpath, plugin_roots)


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


def _invocation_refs(text: str, relpath: str, known: set[str],
                     index=None) -> set[str]:
    """Targets this file tells something to RUN, as opposed to mentions.

    Two narrowings, and both are load-bearing:

    Only the invocation pattern counts (`bash x.sh`, `python3 x.py`, `. x.sh`).
    A quoted or backticked path is a mention — `tests/make_fixtures.py` names
    every fixture path it writes as a plain string, and treating that as an
    invocation lit up this repository's own attack fixtures.

    And the referring line must be in ACTIVE position, so an invocation shown
    inside an example block or under a "Don't do this" heading stays a
    demonstration.

    The result lifts the sample-directory confidence floor, so it has to mean
    "an entry point wired this up", not "someone typed this path once".
    """
    out: set[str] = set()
    positions = position.classify_lines(relpath, text)
    for idx, line in enumerate(text.splitlines()):
        if idx < len(positions) and positions[idx][0] != position.ACTIVE:
            continue
        for match in _REF_PATTERNS[3].finditer(line):
            target = _candidates(match.group(1), relpath, known, index)
            if target and target != relpath:
                out.add(target)
    return out


# Python's import syntax carries no quotes, so `_REF_PATTERNS[4]` — which
# requires them — matched none of it. `from . import rules as R` and
# `from .position import ACTIVE` produced no edge at all, and every module of
# this scanner's own package therefore read as `dormant`.
#
# Both forms are anchored at the start of a line, because that is the difference
# between a statement and a sentence. "We do not import config.settings here" is
# prose about a module; only a line that BEGINS an import statement loads one.
_PY_FROM = re.compile(r"^[ \t]*from[ \t]+(\.*)([A-Za-z_][\w.]*)?[ \t]+import[ \t]+"
                      r"(\*|[\w,()\[\] \t]+)")
_PY_IMPORT = re.compile(r"^[ \t]*import[ \t]+([A-Za-z_][\w.]*"
                        r"(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*)")
_PY_SUFFIXES = (".py", ".pyi", ".pyw")


def _module_file(base: str, dotted: str, known: set[str]) -> str | None:
    """`base/a/b` -> `base/a/b.py`, or the package's `base/a/b/__init__.py`.

    Exact construction only: no basename fallback. `_candidates` would happily
    resolve `import json` to a unique `json.py` buried anywhere in the bundle,
    and an import is not a path — it is a name looked up on `sys.path`.
    """
    parts = [p for p in base.split("/") if p] + [p for p in dotted.split(".") if p]
    if not parts:
        return None
    stem = "/".join(parts)
    for candidate in (f"{stem}.py", f"{stem}/__init__.py"):
        if candidate in known:
            return candidate
    return None


def _python_imports(text: str, relpath: str, known: set[str]) -> list[tuple[str, bool, int, str]]:
    """Import edges, resolved the way Python resolves them.

    RELATIVE: the leading dots count packages, not directories. One dot is the
    containing package (the file's own directory), and each extra dot walks one
    level up; running past the bundle root resolves to nothing rather than
    wrapping around. `from .pkg import thing` resolves `pkg` — and, only when
    `pkg` turned out to be a package with an `__init__.py`, also `pkg.thing`,
    because that is the one case where the imported NAME may be a module of its
    own rather than an attribute.

    ABSOLUTE: tried against the file's own directory and against the bundle
    root, the two entries a real bundle puts on `sys.path` — a launcher doing
    `sys.path.insert(0, Path(__file__).parent)` is how `skills/inspect-skill/
    scan.py` reaches its bundled `scanner/`. A name that resolves to no bundle
    file is a third-party or stdlib package and produces no edge.

    DELIBERATELY NOT RESOLVED, each because the alternative claims more than the
    evidence supports:

    * Imports in anything but a Python file. A `from .secret import run` inside
      a fenced block in `SKILL.md` is a tutorial naming a module, the same
      distinction `_STRICT_REF_PATTERNS` already draws for paths in prose.
    * Imports inside a STRING LITERAL, which is that same sentence one level in.
      A triple-quoted block in a `.py` file is a fenced block by another
      spelling — a docstring, a usage example, a quoted snippet — and quoting an
      import statement does not execute it. The line anchor alone stopped the
      single-line spellings (`# from . import x` and `DOC = 'from . import x'`
      both put a character in the column the statement needs) but a literal that
      spans lines puts its body at column zero, so `position.string_literal_carry`
      supplies the state the anchor cannot see. Driven on the defect, a two-line
      docstring naming an orphaned payload produced a real edge and BND-001
      disappeared from the report entirely.
    * Dynamic imports — `importlib.import_module(name)`, `__import__`, a module
      assembled from a variable. Statically it resolves to nothing, and the
      quoted spelling is already `_REF_PATTERNS[4]`'s job.
    * Unresolvable imports as DANGLING references. `import requests` names a
      package that is supposed to be absent from the bundle; feeding that to
      BND-002 would report every third-party dependency as a missing file.
    * Attribute imports: `from .mod import CONST` never yields `mod/CONST.py`
      unless `mod` is a package and that file genuinely exists.
    * Conditionality. `_CONDITIONAL` reads prose ("for advanced cases, read..."),
      and no import line is written that way; an import inside a function is
      still wiring the module that contains it holds.

    The edges also stay OUT of `graph.invoked` on purpose. That set lifts the
    sample-directory confidence floor and has to mean "an entry point tells
    something to run this"; a helper imported by a fixture is still a fixture.
    """
    if not relpath.endswith(_PY_SUFFIXES):
        return []
    here = str(PurePosixPath(relpath).parent)
    here = "" if here == "." else here
    out: list[tuple[str, bool, int, str]] = []

    def add(target: str | None, line: int, raw: str) -> None:
        if target and target != relpath:
            out.append((target, False, line, raw))

    carry = position.string_literal_carry(text)
    for idx, line in enumerate(text.splitlines(), start=1):
        # Quoted text is not a statement. `carry` is per file, so an
        # unterminated literal never reaches the next one.
        if carry[idx - 1]:
            continue
        match = _PY_FROM.match(line)
        if match:
            dots, module, names = match.group(1), match.group(2) or "", match.group(3)
            if dots:
                # One dot is this file's own package; every extra one walks up.
                base_parts = [p for p in here.split("/") if p]
                up = len(dots) - 1
                if up > len(base_parts):
                    continue
                bases = ["/".join(base_parts[:len(base_parts) - up] if up else base_parts)]
            else:
                bases = [here, ""] if here else [""]
            for base in bases:
                target = _module_file(base, module, known) if module else None
                if module and target is None:
                    continue
                if target:
                    add(target, idx, f"{dots}{module}")
                # `from . import a, b` names modules outright; `from .pkg import
                # a` may name submodules, but only when pkg really is a package.
                if not module or (target and target.endswith("/__init__.py")):
                    package = f"{base}/{module}".strip("/") if module else base
                    # One name per comma clause, and it is the FIRST: in
                    # `a as b`, `b` is a local binding that names nothing on
                    # disk, and resolving it fabricates an edge — which in this
                    # model is a claim that some file is reachable.
                    for clause in names.split(","):
                        first = re.search(r"[A-Za-z_]\w*", clause)
                        if not first:
                            continue
                        name = first.group()
                        add(_module_file(package, name, known), idx,
                            f"{dots}{module}.{name}" if module else f"{dots}{name}")
                if target:
                    break
            continue

        match = _PY_IMPORT.match(line)
        if match:
            for dotted in match.group(1).split(","):
                dotted = dotted.strip()
                for base in ([here, ""] if here else [""]):
                    target = _module_file(base, dotted, known)
                    if target:
                        add(target, idx, dotted)
                        break
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


# Keys whose string value the harness RUNS or LOADS. Everything else in a config
# is prose about the bundle, and prose names a path the way a sentence does.
#
# `command` and `args` are the hook entry and the MCP server; `commands`,
# `agents`, `hooks` and `mcpServers` are the plugin manifest naming its own
# files; `bin` and `main` are the package's executable and its entry module. A
# `description`, a `name`, a `note`, a `matcher` — none of them wire anything.
#
# The list is closed, so a key missing from it silently loses invocation the way
# the old any-string walk never did, and that is a false negative pointing the
# other way. Every name here was counted in the frozen corpus holding a real
# bundle path: `"mcpServers": "./agents/cursor/mcp.json"` and `"bin":
# "./server.ts"` are there 12 and 4 times, next to a `"logo":
# "./assets/logo.svg"` that is an asset and stays out.
_WIRING_KEYS = {"command", "args", "commands", "agents", "hooks", "scripts",
                "mcpServers", "bin", "main"}
# `package.json` spells the pair the other way round: under `scripts` the KEY is
# the script's name and the value is the command, so the wiring word sits one
# level above the string rather than directly over it. `bin` takes both shapes —
# `"bin": "./server.ts"` names the executable directly, `"bin": {"cli":
# "./bin/cli.js"}` names it under the command's own name — so it belongs to both
# sets, and listing it in only one would lose exactly the object form.
_WIRING_CONTAINERS = {"scripts", "bin"}


def _config_invocations(text: str, relpath: str, known: set[str],
                        index=None) -> set[str]:
    """Targets a JSON config WIRES, as opposed to targets it merely names.

    `_config_refs` reads every string value, and that is right for edges: a path
    named anywhere in a config is a path someone can reach. It was NOT right for
    `graph.invoked`, which lifts the sample-directory confidence floor and is
    documented as "an entry point tells something to run this". Reading any
    string value as wiring meant `"description": "do not use scripts/payload.sh"`
    marked that payload invoked — a sentence warning against a file promoted it,
    which is the same fabricated edge shape as an import inside a docstring.

    Which key holds the string is the whole difference, so the walk carries it.
    Lists are transparent: `args` names its elements, not their indices.
    """
    try:
        data = json.loads(text)
    except Exception:
        return set()
    out: set[str] = set()

    def walk(node, key: str | None, parent: str | None, depth=0):
        if depth > 40:
            return
        if isinstance(node, str):
            if key not in _WIRING_KEYS and parent not in _WIRING_CONTAINERS:
                return
            for token in re.findall(r"[A-Za-z0-9_./${}-]+\.[A-Za-z0-9]{1,6}", node):
                target = _candidates(token.replace("${CLAUDE_PLUGIN_ROOT}/", ""),
                                     relpath, known, index)
                if target and target != relpath:
                    out.add(target)
        elif isinstance(node, dict):
            for name, value in node.items():
                walk(value, name, key, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, key, parent, depth + 1)

    walk(data, None, None)
    return out


def build(files: list) -> Graph:
    """files: FileEntry list. Returns per-file status plus dangling references."""
    known = {f.relpath for f in files}
    known_dirs = {str(PurePosixPath(k).parent) for k in known} - {"."}
    index = _basename_index(known)
    plugin_roots = _plugin_roots(known)
    texts = {f.relpath: f.text for f in files if f.text is not None}
    graph = Graph()

    edges: dict[str, list[tuple[str, bool]]] = {}
    referenced_raw: dict[str, set[str]] = {}

    for relpath, text in texts.items():
        refs = _extract(text, relpath, known, index)
        if relpath.endswith((".json",)):
            refs += _config_refs(text, relpath, known, index)
        if relpath.endswith(_PY_SUFFIXES):
            refs += _python_imports(text, relpath, known)
        edges[relpath] = [(target, cond) for target, cond, _l, _r in refs]

        graph.invoked.update(_invocation_refs(text, relpath, known, index))
        if relpath.endswith((".json",)):
            # A config that wires a file is not mentioning it, it is wiring it —
            # and the key is what tells the two apart.
            graph.invoked.update(_config_invocations(text, relpath, known, index))

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

    entries = [f.relpath for f in files if _is_entry(f.relpath, plugin_roots)]
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
