"""Agent control plane and ambient auto-execution — RULES.md sections H and I.

These are structural, not textual: they come from parsing config files. Every
rule here grants execution or tool access without matching anything in A-F,
which is exactly why a generic scanner misses them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from . import rules as R

HOOK_EVENTS = {
    "PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart",
    "SessionEnd", "Stop", "SubagentStop", "PreCompact", "Notification",
}

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "postpack"}

_PERMISSION_RED_FLAGS = re.compile(
    r"bypassPermissions|dangerously-skip-permissions|--yolo"
    r"|approval_policy\s*=\s*[\"']never[\"']"
    r"|sandbox_mode\s*=\s*[\"']danger-full-access[\"']"
    r"|\"defaultMode\"\s*:\s*\"(bypassPermissions|acceptEdits)\"",
    re.IGNORECASE,
)

_PTH_EXEC = re.compile(r"^\s*import\s+", re.MULTILINE)


class StructuralFinding:
    __slots__ = ("rule_id", "severity", "confidence", "capability", "detects",
                 "impact", "legitimate", "check", "relpath", "line", "evidence", "specificity")

    def __init__(self, rule_id, severity, confidence, capability, detects,
                 impact, legitimate, check, relpath, line, evidence, specificity=90):
        self.rule_id = rule_id
        self.severity = severity
        self.confidence = confidence
        self.capability = capability
        self.detects = detects
        self.impact = impact
        self.legitimate = legitimate
        self.check = check
        self.relpath = relpath
        self.line = line
        self.evidence = evidence
        self.specificity = specificity


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _fmt(value, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text[:limit]


def _server_names(value) -> tuple[list[str], bool]:
    """Names declared by an MCP field, and whether it is a pointer to a file.

    A plugin manifest may set `mcpServers` to an inline object OR to a path
    string pointing at an .mcp.json. Iterating a string yields its characters,
    which is how a real marketplace plugin once reported
    `Registers MCP servers: ., ., /, a, c, ...`.
    """
    if isinstance(value, dict):
        return sorted(str(k) for k in value), False
    if isinstance(value, str):
        return [value], True
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))], True
    return [], False


def inspect(root: Path, relpath: str) -> list[StructuralFinding]:
    """Structural checks for one file. Returns findings, never raises."""
    path = root / relpath
    name = PurePosixPath(relpath).name
    out: list[StructuralFinding] = []

    try:
        if name in {"settings.json", "settings.local.json"} or relpath.endswith(".claude/settings.json"):
            out += _claude_settings(path, relpath)
        if name == ".mcp.json":
            out += _mcp_file(path, relpath)
        if name == "package.json":
            out += _package_json(path, relpath)
        if name == "plugin.json" or name == "marketplace.json":
            out += _claude_settings(path, relpath)
        if name == "opencode.json" or name == "opencode.jsonc":
            out += _opencode(path, relpath)
        if name == ".envrc":
            out += _envrc(path, relpath)
        if relpath.endswith(".vscode/tasks.json"):
            out += _vscode_tasks(path, relpath)
        if name in {"sitecustomize.py", "usercustomize.py"}:
            out.append(StructuralFinding(
                "AUT-004", "CRITICAL", "high", R.AUTO_EXEC,
                "Python import-time hook",
                "Runs on every Python process start, system-wide.",
                "Effectively never in a distributed bundle.",
                "Read the whole file — it runs before anything else.",
                relpath, 1, f"{name} present in bundle"))
        if relpath.endswith(".pth"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if _PTH_EXEC.search(text):
                out.append(StructuralFinding(
                    "AUT-004", "CRITICAL", "high", R.AUTO_EXEC,
                    ".pth file with an executable import line",
                    "Runs on every Python process start, system-wide.",
                    "Effectively never.",
                    "Read the import target.",
                    relpath, 1, _fmt(text.strip()[:120])))
        if name in {".gitconfig", "gitconfig", ".gitattributes"}:
            out += _git_config(path, relpath, name)
        if PurePosixPath(relpath).parts[:1] == (".opencode",) and relpath.endswith(".js"):
            out.append(StructuralFinding(
                "HOK-007", "CRITICAL", "high", R.CONTROL_PLANE,
                "Executable opencode plugin code",
                "Not configuration — code that runs inside the agent process.",
                "The plugin is the unit's stated purpose.",
                "Read the plugin entry point in full.",
                relpath, 1, "opencode plugin module"))
        if relpath.endswith("config.toml") and ".codex" in relpath:
            out += _codex_toml(path, relpath)
    except Exception:
        return out

    return out


def _claude_settings(path: Path, relpath: str) -> list[StructuralFinding]:
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    out: list[StructuralFinding] = []

    hooks = data.get("hooks")
    if isinstance(hooks, dict) and hooks:
        events = [e for e in hooks if e in HOOK_EVENTS] or list(hooks)
        out.append(StructuralFinding(
            "HOK-001", "CRITICAL", "high", R.CONTROL_PLANE,
            f"Defines hooks: {', '.join(sorted(events))}",
            "Arbitrary shell on every tool call or session start, outside the visible flow.",
            "Genuine automation — must be declared and every command read.",
            "Read every hook command verbatim.",
            relpath, 1, _fmt(hooks)))
        if "PreToolUse" in hooks:
            out.append(StructuralFinding(
                "HOK-002", "CRITICAL", "high", R.CONTROL_PLANE,
                "PreToolUse hook — can return allow/deny",
                "Can auto-approve dangerous calls, or neutralize this auditor by denying it.",
                "Policy tooling only.",
                "Read the decision logic line by line.",
                relpath, 1, _fmt(hooks.get("PreToolUse"))))

    if data.get("mcpServers"):
        names, is_pointer = _server_names(data["mcpServers"])
        if names:
            out.append(StructuralFinding(
                "HOK-003", "CRITICAL", "high", R.CONTROL_PLANE,
                (f"Declares MCP config at {names[0]}" if is_pointer
                 else f"Registers MCP servers: {', '.join(names)}"),
                "MCP tool descriptions are prompt text injected into the agent context, "
                "controlled by a remote server and refreshed every launch.",
                "The MCP server is the unit's purpose and you trust its operator.",
                "Who operates each server?",
                relpath, 1, _fmt(names if not is_pointer else names[0]),
                specificity=80 if is_pointer else 90))

    raw = path.read_text(encoding="utf-8", errors="replace")
    if _PERMISSION_RED_FLAGS.search(raw):
        match = _PERMISSION_RED_FLAGS.search(raw)
        out.append(StructuralFinding(
            "HOK-006", "CRITICAL", "high", R.CONTROL_PLANE,
            "Lowers agent permissions",
            "Disarms the defenses for whatever comes next. The enabling move.",
            "Never from an installed extension.",
            "Revert this before installing anything else.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0))))

    perms = data.get("permissions", {})
    if isinstance(perms, dict) and perms.get("allow"):
        out.append(StructuralFinding(
            "HOK-006", "HIGH", "high", R.CONTROL_PLANE,
            f"Pre-grants {len(perms['allow'])} tool permissions",
            "Removes approval prompts the user would otherwise see.",
            "Convenience allowlists — read each entry.",
            "Does any entry grant Bash or network access?",
            relpath, 1, _fmt(perms["allow"]), specificity=85))

    return out


def _mcp_file(path: Path, relpath: str) -> list[StructuralFinding]:
    data = _load_json(path)
    names, _pointer = _server_names((data or {}).get("mcpServers") or {})
    if not names:
        return []
    return [StructuralFinding(
        "HOK-003", "CRITICAL", "high", R.CONTROL_PLANE,
        f"Registers MCP servers: {', '.join(names)}",
        "MCP tool descriptions are remote-controlled prompt text refreshed every launch.",
        "The MCP server is the unit's purpose and you trust its operator.",
        "Who operates each server?",
        relpath, 1, _fmt(names))]


def _package_json(path: Path, relpath: str) -> list[StructuralFinding]:
    data = _load_json(path)
    scripts = (data or {}).get("scripts") or {}
    hits = {k: v for k, v in scripts.items() if k in LIFECYCLE_SCRIPTS}
    if not hits:
        return []
    return [StructuralFinding(
        "AUT-001", "CRITICAL", "high", R.AUTO_EXEC,
        f"Package lifecycle scripts: {', '.join(sorted(hits))}",
        "Runs on `npm install` — before anyone reads the code.",
        "Genuine build steps — read the command.",
        "What exactly does the script run?",
        relpath, 1, _fmt(hits))]


def _opencode(path: Path, relpath: str) -> list[StructuralFinding]:
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    out = []
    if data.get("mcp"):
        names, _p = _server_names(data["mcp"])
        out.append(StructuralFinding(
            "HOK-003", "CRITICAL", "high", R.CONTROL_PLANE,
            f"Registers MCP servers: {', '.join(names)}",
            "Remote-controlled tool descriptions injected into the agent context.",
            "The MCP server is the unit's purpose.",
            "Who operates each server?",
            relpath, 1, _fmt(names)))
    if data.get("permission"):
        out.append(StructuralFinding(
            "HOK-006", "CRITICAL", "high", R.CONTROL_PLANE,
            "Sets opencode permission grants",
            "Disarms approval prompts for whatever comes next.",
            "Never from an installed extension.",
            "Read every grant.",
            relpath, 1, _fmt(data["permission"])))
    if data.get("agent"):
        agents, _p = _server_names(data["agent"])
        out.append(StructuralFinding(
            "HOK-004", "HIGH", "high", R.CONTROL_PLANE,
            f"Defines subagents: {', '.join(agents)}",
            "A subagent is a bypass of the parent unit's tool restrictions.",
            "Genuine delegation.",
            "Compare each subagent's tools to the unit's.",
            relpath, 1, _fmt(agents)))
    return out


def _codex_toml(path: Path, relpath: str) -> list[StructuralFinding]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    out = []
    if re.search(r"^\s*\[mcp_servers", raw, re.MULTILINE):
        out.append(StructuralFinding(
            "HOK-003", "CRITICAL", "high", R.CONTROL_PLANE,
            "Registers MCP servers (Codex)",
            "Remote-controlled tool descriptions injected into the agent context.",
            "The MCP server is the unit's purpose.",
            "Who operates each server?",
            relpath, 1, "[mcp_servers] block"))
    match = _PERMISSION_RED_FLAGS.search(raw)
    if match:
        out.append(StructuralFinding(
            "HOK-006", "CRITICAL", "high", R.CONTROL_PLANE,
            "Lowers Codex approval or sandbox policy",
            "Disarms the defenses for whatever comes next.",
            "Never from an installed extension.",
            "Revert before installing.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0))))
    return out


def _envrc(path: Path, relpath: str) -> list[StructuralFinding]:
    body = path.read_text(encoding="utf-8", errors="replace").strip()
    return [StructuralFinding(
        "AUT-002", "CRITICAL", "high", R.AUTO_EXEC,
        ".envrc — direnv shell on directory entry",
        "Shell executed on `cd` into the directory.",
        "Declared dev-environment setup.",
        "Read the whole file; it runs on cd.",
        relpath, 1, _fmt(body))]


def _vscode_tasks(path: Path, relpath: str) -> list[StructuralFinding]:
    data = _load_json(path)
    tasks = (data or {}).get("tasks") or []
    auto = [t for t in tasks if isinstance(t, dict)
            and str((t.get("runOptions") or {}).get("runOn", "")).lower() == "folderopen"]
    if not auto:
        return []
    return [StructuralFinding(
        "AUT-003", "HIGH", "high", R.AUTO_EXEC,
        f"{len(auto)} VS Code task(s) with runOn: folderOpen",
        "Runs when the project is opened.",
        "Declared dev tooling.",
        "Read each task command.",
        relpath, 1, _fmt([t.get("command") for t in auto]))]


def _git_config(path: Path, relpath: str, name: str) -> list[StructuralFinding]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for match in re.finditer(r"^\s*(\w[\w-]*)\s*=\s*!(.+)$", raw, re.MULTILINE):
        out.append(StructuralFinding(
            "AUT-005", "HIGH", "high", R.AUTO_EXEC,
            f"Git alias with shell escape: {match.group(1)}",
            "Runs on an ordinary git command.",
            "Declared repo tooling.",
            "Read the aliased command.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0).strip())))
    for match in re.finditer(r"^\s*\[filter\s+\"([^\"]+)\"\]|(clean|smudge)\s*=\s*(.+)$",
                             raw, re.MULTILINE):
        out.append(StructuralFinding(
            "AUT-005", "HIGH", "high", R.AUTO_EXEC,
            "Git clean/smudge filter",
            "Runs on checkout and commit of matching files.",
            "Declared repo tooling (git-lfs, crypt).",
            "Read the filter command.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0).strip())))
    return out
