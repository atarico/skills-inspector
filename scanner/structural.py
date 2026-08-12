"""Agent control plane and ambient auto-execution — RULES.md sections H and I.

These are structural, not textual: they come from parsing config files. Every
rule here grants execution or tool access without matching anything in A-F,
which is exactly why a generic scanner misses them.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

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
    r"|\"defaultMode\"\s*:\s*\"(bypassPermissions|acceptEdits)\""
    r"|\"enableAllProjectMcpServers\"\s*:\s*true",
    re.IGNORECASE,
)

_PTH_EXEC = re.compile(r"^\s*import\s+", re.MULTILINE)

# ---------------------------------------------------------------- MCP server bodies
# HOK-008…HOK-016. The names were always listed (HOK-003); these read the body
# of each entry — command, args, env, url, autoApprove — one finding per server
# per rule, never a per-file rollup.

_MCP_ENV_INJECTION = {"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
                      "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONPATH", "HOME"}
_SECRETISH_KEY = re.compile(r"key|token|secret|passw|credential|auth", re.IGNORECASE)
# `${VAR}` / `$VAR` is a reference the user resolves at launch, not a shipped value.
_ENV_REFERENCE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
_MUTABLE_REF = re.compile(r"git\+|#(main|master)\b", re.IGNORECASE)
_PINNED_VERSION = re.compile(r"@\d")
# The host must END at a real terminator (port, path, query, fragment, or end
# of string) — a bare prefix would classify attacker-registered hostnames like
# `localhost.evil.example` or `127.evil.example` as local.
_LOCAL_URL = re.compile(
    r"^https?://(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\])"
    r"(:\d+)?([/?#]|$)", re.IGNORECASE)
_SHELL_WRAPPERS = {"sh", "bash", "zsh", "ksh", "dash",
                   "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
_SHELL_EXEC_FLAGS = {"-c", "/c", "-command"}
_SENSITIVE_ARG = re.compile(
    r"^(~|/|\$HOME)$|(^|/)\.(ssh|aws)(/|$)|\.env(\.[\w-]+)?$"
    r"|\.pem$|credentials\.json$|id_rsa")
# Each fragment keeps >=2 regex-shape tokens so the self-scan reads this line
# as the catalogued pattern it is (position.literal_demotion), not a live host.
_EXFIL_HOST = re.compile(
    r"\bngrok\b|webhook\.site|\brequestbin\b|\bpipedream\b|\binteractsh\b"
    r"|/exfil\b|/collect\?data=", re.IGNORECASE)
_SANDBOX_FLAG = re.compile(
    r"^--(no-sandbox|disable-setuid-sandbox|disable-web-security|insecure"
    r"|ignore-certificate-errors|allow-running-insecure-content)(=|$)")

# ---------------------------------------------------------------- hook commands
# HOK-017…HOK-020. Hook commands are shell run by the harness; the event they
# ride on is part of what the capability IS, so severity is event-conditioned
# at emission time. This is not an axis multiplication: a hook that fires on
# every tool call with attacker-influenceable input is a different capability
# than the same line on Stop, where no tool input exists.
_HOOK_INTERPOLATION = re.compile(
    r"\$\{(file|file_path|command|content|input|args?|tool_input|prompt)\}")
_HOOK_ENV_SOURCE = re.compile(r"(?:(?:^|[;&|(]\s*)\.\s+|\bsource\s+)[\"']?\$")
_HOOK_SUPPRESSION = re.compile(r"2>\s*/dev/null|\|\|\s*(?:true\b|:(?:[\s;]|$))")
_HOOK_TMP_WRITE = re.compile(r"(?:>>?\s*|\btee\s+(?:-a\s+)?)[\"']?/tmp/")
# Events where attacker-influenceable input flows into the command environment.
_HOOK_TOOL_INPUT_EVENTS = {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
# Events that fire after the interesting work, or rarely: same pattern, one
# severity level lower.
_HOOK_PASSIVE_EVENTS = {"Stop", "SubagentStop", "SessionEnd",
                        "Notification", "PreCompact"}
_SEVERITY_DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM",
                  "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}

# ---------------------------------------------------------------- permission entries
# HOK-021…HOK-025. permissions.allow entries classified individually.
_PERM_ENTRY = re.compile(r"^([A-Za-z_][\w-]*)\s*(?:\((.*)\))?$")
_MUTABLE_TOOLS = {"Bash", "Write", "Edit"}
_WILDCARD_INNER = {"", "*", "**", ":*", "*:*"}
_DANGEROUS_BASH_TARGET = re.compile(
    r"^\s*(sudo|eval|exec|curl|wget|ssh|scp|nc|docker)\b")
_SENSITIVE_PERM_PATH = re.compile(
    r"~/\.(ssh|aws)|(^|[\s(:])/etc/|\.env(\.[\w-]+)?\b|\.ssh/|\.aws/")
_WILDCARD_ROOT = re.compile(r"^/{1,2}\*\*?($|/)|^~/\*\*$")

# NET-013's structural half: the env block of a settings file. The line pass in
# rules.py covers scripts and prose; this covers the parsed config, whatever
# its formatting.
_ENDPOINT_ENV_VARS = {"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE",
                      "AZURE_OPENAI_ENDPOINT", "MODEL_BASE_URL",
                      "ANTHROPIC_AUTH_TOKEN"}


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


def _load_json(text: str):
    try:
        return json.loads(text)
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


def _line_of(text: str, needle: str) -> int:
    """Line of the first occurrence of `needle`, 1 if absent.

    Structural findings historically all carried line=1, and the dedupe key
    includes the line — so two servers tripping the same rule in one file
    collapsed into one finding. Anchoring each finding to the line its subject
    sits on keeps them distinct AND points the reviewer at the right entry.
    """
    idx = text.find(needle)
    return text[:idx].count("\n") + 1 if idx >= 0 else 1


def _mcp_server_findings(servers, relpath: str, text: str) -> list[StructuralFinding]:
    """HOK-008…HOK-016: one finding per server per rule.

    Never resolves or executes anything: this reads the declared command, args,
    env and url exactly as shipped.
    """
    out: list[StructuralFinding] = []
    if not isinstance(servers, dict):
        return out
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        label = str(name)
        line = _line_of(text, json.dumps(label))

        command = server.get("command")
        if isinstance(command, list):
            tokens = [str(t) for t in command]
        elif isinstance(command, str):
            tokens = command.split()
        else:
            tokens = []
        args = server.get("args")
        if isinstance(args, list):
            arg_list = [str(a) for a in args if isinstance(a, (str, int, float))]
        elif isinstance(args, str):
            arg_list = [args]
        else:
            arg_list = []
        all_tokens = tokens + arg_list
        invocation = " ".join(all_tokens)

        env = server.get("env")
        if not isinstance(env, dict):
            env = server.get("environment")  # opencode spelling
        env = env if isinstance(env, dict) else {}
        env_items = [(str(k), v) for k, v in env.items()]

        def _add(rule_id, severity, capability, detects, impact, legitimate,
                 check, evidence):
            out.append(StructuralFinding(
                rule_id, severity, "high", capability,
                f"MCP server '{label}': {detects}",
                impact, legitimate, check, relpath, line, evidence))

        # HOK-008 — env override of loader/interpreter variables.
        injected = sorted(k for k, _v in env_items if k in _MCP_ENV_INJECTION)
        if injected:
            _add("HOK-008", "CRITICAL", R.CONTROL_PLANE,
                 f"env overrides loader variables: {', '.join(injected)}",
                 "These variables inject code into or redirect every process the "
                 "server spawns — a library preload is arbitrary code execution.",
                 "Effectively never in a distributed config.",
                 "What does each overridden variable point at?",
                 _fmt({k: env.get(k) for k in injected}))

        # HOK-009 — hardcoded secret value in env. Evidence is redacted to a
        # prefix and a length: a finding must never republish the secret.
        hardcoded = []
        for key, value in env_items:
            if not _SECRETISH_KEY.search(key) or not isinstance(value, str):
                continue
            stripped = value.strip()
            if len(stripped) < 6 or _ENV_REFERENCE.match(stripped):
                continue
            if (stripped.startswith("<") or stripped.startswith("{{")
                    or re.fullmatch(r"[A-Z][A-Z0-9_]*", stripped)):
                continue  # placeholder, not a value
            hardcoded.append(f"{key}={stripped[:4]}…({len(stripped)} chars)")
        if hardcoded:
            _add("HOK-009", "CRITICAL", R.SECRETS,
                 "hardcoded secret in env",
                 "A live credential shipped inside the bundle: anyone with the "
                 "file has the key, and the server starts with it every launch.",
                 "Never — reference the user's own env with ${VAR} instead.",
                 "Rotate the key; it is public the moment the bundle is shared.",
                 "; ".join(hardcoded))

        # HOK-010 — auto-approval of the server's tools.
        for key in ("autoApprove", "auto_confirm", "alwaysAllow", "autoapprove"):
            value = server.get(key)
            if value is True or (isinstance(value, list) and value) \
                    or (isinstance(value, str) and value.lower() == "true"):
                _add("HOK-010", "HIGH", R.CONTROL_PLANE,
                     f"auto-approves tool calls ({key})",
                     "Defeats human-in-the-loop: the server's tools run without "
                     "the approval prompt the user expects to see.",
                     "Never from an installed extension — the user may opt in "
                     "for themselves.",
                     "Which tools does this silently approve?",
                     _fmt({key: value}))
                break

        # HOK-011 — unpinned or mutable package source.
        if _MUTABLE_REF.search(invocation):
            _add("HOK-011", "HIGH", R.REMOTE_EXEC,
                 "launches from a mutable source ref",
                 "The code that runs can change after the audit — a branch ref "
                 "is whatever the remote says it is today.",
                 "Internal tooling pinned to a commit SHA.",
                 "Pin the ref to an immutable SHA or version.",
                 _fmt(invocation))
        elif any(PurePosixPath(t).name == "npx" for t in all_tokens) \
                and any(t in ("-y", "--yes") for t in all_tokens) \
                and not _PINNED_VERSION.search(invocation):
            _add("HOK-011", "MEDIUM", R.REMOTE_EXEC,
                 "unpinned npx -y install-and-run",
                 "Fetches and executes whatever version the registry serves at "
                 "launch time, with no prompt and no pin.",
                 "Very common in MCP configs — still worth pinning.",
                 "Pin the package to an exact version.",
                 _fmt(invocation))

        # HOK-012 — non-local URL transport.
        for field in ("url", "serverUrl", "httpUrl", "uri"):
            value = server.get(field)
            if isinstance(value, str) and value.startswith(("http://", "https://")) \
                    and not _LOCAL_URL.match(value):
                _add("HOK-012", "HIGH", R.NETWORK,
                     "remote URL transport",
                     "Tool definitions and results flow to and from a remote "
                     "host on every session, controlled by its operator.",
                     "Hosted MCP services you knowingly subscribe to.",
                     "Who operates that host?",
                     _fmt(value))
                break

        # HOK-013 — shell wrapper around the real command.
        if tokens and PurePosixPath(tokens[0]).name.lower() in _SHELL_WRAPPERS \
                and any(t.lower() in _SHELL_EXEC_FLAGS for t in all_tokens[1:]):
            _add("HOK-013", "HIGH", R.CONTROL_PLANE,
                 "command is a shell wrapper (-c)",
                 "The real command hides inside a shell string — pipes, "
                 "substitutions and redirects the config schema cannot see.",
                 "Rare; a direct binary invocation needs no shell.",
                 "Read the wrapped shell string as if it were a script.",
                 _fmt(invocation))

        # HOK-014 — root, home, or sensitive-file argument.
        sensitive = [t for t in all_tokens[1:] if _SENSITIVE_ARG.search(t)]
        if sensitive:
            _add("HOK-014", "HIGH", R.SECRETS,
                 f"sensitive path in args: {', '.join(sensitive[:3])}",
                 "The server is handed credentials or filesystem roots as its "
                 "working scope.",
                 "A filesystem server the user deliberately scoped that wide.",
                 "Why does this server need that path?",
                 _fmt(sensitive))

        # HOK-015 — known exfil host in args or env values.
        haystack = invocation + " " + " ".join(
            str(v) for _k, v in env_items if isinstance(v, (str, int, float)))
        match = _EXFIL_HOST.search(haystack)
        if match:
            _add("HOK-015", "HIGH", R.NETWORK,
                 "known exfiltration endpoint in args/env",
                 "Disposable collection infrastructure wired into the server's "
                 "own configuration.",
                 "Tunnel-based local dev — verify you started the tunnel yourself.",
                 "Do you control that endpoint?",
                 _fmt(haystack[max(0, match.start() - 20):match.end() + 40]))

        # HOK-016 — sandbox-disabling flags.
        unsafe_flags = [t for t in all_tokens if _SANDBOX_FLAG.match(t)]
        if unsafe_flags:
            _add("HOK-016", "CRITICAL", R.PRIVILEGE,
                 f"sandbox-disabling flag: {', '.join(unsafe_flags)}",
                 "Removes the isolation layer the tool itself considers "
                 "mandatory; content it touches gets code execution.",
                 "Effectively never in a distributed config.",
                 "Remove the flag before allowing this server.",
                 _fmt(unsafe_flags))
    return out


def _hook_commands(hooks) -> list[tuple[str, str]]:
    """(event, command) pairs from a Claude hooks block, defensively.

    The real schema is event → [{matcher, hooks: [{type, command}]}], but this
    walks anything dict/list/str-shaped without raising: hostile configs go
    through here too, and a parser crash is a denial of audit (BND-006).
    """
    pairs: list[tuple[str, str]] = []
    if not isinstance(hooks, dict):
        return pairs
    for event, groups in hooks.items():
        event = str(event)
        if isinstance(groups, str):
            pairs.append((event, groups))
            continue
        if not isinstance(groups, list):
            continue
        for group in groups:
            if isinstance(group, str):
                pairs.append((event, group))
                continue
            if not isinstance(group, dict):
                continue
            inner = group.get("hooks")
            for entry in inner if isinstance(inner, list) else [group]:
                if isinstance(entry, dict) and isinstance(entry.get("command"), str):
                    pairs.append((event, entry["command"]))
    return pairs


def _hook_findings(hooks, relpath: str, text: str) -> list[StructuralFinding]:
    """HOK-017…HOK-020: hook-specific analysis of each command string.

    Severity is event-conditioned at emission: the event is part of what the
    capability is (a ${file} interpolation on PreToolUse receives attacker-
    influenceable tool input; on Stop there is none). This is not an axis
    being multiplied — the axes still never are.
    """
    grouped: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for event, command in _hook_commands(hooks):
        hits: list[tuple[str, str]] = []
        if _HOOK_INTERPOLATION.search(command):
            hits.append(("HOK-017",
                         "CRITICAL" if event in _HOOK_TOOL_INPUT_EVENTS else "HIGH"))
        if _HOOK_ENV_SOURCE.search(command):
            severity = "HIGH"
            if event in _HOOK_PASSIVE_EVENTS:
                severity = _SEVERITY_DOWN[severity]
            hits.append(("HOK-018", severity))
        if _HOOK_SUPPRESSION.search(command):
            hits.append(("HOK-019", "MEDIUM"))
        if _HOOK_TMP_WRITE.search(command):
            severity = "HIGH"
            if event in _HOOK_PASSIVE_EVENTS:
                severity = _SEVERITY_DOWN[severity]
            hits.append(("HOK-020", severity))
        for rule_id, severity in hits:
            key = (rule_id, event)
            prev = grouped.get(key)
            commands = prev[1] if prev else []
            commands.append(command)
            grouped[key] = (severity, commands)

    _TEXTS = {
        "HOK-017": ("interpolates tool input into shell",
                    "Whatever lands in that variable — file paths, command text, "
                    "prompt content — is pasted into a shell line. Command "
                    "injection by whoever influences the input.",
                    "Never — read the value from stdin JSON instead.",
                    "What can an attacker place in the interpolated variable?"),
        "HOK-018": ("sources a script from an env-derived path",
                    "The executed code is chosen by an environment variable at "
                    "runtime, not by the file you are reading.",
                    "Dev-environment loaders — the variable must be yours.",
                    "Who controls the variable, and what does it point at?"),
        "HOK-019": ("suppresses its own errors",
                    "Failures vanish: the hook can act (or be sabotaged) and "
                    "nothing surfaces.",
                    "Noise reduction on genuinely optional steps.",
                    "What failure is being hidden, and from whom?"),
        "HOK-020": ("writes to world-readable /tmp",
                    "Anything written there — session data, env dumps — is "
                    "readable by every local user, and a predictable path "
                    "invites symlink attacks.",
                    "Scratch files with no sensitive content.",
                    "What is written, and does it contain session data?"),
    }
    out: list[StructuralFinding] = []
    for (rule_id, event), (severity, commands) in grouped.items():
        detects, impact, legitimate, what = _TEXTS[rule_id]
        out.append(StructuralFinding(
            rule_id, severity, "high", R.CONTROL_PLANE,
            f"{event} hook {detects}",
            impact, legitimate, what,
            relpath, _line_of(text, json.dumps(event)),
            _fmt("; ".join(commands))))
    return out


def _permission_findings(perms, relpath: str, text: str) -> list[StructuralFinding]:
    """HOK-021…HOK-025: classify each permissions.allow entry.

    HOK-006 already reports that grants exist; these say what each one is. The
    combination rule (HOK-024) is the part a per-line regex cannot express.
    """
    out: list[StructuralFinding] = []
    allow = perms.get("allow")
    if not isinstance(allow, list):
        return out
    granted_tools: set[str] = set()
    any_entry = False
    for entry in allow:
        if not isinstance(entry, str):
            continue
        match = _PERM_ENTRY.match(entry.strip())
        if not match:
            continue
        any_entry = True
        tool, inner = match.group(1), match.group(2)
        granted_tools.add(tool)
        line = _line_of(text, json.dumps(entry))

        if tool in _MUTABLE_TOOLS and (inner is None
                                       or inner.strip() in _WILDCARD_INNER):
            out.append(StructuralFinding(
                "HOK-021", "CRITICAL", "high", R.CONTROL_PLANE,
                f"Unrestricted {tool} grant: {entry}",
                "Every use of the tool runs without a prompt — for Bash that is "
                "arbitrary shell, pre-approved.",
                "Never from an installed extension.",
                "Scope the grant to the specific commands or paths needed.",
                relpath, line, _fmt(entry)))
        elif tool == "Bash" and inner and _DANGEROUS_BASH_TARGET.match(inner):
            out.append(StructuralFinding(
                "HOK-022", "CRITICAL", "high", R.CONTROL_PLANE,
                f"Pre-approved dangerous command: {entry}",
                "sudo, eval, network clients and remote shells run without the "
                "prompt that exists precisely for them.",
                "Effectively never — these are the commands prompts are for.",
                "Why does this unit need that command pre-approved?",
                relpath, line, _fmt(entry)))
        elif inner and (_SENSITIVE_PERM_PATH.search(inner)
                        or _WILDCARD_ROOT.match(inner.strip())):
            out.append(StructuralFinding(
                "HOK-023", "HIGH", "high", R.CONTROL_PLANE,
                f"Grant touches a sensitive or root path: {entry}",
                "Pre-approved access to credentials, system config, or the "
                "whole filesystem.",
                "Rarely — and never for ~/.ssh or ~/.aws.",
                "Narrow the path to what the unit actually needs.",
                relpath, line, _fmt(entry)))

    if _MUTABLE_TOOLS <= granted_tools:
        out.append(StructuralFinding(
            "HOK-024", "HIGH", "high", R.CONTROL_PLANE,
            "Bash, Write and Edit all pre-granted",
            "The full mutation set: run commands, create files, change files — "
            "individually scoped grants that combine into free rein.",
            "Broad dev setups a user configured for themselves.",
            "Does this unit really need all three without prompts?",
            relpath, _line_of(text, '"permissions"'), _fmt(sorted(granted_tools)),
            specificity=85))
    if any_entry and not perms.get("deny"):
        out.append(StructuralFinding(
            "HOK-025", "LOW", "high", R.CONTROL_PLANE,
            "Allowlist with no deny list",
            "Nothing backstops the grants: anything an allow entry reaches is "
            "reachable without a second look.",
            "Common in personal settings; a bundle should ship its own denies.",
            "Should a deny list cap what the allows can reach?",
            relpath, _line_of(text, '"permissions"'), _fmt(perms.get("allow")),
            specificity=70))
    return out


def _endpoint_env_findings(env, relpath: str, text: str) -> list[StructuralFinding]:
    """NET-013, structural half: model endpoint override in a settings env block."""
    out: list[StructuralFinding] = []
    if not isinstance(env, dict):
        return out
    for key, value in env.items():
        if str(key) not in _ENDPOINT_ENV_VARS or not isinstance(value, str):
            continue
        if not value.startswith(("http://", "https://")) or _LOCAL_URL.match(value):
            continue
        out.append(StructuralFinding(
            "NET-013", "CRITICAL", "high", R.NETWORK,
            f"Model endpoint override: {key}",
            "Redirects every API call the agent makes through that host and "
            "hands it the API key. One env var, total interception.",
            "Corporate LLM gateways — must be declared, and you must operate "
            "the host.",
            "Who operates the endpoint now receiving your API traffic and key?",
            relpath, _line_of(text, json.dumps(str(key))),
            _fmt(f"{key}={value}"), specificity=95))
    return out


def inspect(relpath: str, text: str) -> list[StructuralFinding]:
    """Structural checks for one file. Returns findings, never raises.

    Takes the file's TEXT, not its path. This module is the domain core — the
    part that decides what a config file means — and it used to be the only
    place in it that touched the filesystem, re-reading from disk a file the
    caller had already read. That made every check here impossible to unit-test
    without a temporary directory, which is why none of them had tests.
    """
    name = PurePosixPath(relpath).name
    out: list[StructuralFinding] = []

    try:
        if name in {"settings.json", "settings.local.json"} or relpath.endswith(".claude/settings.json"):
            out += _claude_settings(text, relpath)
        if name == ".mcp.json":
            out += _mcp_file(text, relpath)
        if name == "package.json":
            out += _package_json(text, relpath)
        if name == "plugin.json" or name == "marketplace.json":
            out += _claude_settings(text, relpath)
        if name == "opencode.json" or name == "opencode.jsonc":
            out += _opencode(text, relpath)
        if name == ".envrc":
            out += _envrc(text, relpath)
        if relpath.endswith(".vscode/tasks.json"):
            out += _vscode_tasks(text, relpath)
        if name in {"sitecustomize.py", "usercustomize.py"}:
            out.append(StructuralFinding(
                "AUT-004", "CRITICAL", "high", R.AUTO_EXEC,
                "Python import-time hook",
                "Runs on every Python process start, system-wide.",
                "Effectively never in a distributed bundle.",
                "Read the whole file — it runs before anything else.",
                relpath, 1, f"{name} present in bundle"))
        if relpath.endswith(".pth"):
            if _PTH_EXEC.search(text):
                out.append(StructuralFinding(
                    "AUT-004", "CRITICAL", "high", R.AUTO_EXEC,
                    ".pth file with an executable import line",
                    "Runs on every Python process start, system-wide.",
                    "Effectively never.",
                    "Read the import target.",
                    relpath, 1, _fmt(text.strip()[:120])))
        if name in {".gitconfig", "gitconfig", ".gitattributes"}:
            out += _git_config(text, relpath, name)
        if PurePosixPath(relpath).parts[:1] == (".opencode",) and relpath.endswith(".js"):
            out.append(StructuralFinding(
                "HOK-007", "CRITICAL", "high", R.CONTROL_PLANE,
                "Executable opencode plugin code",
                "Not configuration — code that runs inside the agent process.",
                "The plugin is the unit's stated purpose.",
                "Read the plugin entry point in full.",
                relpath, 1, "opencode plugin module"))
        if relpath.endswith("config.toml") and ".codex" in relpath:
            out += _codex_toml(text, relpath)
    except Exception as exc:
        # Swallowing this silently made the fuzz suite VACUOUS for this module:
        # every malformed-input case "passed" because the parser threw, the
        # exception vanished, and an empty result is indistinguishable from a
        # clean file. A structural check that dies on a hostile config is a
        # denial of audit, so it is now reported as one.
        out.append(StructuralFinding(
            "BND-006", "MEDIUM", "high", R.CONTROL_PLANE,
            "Structural analysis failed on this file",
            "The control-plane checks could not run here, so whatever this file "
            "configures was never examined.",
            "Genuinely malformed config, or a format this version cannot parse.",
            "Open the file yourself — the audit did not cover it.",
            relpath, 1, f"{type(exc).__name__}: {exc}"))
        return out

    return out


def _claude_settings(text: str, relpath: str) -> list[StructuralFinding]:
    data = _load_json(text)
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
        out += _hook_findings(hooks, relpath, text)

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
        out += _mcp_server_findings(data["mcpServers"], relpath, text)

    raw = text
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
    if isinstance(perms, dict):
        out += _permission_findings(perms, relpath, text)

    out += _endpoint_env_findings(data.get("env"), relpath, text)

    return out


def _mcp_file(text: str, relpath: str) -> list[StructuralFinding]:
    data = _load_json(text)
    servers = (data or {}).get("mcpServers") if isinstance(data, dict) else {}
    names, _pointer = _server_names(servers or {})
    if not names:
        return []
    return [StructuralFinding(
        "HOK-003", "CRITICAL", "high", R.CONTROL_PLANE,
        f"Registers MCP servers: {', '.join(names)}",
        "MCP tool descriptions are remote-controlled prompt text refreshed every launch.",
        "The MCP server is the unit's purpose and you trust its operator.",
        "Who operates each server?",
        relpath, 1, _fmt(names))] + _mcp_server_findings(servers, relpath, text)


def _package_json(text: str, relpath: str) -> list[StructuralFinding]:
    data = _load_json(text)
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


def _opencode(text: str, relpath: str) -> list[StructuralFinding]:
    data = _load_json(text)
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
        out += _mcp_server_findings(data["mcp"], relpath, text)
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


def _codex_toml(text: str, relpath: str) -> list[StructuralFinding]:
    raw = text
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


def _envrc(text: str, relpath: str) -> list[StructuralFinding]:
    body = text.strip()
    return [StructuralFinding(
        "AUT-002", "CRITICAL", "high", R.AUTO_EXEC,
        ".envrc — direnv shell on directory entry",
        "Shell executed on `cd` into the directory.",
        "Declared dev-environment setup.",
        "Read the whole file; it runs on cd.",
        relpath, 1, _fmt(body))]


def _vscode_tasks(text: str, relpath: str) -> list[StructuralFinding]:
    data = _load_json(text)
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


def _git_config(text: str, relpath: str, name: str) -> list[StructuralFinding]:
    raw = text
    out = []
    for match in re.finditer(r"^\s*(\w[\w-]*)\s*=\s*!(.+)$", raw, re.MULTILINE):
        out.append(StructuralFinding(
            "AUT-005", "HIGH", "high", R.AUTO_EXEC,
            f"Git alias with shell escape: {match.group(1)}",
            "Runs on an ordinary git command.",
            "Declared repo tooling.",
            "Read the aliased command.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0).strip())))
    # Anchored, and the section header no longer produces a finding of its own.
    # The old alternation bound `^\s*` to the first branch only and had no word
    # boundary on `clean`, so git's own stock `autoclean = true` contained
    # "clean = true" and was reported as an executable filter — HIGH severity,
    # on a default config. The header `[filter "lfs"]` is not executable either;
    # the command lines under it are, and those are what get reported now.
    for match in re.finditer(r"^\s*(clean|smudge)\s*=\s*(.+)$", raw, re.MULTILINE):
        out.append(StructuralFinding(
            "AUT-005", "HIGH", "high", R.AUTO_EXEC,
            f"Git {match.group(1)} filter",
            "Runs on checkout and commit of matching files.",
            "Declared repo tooling (git-lfs, crypt).",
            "Read the filter command.",
            relpath, raw[:match.start()].count("\n") + 1, _fmt(match.group(0).strip())))
    return out
