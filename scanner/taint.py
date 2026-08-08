"""Taint tracking — RULES.md section 4.

Separates *has network* from *exfiltrates*. Co-occurrence is not data flow: a
deploy tool reads .env and calls an API, and that is normal. What is not normal
is the read reaching the call.

Tracks four propagation channels: variable, filesystem, environment, and direct
pipe. The filesystem channel is not optional — without it the model is defeated
by `cat secret > /tmp/x; curl -T /tmp/x`, which is the first thing anyone tries.

Sound-ish, definitely not complete. Catches direct and one-hop-indirect flows
inside a single file. Does not follow flows through a spawned interpreter, a
config file read later, or anything needing program semantics. That is a
completeness gap (reported in coverage limits), never a confidence discount on
the flows it does find.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import position as pos
from . import rules as R

SOURCE_CAPABILITIES = {R.SECRETS, R.RECON}
SINK_CAPABILITIES = {R.NETWORK}

_SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", "", ".ksh"}

# VAR=..., export VAR=..., const/let/var v = ..., v: T = ...
_ASSIGN = re.compile(
    r"^\s*(?:export\s+|declare\s+-\w+\s+|local\s+|const\s+|let\s+|var\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=\n]+)?=(?!=)\s*(.+)$")

# cmd > path   cmd >> path   | tee path
_REDIRECT = re.compile(r"(?:>>?|\|\s*tee(?:\s+-a)?)\s+[\"']?([^\s\"'|;&]+)")

# open(p,'w').write(x) / Path(p).write_text(x) / fs.writeFileSync(p, x)
_WRITE_CALL = re.compile(
    r"(?:open\s*\(\s*[\"']([^\"']+)[\"'][^)]*[\"']w|"
    r"[Pp]ath\s*\(\s*[\"']([^\"']+)[\"']\s*\)\s*\.write_text|"
    r"writeFileSync\s*\(\s*[\"']([^\"']+)[\"'])")

# A sink consuming a file: -T f, @f, --data-binary @f, < f, upload(f)
_FILE_CONSUMED = re.compile(
    r"(?:-T\s+|--data(?:-binary|-raw)?\s+@|-d\s+@|@|<\s*|files=\{[^}]*open\s*\(\s*[\"'])"
    r"[\"']?([^\s\"'|;&)]+)")

# Reading stdin from a pipe: the left side of `|` feeds the right side.
_STDIN_MARKER = re.compile(r"(?:-d\s+@-|--data-binary\s+@-|-T\s+-|\s-\s*$|\|\s*(?:curl|wget|nc)\b)")


@dataclass
class Origin:
    line: int
    kind: str          # "variable" | "filesystem" | "environment"
    rule_id: str
    evidence: str


@dataclass
class Chain:
    file: str
    sink_line: int
    sink_rule: str
    sink_evidence: str
    origin: Origin
    channel: str
    absorbed: list[tuple[str, int, str]] = field(default_factory=list)

    def hops(self) -> list[dict]:
        return [
            {"step": "source", "line": self.origin.line,
             "rule": self.origin.rule_id, "evidence": self.origin.evidence},
            {"step": "propagation", "channel": self.channel},
            {"step": "sink", "line": self.sink_line,
             "rule": self.sink_rule, "evidence": self.sink_evidence},
        ]


def _matching_rules(line: str) -> list[R.Rule]:
    return [rule for rule in R.RULES if rule.pattern.search(line)]


def _is_shell(relpath: str) -> bool:
    return PurePosixPath(relpath).suffix.lower() in _SHELL_SUFFIXES


def _references_var(line: str, var: str, shell: bool) -> bool:
    if shell:
        return bool(re.search(r"\$\{?" + re.escape(var) + r"\b", line))
    return bool(re.search(r"(?<![.\w])" + re.escape(var) + r"(?![\w])", line))


def _normalize(path: str) -> str:
    return PurePosixPath(path.strip("\"'")).name


def analyze(relpath: str, text: str, positions: list[tuple[str, str]]) -> list[Chain]:
    """Find source -> sink flows in one file."""
    shell = _is_shell(relpath)
    lines = text.splitlines()
    tainted_vars: dict[str, Origin] = {}
    tainted_files: dict[str, Origin] = {}
    chains: list[Chain] = []

    for idx, raw in enumerate(lines):
        line = raw.rstrip()
        if not line.strip():
            continue
        position = positions[idx][0] if idx < len(positions) else pos.ACTIVE
        # Only live statements carry data. A documented example does not run.
        if position != pos.ACTIVE:
            continue
        if pos.literal_demotion(line, 0) and not shell:
            continue

        matched = _matching_rules(line)
        source_rules = [r for r in matched if r.capability in SOURCE_CAPABILITIES]
        sink_rules = [r for r in matched
                      if r.capability in SINK_CAPABILITIES and r.severity != "INFO"]
        if not sink_rules:
            sink_rules = [r for r in matched if r.capability in SINK_CAPABILITIES]

        lineno = idx + 1
        snippet = line.strip()[:160]

        # --- source and sink joined on one line --------------------------------
        # Two shapes: piped (`cat secret | curl`) and the sink consuming the
        # secret path inline (`curl --data-binary @~/.ssh/id_rsa`). The second is
        # the most blatant exfiltration there is and has no variable to track.
        if source_rules and sink_rules:
            piped = "|" in line or bool(_STDIN_MARKER.search(line))
            consumes = bool(_FILE_CONSUMED.search(line))
            if piped or consumes:
                channel = "direct pipe" if piped else "sink reads the secret path"
                origin = Origin(lineno, channel, source_rules[0].id, snippet)
                chains.append(Chain(relpath, lineno, sink_rules[0].id, snippet,
                                    origin, channel,
                                    absorbed=[(relpath, lineno, source_rules[0].id),
                                              (relpath, lineno, sink_rules[0].id)]))
                continue

        # --- sink consuming a tainted variable or file -------------------------
        if sink_rules:
            hit = None
            for var, origin in tainted_vars.items():
                if _references_var(line, var, shell):
                    hit = (origin, f"variable ${var}" if shell else f"variable {var}")
                    break
            if hit is None:
                for consumed in _FILE_CONSUMED.findall(line):
                    key = _normalize(consumed)
                    if key in tainted_files:
                        hit = (tainted_files[key], f"file {key}")
                        break
            if hit:
                origin, channel = hit
                chains.append(Chain(relpath, lineno, sink_rules[0].id, snippet,
                                    origin, channel,
                                    absorbed=[(relpath, origin.line, origin.rule_id),
                                              (relpath, lineno, sink_rules[0].id)]))
                continue

        if not source_rules:
            continue

        # --- propagation: the source lands somewhere ---------------------------
        origin_rule = source_rules[0]

        assign = _ASSIGN.match(line)
        if assign:
            var = assign.group(1)
            kind = "environment" if line.lstrip().startswith("export") else "variable"
            tainted_vars[var] = Origin(lineno, kind, origin_rule.id, snippet)
            continue

        for match in (_REDIRECT.search(line), _WRITE_CALL.search(line)):
            if not match:
                continue
            target = next((g for g in match.groups() if g), None)
            if target and not target.startswith(("&", "/dev/")):
                tainted_files[_normalize(target)] = Origin(
                    lineno, "filesystem", origin_rule.id, snippet)
            break

    return chains
