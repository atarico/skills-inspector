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

_SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".ksh"}

# An extensionless file is shell only if it says so. The empty string used to be
# in the set above, which made every Makefile, Dockerfile, LICENSE and README
# without a suffix take the shell branch: `$VAR` reference syntax instead of the
# language-neutral one, and — worse — a skipped `literal_demotion` probe, since
# that check is guarded by `not shell`.
_SHEBANG = re.compile(r"^#!.*\b(?:ba|z|k|da)?sh\b")

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

# $(...) or `...` embedded in the line: the source's output is substituted
# straight into the sink's arguments.
_SUBSTITUTION = re.compile(r"\$\([^)]{2,200}\)|`[^`\n]{2,200}`")


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


def _is_shell(relpath: str, text: str = "") -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix:
        return suffix in _SHELL_SUFFIXES
    return bool(_SHEBANG.match(text.partition("\n")[0]))


def _references_var(line: str, var: str, shell: bool) -> bool:
    if shell:
        return bool(re.search(r"\$\{?" + re.escape(var) + r"\b", line))
    return bool(re.search(r"(?<![.\w])" + re.escape(var) + r"(?![\w])", line))


def _normalize(path: str) -> str:
    """Canonical form of a path, keeping its directory.

    This used to return the basename, so `backup/creds.txt` and
    `logs/creds.txt` were the same key and a write to one plus a read of the
    other was reported as an exfiltration chain that does not exist. A false
    chain is worse than a missed one: it accuses.
    """
    cleaned = path.strip("\"'").strip()
    if not cleaned:
        return cleaned
    try:
        return str(PurePosixPath(cleaned))
    except ValueError:
        return cleaned


def analyze(relpath: str, text: str, positions: list[tuple[str, str]],
            line_matches: dict[int, list] | None = None) -> list[Chain]:
    """Find source -> sink flows in one file.

    `line_matches` is the rule-match map the scanning pass already computed.
    Recomputing it here re-ran all 68 patterns over every line a second time —
    a third of the total regex work on a large bundle, for no new information.
    """
    shell = _is_shell(relpath, text)
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
        matched = (line_matches.get(idx) if line_matches is not None
                   else _matching_rules(line))

        # Reassignment, handled BEFORE the no-match bail. A line that clears a
        # tainted variable (`K=hello`) matches no rule, so it never reached the
        # propagation code below and the stale taint survived — producing a
        # CRITICAL chain whose reported source was a value no longer being sent.
        # The same pass propagates var-to-var (`payload = secret`), which a
        # single rename otherwise used to break the chain entirely.
        if tainted_vars:
            assign = _ASSIGN.match(line)
            if assign:
                target, rhs = assign.group(1), assign.group(2)
                donor = next((v for v in list(tainted_vars)
                              if v != target and _references_var(rhs, v, shell)), None)
                if donor is not None:
                    tainted_vars[target] = tainted_vars[donor]
                elif target in tainted_vars and not any(
                        r.capability in SOURCE_CAPABILITIES for r in (matched or [])):
                    del tainted_vars[target]

        if not matched:
            continue
        # Skip anything that is not a live statement. Passing index 0 to
        # literal_demotion never detects a comment (nothing precedes column 0),
        # so probe at the first rule match instead — otherwise a comment
        # *explaining* an exfil one-liner is reported as one.
        if matched and not shell:
            probe = min((m.start() for m in
                         (r.pattern.search(line) for r in matched) if m), default=0)
            # Only level 2 — a comment, or a regex/rule-catalogue literal. Level 1
            # is a plain string literal, which is exactly how real code names the
            # file it reads: `Path('.env').read_text()` is a genuine source.
            if pos.literal_demotion(line, probe) >= 2:
                continue
        elif shell and line.lstrip().startswith("#"):
            continue
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
            # `curl -d "$(cat ~/.claude.json)" url` — the source is substituted
            # straight into the sink's argument. No pipe, no file handle, no
            # variable to track, and it is one of the most common exfil shapes.
            substituted = bool(_SUBSTITUTION.search(line))
            if piped or consumes or substituted:
                channel = ("direct pipe" if piped
                           else "command substitution into the sink" if substituted
                           else "sink reads the secret path")
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

        # Every destination on the line, not the first one. Two bugs lived here:
        # `search` returned only the first redirect, and the `break` sat OUTSIDE
        # the target guard — so a redirect to an ignored target consumed the
        # iteration and nothing else was examined. Together they meant
        # `cat secret | tee /dev/tty > /tmp/steal` recorded no tainted file at
        # all and the chain was never built: /dev/tty was matched, skipped as
        # uninteresting, and took the real destination down with it.
        for match in [*_REDIRECT.finditer(line), *_WRITE_CALL.finditer(line)]:
            target = next((g for g in match.groups() if g), None)
            if target and not target.startswith(("&", "/dev/")):
                tainted_files[_normalize(target)] = Origin(
                    lineno, "filesystem", origin_rule.id, snippet)

    return chains
