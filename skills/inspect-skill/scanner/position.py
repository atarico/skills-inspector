"""Position taxonomy — RULES.md section 3.

Position sets `confidence` and nothing else. The pattern is equally dangerous
wherever it appears; what changes is the odds that it is live.

This is the load-bearing mechanism of the whole ruleset. Without it the scanner
flags itself, every security skill, every README documenting an attack, and every
test fixture. It is also the most heuristic part of the tool — treat a v0 result
here as an experiment, not a guarantee.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

ACTIVE = "active"
ILLUSTRATIVE = "illustrative"
DOCUMENTARY = "documentary"

_ORDER = [ACTIVE, ILLUSTRATIVE, DOCUMENTARY]

# Directories whose contents are illustrative by convention.
_ILLUSTRATIVE_DIRS = {
    "test", "tests", "__tests__", "spec", "specs",
    "fixture", "fixtures", "example", "examples", "sample", "samples",
    "testdata", "golden", "goldens", "snapshots",
}

# Headings under which a dangerous pattern is being shown, not invoked.
_ILLUSTRATIVE_HEADING = re.compile(
    r"(?i)\b(example|examples|sample|don'?t|do not|bad|anti-?pattern|"
    r"avoid|never|wrong|incorrect|vulnerab|attack|threat|detect|rule|"
    r"what we (?:look for|flag)|red flag)\b"
)

# A fence stops being illustrative when the sentence above it says to run it.
_IMPERATIVE_LEAD = re.compile(
    r"(?i)\b(run|execute|paste|copy|apply|invoke|call|launch|start|"
    r"add the following|use the following|run the following|"
    r"ejecut|corr[ée])\b"
)

# Imperative mood at the head of a markdown prose line.
_IMPERATIVE_VERB = re.compile(
    r"(?i)^\s*(?:[-*+]\s+|\d+[.)]\s+)?"
    r"(run|execute|install|download|fetch|curl|wget|send|post|upload|"
    r"read|write|append|delete|remove|create|copy|move|export|set|"
    r"add|register|enable|disable|configure|source|eval|chmod|sudo|"
    r"always|never|you must|you should|make sure to|be sure to|ensure that)\b"
)

_FENCE = re.compile(r"^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)")
_HEADING = re.compile(r"^\s*(#{1,6})\s+(.*)$")
_TABLE_ROW = re.compile(r"^\s*\|")
_BLOCKQUOTE = re.compile(r"^\s*>")

_TEXT_CODE_SUFFIXES = {
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".lua", ".r",
}
_CONFIG_SUFFIXES = {".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".env"}
_DOC_SUFFIXES = {".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc"}


# Execution sinks. A string literal is inert data UNLESS it flows into one of
# these — the same logic as an imperative sentence above a markdown fence.
# Blanket-demoting string literals would make `os.system("curl x | sh")` invisible,
# which is a trivial bypass.
_EXEC_SINK = re.compile(
    r"\b(os\.system|os\.popen|subprocess\.|Popen|check_output|commands\.getoutput"
    r"|child_process|execSync|spawnSync|shell_exec|passthru|system\s*\("
    r"|shell\s*=\s*True|\beval\b|\bexec\b|Bash\s*\(|run_command)\b"
)


def in_string_literal(line: str, index: int) -> bool:
    """Is `index` inside a quoted literal on this line?

    Deliberately simple: a rule catalogue holds attack patterns as data, and
    a pattern that is data is not an invocation.
    """
    quote: str | None = None
    i = 0
    while i < min(index, len(line)):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        i += 1
    return quote is not None


# A regex literal is definitionally a *description* of a pattern, not a value.
# This is the source-code equivalent of a markdown table row: the strongest
# available signal that the dangerous text is catalogued, not invoked.
_REGEX_CONSTRUCTION = re.compile(
    r"re\.(compile|search|match|findall|finditer|sub)\s*\(|_r\s*\(|RegExp\s*\(|=~|"
    r"\bregexp?\s*[:=]|\bpattern\s*[:=]"
)
_REGEX_SHAPE = re.compile(r"\\[bswdWSDA]|\[\^|\{\d*,\d*\}|\(\?[:=!i]|\\\.")


def in_inline_code(line: str, index: int) -> bool:
    """Is `index` inside a `backtick` span? Content shown in inline code is being
    quoted, not emitted — a token in backticks is documentation, like a fence."""
    return line.count("`", 0, index) % 2 == 1


_COMMENT = re.compile(r"(^|\s)(#|//|--)\s")


def _in_comment(line: str, index: int) -> bool:
    for match in _COMMENT.finditer(line):
        if match.start() < index and not in_string_literal(line, match.start()):
            return True
    return False


def literal_demotion(line: str, index: int) -> int:
    """Confidence levels a code-file match loses for being inert data.

    Never demotes when an execution sink is on the same line — otherwise
    `os.system("curl x | sh")` becomes invisible, which is a trivial bypass.
    """
    if _in_comment(line, index):
        return 2
    if not in_string_literal(line, index):
        return 0
    if _EXEC_SINK.search(line):
        return 0
    if _REGEX_CONSTRUCTION.search(line) or len(_REGEX_SHAPE.findall(line)) >= 2:
        return 2
    return 1


def demote(confidence: str, position: str) -> str:
    """Lower confidence by position. Floor is `low`."""
    levels = ["high", "medium", "low"]
    steps = {ACTIVE: 0, ILLUSTRATIVE: 1, DOCUMENTARY: 2}[position]
    try:
        idx = levels.index(confidence)
    except ValueError:
        return "low"
    return levels[min(idx + steps, len(levels) - 1)]


def in_sample_dir(relpath: str) -> bool:
    """Is the file inside a dedicated test/fixtures/examples directory?

    A single chokepoint: nothing from such a file may exceed low confidence,
    overriding every per-rule exemption. This is what stops a scanner from
    flagging its own attack fixtures — the one property section 3 exists to give.
    """
    parts = PurePosixPath(relpath).parts[:-1]
    return any(part.lower() in _ILLUSTRATIVE_DIRS for part in parts)


def file_base_position(relpath: str) -> str:
    """Base position implied by where the file sits and what it is.

    A whole test/fixtures/examples directory is a stronger 'not live' signal than
    a fenced snippet under an example heading — it reads as documentary (two
    levels, floor low), enough to leave the headline. A genuinely live payload
    hidden in tests/ is what the reachability graph (section 5, deferred) is for;
    until then it is reported at low confidence, never dropped.
    """
    p = PurePosixPath(relpath)
    if any(part.lower() in _ILLUSTRATIVE_DIRS for part in p.parts[:-1]):
        return DOCUMENTARY
    suffix = p.suffix.lower()
    if suffix in _TEXT_CODE_SUFFIXES or suffix in _CONFIG_SUFFIXES:
        return ACTIVE
    if suffix in _DOC_SUFFIXES:
        return DOCUMENTARY
    return ACTIVE


# Line kinds, so an exemption can target genuine body prose without also lifting
# attack phrases quoted in a table cell or blockquote (a rules catalogue).
PROSE = "prose"
STRUCTURAL = "structural"  # table, heading, blockquote, fence, code, docstring


def classify_lines(relpath: str, text: str) -> list[tuple[str, str]]:
    """(position, kind) for every line, 0-indexed."""
    base = file_base_position(relpath)
    lines = text.splitlines()

    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix not in _DOC_SUFFIXES:
        return _classify_code(lines, base, suffix)

    return _classify_markdown(lines, base)


# Triple-quoted / heredoc bodies are prose, not statements. A security tool that
# documents attacks in its docstrings is the canonical false positive without this.
_TRIPLE = re.compile(r'"""|\'\'\'')


def _classify_code(lines: list[str], base: str, suffix: str) -> list[tuple[str, str]]:
    if base in (ILLUSTRATIVE, DOCUMENTARY):
        return [(base, STRUCTURAL)] * len(lines)

    positions: list[tuple[str, str]] = []
    in_docstring = False
    delim = ""
    for raw in lines:
        if in_docstring:
            positions.append((DOCUMENTARY, STRUCTURAL))
            if delim in raw:
                in_docstring = False
            continue
        marks = _TRIPLE.findall(raw)
        if marks:
            first = marks[0]
            after = raw.split(first, 1)[1]
            # Opens and does not close on the same line -> body is documentary.
            if first not in after:
                in_docstring = True
                delim = first
                positions.append((DOCUMENTARY, STRUCTURAL))
                continue
        positions.append((ACTIVE, STRUCTURAL))
    return positions


def _classify_markdown(lines: list[str], base: str) -> list[tuple[str, str]]:
    positions: list[tuple[str, str]] = []
    in_fence = False
    fence_marker = ""
    fence_is_active = False
    fence_is_output = False
    heading_illustrative = False
    prev_prose = ""

    for raw in lines:
        fence_match = _FENCE.match(raw)

        if in_fence:
            if fence_match and raw.strip().startswith(fence_marker):
                in_fence = False
                positions.append((DOCUMENTARY if fence_is_output else ILLUSTRATIVE, STRUCTURAL))
                continue
            if fence_is_active:
                positions.append((ACTIVE, STRUCTURAL))
            else:
                positions.append((DOCUMENTARY if fence_is_output else ILLUSTRATIVE, STRUCTURAL))
            continue

        if fence_match:
            in_fence = True
            fence_marker = fence_match.group(1)[:3]
            lang = fence_match.group(2).strip().lower()
            # A fence introduced by "run the following" is live regardless of
            # being fenced. Being inside a code block is not proof of inertness.
            fence_is_active = bool(_IMPERATIVE_LEAD.search(prev_prose)) and not heading_illustrative
            # A fence with no declared language is sample output, not code.
            fence_is_output = not lang and not fence_is_active
            positions.append((DOCUMENTARY if fence_is_output else ILLUSTRATIVE, STRUCTURAL))
            continue

        heading = _HEADING.match(raw)
        if heading:
            heading_illustrative = bool(_ILLUSTRATIVE_HEADING.search(heading.group(2)))
            positions.append((DOCUMENTARY, STRUCTURAL))
            prev_prose = ""
            continue

        if _TABLE_ROW.match(raw) or _BLOCKQUOTE.match(raw):
            positions.append((DOCUMENTARY, STRUCTURAL))
            continue

        stripped = raw.strip()
        if not stripped:
            positions.append((DOCUMENTARY if base == DOCUMENTARY else base, STRUCTURAL))
            continue

        prev_prose = stripped

        if heading_illustrative:
            positions.append((ILLUSTRATIVE, PROSE))
        elif _IMPERATIVE_VERB.match(raw):
            # Imperative prose in a skill body IS an instruction to the model.
            positions.append((ACTIVE, PROSE))
        else:
            positions.append((DOCUMENTARY, PROSE))

    return positions
