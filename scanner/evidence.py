"""Evidence sanitization — RULES.md section 10.

Everything that leaves this module is attacker-controlled text on its way into a
report that a tool-capable agent will read. This is a mandatory output filter,
not hygiene.
"""

from __future__ import annotations

import re

MAX_EVIDENCE = 200

# Characters a human reviewer cannot see but a model can.
_ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff\u180e"
_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_INVISIBLE_RE = re.compile(f"[{_ZERO_WIDTH}{_BIDI}]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Sequences that could fake a conversation turn or break out of a quarantine
# wrapper once the finding is rendered into another agent's context.
_HARNESS_PATTERNS = [
    (re.compile(r"<\|[^|>]{0,40}\|>"), "<!HARNESS!>"),
    (re.compile(r"(?im)^\s*(Human|Assistant|System|User)\s*:"), r"[\1_]"),
    (re.compile(r"(?m)^---\s*$"), "[---]"),
    (re.compile(r"</\s*(system|instructions?|user|assistant|human)\s*>", re.I), "[/tag]"),
    (re.compile(r"```"), "[fence]"),
]


def invisible_counts(text: str) -> dict[str, int]:
    """Count hidden characters. The count is the AGT-006 finding — never drop it."""
    counts: dict[str, int] = {}
    for ch in text:
        if ch in _ZERO_WIDTH:
            counts["zero_width"] = counts.get("zero_width", 0) + 1
        elif ch in _BIDI:
            counts["bidi_override"] = counts.get("bidi_override", 0) + 1
        elif _CONTROL_RE.match(ch):
            counts["control"] = counts.get("control", 0) + 1
    return counts


def sanitize(text: str, *, centre: tuple[int, int] | None = None) -> str:
    """Render a snippet safe to place in a finding.

    1. truncate hard, centred on the match
    2. strip invisibles (counted separately by invisible_counts)
    3. neutralize harness delimiters
    4. single line
    """
    if centre is not None:
        start, end = centre
        pad = max(0, (MAX_EVIDENCE - (end - start)) // 2)
        lo = max(0, start - pad)
        hi = min(len(text), end + pad)
        snippet = text[lo:hi]
        prefix = "…" if lo > 0 else ""
        suffix = "…" if hi < len(text) else ""
        snippet = f"{prefix}{snippet}{suffix}"
    else:
        snippet = text

    counts = invisible_counts(snippet)
    snippet = _INVISIBLE_RE.sub("", snippet)
    snippet = _CONTROL_RE.sub("", snippet)

    for pattern, replacement in _HARNESS_PATTERNS:
        snippet = pattern.sub(replacement, snippet)

    snippet = snippet.replace("\n", "\\n").replace("\r", "").replace("\t", "    ")
    snippet = snippet.strip()

    if len(snippet) > MAX_EVIDENCE:
        snippet = snippet[:MAX_EVIDENCE] + "…"

    for kind, n in sorted(counts.items()):
        snippet += f" <{kind}x{n}>"

    return snippet


def sanitize_path(path: str) -> str:
    """Paths and filenames are attacker-controlled too, and they reach the agent
    context through the file listing, not only through evidence."""
    cleaned = _INVISIBLE_RE.sub("", path)
    cleaned = _CONTROL_RE.sub("", cleaned)
    cleaned = cleaned.replace("\n", "\\n").replace("\r", "")
    if len(cleaned) > 120:
        cleaned = cleaned[:60] + "…" + cleaned[-40:]
    return cleaned
