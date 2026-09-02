"""The version the CLI prints must be the version the bundle advertises.

Two hand-written strings name the same artifact: `scanner.__version__`, which
`--version` prints, and `metadata.version` in the installable bundle's
SKILL.md. They disagreed silently for the life of the repository — 0.1.0
against 0.2 — because nothing compared them and neither was printed anywhere a
reader could see.

The left side is read THROUGH the CLI rather than imported, so one check proves
both halves: that `--version` still answers, and that what it answers is what
the bundle advertises. Importing `__version__` would compare a string to itself
and leave the flag — the only way a user ever sees this number — exercised by
nothing.

    python -m tests.version_test

A BROKEN CLI IS NOT A MISMATCH, and saying so was this file's own first defect.
The first draft lived in a Makefile one-liner that funnelled every outcome into
one message, so a crashed subprocess reported "VERSION MISMATCH" — a claim the
evidence did not support, in the guard written to catch exactly that. The two
failures are distinct, they print differently, and a CLI failure surfaces the
subprocess's own stderr instead of swallowing it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
SKILL = PROJECT / "skills" / "inspect-skill" / "SKILL.md"

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"

# The frontmatter shape this reads: two-space indent under `metadata:`. Anchored
# and multiline so a `version:` word in prose further down cannot answer for it.
_FRONTMATTER_VERSION = re.compile(r"^  version: \"([^\"]+)\"", re.MULTILINE)

# `--version` prints `inspector-skills <v>` (argparse's version action). Match
# the shape rather than splitting on whitespace and trusting the last token,
# which would read the tail of any string at all as a version.
_CLI_VERSION = re.compile(r"^inspector-skills (\S+)$")


def cli_version() -> tuple[str | None, str]:
    """(version, detail). version is None when the CLI did not answer."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "scanner", "--version"],
            capture_output=True, text=True, cwd=PROJECT, timeout=60,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return None, "`--version` did not return within 60s"
    except OSError as exc:
        return None, f"could not run the CLI: {exc}"

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or "no output"
        return None, f"`--version` exited {proc.returncode}: {detail}"

    match = _CLI_VERSION.match(proc.stdout.strip())
    if not match:
        return None, f"`--version` printed an unrecognised line: {proc.stdout.strip()!r}"
    return match.group(1), ""


def bundle_version() -> tuple[str | None, str]:
    """(version, detail). version is None when SKILL.md did not declare one."""
    try:
        text = SKILL.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"could not read {SKILL.relative_to(PROJECT)}: {exc}"
    match = _FRONTMATTER_VERSION.search(text)
    if not match:
        return None, f"no `  version: \"...\"` line in {SKILL.relative_to(PROJECT)}"
    return match.group(1), ""


def main() -> int:
    cli, cli_detail = cli_version()
    if cli is None:
        print(f"{RED}CLI FAILED{RESET}  {cli_detail}")
        return 1

    bundle, bundle_detail = bundle_version()
    if bundle is None:
        print(f"{RED}BUNDLE UNREADABLE{RESET}  {bundle_detail}")
        return 1

    if cli != bundle:
        print(f"{RED}VERSION MISMATCH{RESET}  CLI says {cli}, "
              f"SKILL.md advertises {bundle}")
        return 1

    print(f"{GREEN}version {cli}{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
