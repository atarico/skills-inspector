"""Three surfaces all have to agree on what version this is.

`scanner.__version__` is the one hand-written string. Two things are supposed
to echo it without becoming a second hand-written copy:

1. `--version` — the CLI, which prints `scanner.__version__` directly.
2. The installable bundle's SKILL.md `metadata.version`. This one IS a second
   hand-written string, and it disagreed silently for the life of the
   repository — 0.1.0 against 0.2 — because nothing compared them and neither
   was printed anywhere a reader could see.
3. `pyproject.toml` (Task A). This one is not supposed to be a hand-written
   string at all: `[project] dynamic = ["version"]` and
   `[tool.setuptools.dynamic] version = {attr = "scanner.__version__"}` make
   setuptools read the version FROM `scanner.__version__` at build time. A
   literal string comparison cannot prove that wiring — `version = "0.2.0"`
   hardcoded into `[project]` would read back as "0.2.0" too, and happens to
   match today by coincidence. So surface 3's check is structural: it asserts
   `dynamic` names `version` and `tool.setuptools.dynamic.version.attr` is
   exactly `scanner.__version__`, so hardcoding a literal value later fails
   this test even though the literal might currently be correct.

Surface 1 is read THROUGH the CLI rather than imported, so one check proves
both that `--version` still answers AND that what it answers is what the
bundle advertises — importing `__version__` would compare a string to itself
and leave the flag, the only way a user ever sees this number, exercised by
nothing.

    python -m tests.version_test

A BROKEN CLI IS NOT A MISMATCH, and saying so was this file's own first defect.
The first draft lived in a Makefile one-liner that funnelled every outcome into
one message, so a crashed subprocess reported "VERSION MISMATCH" — a claim the
evidence did not support, in the guard written to catch exactly that. Each of
the three checks below keeps that discipline: a missing or unreadable
`pyproject.toml` is reported as UNREADABLE, never folded into "MISCONFIGURED"
(wrong wiring) or "MISMATCH" (wrong value) — those are three different defects
and collapsing them back into one message is the exact mistake this file was
first written to fix.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.deps_test import _has_tomllib, _parse_fallback, _parse_tomllib  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
SKILL = PROJECT / "skills" / "inspect-skill" / "SKILL.md"
PYPROJECT = PROJECT / "pyproject.toml"

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


def pyproject_wiring() -> tuple[bool | None, str]:
    """(ok, detail). `ok` is None when pyproject.toml could not be loaded at
    all — distinct from False, which means it loaded but is wired wrong. A
    missing/unreadable file is not a "mismatch": there is no value to compare.
    """
    if not PYPROJECT.exists():
        return None, f"{PYPROJECT.relative_to(PROJECT)} does not exist"
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        doc = _parse_tomllib(text) if _has_tomllib() else _parse_fallback(text)
    except Exception as exc:  # noqa: BLE001 — any parse failure is "unreadable"
        return None, f"could not parse {PYPROJECT.relative_to(PROJECT)}: {exc}"

    project = doc.get("project", {})
    if "version" in project:
        return False, (f"[project] hardcodes version = {project['version']!r} instead of "
                        f"declaring it dynamic — a third hand-written version string")
    if "version" not in project.get("dynamic", []):
        return False, "[project] dynamic does not list 'version'"

    setuptools_dynamic = doc.get("tool", {}).get("setuptools", {}).get("dynamic", {})
    source = setuptools_dynamic.get("version") if isinstance(setuptools_dynamic, dict) else None
    if not isinstance(source, dict) or source.get("attr") != "scanner.__version__":
        return False, (f"[tool.setuptools.dynamic] version is not sourced from "
                        f"scanner.__version__: {source!r}")
    return True, "version is dynamic, sourced from scanner.__version__"


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

    wired, wiring_detail = pyproject_wiring()
    if wired is None:
        print(f"{RED}PYPROJECT UNREADABLE{RESET}  {wiring_detail}")
        return 1
    if wired is False:
        print(f"{RED}PYPROJECT MISCONFIGURED{RESET}  {wiring_detail}")
        return 1

    print(f"{GREEN}version {cli}{RESET}  {GREEN}pyproject.toml wiring OK{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
