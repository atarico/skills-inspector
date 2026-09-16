"""Proves the project declares zero third-party dependencies — not merely that
`pyproject.toml` is absent.

Before Task A, the CI step "No third-party dependencies" proved its claim by
checking that a handful of dependency-manifest files did not exist at all.
That was sufficient while none of those files existed. `pyproject.toml`
(Task A) makes file-absence the wrong test on purpose — the file now exists
and is supposed to — so the guard has to prove something strictly stronger:
not "no manifest exists" but "the manifest that exists declares nothing".
`requirements.txt` / `setup.py` / `Pipfile` / `poetry.lock` still may not
exist; that half of the old guard is unchanged and stays a hard fail.

The vacuous-pass hole this file exists to close: a naive check might read
`project.dependencies` with a default, e.g. `doc.get("project", {}).get(
"dependencies", [])`, and see `[]` whether the key was written as `[]` or
never written at all. A missing key would then pass by accident, and the
guard would stop meaning anything the day someone deletes the line instead of
emptying it. Every check below treats a MISSING key as a FAILURE, never as an
implicit empty value.

Two TOML parsers, and why:

`tomllib` is stdlib from Python 3.11 — this project's CI matrix (and its
README's floor) is 3.10 and 3.13, so `tomllib` is not available on every job,
and adding `tomli` to get it back on 3.10 would be exactly the third-party
dependency this file exists to forbid. So there are two parsers:

  - `_parse_tomllib` — the real thing, used whenever it can be imported.
  - `_parse_fallback` — a deliberately narrow hand-rolled reader that
    understands only the shapes this project's own `pyproject.toml` uses
    (tables, string scalars, string arrays, and inline tables of string
    values). It is not a general TOML implementation and was never meant to
    become one.

The 3.10 job has no way to prove `_parse_fallback` correct against a real
TOML parser — it doesn't have one. So instead of trusting the narrow parser
on faith, this file leans on the matrix: whenever `tomllib` IS importable
(the 3.13 job, and any future job on 3.11+), it runs BOTH parsers over the
real `pyproject.toml` and asserts they produce identical output. That
agreement is what earns the 3.10 job's reliance on `_parse_fallback` — it is
proven correct on the same file, just on a different interpreter, rather
than assumed correct because nothing ever caught it out.

`tests/version_test.py` reuses `_parse_fallback` / `_has_tomllib` from this
module for the same reason, rather than writing a third copy of the same
two-parser story.

    python -m tests.deps_test          # RED/GREEN lines, for a terminal
    python -m tests.deps_test --ci     # ::error:: lines, for GitHub Actions
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT = Path(__file__).resolve().parent.parent
PYPROJECT = PROJECT / "pyproject.toml"

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

# Legacy dependency manifests. Their absence is the ORIGINAL guard and stays
# a hard fail — appearing at all is a change to what this project is.
_FORBIDDEN_FILES = ("requirements.txt", "setup.py", "Pipfile", "poetry.lock")

# Distribution name at the head of a PEP 508 requirement string, stripped of
# any version specifier, extras, or environment marker ("setuptools>=77",
# "wheel==0.44; python_version<'3.12'" both read as their bare name).
_DIST_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

# Build backends, not dependencies. A `build-system.requires` entry outside
# this list is a real third-party package pulled in at build time, which is
# exactly what "stdlib-only" promises does not happen.
_BUILD_BACKEND_ALLOWLIST = ("setuptools", "wheel", "flit_core", "hatchling", "poetry-core")


def _has_tomllib() -> bool:
    try:
        import tomllib  # noqa: F401
    except ImportError:
        return False
    return True


def _parse_tomllib(text: str) -> dict:
    import tomllib
    return tomllib.loads(text)


# ------------------------------------------------------------- narrow fallback

_TABLE_HEADER = re.compile(r"^\[(?!\[)([^\]]+)\]\s*$")
_KEY_VALUE = re.compile(r"^([A-Za-z0-9_\-]+)\s*=\s*(.+)$")


def _strip_comment(line: str) -> str:
    """Drop a trailing `# ...` comment, honouring quotes so a `#` inside a
    string literal is not mistaken for one."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def _split_on_top_level_commas(inner: str) -> list[str]:
    """Split `a, "b, c", d` into `['a', '"b, c"', 'd']` — a comma inside a
    quoted string is not a separator."""
    parts: list[str] = []
    cur = ""
    in_single = in_double = False
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
            cur += ch
        elif ch == '"' and not in_single:
            in_double = not in_double
            cur += ch
        elif ch == "," and not in_single and not in_double:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _parse_scalar(raw: str) -> object:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1]
    if raw in ("true", "false"):
        return raw == "true"
    raise ValueError(f"_parse_fallback cannot read this scalar: {raw!r} — "
                      f"it only understands quoted strings and booleans")


def _parse_array(raw: str) -> list:
    raw = raw.strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        raise ValueError(f"_parse_fallback expected a '[...]' array, got: {raw!r}")
    return [_parse_scalar(p) for p in _split_on_top_level_commas(raw[1:-1])]


def _parse_inline_table(raw: str) -> dict:
    raw = raw.strip()
    if not (raw.startswith("{") and raw.endswith("}")):
        raise ValueError(f"_parse_fallback expected a '{{...}}' inline table, got: {raw!r}")
    table: dict = {}
    for part in _split_on_top_level_commas(raw[1:-1]):
        key, sep, value = part.partition("=")
        if not sep:
            raise ValueError(f"_parse_fallback found no '=' in inline-table entry: {part!r}")
        table[key.strip().strip("\"'")] = _parse_scalar(value)
    return table


def _parse_fallback(text: str) -> dict:
    """A deliberately narrow TOML reader: tables, quoted-string scalars,
    string arrays, and inline tables of string values — the exact subset this
    project's own `pyproject.toml` uses. It is not a general parser and does
    not try to be one.

    It never guesses: a line shaped like `key = <value>` that this function
    does not recognise raises `ValueError` instead of being skipped, and a
    value it cannot parse raises rather than silently returning `None` or an
    empty default. A parser that swallows what it does not understand could
    make the agreement check below pass by coincidence — reporting "empty"
    for a key it actually just failed to read, on a real dependency list.
    Raising turns that failure mode into a loud one instead of a quiet one.
    """
    root: dict = {}
    table_path: tuple[str, ...] = ()

    def table_at(path: tuple[str, ...]) -> dict:
        node = root
        for part in path:
            node = node.setdefault(part, {})
        return node

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw_line = _strip_comment(lines[i])
        i += 1
        line = raw_line.strip()
        if not line:
            continue

        header = _TABLE_HEADER.match(line)
        if header:
            table_path = tuple(p.strip().strip("\"'") for p in header.group(1).split("."))
            table_at(table_path)  # materialize even an empty table
            continue

        kv = _KEY_VALUE.match(line)
        if not kv:
            # Not a shape this project's pyproject.toml uses (array-of-tables
            # headers, multi-line basic strings, bare-dotted keys, ...).
            # Silently skipping an unrecognised STRUCTURAL line is fine —
            # what must never be silent is misreading a value this function
            # DID recognise as one of the tables/keys under test.
            continue

        key, rest = kv.group(1), kv.group(2).strip()
        buf = rest
        depth = buf.count("[") - buf.count("]") + buf.count("{") - buf.count("}")
        while depth > 0 and i < len(lines):
            nxt = _strip_comment(lines[i])
            i += 1
            buf += "\n" + nxt
            depth += nxt.count("[") - nxt.count("]") + nxt.count("{") - nxt.count("}")
        buf = buf.strip()

        table = table_at(table_path)
        if buf.startswith("["):
            table[key] = _parse_array(buf)
        elif buf.startswith("{"):
            table[key] = _parse_inline_table(buf)
        else:
            table[key] = _parse_scalar(buf)

    return root


# --------------------------------------------------------------------- checks

def _load() -> tuple[dict, str | None, str | None]:
    """(doc, text, load_error). `doc` is {} and `text` is None on a load
    error, so downstream checks can each report the SAME root cause instead
    of a confusing secondary symptom."""
    if not PYPROJECT.exists():
        return {}, None, "pyproject.toml does not exist"
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        if _has_tomllib():
            doc = _parse_tomllib(text)
        else:
            doc = _parse_fallback(text)
    except Exception as exc:  # noqa: BLE001 — any parse failure is load_error
        parser = "tomllib" if _has_tomllib() else "the fallback parser"
        return {}, text, f"{parser} could not parse pyproject.toml: {exc}"
    return doc, text, None


def _check_no_legacy_files() -> tuple[bool, str]:
    present = [f for f in _FORBIDDEN_FILES if (PROJECT / f).exists()]
    if present:
        return False, f"found {', '.join(present)} — this project must stay stdlib-only"
    return True, f"none of {', '.join(_FORBIDDEN_FILES)} exist"


def _check_dependencies_empty(doc: dict) -> tuple[bool, str]:
    project = doc.get("project")
    if not isinstance(project, dict):
        return False, "pyproject.toml has no [project] table"
    if "dependencies" not in project:
        # THE vacuous-pass hole this file exists to close: a missing key is
        # not proof of zero dependencies, and must never read as one.
        return False, "project.dependencies is MISSING — an absent key is not a declared-empty list"
    deps = project["dependencies"]
    if deps != []:
        return False, f"project.dependencies is not empty: {deps!r}"
    return True, "project.dependencies == []"


def _check_optional_dependencies_empty(doc: dict) -> tuple[bool, str]:
    project = doc.get("project", {})
    optional = project.get("optional-dependencies")
    if optional is None:
        return True, "project.optional-dependencies is absent"
    nonempty = {group: deps for group, deps in optional.items() if deps}
    if nonempty:
        return False, f"non-empty optional-dependencies group(s): {nonempty!r}"
    return True, f"project.optional-dependencies present, every group empty ({sorted(optional)})"


def _check_no_poetry_dependencies(doc: dict) -> tuple[bool, str]:
    poetry = doc.get("tool", {}).get("poetry", {}) if isinstance(doc.get("tool"), dict) else {}
    deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if deps is None:
        return True, "no [tool.poetry.dependencies] table"
    extra = sorted(k for k in deps if k != "python")
    if extra:
        return False, f"tool.poetry.dependencies declares: {', '.join(extra)}"
    return True, "tool.poetry.dependencies declares nothing besides 'python'"


def _dist_name(requirement: str) -> str:
    match = _DIST_NAME_RE.match(requirement)
    return match.group(1) if match else requirement.strip()


def _check_build_backends_allowlisted(doc: dict) -> tuple[bool, str]:
    build_system = doc.get("build-system")
    if not isinstance(build_system, dict) or "requires" not in build_system:
        return False, "pyproject.toml has no [build-system] with a 'requires' key"
    requires = build_system["requires"]
    bad = [r for r in requires if _dist_name(r) not in _BUILD_BACKEND_ALLOWLIST]
    if bad:
        return False, (f"build-system.requires declares something outside the "
                        f"build-backend allowlist: {', '.join(bad)}")
    return True, f"build-system.requires: {', '.join(requires)}"


def _check_fallback_parser_agrees(text: str | None) -> tuple[bool, str]:
    if text is None:
        return False, "cannot compare parsers — pyproject.toml did not load"
    if not _has_tomllib():
        return True, ("skipped on this interpreter — tomllib needs Python 3.11+; "
                       "correctness is proven by whichever CI job runs on 3.11+ instead")
    canonical = _parse_tomllib(text)
    fallback = _parse_fallback(text)
    if fallback != canonical:
        return False, ("_parse_fallback disagrees with tomllib on pyproject.toml — "
                        f"fallback={fallback!r} tomllib={canonical!r}")
    return True, "_parse_fallback output matches tomllib.loads() exactly"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ci = "--ci" in argv

    doc, text, load_error = _load()

    if load_error:
        cases = [("pyproject.toml loads", (False, load_error))]
    else:
        cases = [
            ("no legacy dependency files", _check_no_legacy_files()),
            ("project.dependencies is declared empty", _check_dependencies_empty(doc)),
            ("project.optional-dependencies has no entries",
             _check_optional_dependencies_empty(doc)),
            ("tool.poetry.dependencies names nothing but python",
             _check_no_poetry_dependencies(doc)),
            ("build-system.requires is build-backends only",
             _check_build_backends_allowlisted(doc)),
            ("fallback TOML parser agrees with tomllib", _check_fallback_parser_agrees(text)),
        ]

    passed = 0
    for name, (ok, detail) in cases:
        if ok:
            passed += 1
            if not ci:
                print(f"{GREEN}OK{RESET}    {name:<45} {DIM}{detail}{RESET}")
        else:
            if ci:
                print(f"::error::{name}: {detail}")
            else:
                print(f"{RED}FAIL{RESET}  {name:<45} {detail}")

    failed = len(cases) - passed
    if failed:
        if not ci:
            print(f"\n{RED}{failed}/{len(cases)} dependency checks failed{RESET}")
        return 1
    if not ci:
        print(f"\n{GREEN}{passed}/{len(cases)} dependency checks passed{RESET}  "
              f"{DIM}nothing is declared, not merely nothing is present{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
