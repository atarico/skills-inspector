"""The README's "Measured, not asserted" table must quote what the suite prints.

Four times in a row, a batch of work moved a real number — a rule started
firing, a fixture was added, the corpus was re-frozen — and the front page kept
the old one. `make check` stayed green every time, because nothing in the check
suite ever looked at README.md. Twice the published number understated the
project by tens of points; once a stale claim made it into release notes. The
table's own opening line promises "every number below is reproducible on your
own machine", and nothing enforced that promise either.

This file is the enforcement. It does not count anything itself — that would
just be a second place for the same drift to happen, this time between two
pieces of code instead of between code and prose. Instead it runs the exact
harness each number already comes from (`tests.unit_test`, `tests.truepos`,
`tests.semantic_test`, `tests.fuzz`, `tests.coverage`, plus the frozen corpus
report at `bench/drift-baseline.json`, which only changes when a human
deliberately re-freezes it), captures the sentence that harness already prints
for humans, and diffs that sentence against what the README claims. One
implementation of the truth; this only compares two readings of it.

A claim the parser cannot find in a README is treated as a failure, not
skipped. A check that silently shrugs past a row it could not locate is the
same defect this file exists to prevent wearing a different hat — it would
report green on a README that deleted the whole table. So every row named
below must be found in both README.md and README.es.md, or the run fails and
says which file is missing which row.

    python -m tests.readme_test
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT = Path(__file__).resolve().parent.parent
BASELINE = PROJECT / "bench" / "drift-baseline.json"
README_EN = PROJECT / "README.md"
README_ES = PROJECT / "README.es.md"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _captured(fn: Callable[..., object], *args: object) -> str:
    """Run an in-process harness with stdout captured, ANSI colour stripped.

    Every harness this file calls prints its own headline sentence for a human
    to read at the terminal. Capturing that exact text — rather than reaching
    into the harness's return value or its internals — is the point: it is the
    same string a person sees when they run `make check`, so there is no
    second formatting path that could drift from the one the README quotes.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args)
    return ANSI.sub("", buf.getvalue())


def measure() -> dict[str, str]:
    """Every number this file checks, read from the harness that owns it.

    Returns strings, not ints: every value here is about to be compared
    against text pulled out of a README with a regex, and keeping both sides
    as strings means the comparison is exact rather than laundered through a
    second round of int-to-str formatting that could itself disagree with the
    harness's own rendering (leading zeros, no thousands separator, and so on
    are the harness's choice to make, not this file's).
    """
    import tests.coverage as coverage
    import tests.fuzz as fuzz
    import tests.semantic_test as semantic_test
    import tests.truepos as truepos
    import tests.unit_test as unit_test

    values: dict[str, str] = {}

    unit_out = _captured(unit_test.main)
    m = re.search(r"(\d+)/(\d+) unit checks passed", unit_out)
    if not m:
        raise RuntimeError(
            "tests.unit_test printed no 'N/N unit checks passed' line — "
            "the harness contract this file depends on is broken")
    values["unit_n"], values["unit_d"] = m.group(1), m.group(2)

    truepos_out = _captured(truepos.main)
    m = re.search(r"(\d+)/(\d+) detection checks passed\s+(\d+) known blind spots confirmed",
                  truepos_out)
    if not m:
        raise RuntimeError(
            "tests.truepos printed no 'N/N detection checks passed  M known "
            "blind spots confirmed' line — the harness contract broke")
    values["detect_n"], values["detect_d"], values["blind"] = m.groups()

    semantic_out = _captured(semantic_test.main)
    m = re.search(r"(\d+)/(\d+) semantic checks passed", semantic_out)
    if not m:
        raise RuntimeError(
            "tests.semantic_test printed no 'N/N semantic checks passed' line")
    values["sem_n"], values["sem_d"] = m.groups()

    fuzz_out = _captured(fuzz.main)
    m = re.search(r"(\d+)/(\d+) fuzz cases survived", fuzz_out)
    if not m:
        raise RuntimeError("tests.fuzz printed no 'N/N fuzz cases survived' line")
    values["fuzz_n"], values["fuzz_d"] = m.groups()

    coverage_out = _captured(coverage.main, [])
    m = re.search(r"^\s*all\s+(\d+)\s+(\d+)\s+(\d+)%", coverage_out, re.M)
    if not m:
        raise RuntimeError(
            "tests.coverage printed no 'all <impl> <exer> <cover>%' totals row — "
            "the table this file reads from changed shape")
    values["impl"], values["exer"], values["cover_pct"] = m.groups()

    if not BASELINE.exists():
        raise RuntimeError(f"{BASELINE.relative_to(PROJECT)} is missing — "
                            "the corpus row has no source to read")
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    for key in ("discovered", "clean_units", "clean_pct", "median", "p90"):
        if key not in baseline:
            raise RuntimeError(f"{BASELINE.relative_to(PROJECT)} has no '{key}' key")
        values[key] = str(baseline[key])

    # The two prose claims ("27% false positives", "Of the 27 units...") are
    # derived from the same baseline, not printed by any harness — there is no
    # sentence to capture them from. This is the one place this file computes
    # anything, and it computes only what the README brief spells out: the
    # complement of the corpus's own clean count, rounded the way a human
    # reads a percentage (round-half, not the floor `coverage.py` uses for its
    # per-family ratios — the two tables are answering different questions).
    discovered, clean = baseline["discovered"], baseline["clean_units"]
    noisy = discovered - clean
    values["fp_units"] = str(noisy)
    values["fp_pct"] = str(round(100 * noisy / discovered))

    return values


# --------------------------------------------------------------------- claims

@dataclass(frozen=True)
class Claim:
    """One published number, and the regex that reads it out of a README.

    `pattern` must have exactly as many capture groups as `expect` returns
    values for — checked at comparison time, not declared here, because a
    mismatched pattern is itself a bug in this file and should fail loudly
    rather than silently compare the wrong groups.
    """
    name: str
    pattern: re.Pattern[str]
    expect: Callable[[dict[str, str]], tuple[str, ...]]


def _claims(lang: str) -> list[Claim]:
    """The eight rows the design brief names, once per language.

    Wording differs by language (English "of" vs Spanish "de", the
    URL-encoded "detecci%C3%B3n-" badge slug, and so on) so the patterns are
    not shared, but every pattern in the `en` list has an `es` counterpart
    checking the same fact.
    """
    if lang == "en":
        return [
            Claim("invariant unit tests",
                  re.compile(r"\|\s*Invariant unit tests\s*\|\s*\*\*(\d+)/(\d+)\*\*"),
                  lambda v: (v["unit_n"], v["unit_d"])),
            Claim("detection + semantic",
                  re.compile(r"\|\s*Detection, against `fixtures/`\s*\|\s*"
                             r"\*\*(\d+)/(\d+)\*\*, plus \*\*(\d+)/(\d+)\*\* semantic cross-checks"),
                  lambda v: (v["detect_n"], v["detect_d"], v["sem_n"], v["sem_d"])),
            Claim("ruleset exercised",
                  re.compile(r"\|\s*Ruleset exercised by the corpus\s*\|\s*"
                             r"\*\*(\d+)%\*\* — (\d+) of (\d+) implemented rules have a fixture"),
                  lambda v: (v["cover_pct"], v["exer"], v["impl"])),
            Claim("documented blind spots",
                  re.compile(r"\|\s*Documented blind spots, confirmed still open\s*\|\s*\*\*(\d+)\*\*"),
                  lambda v: (v["blind"],)),
            Claim("malformed input",
                  re.compile(r"\|\s*Malformed input[^|]*\|\s*\*\*(\d+)/(\d+)\*\* survived"),
                  lambda v: (v["fuzz_n"], v["fuzz_d"])),
            Claim("corpus row",
                  re.compile(r"\|\s*Headline findings across (\d+) distinct installed extensions\s*\|\s*"
                             r"\*\*(\d+)% completely silent\*\* \((\d+)/(\d+)\), "
                             r"median \*\*(\d+)\*\*, p90 \*\*(\d+)\*\*"),
                  lambda v: (v["discovered"], v["clean_pct"], v["clean_units"], v["discovered"],
                             v["median"], v["p90"])),
            Claim("detection badge",
                  re.compile(r"badge/detection-(\d+)%2F(\d+)-brightgreen"),
                  lambda v: (v["detect_n"], v["detect_d"])),
            Claim("fuzz badge",
                  re.compile(r"badge/malformed%20input-(\d+)%2F(\d+)-brightgreen"),
                  lambda v: (v["fuzz_n"], v["fuzz_d"])),
            # The heading quotes the corpus row's silent percentage back at the
            # reader, two lines under the table. It went stale on 2026-09-13
            # when the row moved from 76% to 73% and the heading did not, which
            # is the exact shape this file exists to catch — and it survived
            # the first version of this gate because the gate was written
            # against a list of rows, and a heading is not a row.
            Claim("heading: the silent percentage",
                  re.compile(r"### That (\d+)% is not a false-positive rate"),
                  lambda v: (v["clean_pct"],)),
            Claim("prose: false-positive percentage",
                  re.compile(r'read the last row as "(\d+)% false positives"'),
                  lambda v: (v["fp_pct"],)),
            Claim("prose: units that produce one",
                  re.compile(r"Of the (\d+) units that produce one"),
                  lambda v: (v["fp_units"],)),
        ]
    if lang == "es":
        return [
            Claim("invariant unit tests",
                  re.compile(r"\|\s*Tests unitarios de invariantes\s*\|\s*\*\*(\d+)/(\d+)\*\*"),
                  lambda v: (v["unit_n"], v["unit_d"])),
            Claim("detection + semantic",
                  re.compile(r"\|\s*Detección, contra `fixtures/`\s*\|\s*"
                             r"\*\*(\d+)/(\d+)\*\*, más \*\*(\d+)/(\d+)\*\* contrastes semánticos"),
                  lambda v: (v["detect_n"], v["detect_d"], v["sem_n"], v["sem_d"])),
            Claim("ruleset exercised",
                  re.compile(r"\|\s*Ruleset ejercitado por el corpus\s*\|\s*"
                             r"\*\*(\d+)%\*\* — (\d+) de (\d+) reglas implementadas tienen fixture"),
                  lambda v: (v["cover_pct"], v["exer"], v["impl"])),
            Claim("documented blind spots",
                  re.compile(r"\|\s*Puntos ciegos documentados, confirmados aún abiertos\s*\|\s*\*\*(\d+)\*\*"),
                  lambda v: (v["blind"],)),
            Claim("malformed input",
                  re.compile(r"\|\s*Entrada malformada[^|]*\|\s*\*\*(\d+)/(\d+)\*\* sobrevividos"),
                  lambda v: (v["fuzz_n"], v["fuzz_d"])),
            Claim("corpus row",
                  re.compile(r"\|\s*Hallazgos de titular sobre (\d+) extensiones instaladas distintas\s*\|\s*"
                             r"\*\*(\d+)% completamente silenciosas\*\* \((\d+)/(\d+)\), "
                             r"mediana \*\*(\d+)\*\*, p90 \*\*(\d+)\*\*"),
                  lambda v: (v["discovered"], v["clean_pct"], v["clean_units"], v["discovered"],
                             v["median"], v["p90"])),
            Claim("detection badge",
                  re.compile(r"badge/detecci%C3%B3n-(\d+)%2F(\d+)-brightgreen"),
                  lambda v: (v["detect_n"], v["detect_d"])),
            Claim("fuzz badge",
                  re.compile(r"badge/entrada%20malformada-(\d+)%2F(\d+)-brightgreen"),
                  lambda v: (v["fuzz_n"], v["fuzz_d"])),
            Claim("heading: the silent percentage",
                  re.compile(r"### Ese (\d+)% no es una tasa de falsos positivos"),
                  lambda v: (v["clean_pct"],)),
            Claim("prose: false-positive percentage",
                  re.compile(r'leer la última fila como "(\d+)% de falsos positivos"'),
                  lambda v: (v["fp_pct"],)),
            Claim("prose: units that produce one",
                  re.compile(r"De las (\d+) unidades que producen uno"),
                  lambda v: (v["fp_units"],)),
        ]
    raise ValueError(lang)


def check_file(path: Path, lang: str, measured: dict[str, str]) -> tuple[int, list[tuple[str, str, str]]]:
    """(claims verified, [(row name, claimed text, measured text) for each mismatch or miss]).

    A row the pattern cannot find is reported with claimed text `<not found>`
    rather than skipped — see the module docstring for why that distinction
    matters.
    """
    text = path.read_text(encoding="utf-8")
    verified = 0
    problems: list[tuple[str, str, str]] = []

    for claim in _claims(lang):
        want = claim.expect(measured)
        match = claim.pattern.search(text)
        if not match:
            problems.append((claim.name, "<claim not found>", "/".join(want)))
            continue
        got = match.groups()
        if len(got) != len(want):
            raise RuntimeError(
                f"{claim.name}: pattern captured {len(got)} group(s) but expect() "
                f"returned {len(want)} — fix the Claim definition")
        if got != want:
            problems.append((claim.name, "/".join(got), "/".join(want)))
        else:
            verified += 1

    return verified, problems


def main() -> int:
    measured = measure()

    verified_total = 0
    all_problems: list[tuple[str, str, str, str]] = []  # (file, row, claimed, measured)

    for path, lang in ((README_EN, "en"), (README_ES, "es")):
        verified, problems = check_file(path, lang, measured)
        verified_total += verified
        rel = path.relative_to(PROJECT).as_posix()
        for name, claimed, want in problems:
            all_problems.append((rel, name, claimed, want))

    if all_problems:
        print(f"{RED}README claims out of sync with the measured suite:{RESET}\n")
        file_w = max(len(p[0]) for p in all_problems)
        row_w = max(len(p[1]) for p in all_problems)
        for rel, name, claimed, want in all_problems:
            print(f"  {RED}{rel:<{file_w}}{RESET}  {name:<{row_w}}  "
                  f"claims {YELLOW}{claimed}{RESET}, measured {GREEN}{want}{RESET}")
        print(f"\n{DIM}edit the line above named by 'row' in the file named by 'file' "
              f"so it reads the 'measured' value{RESET}")
        return 1

    print(f"{GREEN}{verified_total} published claims verified against the measured "
          f"suite across README.md and README.es.md{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
