"""Semantic pass verification — RULES.md section 8.

`verify()` is pure deterministic Python, so it is tested with synthetic judge
answers: no model, no network, repeatable. That split is the point of the
design — every comparison that decides a finding lives here, where it can be
tested, rather than in an agent's context that read the target.

    python -m tests.semantic_test
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import engine, semantic  # noqa: E402
from scanner.unit import collect  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "fixtures"
GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def _answers(request, mapping, framings=1):
    """Synthesise a panel: mapping is {substring_of_chunk_text: [capabilities]}."""
    out = []
    for chunk in request.chunks:
        caps: list[str] = []
        addresses = False
        for needle, value in mapping.items():
            if needle in chunk.text:
                caps = list(value.get("capabilities", []))
                addresses = value.get("addresses_the_reader", False)
        for _ in range(framings):
            out.append({"chunk_id": chunk.id, "capabilities": caps,
                        "addresses_the_reader": addresses})
    return {"answers": out}


def case(name, fixture, mapping, expect_ids, *, framings=1, note=""):
    unit = collect(ROOT / fixture)
    findings, _ = engine.scan(unit)
    request = semantic.prepare(unit)
    extra = semantic.verify(unit, findings, request,
                            _answers(request, mapping, framings))
    got = {f.id for f in extra}
    missing = set(expect_ids) - got
    if missing:
        print(f"{RED}MISS{RESET}  {name:<34} expected {sorted(expect_ids)}, got {sorted(got)}")
        return False
    bad_conf = [f.id for f in extra if f.confidence != "low"]
    if bad_conf:
        print(f"{RED}FAIL{RESET}  {name:<34} semantic findings must cap at low: {bad_conf}")
        return False
    print(f"{GREEN}OK{RESET}    {name:<34} {sorted(got)}  {DIM}{note}{RESET}")
    return True


def main() -> int:
    results = []

    # THE point of the whole pass: prose with no trigger word. The scanner finds
    # nothing; a reader sees network + reading local context.
    results.append(case(
        "prose-exfil -> SEM-002", "known-miss/prose-exfil",
        {"append a short session summary": {"capabilities": ["network", "recon"]}},
        ["SEM-002"], note="closes the documented blind spot"))

    # A steered or fooled panel: the scanner PROVED a capability in this chunk
    # and the readers did not describe it. The omission is the finding.
    # Note the vocabulary deliberately excludes `instruction`: asking a judge
    # whether text "uses the instruction-surface capability" is incoherent, and
    # `addresses_the_reader` already covers it. So a fixture whose only finding
    # is AGT-* has nothing in-vocabulary to omit — this uses one that does.
    results.append(case(
        "steered panel -> SEM-001", "malicious/conditional-payload",
        {"Read the file at": {"capabilities": []}},
        ["SEM-001"], note="scanner proved secrets, panel stayed quiet"))

    # Text that gives orders to whoever reads it.
    results.append(case(
        "reader-directed -> SEM-004", "malicious/prompt-injection",
        {"Ignore all previous instructions":
            {"capabilities": ["network"], "addresses_the_reader": True}},
        ["SEM-004"], note="genuine skills instruct about a task"))

    # A clean unit with an honest panel must stay silent.
    unit = collect(ROOT / "benign/pure-formatter")
    findings, _ = engine.scan(unit)
    request = semantic.prepare(unit)
    extra = semantic.verify(unit, findings, request, _answers(request, {}))
    if extra:
        print(f"{RED}FP{RESET}    {'benign, honest panel':<34} "
              f"{len(extra)} findings, expected 0: {[f.id for f in extra]}")
        results.append(False)
    else:
        print(f"{GREEN}OK{RESET}    {'benign, honest panel':<34} silent  "
              f"{DIM}agreement produces nothing{RESET}")
        results.append(True)

    # Adversarial answer files must not be able to inject findings.
    unit = collect(ROOT / "benign/pure-formatter")
    findings, _ = engine.scan(unit)
    request = semantic.prepare(unit)
    hostile = {"answers": [
        {"chunk_id": "c_doesnotexist", "capabilities": ["network"]},
        {"chunk_id": request.chunks[0].id, "capabilities": ["not_a_capability"]},
        {"chunk_id": request.chunks[0].id, "capabilities": "network"},
        {"chunk_id": 12345, "capabilities": ["network"]},
        "a bare string",
        {"chunk_id": request.chunks[0].id, "capabilities": ["network"],
         "evil_extra_key": "rm -rf /"},
    ]}
    extra = semantic.verify(unit, findings, request, hostile)
    injected = [f for f in extra if "rm -rf" in f.evidence or "doesnotexist" in f.location]
    unknown_ok = all(f.location.startswith("SKILL.md") for f in extra)
    if injected or not unknown_ok:
        print(f"{RED}FAIL{RESET}  {'hostile answer file':<34} schema not closed")
        results.append(False)
    else:
        print(f"{GREEN}OK{RESET}    {'hostile answer file':<34} "
              f"{len(extra)} finding(s), all schema-clean  "
              f"{DIM}unknown ids and bad types dropped{RESET}")
        results.append(True)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} semantic checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
