"""Report model — RULES.md section 11.

Leads with the disclosure gap, then the capability profile, then findings.
Severity ranking is not the headline — surprise is.

NOT ANALYZED and COVERAGE LIMITS are mandatory output, not documentation.
A report that omits them implies a completeness the tool does not have.
"""

from __future__ import annotations

import json

from . import evidence as ev
from . import rules as R
from .engine import Finding
from .unit import Unit

CAPABILITY_LABELS = {
    R.NETWORK: "Network",
    R.SECRETS: "Reads secrets",
    R.WRITE_OUTSIDE: "Writes outside unit",
    R.PERSISTENCE: "Persistence",
    R.CONTROL_PLANE: "Control plane",
    R.AUTO_EXEC: "Auto-execution",
    R.REMOTE_EXEC: "Executes code",
    R.HIDDEN: "Hidden content",
    R.PRIVILEGE: "Privilege",
    R.DESTRUCTIVE: "Destructive",
    R.RECON: "Broad reads",
    R.INSTRUCTION: "Instruction surface",
}

COVERAGE_LIMITS = [
    "Instruction detection is phrase-seeded. Plain non-imperative prose "
    "instructing harmful behavior is not detectable by this tool.",
    "Taint tracking is not implemented in this version: reading a secret and "
    "sending data are reported separately, never as a proven flow.",
    "The reachability graph is not implemented: dormant and conditional payloads "
    "are not distinguished from active ones.",
    "The semantic pass is not implemented: description/body mismatch is not checked.",
    "Position classification is heuristic. A dangerous pattern in prose may be "
    "demoted to low confidence incorrectly.",
    "A clean report is not a safety claim.",
]


def to_json(unit: Unit, findings: list[Finding], profile: dict) -> str:
    return json.dumps({
        "unit": {
            "name": ev.sanitize(unit.name),
            "kind": unit.kind,
            "root": str(unit.root),
            "scope_widened": unit.widened,
            "description": ev.sanitize(unit.description),
            "declared_tools": [ev.sanitize(t) for t in unit.declared_tools],
            "file_count": len(unit.files),
        },
        "profile": profile,
        "findings": [f.as_dict() for f in findings],
        "not_analyzed": [{"file": ev.sanitize_path(p), "reason": r} for p, r in unit.skipped],
        "coverage_limits": COVERAGE_LIMITS,
        "deferred_rules": R.DEFERRED,
    }, indent=2, ensure_ascii=False)


def to_text(unit: Unit, findings: list[Finding], profile: dict, *, verbose: bool = False) -> str:
    out: list[str] = []
    w = out.append

    w(f"UNIT      {ev.sanitize(unit.name)}  ({unit.kind}, {len(unit.files)} files)")
    if unit.widened:
        w(f"          scope widened to the installation unit: {unit.root}")
    desc = ev.sanitize(unit.description) or "(no description found)"
    w(f"DECLARED  \"{desc[:300]}\"")
    if unit.declared_tools:
        w(f"TOOLS     {', '.join(unit.declared_tools)}")
    w("")

    from .engine import headline
    gap = headline(findings)
    if gap:
        w(f"!  {len(gap)} CAPABILIT{'Y' if len(gap) == 1 else 'IES'} THE DESCRIPTION DOES NOT MENTION")
        for f in gap[:12]:
            w(f"   - {f.detects[:64]:<64} {f.severity:<8} {f.confidence:<6} {f.location}:{f.line}")
        if len(gap) > 12:
            w(f"   ... and {len(gap) - 12} more")
        w("")

    w("CAPABILITY PROFILE")
    caps = profile["capabilities"]
    for key, label in CAPABILITY_LABELS.items():
        hits = caps.get(key)
        if hits:
            w(f"  {label:<22} yes -> {', '.join(hits[:3])}")
        else:
            w(f"  {label:<22} no")
    if len([k for k in caps if k in (R.SECRETS, R.NETWORK)]) == 2:
        w("  [CHN-003] reads secrets AND has network. Co-occurrence only —")
        w("            this is NOT proof of exfiltration and does not escalate.")
    w("")

    counts = profile["severity_counts"]
    summary = "  ".join(f"{k} {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                        if counts.get(k))
    w(f"FINDINGS  {profile['finding_count']} total   {summary or 'none'}")
    w("")

    deterministic = [f for f in findings if f.confidence in ("high", "medium")]
    heuristic = [f for f in findings if f.confidence == "low"]

    if deterministic:
        limit = len(deterministic) if verbose else 25
        for f in deterministic[:limit]:
            _emit(w, f)
        if len(deterministic) > limit:
            w(f"  ... {len(deterministic) - limit} more (use --verbose)")
            w("")

    if heuristic:
        w(f"LOW CONFIDENCE ({len(heuristic)}) — heuristics, grouped so they do not dilute the rest")
        limit = len(heuristic) if verbose else 10
        for f in heuristic[:limit]:
            w(f"  {f.id:<9} {f.severity:<8} {f.location}:{f.line}  {f.detects[:70]}")
        if len(heuristic) > limit:
            w(f"  ... {len(heuristic) - limit} more (use --verbose)")
        w("")

    if unit.skipped:
        w("NOT ANALYZED")
        for path, reason in unit.skipped[:15]:
            w(f"  {ev.sanitize_path(path):<44} {reason}")
        if len(unit.skipped) > 15:
            w(f"  ... and {len(unit.skipped) - 15} more")
        w("")

    w("COVERAGE LIMITS")
    for limit_text in COVERAGE_LIMITS:
        w(f"  - {limit_text}")

    return "\n".join(out)


def _emit(w, f: Finding) -> None:
    w(f"  [{f.severity}/{f.confidence}] {f.id}  {f.location}:{f.line}"
      f"   status={f.status} disclosure={f.disclosure}")
    w(f"      {f.detects}")
    w(f"      evidence   {f.evidence}")
    w(f"      impact     {f.impact}")
    w(f"      normal if  {f.legitimate_use}")
    w(f"      check      {f.what_to_check}")
    if f.related_rules:
        w(f"      also matched {', '.join(f.related_rules)} (collapsed)")
    w("")
