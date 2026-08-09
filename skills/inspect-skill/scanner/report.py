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

_BASE_LIMITS = [
    "Taint tracking covers direct and one-hop-indirect flows inside a single "
    "file (variable, filesystem, environment, direct pipe). Flows through a "
    "spawned interpreter, across files, or via a config read later are not seen.",
    "Reachability is resolved from explicit references only. A file loaded by a "
    "path built at runtime looks dormant, and a dangling reference is reported "
    "only when the bundle itself owns the parent directory.",
    "Position classification is heuristic. A dangerous pattern in prose may be "
    "demoted to low confidence incorrectly.",
    "A clean report is not a safety claim.",
]

_NO_SEMANTIC = (
    "The semantic pass did not run. Instruction detection is phrase-seeded, so "
    "plain non-imperative prose that instructs harmful behavior is invisible "
    "here — run `semantic-prep` / `semantic-verify` to cover it.")

_WITH_SEMANTIC = (
    "The semantic pass ran. Its findings (SEM-*) are low confidence by "
    "construction: the readers see adversarial text and can be steered past a "
    "capability the scanner also missed. Treat them as questions, not verdicts.")


def coverage_limits(findings=()) -> list[str]:
    """Limits depend on which passes actually ran, so the report cannot claim a
    coverage it does not have — or deny one it does."""
    semantic_ran = any(f.id.startswith("SEM-") for f in findings)
    return [_WITH_SEMANTIC if semantic_ran else _NO_SEMANTIC, *_BASE_LIMITS]


# Kept for callers that want the pessimistic default.
COVERAGE_LIMITS = coverage_limits()

# Generic label for a group whose members word the same fact differently.
RULE_SUMMARY = {
    "HOK-001": "Defines agent hooks",
    "HOK-003": "Registers MCP servers",
    "HOK-004": "Defines subagents",
    "HOK-006": "Lowers agent permissions",
    "AUT-001": "Package lifecycle scripts",
    "BND-001": "Files referenced by nothing",
    "BND-002": "References a path that does not exist",
    "BND-003": "Files loaded only under a condition",
}


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
        "coverage_limits": coverage_limits(findings),
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
        # One fact repeated across sibling files is one line. A plugin shipping
        # the same MCP server in five platform manifests is not five decisions
        # to a human, and printing it five times buries the other four.
        groups: list[tuple[Finding, list[Finding]]] = []
        index: dict[tuple, int] = {}
        for f in gap:
            key = (f.id, f.capability, f.severity)
            if key in index:
                groups[index[key]][1].append(f)
            else:
                index[key] = len(groups)
                groups.append((f, []))

        undeclared = sum(1 for lead, rest in groups
                         if any(f.disclosure != "declared" for f in (lead, *rest)))
        count = len(groups)
        w(f"!  {count} CAPABILIT{'Y NEEDS' if count == 1 else 'IES NEED'} YOUR DECISION"
          + (f", from {len(gap)} findings" if len(gap) != count else "")
          + (f"  ({undeclared} not mentioned in the description)" if undeclared else ""))

        for lead, rest in groups[:12]:
            members = [lead, *rest]
            tag = "" if any(f.disclosure != "declared" for f in members) \
                else "  [author declared it]"
            if not rest:
                label, where = lead.detects, f"{lead.location}:{lead.line}"
            else:
                # Members of a group can differ in wording (one manifest points
                # at an .mcp.json, another inlines it). Showing one member's
                # text while claiming N files would misdescribe the others.
                variants = {f.detects for f in members}
                label = (lead.detects if len(variants) == 1
                         else RULE_SUMMARY.get(lead.id, lead.detects.split(":")[0]))
                where = f"{len(members)} files, e.g. {lead.location}"
            w(f"   - {label[:56]:<56} {lead.severity:<8} "
              f"{lead.confidence:<6} {where}{tag}")
        if len(groups) > 12:
            w(f"   ... and {len(groups) - 12} more")
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
    for limit_text in coverage_limits(findings):
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
    for hop in f.chain:
        if hop["step"] == "propagation":
            w(f"      flow       via {hop['channel']}")
        else:
            w(f"      {hop['step']:<10} line {hop['line']} [{hop['rule']}]  {hop['evidence']}")
    if f.related_rules:
        w(f"      also matched {', '.join(f.related_rules)} (collapsed)")
    w("")
