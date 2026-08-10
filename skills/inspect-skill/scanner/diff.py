"""Diff mode — RULES.md section 12.

Supply chain attacks arrive as the update, not the install. Marketplaces
auto-update and nobody re-reads v2.

Compares **capabilities**, not lines. A 400-line refactor that changes nothing
the unit can do is silence; three new lines that add network egress are the
report. Line diffs are what `git diff` is for and they bury exactly this.

The loudest signal this tool can produce: a capability appears while the
description stays the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import evidence as ev
from . import rules as R
from .finding import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Delta:
    old_name: str = ""
    new_name: str = ""
    old_description: str = ""
    new_description: str = ""
    description_changed: bool = False
    new_capabilities: dict[str, list[str]] = field(default_factory=dict)
    removed_capabilities: list[str] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[tuple[str, str]] = field(default_factory=list)
    old_file_count: int = 0
    new_file_count: int = 0

    @property
    def silent_escalation(self) -> list[Finding]:
        """New severe capability with no change to what the unit says it does.

        This is the shape of a real supply-chain update: the code gains reach,
        the description does not admit it.
        """
        if self.description_changed:
            return []
        return [f for f in self.new_findings
                if f.severity in ("CRITICAL", "HIGH") and f.confidence != "low"]

    @property
    def has_change(self) -> bool:
        return bool(self.new_capabilities or self.removed_capabilities
                    or self.new_findings or self.description_changed)


def _key(finding: Finding) -> tuple[str, str]:
    """Identity that survives an update: what it is, not where it sits.

    Line numbers and even file names shift between versions for ordinary
    reasons; keying on them would report every reshuffle as a new capability.
    """
    return (finding.id, finding.capability)


def compare(old_unit, old_findings: list[Finding], old_profile: dict,
            new_unit, new_findings: list[Finding], new_profile: dict) -> Delta:
    delta = Delta(
        old_name=old_unit.name, new_name=new_unit.name,
        old_description=old_unit.description, new_description=new_unit.description,
        description_changed=(old_unit.description.strip()
                             != new_unit.description.strip()),
        old_file_count=len(old_unit.files), new_file_count=len(new_unit.files),
    )

    old_caps = set(old_profile["capabilities"])
    new_caps = new_profile["capabilities"]
    for capability, locations in new_caps.items():
        if capability not in old_caps:
            delta.new_capabilities[capability] = locations
    delta.removed_capabilities = sorted(old_caps - set(new_caps))

    old_keys = {_key(f) for f in old_findings}
    seen: set[tuple[str, str]] = set()
    for finding in new_findings:
        key = _key(finding)
        if key not in old_keys and key not in seen:
            seen.add(key)
            delta.new_findings.append(finding)
    delta.new_findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id))

    new_keys = {_key(f) for f in new_findings}
    delta.resolved_findings = sorted(
        {(f.id, f.severity) for f in old_findings if _key(f) not in new_keys})

    return delta


CAPABILITY_LABELS = {
    R.NETWORK: "Network egress", R.SECRETS: "Reads secrets",
    R.WRITE_OUTSIDE: "Writes outside unit", R.PERSISTENCE: "Persistence",
    R.CONTROL_PLANE: "Control plane", R.AUTO_EXEC: "Auto-execution",
    R.REMOTE_EXEC: "Executes code", R.HIDDEN: "Hidden content",
    R.PRIVILEGE: "Privilege", R.DESTRUCTIVE: "Destructive",
    R.RECON: "Broad reads", R.INSTRUCTION: "Instruction surface",
}


def to_text(delta: Delta) -> str:
    out: list[str] = []
    w = out.append

    w(f"CAPABILITY DELTA   {ev.sanitize(delta.old_name)} -> {ev.sanitize(delta.new_name)}")
    w(f"                   {delta.old_file_count} -> {delta.new_file_count} files")
    w("")

    escalation = delta.silent_escalation
    if escalation:
        w(f"!!  {len(escalation)} NEW SEVERE CAPABILIT"
          f"{'Y' if len(escalation) == 1 else 'IES'}, DESCRIPTION UNCHANGED")
        w("    The update gained reach without saying so. This is the shape of a")
        w("    supply-chain update — review it before letting it install.")
        for f in escalation[:10]:
            w(f"    + {f.detects[:58]:<58} {f.severity:<8} {ev.sanitize_path(f.location)}:{f.line}")
        w("")

    if delta.new_capabilities:
        w("NEW CAPABILITIES")
        for capability, locations in sorted(delta.new_capabilities.items()):
            label = CAPABILITY_LABELS.get(capability, capability)
            w(f"  + {label:<22} NEW -> {', '.join(locations[:3])}")
        w("")

    if delta.new_findings:
        w(f"NEW FINDINGS ({len(delta.new_findings)})")
        for f in delta.new_findings[:20]:
            w(f"  + [{f.severity}/{f.confidence}] {f.id:<9} {ev.sanitize_path(f.location)}:{f.line}"
              f"  {f.detects[:52]}")
        if len(delta.new_findings) > 20:
            w(f"  ... and {len(delta.new_findings) - 20} more")
        w("")

    if delta.removed_capabilities:
        w("REMOVED CAPABILITIES")
        for capability in delta.removed_capabilities:
            w(f"  - {CAPABILITY_LABELS.get(capability, capability)}")
        w("")

    if delta.resolved_findings:
        w(f"NO LONGER PRESENT ({len(delta.resolved_findings)})")
        w("  " + ", ".join(f"{rid}" for rid, _sev in delta.resolved_findings[:15]))
        w("")

    if delta.description_changed:
        w("DESCRIPTION CHANGED")
        w(f"  was  \"{ev.sanitize(delta.old_description)[:200]}\"")
        w(f"  now  \"{ev.sanitize(delta.new_description)[:200]}\"")
        w("")
    else:
        w("DESCRIPTION       unchanged")
        w("")

    if not delta.has_change:
        w("No capability change. Files may differ; what the unit can do does not.")
        w("")

    w("COVERAGE LIMITS")
    w("  - Compares capabilities, not lines. A behavioural change that adds no")
    w("    new capability is invisible here; run a full scan on the new version.")
    w("  - Both sides carry the coverage limits of a normal scan.")

    return "\n".join(out)


def to_dict(delta: Delta) -> dict:
    return {
        "old": {"name": ev.sanitize(delta.old_name),
                "description": ev.sanitize(delta.old_description),
                "file_count": delta.old_file_count},
        "new": {"name": ev.sanitize(delta.new_name),
                "description": ev.sanitize(delta.new_description),
                "file_count": delta.new_file_count},
        "description_changed": delta.description_changed,
        "silent_escalation": [f.as_dict() for f in delta.silent_escalation],
        "new_capabilities": delta.new_capabilities,
        "removed_capabilities": delta.removed_capabilities,
        "new_findings": [f.as_dict() for f in delta.new_findings],
        "resolved_findings": [{"id": i, "severity": s}
                              for i, s in delta.resolved_findings],
    }
