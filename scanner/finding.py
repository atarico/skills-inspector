"""The Finding record, the axis orderings, and the headline selection.

Split out of `engine.py` so that the things which merely *describe* a finding do
not depend on the machinery that *produces* one. Before this, `report.py` and
`semantic.py` both needed `engine`, and `engine` needed them back, so three
imports were pushed inside function bodies to break the cycle at runtime. Those
deferred imports were not an optimisation; they were the circular dependency
showing through.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import evidence as ev
from . import position as pos

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
DISCLOSURE_ORDER = {"undeclared": 0, "euphemistic": 1, "declared": 2}


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    status: str
    disclosure: str
    capability: str
    # RAW bundle-relative path, never sanitized. This is a lookup key: the
    # reachability graph, taint supersession, dedupe and the capability profile
    # all index on it. Sanitizing at construction time truncated paths over 120
    # characters, and every one of those lookups then silently missed — a chain
    # would be reported alongside the very components it was built to absorb.
    # Sanitization is an OUTPUT filter and belongs at the output boundary:
    # `as_dict` below, and the writers in report.py / diff.py.
    location: str
    line: int
    detects: str
    evidence: str
    impact: str
    legitimate_use: str
    what_to_check: str
    position: str = pos.ACTIVE
    related_rules: list[str] = field(default_factory=list)
    specificity: int = 50
    chain: list[dict] = field(default_factory=list)
    extra_capabilities: list[str] = field(default_factory=list)
    # Produced by structural.inspect rather than by a line pattern. Structural
    # findings describe a whole config file and all carry line=1, so they are
    # exempt from line-level dedupe — see engine._dedupe.
    structural: bool = False

    def sort_key(self):
        """Body ordering: disclosure first.

        Grouping "never mentioned" together is the report's thesis, so this is
        right for the body — and deliberately wrong for the headline, which
        sorts by severity instead. See `headline`.
        """
        return (
            DISCLOSURE_ORDER.get(self.disclosure, 3),
            SEVERITY_ORDER.get(self.severity, 9),
            CONFIDENCE_ORDER.get(self.confidence, 9),
            self.location,
            self.line,
        )

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "disclosure": self.disclosure,
            "capability": self.capability,
            "location": {"file": ev.sanitize_path(self.location), "line": self.line},
            "position": self.position,
            "detects": self.detects,
            "evidence": self.evidence,
            "impact": self.impact,
            "legitimate_use": self.legitimate_use,
            "what_to_check": self.what_to_check,
            "related_rules": self.related_rules,
            "chain": self.chain,
        }


def headline(findings: list[Finding]) -> list[Finding]:
    """The report's lead (RULES.md section 11).

    `disclosure` never removes a finding from the REPORT. The description is
    written by the author of the audited unit, so letting `declared` delete a
    finding would hand the attacker control of the output: keyword-stuffing a
    description would blank the report while the unit steals SSH keys. Anything
    excluded here is still printed in the body.

    What disclosure decides is what LEADS:

    - CRITICAL always leads, declared or not. There is no benign declared
      CRITICAL — the level means "assume compromise if executed", so the human
      looks at it either way.
    - HIGH leads only when the description did not name it. A declared HIGH
      (a notifier that says it posts to Slack) belongs in the body.

    Heuristics never lead, so low confidence is excluded and grouped downstream.

    The sort is severity-first, deliberately NOT `Finding.sort_key`. That key
    orders by disclosure first, which is right for the body but inside the
    headline it contradicted the promise directly above: a HIGH/undeclared
    sorted above a CRITICAL/declared, so CRITICAL did not, in fact, lead.
    """
    out = [f for f in findings
           if f.confidence in ("high", "medium")
           and (f.severity == "CRITICAL"
                or (f.severity == "HIGH" and f.disclosure != "declared"))]
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                            DISCLOSURE_ORDER.get(f.disclosure, 3),
                            CONFIDENCE_ORDER.get(f.confidence, 9),
                            f.location, f.line))
    return out
