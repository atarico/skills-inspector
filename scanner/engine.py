"""Matching, the four axes, and deduplication — RULES.md sections 2, 7.

The four axes are computed independently and never multiplied together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import evidence as ev
from . import position as pos
from . import rules as R
from . import structural
from .disclosure import classify_disclosure
from .unit import Unit

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
DISCLOSURE_ORDER = {"undeclared": 0, "euphemistic": 1, "declared": 2}


def headline(findings: list["Finding"]) -> list["Finding"]:
    """The disclosure gap — the report's lead (RULES.md section 11).

    A gap is undeclared OR euphemistic: 'declared' is the only disclosure state
    where the author actually told you. Heuristics never lead, so low-confidence
    findings are excluded here and grouped separately downstream.
    """
    return [f for f in findings
            if f.disclosure in ("undeclared", "euphemistic")
            and f.severity in ("CRITICAL", "HIGH")
            and f.confidence in ("high", "medium")]


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    status: str
    disclosure: str
    capability: str
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

    def sort_key(self):
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
            "location": {"file": self.location, "line": self.line},
            "position": self.position,
            "detects": self.detects,
            "evidence": self.evidence,
            "impact": self.impact,
            "legitimate_use": self.legitimate_use,
            "what_to_check": self.what_to_check,
            "related_rules": self.related_rules,
        }


_MD_SUFFIXES = {".md", ".markdown", ".mdx"}


def scan(unit: Unit) -> tuple[list[Finding], dict]:
    raw: list[Finding] = []

    for entry in unit.files:
        if entry.is_binary:
            raw.append(_binary_finding(entry))
            continue
        if entry.text is None:
            continue
        if entry.executable and not entry.relpath.endswith((".md", ".json", ".txt")):
            raw.append(_exec_bit_finding(entry))

        raw += _scan_text(unit, entry.relpath, entry.text)

        base_position = pos.file_base_position(entry.relpath)
        for hit in structural.inspect(unit.root, entry.relpath):
            # Structural findings respect position too: a settings.json inside a
            # fixtures/ tree is a sample, not a live control-plane change.
            confidence = pos.demote(hit.confidence, base_position)
            raw.append(Finding(
                id=hit.rule_id, severity=hit.severity, confidence=confidence,
                status="active", disclosure="undeclared", capability=hit.capability,
                location=ev.sanitize_path(hit.relpath), line=hit.line,
                detects=hit.detects, evidence=ev.sanitize(str(hit.evidence)),
                impact=hit.impact, legitimate_use=hit.legitimate,
                what_to_check=hit.check, position=base_position,
                specificity=hit.specificity))

    # Location floor: a file inside a test/fixtures/examples tree caps at low,
    # after every rule and exemption has run. One place, no bypass.
    for finding in raw:
        if pos.in_sample_dir(finding.location):
            finding.confidence = "low"

    findings = _dedupe(raw)
    for finding in findings:
        finding.disclosure = classify_disclosure(finding.capability, unit.description)

    findings.sort(key=Finding.sort_key)
    return findings, _profile(findings, unit)


def _scan_text(unit: Unit, relpath: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    positions = pos.classify_lines(relpath, text)
    is_md = Path(relpath).suffix.lower() in _MD_SUFFIXES

    base_position = pos.file_base_position(relpath)
    hidden = ev.invisible_counts(text)
    total_hidden = sum(hidden.values())
    if total_hidden > 0:
        severity = "HIGH" if total_hidden >= 5 else "LOW"
        out.append(Finding(
            id="AGT-006", severity=severity, confidence="high", status="active",
            disclosure="undeclared", capability=R.HIDDEN,
            location=ev.sanitize_path(relpath), line=1, position=base_position,
            detects="Hidden characters: " + ", ".join(f"{k}x{v}" for k, v in sorted(hidden.items())),
            evidence=f"{total_hidden} invisible characters across the file",
            impact="Content the human reviewer never sees but the model does.",
            legitimate_use="Small counts are often accidental (emoji joiners, copied text).",
            what_to_check="Render the file with invisibles shown before trusting it.",
            specificity=90))

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        position, kind = positions[idx] if idx < len(positions) else (pos.ACTIVE, pos.PROSE)
        for rule in R.RULES:
            if rule.markdown_only and not is_md:
                continue
            if rule.code_only and is_md:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            # Instruction-surface rules in prose are inherently ambiguous: a
            # deterministic match cannot tell a live injection from a doc quoting
            # one ("ignore previous instructions" appears in both). They are
            # reported at low confidence, grouped separately — distinguishing the
            # two is exactly the job of the semantic pass (section 8, deferred).
            effective = position
            if is_md and pos.in_inline_code(line, match.start()):
                effective = pos.DOCUMENTARY
            confidence = pos.demote(rule.confidence, effective)
            if not is_md:
                for _ in range(pos.literal_demotion(line, match.start())):
                    confidence = pos.demote(confidence, pos.ILLUSTRATIVE)
            out.append(Finding(
                id=rule.id, severity=rule.severity, confidence=confidence,
                status="active", disclosure="undeclared", capability=rule.capability,
                location=ev.sanitize_path(relpath), line=idx + 1,
                detects=rule.detects,
                evidence=ev.sanitize(line, centre=(match.start(), match.end())),
                impact=rule.impact, legitimate_use=rule.legitimate,
                what_to_check=rule.check, position=position,
                specificity=rule.specificity))
    return out


def _binary_finding(entry) -> Finding:
    return Finding(
        id="EXE-001", severity="MEDIUM", confidence="high", status="active",
        disclosure="undeclared", capability=R.REMOTE_EXEC,
        location=ev.sanitize_path(entry.relpath), line=1,
        detects=f"Bundled non-text file ({entry.binary_kind})",
        evidence=f"{entry.binary_kind}, {entry.size} bytes",
        impact="Contents cannot be reviewed by reading the bundle.",
        legitimate_use="Vendored assets, fixtures, images.",
        what_to_check="What is this file, and does anything in the bundle run it?",
        specificity=85)


def _exec_bit_finding(entry) -> Finding:
    return Finding(
        id="EXE-002", severity="MEDIUM", confidence="high", status="active",
        disclosure="undeclared", capability=R.REMOTE_EXEC,
        location=ev.sanitize_path(entry.relpath), line=1,
        detects="File ships with the executable bit set",
        evidence="mode +x",
        impact="Ready-to-run payload shipped with the unit.",
        legitimate_use="Helper CLI the unit legitimately invokes.",
        what_to_check="Is this script referenced from the entry point?",
        specificity=80)


def _dedupe(raw: list[Finding]) -> list[Finding]:
    """Section 7: group by (file, line, capability). Most specific rule wins;
    the rest collapse into related_rules and are not counted separately."""
    buckets: dict[tuple, list[Finding]] = {}
    for finding in raw:
        key = (finding.location, finding.line, finding.capability)
        buckets.setdefault(key, []).append(finding)

    out: list[Finding] = []
    for group in buckets.values():
        group.sort(key=lambda f: (-f.specificity, SEVERITY_ORDER.get(f.severity, 9)))
        winner = group[0]
        winner.related_rules = sorted({f.id for f in group[1:]} - {winner.id})
        out.append(winner)
    return out


def _profile(findings: list[Finding], unit: Unit) -> dict:
    """Capability profile. CHN-003 lives here and only here: co-occurrence is
    reported, never escalated."""
    caps: dict[str, list[str]] = {}
    for finding in findings:
        if finding.severity == "INFO" and finding.capability in caps:
            continue
        caps.setdefault(finding.capability, [])
        detail = f"{finding.location}:{finding.line}"
        if len(caps[finding.capability]) < 4 and detail not in caps[finding.capability]:
            caps[finding.capability].append(detail)

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    return {
        "capabilities": caps,
        "severity_counts": counts,
        "finding_count": len(findings),
        "file_count": len(unit.files),
        "unreadable_count": len([f for f in unit.files if f.is_binary]),
    }
