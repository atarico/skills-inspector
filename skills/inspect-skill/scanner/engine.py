"""Matching, the four axes, and deduplication — RULES.md sections 2, 7.

The four axes are computed independently and never multiplied together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import evidence as ev
from . import position as pos
from . import reachability
from . import rules as R
from . import structural
from . import taint
from .disclosure import classify_disclosure
from .unit import Unit

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
DISCLOSURE_ORDER = {"undeclared": 0, "euphemistic": 1, "declared": 2}


def headline(findings: list["Finding"]) -> list["Finding"]:
    """The report's lead (RULES.md section 11).

    `disclosure` ORDERS this list; it must never filter it. The description is
    written by the author of the audited unit, so letting `declared` suppress a
    finding hands the attacker control of the report: keyword-stuffing a
    description would blank the headline while the unit steals SSH keys.

    - CRITICAL always leads, declared or not. There is no benign declared
      CRITICAL — the level means "assume compromise if executed", so the human
      looks at it either way.
    - HIGH leads only when the description did not name it. A declared HIGH
      (a notifier that says it posts to Slack) belongs in the body.

    Heuristics never lead, so low confidence is excluded and grouped downstream.
    """
    out = [f for f in findings
           if f.confidence in ("high", "medium")
           and (f.severity == "CRITICAL"
                or (f.severity == "HIGH" and f.disclosure != "declared"))]
    out.sort(key=Finding.sort_key)
    return out


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
    chain: list[dict] = field(default_factory=list)
    extra_capabilities: list[str] = field(default_factory=list)

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
            "chain": self.chain,
        }


_MD_SUFFIXES = {".md", ".markdown", ".mdx"}


def scan(unit: Unit) -> tuple[list[Finding], dict]:
    raw: list[Finding] = []
    chains: list[taint.Chain] = []
    graph = reachability.build(unit.files)
    unit_budget = unit_line_budget()
    lines_used = 0

    for entry in unit.files:
        if entry.symlink_target:
            raw.append(Finding(
                id="FSW-008", severity="HIGH", confidence="high", status="active",
                disclosure="undeclared", capability=R.WRITE_OUTSIDE,
                location=ev.sanitize_path(entry.relpath), line=1,
                detects="Bundled symlink pointing outside the unit",
                evidence=f"-> {ev.sanitize_path(entry.symlink_target)}",
                impact="The bundle reaches a path you did not put in scope; "
                       "a write through the link lands outside the unit.",
                legitimate_use="Never inside a distributed bundle.",
                what_to_check="Why does the package link to a path outside itself?",
                specificity=90))
            continue
        if entry.is_binary:
            raw.append(_binary_finding(entry))
            continue
        if entry.text is None:
            continue
        if entry.executable and not entry.relpath.endswith((".md", ".json", ".txt")):
            raw.append(_exec_bit_finding(entry))

        line_count = entry.text.count("\n") + 1
        if lines_used + line_count > unit_budget:
            unit.skipped.append((entry.relpath,
                                 f"{line_count} lines, unit line budget exhausted"))
            continue
        lines_used += line_count

        line_matches: dict[int, list] = {}
        raw += _scan_text(unit, entry.relpath, entry.text, line_matches)
        chains += taint.analyze(entry.relpath, entry.text,
                                pos.classify_lines(entry.relpath, entry.text),
                                line_matches)

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

    raw += _reachability_findings(graph, unit)

    # Location floor: a file inside a test/fixtures/examples tree caps at low.
    # Runs after EVERY producer — rules, structural, reachability — so nothing
    # added later can bypass it. One place, no exceptions.
    for finding in raw:
        if pos.in_sample_dir(finding.location):
            finding.confidence = "low"

    # `status` annotates; it must never lower severity (RULES.md section 2.3).
    # A dormant CRITICAL is still CRITICAL.
    for finding in raw:
        node = graph.status.get(finding.location)
        if node == reachability.DORMANT:
            finding.status = "dormant"
        elif node == reachability.CONDITIONAL:
            finding.status = "conditional"

    raw = _supersede(raw, chains)
    findings = _dedupe(raw)
    for finding in findings:
        finding.disclosure = classify_disclosure(finding.capability, unit.description)

    findings.sort(key=Finding.sort_key)
    return findings, profile(findings, unit)


def unit_line_budget() -> int:
    from .unit import MAX_TOTAL_LINES
    return MAX_TOTAL_LINES


def _scan_text(unit: Unit, relpath: str, text: str,
               line_matches: dict | None = None) -> list[Finding]:
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
            if line_matches is not None:
                line_matches.setdefault(idx, []).append(rule)
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


def _reachability_findings(graph, unit: Unit) -> list[Finding]:
    """BND-001/002/003 — structure findings the rule engine cannot see."""
    out: list[Finding] = []

    for relpath, status in sorted(graph.status.items()):
        if not reachability.is_interesting(relpath):
            continue
        if pos.in_sample_dir(relpath):
            continue
        if status == reachability.DORMANT:
            out.append(Finding(
                id="BND-001", severity="MEDIUM", confidence="high", status="dormant",
                disclosure="undeclared", capability=R.REMOTE_EXEC,
                location=ev.sanitize_path(relpath), line=1,
                detects="File in the bundle is referenced by nothing",
                evidence="no path from any entry point",
                impact="Dormant payload: shipped but not wired up. Severity comes "
                       "from whatever the file contains.",
                legitimate_use="Vendored deps, assets, docs, tests.",
                what_to_check="Why is this shipped if nothing loads it?",
                position=pos.file_base_position(relpath), specificity=70))
        elif status == reachability.CONDITIONAL:
            source = graph.conditional_from.get(relpath, "?")
            out.append(Finding(
                id="BND-003", severity="MEDIUM", confidence="high",
                status="conditional", disclosure="undeclared",
                capability=R.INSTRUCTION,
                location=ev.sanitize_path(relpath), line=1,
                detects="File loaded only under a runtime condition",
                evidence=f"reached conditionally from {ev.sanitize_path(source)}",
                impact="The human reviews the entry point; the model loads this "
                       "on a trigger. The skill-native 'below the fold'.",
                legitimate_use="Genuine progressive disclosure.",
                what_to_check="Read this file as carefully as the entry point.",
                position=pos.file_base_position(relpath), specificity=70))

    for raw_ref, path, line in sorted(graph.dangling)[:20]:
        out.append(Finding(
            id="BND-002", severity="HIGH", confidence="medium", status="active",
            disclosure="undeclared", capability=R.REMOTE_EXEC,
            location=ev.sanitize_path(path), line=line,
            detects="Reference to a bundle path that does not exist",
            evidence=ev.sanitize(raw_ref),
            impact="The file arrives after your audit, or is fetched at runtime.",
            legitimate_use="A broken docs link. Verify which.",
            what_to_check="Does anything create this path later?",
            position=pos.file_base_position(path), specificity=75))

    return out


def _supersede(raw: list[Finding], chains: list) -> list[Finding]:
    """A taint chain replaces the findings it is made of (RULES.md section L).

    Line-level dedup cannot express this: a chain spans several lines and two
    different capabilities, so its components must be absorbed across the whole
    file rather than collapsed within one line. Without this the report shows
    the flow AND both of its halves, and the severity counts triple-count it.
    """
    if not chains:
        return raw

    absorbed: set[tuple[str, int, str]] = set()
    by_line = {(f.location, f.line, f.id): f for f in raw}
    out: list[Finding] = []
    for chain in chains:
        absorbed.update(chain.absorbed)
        component_ids = sorted({rule_id for _f, _l, rule_id in chain.absorbed})
        # Absorbing the source must not erase it from the capability profile:
        # this unit really does read secrets, chain or no chain.
        swallowed_caps = sorted({
            by_line[key].capability for key in chain.absorbed if key in by_line})
        out.append(Finding(
            id="CHN-001", severity="CRITICAL", confidence="high", status="active",
            disclosure="undeclared", capability=R.NETWORK,
            location=ev.sanitize_path(chain.file), line=chain.sink_line,
            detects=f"Data flow: a secret read reaches an outbound sink "
                    f"via {chain.channel}",
            evidence=ev.sanitize(chain.sink_evidence),
            impact="This is exfiltration, not communication: local data leaves "
                   "the machine.",
            legitimate_use="Only if moving this data outward is the unit's "
                           "stated purpose.",
            what_to_check="Follow the chain and confirm the destination is yours.",
            related_rules=component_ids, specificity=99,
            extra_capabilities=swallowed_caps,
            chain=[{**hop, "evidence": ev.sanitize(hop["evidence"])}
                   if "evidence" in hop else hop
                   for hop in chain.hops()]))

    for finding in raw:
        if (finding.location, finding.line, finding.id) in absorbed:
            continue
        out.append(finding)
    return out


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


def profile(findings: list[Finding], unit: Unit) -> dict:
    """Capability profile. CHN-003 lives here and only here: co-occurrence is
    reported, never escalated."""
    caps: dict[str, list[str]] = {}
    for finding in findings:
        if finding.severity == "INFO" and finding.capability in caps:
            continue
        detail = f"{finding.location}:{finding.line}"
        for capability in [finding.capability, *finding.extra_capabilities]:
            caps.setdefault(capability, [])
            if len(caps[capability]) < 4 and detail not in caps[capability]:
                caps[capability].append(detail)

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
