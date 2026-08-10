"""Approved-state store — the update check (RULES.md section 12).

`diff` answers "what changed between these two trees", which assumes you still
have both. You usually do not: `~/.claude/skills/*` is overwritten in place by an
update, and most marketplace caches are not git repositories. By the time there
is a v2 to inspect, v1 is gone — and the attacker did not have to do anything to
make that happen.

So this stores the *result* of an approved audit, not the tree. `diff.compare`
never needed the old files: it reads a name, a description, a file count, the
capability keys, and `(id, capability, severity)` per finding. That is a few
kilobytes, which is why this is a directory of JSON files and not a database. A
plain file you can read with `cat` is the right shape for something whose entire
job is to tell you what you already approved.

The model is trust-on-first-use, like SSH `known_hosts`:

    baseline <target>   record the current state as approved
    check <target>      scan now, compare against the recorded state

A first `check` has nothing to compare against and says so. It never records a
baseline on its own — silently blessing whatever is on disk the first time it
runs is how you approve a payload without reading it.

## On tampering, stated honestly

The store lives OUTSIDE `~/.claude/` on purpose. That directory is writable by
any skill with filesystem access, and writing to it is a finding this scanner
reports (`FSW-002`); keeping the trust anchor there would mean a compromised
extension could bless its own next version.

The recorded checksum detects corruption and casual tampering. It is NOT a
defence against an attacker who already has write access to your home directory
— they can recompute it. Nothing stored on the same machine can be, and claiming
otherwise would be the kind of overselling this project's README refuses to do.
What the checksum buys is that silent modification takes deliberate effort and
leaves the store in a state this tool will refuse to trust.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .finding import Finding

SCHEMA = 1

# Deliberately not under ~/.claude — see the module docstring.
DEFAULT_DIR = Path.home() / ".inspector-baselines"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class BaselineError(Exception):
    """Raised when a stored baseline exists but cannot be trusted."""


def store_dir() -> Path:
    """Where baselines live. `INSPECTOR_BASELINE_DIR` overrides, for tests."""
    override = os.environ.get("INSPECTOR_BASELINE_DIR")
    return Path(override).expanduser() if override else DEFAULT_DIR


def key_for(root: Path) -> str:
    """Stable identity for an audited unit: its resolved absolute path.

    Hashed so the filename cannot collide or escape the store, prefixed with the
    directory name so a human scanning `ls` can tell what they are looking at.
    """
    resolved = str(Path(root).expanduser().resolve())
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]
    label = _SAFE_NAME.sub("-", Path(resolved).name).strip("-") or "unit"
    return f"{label[:40]}-{digest}"


def path_for(root: Path) -> Path:
    return store_dir() / f"{key_for(root)}.json"


def _payload(unit, findings: list[Finding], profile: dict, root: Path) -> dict:
    """The subset `diff.compare` actually reads from the old side.

    Storing whole Finding objects would be wasteful and would tie the format to
    a dataclass that keeps changing. The prose fields (impact, legitimate_use,
    what_to_check) are never read from a baseline — they describe a rule, and
    the rule is looked up fresh on the new side.
    """
    return {
        "schema": SCHEMA,
        "target": str(Path(root).expanduser().resolve()),
        "approved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "unit": {
            "name": unit.name,
            "description": unit.description,
            "file_count": len(unit.files),
        },
        "capabilities": sorted(profile.get("capabilities", {})),
        "findings": sorted(
            ({"id": f.id, "capability": f.capability, "severity": f.severity,
              "confidence": f.confidence, "location": f.location, "line": f.line,
              "detects": f.detects}
             for f in findings),
            key=lambda d: (d["id"], d["capability"], d["location"], d["line"]),
        ),
    }


def _checksum(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save(root: Path, unit, findings: list[Finding], profile: dict) -> Path:
    """Record the current scan as the approved state. Overwrites any previous one."""
    payload = _payload(unit, findings, profile, root)
    document = {**payload, "checksum": _checksum(payload)}

    directory = store_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)

    target = directory / f"{key_for(root)}.json"
    # Write-then-rename: an interrupted save must not leave a half-written
    # baseline that the next check would reject or, worse, half-trust.
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    return target


def load(root: Path):
    """The approved state, or None if this unit has never been approved.

    Raises BaselineError when a baseline exists but fails its checksum or
    carries a schema this build does not understand. Refusing to compare is the
    correct response — a baseline that cannot be trusted is worse than none,
    because it produces a confident "nothing changed".
    """
    target = path_for(root)
    if not target.exists():
        return None

    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"baseline is unreadable ({exc}); delete it and re-approve")

    if not isinstance(document, dict):
        raise BaselineError("baseline is not an object; delete it and re-approve")

    recorded = document.pop("checksum", None)
    if recorded != _checksum(document):
        raise BaselineError(
            "baseline checksum does not match its contents — it was modified "
            "after it was approved. Re-audit this unit from scratch rather than "
            "trusting the comparison")

    if document.get("schema") != SCHEMA:
        raise BaselineError(
            f"baseline uses schema {document.get('schema')}, this build "
            f"understands {SCHEMA}; re-approve to upgrade it")

    return document


class StoredUnit:
    """The `unit` half of a baseline, shaped for `diff.compare`.

    `compare` reads `.name`, `.description`, and `len(.files)`. `files` is a
    plain list of the right length: nothing downstream inspects its contents,
    and inventing FileEntry objects to satisfy a length check would be a lie
    with more moving parts.
    """

    __slots__ = ("name", "description", "files")

    def __init__(self, document: dict):
        unit = document.get("unit", {})
        self.name = unit.get("name", "")
        self.description = unit.get("description", "")
        self.files = [None] * int(unit.get("file_count", 0))


def restore(document: dict) -> tuple[StoredUnit, list[Finding], dict]:
    """Rebuild the (unit, findings, profile) triple `diff.compare` expects."""
    findings = [
        Finding(
            id=entry.get("id", ""), severity=entry.get("severity", "INFO"),
            confidence=entry.get("confidence", "low"), status="active",
            disclosure="undeclared", capability=entry.get("capability", ""),
            location=entry.get("location", ""), line=int(entry.get("line", 1)),
            detects=entry.get("detects", ""), evidence="",
            impact="", legitimate_use="", what_to_check="",
        )
        for entry in document.get("findings", [])
    ]
    # `compare` reads only the capability KEYS from the old profile, so the
    # location lists are not stored and an empty list is the honest value.
    profile = {"capabilities": {name: [] for name in document.get("capabilities", [])}}
    return StoredUnit(document), findings, profile
