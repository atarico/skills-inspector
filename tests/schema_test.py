"""Proves a live `scanner --json` report matches `schemas/report-v1.schema.json`.

No `jsonschema` dependency, ever — see tests/deps_test.py. This file is not a
general JSON Schema implementation; it walks exactly the subset of the draft
2020-12 vocabulary `schemas/report-v1.schema.json` actually uses (`type`,
`required`, `properties`, `additionalProperties`, `propertyNames`, `items`,
`enum`, `const`, `oneOf`, `$ref` into `$defs`, `minimum`) and proves THIS
repo's output matches THIS repo's published schema — nothing more general is
needed or attempted.

Three reports are validated, not one, because a schema that only sees a clean
self-scan never exercises its own enums or its `chain` shape: the self-scan
of `.`, a `fixtures/malicious/*` unit whose findings carry a non-empty
`chain` (so `chain_hop`'s two shapes both get walked), and a
`fixtures/benign/*` unit.

    python -m tests.schema_test
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PROJECT / "schemas" / "report-v1.schema.json"

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

REF_PREFIX = "#/$defs/"


def _type_ok(json_type: str, value: object) -> bool:
    if json_type == "object":
        return isinstance(value, dict)
    if json_type == "array":
        return isinstance(value, list)
    if json_type == "string":
        return isinstance(value, str)
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if json_type == "boolean":
        return isinstance(value, bool)
    if json_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ValueError(f"schema_test does not understand JSON Schema type {json_type!r} — "
                      f"this validator only covers what report-v1.schema.json uses")


def validate(schema: dict, instance: object, defs: dict, path: str = "$") -> list[str]:
    """Structural check, not a general JSON Schema engine. Returns error
    strings; an empty list means `instance` satisfies `schema` at `path`."""
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith(REF_PREFIX):
            raise ValueError(f"schema_test only resolves refs shaped '{REF_PREFIX}...', got {ref!r}")
        return validate(defs[ref[len(REF_PREFIX):]], instance, defs, path)

    if "oneOf" in schema:
        branch_results = [validate(sub, instance, defs, path) for sub in schema["oneOf"]]
        matches = [r for r in branch_results if not r]
        if len(matches) != 1:
            return [f"{path}: oneOf matched {len(matches)} branch(es) (want exactly 1) "
                    f"for value {instance!r}"]
        return []

    errors: list[str] = []

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")

    if "type" in schema:
        if not _type_ok(schema["type"], instance):
            errors.append(f"{path}: expected type {schema['type']}, "
                          f"got {type(instance).__name__} ({instance!r})")
            return errors  # a type mismatch makes deeper structural checks meaningless

    if schema.get("type") == "object" and isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required key {key!r}")
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(instance) - set(properties))
            if unexpected:
                errors.append(f"{path}: unexpected key(s) {unexpected!r} — not in the schema")
        for key, sub_schema in properties.items():
            if key in instance:
                errors.extend(validate(sub_schema, instance[key], defs, f"{path}.{key}"))
        if "propertyNames" in schema:
            for key in instance:
                errors.extend(validate(schema["propertyNames"], key, defs,
                                       f"{path} propertyName {key!r}"))
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            for key, value in instance.items():
                if key not in properties:
                    errors.extend(validate(additional, value, defs, f"{path}.{key}"))

    if schema.get("type") == "array" and isinstance(instance, list):
        items_schema = schema.get("items")
        if items_schema is not None:
            for i, item in enumerate(instance):
                errors.extend(validate(items_schema, item, defs, f"{path}[{i}]"))

    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        errors.append(f"{path}: {instance} is below minimum {schema['minimum']}")

    return errors


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def scan_json(target: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "scanner", target, "--json"],
        capture_output=True, text=True, cwd=PROJECT, timeout=60,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"scanner exited {proc.returncode} on {target}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _check(target: str, *, require_nonempty_chain: bool = False) -> tuple[bool, str]:
    schema = load_schema()
    defs = schema["$defs"]
    try:
        report = scan_json(target)
    except Exception as exc:  # noqa: BLE001 — a scan/parse failure is this case's failure
        return False, f"could not produce a report: {exc}"

    errors = validate(schema, report, defs)
    if errors:
        return False, f"{len(errors)} violation(s), first: {errors[0]}"

    if require_nonempty_chain:
        has_chain = any(f["chain"] for f in report["findings"])
        if not has_chain:
            return False, "expected at least one finding with a non-empty chain — fixture drifted"

    return True, f"{len(report['findings'])} findings, schema_version {report['schema_version']}"


def main() -> int:
    cases = [
        ("self-scan of .", lambda: _check(".")),
        ("fixtures/malicious/conditional-script (chain-bearing)",
         lambda: _check("fixtures/malicious/conditional-script", require_nonempty_chain=True)),
        ("fixtures/benign/agent-config-manager", lambda: _check("fixtures/benign/agent-config-manager")),
    ]

    if not SCHEMA_PATH.exists():
        print(f"{RED}FAIL{RESET}  {SCHEMA_PATH.relative_to(PROJECT)} does not exist")
        return 1

    passed = 0
    for name, run in cases:
        ok, detail = run()
        if ok:
            passed += 1
            print(f"{GREEN}OK{RESET}    {name:<52} {DIM}{detail}{RESET}")
        else:
            print(f"{RED}FAIL{RESET}  {name:<52} {detail}")

    failed = len(cases) - passed
    if failed:
        print(f"\n{RED}{failed}/{len(cases)} schema checks failed{RESET}")
        return 1
    print(f"\n{GREEN}{passed}/{len(cases)} schema checks passed{RESET}  "
          f"{DIM}live output matches schemas/report-v1.schema.json{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
