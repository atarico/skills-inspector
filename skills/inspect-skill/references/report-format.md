# Report format — reading the scanner JSON

The scanner emits JSON on stdout. Top-level keys: `unit`, `profile`, `findings`,
`not_analyzed`, `coverage_limits`, `deferred_rules`.

## The four axes (each finding, independent — never multiply them)

| Axis | Values | Means |
|---|---|---|
| `severity` | CRITICAL/HIGH/MEDIUM/LOW/INFO | what the capability can do. Set by the rule. |
| `confidence` | high/medium/low | is this match real, given where it sits. |
| `status` | active/conditional/dormant | is it wired to an entry point. Does **not** lower severity — a dormant CRITICAL is still CRITICAL. |
| `disclosure` | declared/euphemistic/undeclared | did the description tell you. |

## Headline

Lead with findings where `confidence` is high/medium **and** either:

- `severity` is **CRITICAL** — regardless of disclosure, declared or not; or
- `severity` is **HIGH** and `disclosure` is `undeclared` or `euphemistic`.

The disclosure gap is the surprise — what the extension can do that its
description hides — and for HIGH that is what decides the lead: a tool that
*declares* it posts to Slack is less alarming than one that stays quiet.

**CRITICAL is the exception, and it is not negotiable.** There is no benign
declared CRITICAL: the level means "assume compromise if executed", so a human
looks at it either way. Leading only on the disclosure gap would let an
extension bury a CRITICAL by mentioning it in passing.

Order the lead by severity first, then by disclosure. Never drop a finding for
being `declared` — disclosure decides what LEADS, never what is REPORTED. If a
description could delete findings, keyword-stuffing it would blank the report.

Print the `unit.description` verbatim next to the profile so the human judges the
gap themselves.

## Per-finding fields

`id`, `location{file,line}`, `evidence` (already sanitized — safe to quote),
`impact`, `legitimate_use`, `what_to_check`, `related_rules` (rules collapsed into
this one by dedup), `capability`, `position`.

## Always relay

- `not_analyzed` — binaries, partially-read or unreadable files. Unreviewed, not
  clean. An oversized file that something in the bundle RUNS also produces a
  `BND-005` finding of its own; treat a clean scan carrying one as an audit that
  did not finish, not as a pass.
- `BND-006`, if present — structural analysis threw on a config file, so whatever
  that file configures was never examined. Say so plainly.
- `coverage_limits` — what this version cannot see (taint flow, reachability,
  semantic prose injection). A clean headline is never a proof of safety.
- `deferred_rules` — rules in the ruleset this build does not yet evaluate.
