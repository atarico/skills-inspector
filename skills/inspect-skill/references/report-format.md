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

## Headline = the disclosure gap

Lead the report with findings where `disclosure` is `undeclared` or `euphemistic`
**and** `severity` is CRITICAL/HIGH **and** `confidence` is high/medium. That is
the surprise: what the extension can do that its description hides. This matters
more than raw severity — a tool that *declares* it reads your credentials is less
alarming than one that stays quiet.

Print the `unit.description` verbatim next to the profile so the human judges the
gap themselves.

## Per-finding fields

`id`, `location{file,line}`, `evidence` (already sanitized — safe to quote),
`impact`, `legitimate_use`, `what_to_check`, `related_rules` (rules collapsed into
this one by dedup), `capability`, `position`.

## Always relay

- `not_analyzed` — binaries, oversized or unreadable files. Unreviewed, not clean.
- `coverage_limits` — what this version cannot see (taint flow, reachability,
  semantic prose injection). A clean headline is never a proof of safety.
- `deferred_rules` — rules in the ruleset this build does not yet evaluate.
