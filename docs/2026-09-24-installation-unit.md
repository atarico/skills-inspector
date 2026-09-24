# Proposal: what the installation unit is

Status: accepted 2026-09-24, implemented. Date: 2026-09-24.

Implementation notes, against the proposal above:

- (a) implemented as proposed: `unit.py::_narrow_marketplace` reads
  `plugins[].source` and narrows to the one declared source the target sits
  inside. The target being the marketplace root itself keeps today's
  single-unit behavior, per-plugin separate units were not built (out of
  scope for this change; see the open question below).
- Fail-wide covers every case listed: malformed/unreadable manifest, a
  `plugins` field that is not a list, an absolute or `..`-escaping `source`, a
  URL or git/github object form, and a symlinked `source` that resolves
  outside the marketplace directory. Any one untrustworthy entry taints the
  whole manifest, even for a target that would have matched a different valid
  entry — the simplest reading of "never narrow" that a fail-wide guarantee
  can make.
- (b) implemented as proposed: an excluded sibling is recorded under NOT
  ANALYZED with the reason "outside every declared plugin source", one entry
  per excluded directory or file (never per file inside it).
- `target_subtree` implemented per the maintainer's decision below: shown in
  BOTH the JSON and the text report, on every widened scan (not only a
  narrowed marketplace one).
- Per-plugin separate units for a marketplace-root scan were NOT built: the
  existing `Unit`/report model represents exactly one unit per scan, and
  splitting a marketplace root into N separate reports is a bigger, separate
  change than this proposal's fail-wide + narrowing scope. RULES.md section
  0.1 documents this truthfully instead of leaving the old, inaccurate claim
  in place.

**Post-implementation fix.** Parent verification caught a CRITICAL evasion in
the first version of narrowing: `.claude-plugin` was treated as a sibling of
the chosen plugin source and excluded like any other, but Claude Code lets a
marketplace plugin ENTRY declare that plugin's hooks/mcpServers/commands
inline (`"strict": false`) — so `marketplace.json` is itself control plane,
and excluding it reintroduced the exact false clean this section exists to
prevent. Fixed by never excluding `.claude-plugin` and instead reading it back
into the narrowed unit as extra files (a `../`-prefixed relpath, same shape as
every other outside-root NOT ANALYZED entry). The manifest is now always
inside the unit, narrowed or not — RULES.md section 0.1 updated to say so.

Also surfaced, and deliberately NOT fixed here: the structural HOK-001/
HOK-003 checks read only a JSON file's TOP-LEVEL `hooks`/`mcpServers` keys, so
grants a marketplace entry declares inline (nested one level down, inside
`plugins[i]`) are invisible to them — only the line-based rules (curl-pipe-
shell, outbound host) still catch the raw text regardless of nesting. Pinned
as a known-miss fixture, `fixtures/known-miss/marketplace-inline-hook-structural`.

## The question

Scanning `coji/natural-japanese/skills/natural-japanese` widens to the whole
repository (102 files) and reports findings from `corpus/`, a folder of research
experiments. skills.sh audits per skill, so the two tools' numbers cannot be
compared. The widening exists on purpose: a `SKILL.md` audited without its plugin
manifest produces a false clean (RULES.md §0).

Two design questions:

- (a) What is the unit when a repository contains several independent skills or
  plugins?
- (b) Should sibling directories that no `SKILL.md` or manifest references be
  inside the audited unit?

## What the code does today

`scanner/unit.py::resolve` (lines 116-221) climbs at most 8 levels and stops at
the first of `.claude-plugin/marketplace.json`, `.claude-plugin/plugin.json`, or
`opencode.json` (`UNIT_MARKERS`, lines 69-74). A plugin or marketplace marker
always beats a `SKILL.md` found lower down. `tests/unit_test.py::_resolve_cases`
(lines 374-587) pins one case per `scope_search` value.

**RULES.md §0 claims more than the code does.** Its marker table says a
`marketplace.json` resolves to "every plugin it lists, audited separately".
`unit.py` never reads the marketplace's `plugins` list or any `source` field.
The whole directory holding the marketplace becomes one unit.

## What natural-japanese actually ships

Measured on `9a78a42` with scanner output only:

- There is one `SKILL.md`, at `skills/natural-japanese/SKILL.md`.
- `.claude-plugin/marketplace.json` lists one plugin with `"source": "./"`.
  So the repository root is what installs, `corpus/` included.
- Scanning the skill directory and scanning the repository root give the same
  unit: 102 files and 44 findings, with a headline of one finding (`PER-003`).
- `skills/natural-japanese/` contributes **0** findings. `corpus/` contributes
  37, and `.githooks/`, `dev/`, `README.md`, and `AGENTS.md` contribute the rest.
- The one headline finding is a `PER-003` in the root `README.md`. A second
  `PER-003`, in `.githooks/pre-commit`, is reported but is not in the headline.
  A scan of the skill directory alone would have missed both.

So for this repository the wide unit is not a scanner artifact. It is what the
manifest says gets installed. The disagreement with skills.sh is real: skills.sh
audits a subset of what installs.

## Proposal

### (a) The unit is the declared install boundary, per plugin

1. Implement the marketplace row RULES.md already promises. When the climb stops
   at a `marketplace.json`, read its `plugins[].source`. If the user's target
   sits inside exactly one plugin's source directory, that directory is the
   unit. If the target is the marketplace root, audit each listed plugin as a
   separate unit, which is what §0 says.
2. For `plugin.json`, `opencode.json`, and a bare `SKILL.md`, keep the current
   behavior.
3. When the manifest cannot be trusted, fail wide and never narrow. That covers
   a missing, malformed, or unreadable `marketplace.json`, a `source` that
   leaves the marketplace directory (`..`, an absolute path, or a symlink that
   escapes it), and a `source` that is a URL or a git reference. In each case
   the unit is the marketplace directory, as it is today, and the report says
   why. A manifest must never be able to shrink its own audit.

### (b) Undeclared siblings stay in when a declared source covers them

- A sibling inside a plugin's declared `source` stays in the unit, even if no
  `SKILL.md` names it. Following only the files a skill references would
  exclude exactly the files that do not announce themselves: a git hook, a
  build script, a `conftest.py` the toolchain runs on its own. That is the false
  clean the widening exists to prevent.
- A sibling outside every declared `source` is out of that plugin's unit. It
  is listed under NOT ANALYZED with the reason "outside every declared plugin
  source". It is never dropped silently.

### Making the numbers comparable without narrowing the audit

Add attribution, not a narrower scope. When the unit is wider than the target
the user named, the report adds a `target_subtree` block in the JSON and one
line in the text report. The block holds the finding count, the headline count,
and the undeclared CRITICAL count for findings inside the named path, and the
same three numbers for the rest of the unit. The headline itself stays computed
over the whole unit.

A skills.sh comparison then reads the `target_subtree` numbers, and the audit
still covers everything that installs.

## What does not change

- The headline, severity, disclosure, and position rules.
- The false-clean protection: a skill inside a plugin still widens.
- A unit marker at the target still stops the climb (`stopped_at_unit_marker`).

## Tests required (both directions)

- A marketplace listing two plugins, with the target inside plugin A: the unit
  is A, and B's files are absent from the unit and listed under NOT ANALYZED.
- The same marketplace with a payload in A's hook: the payload is still found.
  This pins that narrowing to A never loses A's own control plane.
- `source: "../elsewhere"`, `source: "/abs"`, a symlinked source that escapes,
  and a URL source: each falls back to the marketplace directory and says why.
- A malformed `marketplace.json`: falls back wide and says why.
- `source: "./"`, the natural-japanese shape: the unit is the whole
  directory, unchanged from today.
- `target_subtree` counts add up to the unit totals.

## Decided

The maintainer chose text on every widened scan, in both the human report and
the JSON — implemented as `TARGET` in `scanner/report.py::to_text` and
`target_subtree` in `to_json`, both built from `scanner/report.py::_target_subtree`.
