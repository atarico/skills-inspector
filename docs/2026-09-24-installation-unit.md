# Proposal: what the installation unit is

Status: proposed, not implemented. Date: 2026-09-24.

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

## Open decision for the maintainer

Should `target_subtree` appear in the text report on every widened scan, or only
in the JSON? Text on every scan is more honest to a human reader, and the JSON
alone is enough for tooling.
