# ECC / AgentShield Review — Findings & Improvement Plan

**Date:** 2026-08-11
**Sources reviewed (static analysis, nothing installed or executed):**
- `github.com/affaan-m/ECC` (shallow clone, 285 skills) — reviewed in a session-temp directory, now discardable
- `github.com/affaan-m/agentshield` (upstream scanner source, 102 rules) — AgentShield's code is NOT in the ECC repo; ECC only integrates it via `commands/security-scan.md` and `skills/security-scan/SKILL.md`
- Baseline: our scanner at `~/.claude/skills/inspect-skill/` (source: this repo)

**Safety note:** both repos were treated as untrusted content. No script from them was executed; no instruction inside them was followed.

---

## Part A — Skill catalog patterns worth porting (ECC's 285 skills)

### Context: mine the mechanisms, not the hygiene

ECC's own quality is uneven: only 7 of 285 skills use progressive disclosure (`references/` subdirs), their CI validation (`scripts/ci/validate-skills.js`) enforces almost nothing, several skills run 700–950 lines, and one live skill is a deprecated stub. The value is in specific mechanisms, not in adopting the system.

Useful structural conventions observed:
- **Four-suffix family per stack**: `<stack>-patterns` / `<stack>-tdd` / `<stack>-security` / `<stack>-verification` — predictable lifecycle slots per technology.
- **`## When NOT to Use` + negative-routing tables** ("Instead of X → use Y") in nearly every skill body; best example in `skills/council/SKILL.md`.
- **CI count enforcement**: `scripts/ci/catalog.js` fails CI if the advertised skill count drifts from the directory count.
- **Unicode safety CI**: `scripts/ci/check-unicode-safety.js` strips emoji/invisible/homoglyph codepoints from agent-facing prose; `tests/ci/agent-instruction-safety.test.js` asserts that named guardrail headings still exist in high-risk skills (regression test against safety-section deletion).

### Top mechanisms to steal (ranked by fit with our stack)

1. **`gateguard` — pre-write fact-forcing gate.** DENY → FORCE → ALLOW: blocks the first Edit/Write per file and every destructive Bash until the agent states four concrete facts: (1) every file importing this file, (2) affected public symbols, (3) for data files: field names/structure/format with redacted values, (4) **the user's current instruction quoted verbatim** (anti-drift). Context-hygiene detail: only the first ~3 denials emit the full block; later ones condense to one line. Our stack reviews post-write only; this is the missing pre-write lens.

2. **`delivery-gate` + `growth-log` — enforced learning capture.** A Stop hook blocks "done" when the task was complex (≥3 Edit/Write) and no learning file was touched today (mtime check). Tiered response: rationalization regexes ("skip tests for now") only WARN — only machine-verifiable facts block. `growth-log` supplies the content discipline: failures > achievements; search existing entries for the same root cause before writing (merge, don't duplicate); every entry must contain a literal "Next time I see [signal], I will [action]" sentence; 4–8 sentences as a quality proxy. **Direct upgrade path for Engram: nothing currently forces a memory write before closing.**

3. **`orch-pipeline` — ceremony scales to blast radius.** Step-0 size classifier scores three signals (files touched / new dependency-contract / design ambiguity), takes the highest tier any signal reaches, and emits a phase mask (trivial → skip planning phases; large → full pipeline). Security-trigger or public-contract changes are at least "standard" regardless of file count. Exactly two human gates (after Plan, before Commit). **Direct fix for SDD's uniform-ceremony problem.**

4. **`santa-method` — review quality metrics.** Adds to blind dual review: (a) failure-mode → mitigation table (rubber-stamping, fix regression → fresh reviewers per round, agreement bias → third reviewer); (b) longitudinal metrics: first-pass rate (>70%), mean iterations to convergence (<1.5), **reviewer agreement rate** (low agreement = loose rubric), escape rate (target 0); (c) stratified batch sampling for 100+ items (review 10–15%, classify failure types, batch-fix by type). Deterministic verification (build/lint/test) runs FIRST, semantic review second. **Judgment-day currently has no quality metrics over time.**

5. **`skill-comply` — does the agent actually follow the skill?** Auto-generates a behavioral spec from the skill, generates scenarios at three prompt-strictness levels (supportive → neutral → competing), runs the agent, classifies tool-call traces against spec steps. Key concept: **prompt independence** — a skill that only fires when the prompt begs for it is worthless; compliance at the "competing prompt" level is the real signal. Also recommends promoting low-compliance steps to hooks (skill → hook escalation path).

6. **`rules-distill` — promote cross-cutting principles from skills into rules.** Admission criteria: appears in 2+ skills; phrased as do/don't; stated violation risk; not already in rules even if worded differently. Six-way verdict (Append / Revise / New Section / New File / Already Covered / Too Specific) with evidence and confidence. Maintenance loop from skills → durable rules that our stack lacks.

7. **`loop-design-check` — autonomous-loop failure modes.** Five-row table, any single hit = the loop will misfire. Highlights: "gates only on 'all tests pass' → agent deletes the tests" (antibody: done-criterion PLUS boundary — "no test file deleted or weakened AND coverage not lowered"); "is the judge the defendant itself?"; "counts on the agent asking mid-run — it won't; front-load clarifications". Red line: the more self-improving a loop is, the stricter the human review, and the gate sits BEFORE the action. Applicable to sdd-apply autonomy and skill-improver.

8. **`production-audit` — score caps instead of averages.** Hard caps beat weighted averaging: cap at 69 if auth missing / webhooks non-idempotent / no rollback; cap at 84 if CI not green. Output contract forces `Evidence checked` AND `Evidence missing` ("what would change confidence if provided") — an epistemic-honesty field our 4R lenses could adopt.

9. **`skill-stocktake` — fleet-level periodic skill audit.** Quick Scan (changed-since-last-run) vs Full; ~20 skills per subagent chunk; resumable state (`results.json` with `batch_progress`). Five-verdict vocabulary (Keep / Improve / Update / Retire / Merge into X) with per-verdict good/bad reason examples; blind evaluation regardless of origin. Our skill-improver is per-skill on demand; this is fleet-level and incremental.

10. **`config-gc` — garbage collection for the harness config.** Eight scan channels, each with its own staleness signals. Principles: append-only configs leak; soft-delete first (`.disabled` → trash dir → real deletion, always undoable); forced per-item human confirmation (no "yes to all"); append-only `gc_log.md`; ~20 candidates per run.

Honorable mentions: `council` (anti-anchoring: form own position first, fresh subagents get only the question, never the transcript; always surface strongest dissent), `parallel-execution-optimizer` (lane matrix — only parallelize lanes whose write surfaces don't collide), `intent-driven-development` (business rules/SLAs cannot be read from a repository — record as flagged assumptions, never discovered facts), `ai-regression-testing` (documented 4-round failure of self-review; sandbox/production path-mismatch test pattern).

### Mechanisms our stack lacks entirely

- **Skill execution telemetry + versioning + rollback** (`scripts/lib/skill-evolution/`): per-run JSONL (outcome, user feedback, tokens, duration) → per-skill 7d vs 30d success-rate trend with decline warnings. Nothing tells us which skill is degrading.
- **Provenance schema** for imported/learned skills (`schemas/provenance.schema.json`: source, created_at, confidence, author — required).
- **Dispatcher hook architecture** with stable per-hook IDs, kill switches (env vars), and a standard/strict profile system (same hook advisory vs blocking).
- **"Instincts" layer** (`continuous-learning-v2`): PreToolUse/PostToolUse observation capture → background small-model distillation into atomic, confidence-weighted, project-scoped instincts → promotion to skills/global when repeated across projects. A middle tier between Engram observations and skills.
- **`skill-scout` — search before create**: local → marketplace → GitHub code search → web, with security vetting of external matches; verdict Use existing / Fork / Create fresh. Our skill-creator starts at "create".
- **Structured, versioned report schemas** as skill outputs (machine-readable, diffable, resumable), vs our prose reports.
- **Context-budget accounting** (`context-budget`, `token-budget-advisor`): nothing measures our stack's resting token overhead (skills + Engram + MCP servers).

---

## Part B — AgentShield vs inspect-skill: gap analysis

### AgentShield inventory (summary)

102 rules / 5 scored categories. Surfaces: CLAUDE.md, settings.json, mcp.json, agents/, skills/, commands/, hooks/, rules/, package-manager configs, VS Code/Zed tasks, persistence paths. Categories: Secrets (~36 value-patterns), Permissions (12), Hooks (~38), MCP (32 incl. tool-poisoning + CVE DB), Agents/prompts (~50), Package manager (3), Supply chain (blocklist + Levenshtein typosquat), proximity-based taint, dynamic modes (sandbox hook execution, 60+ injection payload corpus, attacker/defender/auditor LLM pipeline). Reporting: 0–100 score with A–F grade, confidence multipliers by file class, SARIF/GitHub Action output, policy packs with time-boxed exceptions, baseline drift, auto-fix.

### Gaps in inspect-skill (ranked by security value)

1. **MCP server bodies are never analyzed — only names listed.** `structural.py` emits one HOK-003 per config naming the servers; `command`, `args`, `env`, `url`, `autoApprove` are never examined. AgentShield has 32 MCP rules here. Biggest hole; the JSON is already parsed. Proposed new rules (one finding per server):
   - `HOK-008` env override of `PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|NODE_OPTIONS|PYTHONPATH|HOME` (CRITICAL)
   - `HOK-009` hardcoded secret in `env` where value is not `${VAR}` (CRITICAL)
   - `HOK-010` `autoApprove`/`auto_confirm` truthy (HIGH — defeats human-in-the-loop)
   - `HOK-011` unpinned `npx -y` / `git+https` / `#main` (MED–HIGH)
   - `HOK-012` non-local `url` transport (HIGH)
   - `HOK-013` shell wrapper (`command` in sh/bash/zsh/cmd with `-c`) (HIGH)
   - `HOK-014` root/`~`/sensitive-file arg (`.env`, `.pem`, `credentials.json`, `id_rsa`, `.ssh/`, `.aws/`) (HIGH)
   - `HOK-015` exfil host in args/env (`ngrok`, `webhook.site`, `requestbin`, `pipedream`, `interactsh`, `/exfil`, `/collect?data=`) (HIGH)
   - `HOK-016` `--no-sandbox` / `--disable-web-security` / `--insecure` class flags (CRITICAL)
   - Plus: add `enableAllProjectMcpServers"\s*:\s*true` to `_PERMISSION_RED_FLAGS` (one-line fix, CRITICAL upstream); apply AGT-001/AGT-004-style prompt-injection patterns to `mcpServers[*].description` and server names (description poisoning; newline in server name).

2. **Hook command strings get no hook-specific analysis.** Proposed:
   - `HOK-017` command injection via interpolation `\$\{(file|file_path|command|content|input|args?|tool_input|prompt)\}` (CRITICAL — attacker-influenceable tool input becomes shell)
   - `HOK-018` `source`/`.` of env-derived path (HIGH)
   - `HOK-019` silent error suppression `2>/dev/null | \|\| true | \|\| :` (MEDIUM)
   - `HOK-020` writes to world-readable `/tmp` (HIGH)
   - Event-conditioned severity: `SessionStart` + pipe-to-shell is worse than the same line in `Stop` (event names already available in `HOOK_EVENTS`).

3. **Permission entries counted, not classified.** Add per-entry classification of `permissions.allow`: `Bash(*)|Write(*)|Edit(*)` and `Bash(sudo|eval|exec|curl|wget|ssh|scp|nc|docker …)` (CRITICAL); sensitive paths (`~/.ssh`, `~/.aws`, `/etc/`, `.env`); wildcard roots; **all-mutable-tools combination** (Bash AND Write AND Edit → HIGH; combination rules are what a per-line regex can't express); missing `deny` with non-empty `allow`. **Highest single-value item: model endpoint override** — `(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|AZURE_OPENAI_ENDPOINT|MODEL_BASE_URL|ANTHROPIC_AUTH_TOKEN)\s*[=:]\s*["']?https?://(?!localhost|127\.)` — CRITICAL (CVE-2026-21852; redirects every API call and leaks the key). Belongs in both `rules.py` (line pass) and `structural.py` `_claude_settings` (env block).

4. **No hardcoded-secret-VALUE detection.** CRD-* detects reading secrets, not shipping them. Add a `SEC-*` family: `sk-ant-`, `sk-proj-`, `ghp_`, `github_pat_`, `AKIA[0-9A-Z]{16}`, `AIza[\w-]{35}`, `xox[bprs]-`, `npm_…`, JWT `eyJ….eyJ…`, `https?://user:pass@`, `-----BEGIN .* PRIVATE KEY-----`, `password\s*[=:]\s*["'][^"']{4,}`. With suppressions (skip `${VAR}` / `process.env.X` / placeholders) and redacted evidence (prefix + length only). **Exempt SEC-* from `_apply_sample_floor`** — a live key in `examples/` is still a live key.

5. **No known-bad / reputation layer (offline).** Add `scanner/ioc.json` (no network — preserves the stdlib-only, never-resolve contract): (a) `SUP-001` sha256 binaries already detected via `BINARY_MAGIC` against known-malicious hashes (turns "unreviewable" EXE-001 into decidable); (b) `SUP-002` dependency blocklist + Levenshtein typosquat (≤3 edits / >80% similarity); (c) `SUP-004` IOC filenames/markers. Reusable data shapes exist in ECC's own `scripts/ci/scan-supply-chain-iocs.js` (package@version blocklist L14–214, IOC strings L215–319, sha256 hashes L320–338, persistence/payload filenames L339–389).

6. **`declared_tools` parsed but never evaluated.** Three rules from data we already have:
   - `AGT-017` escalation chain: discovery (Glob/Grep/LS) + Read + Write/Edit + Bash all granted → HIGH
   - `AGT-018` WebFetch/WebSearch + Write/Edit/Bash (lethal trifecta) → HIGH
   - `AGT-019` **declared-vs-observed mismatch**: unit declares `allowed-tools: Read` but files carry NETWORK/REMOTE_EXEC findings. AgentShield cannot do this (no capability profile). Cheapest high-signal rule on the list; extends our disclosure thesis.

7. **Package-manager posture.** Add `.npmrc`/`.pnpmrc`/`.yarnrc` parsers to `structural.py` dispatch: plaintext `_auth`/`_authToken`/`_password` (CRITICAL — leaked secret + publish capability); `ignore-scripts=false` / yarn `enableScripts: true` / pnpm `dangerouslyAllowAllBuilds`; missing `minimum-release-age` cooldown.

8. **New instruction-surface regexes** (each a distinct attack shape not covered by existing 68 rules):
   | Rule | Shape |
   |---|---|
   | Downstream-agent injection ("russian doll") | `when\s+(the\s+)?(next|downstream|another)\s+agent\s+(reads|receives|processes)` |
   | Output manipulation | `always\s+(report|say|respond)\s+(ok|fine|clean|secure|success)`; `remove\s+(the\s+)?warnings?\s+from\s+(the\s+)?output` |
   | Jailbreak framing | `(hypothetical|fictional|roleplay|for\s+educational\s+purposes|debug\s+mode)[^\n]{0,60}(no\s+)?(rules|restrictions|limits)` |
   | Allowlist tampering | `(modify|edit|update|add\s+to)[^\n]{0,40}(allowlist|whitelist|allowed[_\s-]?tools|permissions\.allow)` |
   | Identity impersonation | `(commit|sign|push)[^\n]{0,40}as\s+(another|different|someone)`; `git\s+config[^\n]{0,30}user\.(email|name)` |
   | Crypto mining | `\b(xmrig|cpuminer|cgminer|minerd|ethminer)\b|stratum\+tcp://` |
   | Oversized instruction file | effective non-code char count > 5000 in an entry-point `.md` (BND-007; BND-003 only fires on conditional files) |

9. **Hook manifest → implementation resolution.** A hook script in `examples/` wired up from `settings.json` currently gets floored to `confidence: low` by `_apply_sample_floor` — the exact evasion that function warns about, via a path it doesn't cover. Fix: in `_claude_settings`, extract each hook `command` script path and feed it into `graph.invoked`.

10. **Hidden-char + markdown-exfil widening.** Add soft hyphen U+00AD and Private Use Area U+E000–F8FF to `evidence.py` invisible sets (PUA = known tag-smuggling channel). Widen NET-011 to also fire on static image URLs with `?…(data|token|key|secret|session)=` (currently requires interpolation).

11. **Prompt-defense posture (narrow adoption only).** When a unit has AGT-005 (runtime instruction fetching) or NET-* reads of external content, report the *absence* of a guardrail sentence as INFO/LOW. Full OWASP-style posture checks are out of scope for a pre-install auditor.

12. **Regression corpus.** Build a fixtures corpus with expected-findings per fixture and per-category precision before growing the rule count further — comments in `rules.py`/`structural.py` document already-paid-for false positives.

13. **CI output — adopt carefully.** Optional `--sarif` and `--exit-code` flags for CI. Keep exit-0 default: "report, never block" is a design choice.

### Explicitly rejected

- **A–F grade / 0–100 score.** Contradicts our contract that a clean scan is never a safety claim ("Grade A" reads as "safe"). At most adopt the per-category severity breakdown, which `profile.severity_counts` already provides.

### What inspect-skill does BETTER — do not regress

1. **The auditor never reads the target** (no `Read` in tool set; model consumes scanner JSON only). AgentShield's `--opus` mode feeds target content to three LLMs — the persuasion surface we deliberately closed.
2. **Mandatory evidence/label/path sanitization** (`evidence.py`) — strips invisibles, C0/C1, harness delimiters from evidence AND labels AND paths (MCP names and hook events are attacker-controlled). No upstream equivalent.
3. **Disclosure axis** (declared / euphemistic / undeclared) — genuinely novel; AgentShield has no "did the extension admit it" concept.
4. **Four independent axes, never multiplied; dormant CRITICAL stays CRITICAL.** AgentShield's confidence multipliers make low-confidence findings quietly vanish from the score.
5. **Reachability graph** (BND-001/002/003/005): dangling refs, conditional loads, reachable-but-unread files. AgentShield's discovery is a flat path list.
6. **Anti-evasion budget design** (per-unit line budget vs per-file caps; sample-floor override for entry-point-invoked files).
7. **Higher-precision taint** (named channels, filesystem hop, taint cleared on reassignment, supersession into a single CHN-001 — no triple counting; "a false chain accuses").
8. **Semantic pass epistemics** (judges describe, never judge; closed capability vocabulary; ground truth never sent to judges; SEM-001 inversion catches judge steering). Better than attacker/defender/auditor asking models for verdicts on persuasive text.
9. **TOFU baseline** stored outside `~/.claude` (writing there is itself a finding we report), atomic writes, no auto-approve on first check.
10. **Capability-level diff** — "new CRITICAL capability while the description is unchanged" = the shape of a supply-chain update. Keyed on `(rule_id, capability)` so refactors don't produce noise.
11. **Honest incompleteness as output**: DEFERRED table, `coverage_limits()`, `not_analyzed`, BND-006 (crashed parser = reported denial-of-audit, not a silent empty result). AgentShield never reports which of its 102 rules didn't evaluate.
12. **Multi-harness today** (Claude Code / Codex / opencode parsers shipped); AgentShield's adapter registry is a roadmap item.
13. **AGT-015** (writes instructions for a different assistant: `.cursor/rules`, `copilot-instructions.md`, `.windsurfrules`) — cross-tool evasion with no upstream equivalent.

---

## Implementation plan

**Sprint 1 — highest value / lowest cost (all in `structural.py`):**
MCP server-body rules (HOK-008…016) + `enableAllProjectMcpServers` red flag + hook interpolation injection (HOK-017…020) + permission-entry classification + `ANTHROPIC_BASE_URL` endpoint-override rule.

**Sprint 2:**
`SEC-*` hardcoded-secret family (with env-ref suppression + sample-floor exemption) + hook-manifest → `graph.invoked` resolution.

**Sprint 3:**
Offline `ioc.json` (hashes + package blocklist + typosquat) + `.npmrc`-family parsers + declared-vs-observed tool rules (AGT-017/018/019) + the new instruction-surface regexes + invisible-char/markdown-exfil widening.

**Ongoing:**
Fixtures corpus with expected findings per fixture, before the rule count grows further.

**Separate track (gentle-ai stack, not this repo):** gateguard-style pre-write gate; delivery-gate + growth-log for Engram enforcement; orch-pipeline size classifier for SDD; santa-method metrics for judgment-day; rules-distill maintenance loop; config-gc.
