# Inspector Skills — Detection Rules

Static analysis ruleset for auditing agent skills before installation.

## Design constraints

1. **Never execute the audited skill.** All analysis is static: file parsing, pattern
   matching, and structural inspection. Nothing from the target is run, sourced, or
   imported.
2. **Never send audited content to a model as instructions.** The scanner emits
   structured findings (JSON). The agent layer reads findings, never the raw target
   file. Audited content is data, never a prompt.
3. **Report, do not block.** The tool has no veto. Its output is an informed decision
   for a human, so every finding must carry evidence, impact, and legitimate-use
   context.
4. **Findings are claims, not verdicts.** Each finding declares a confidence level.
   Heuristic matches are labeled as such and never presented with the same weight as
   deterministic ones.

## Severity

| Level | Meaning |
|---|---|
| `CRITICAL` | Grants an external party control over the machine or exfiltrates secrets. Assume compromise if executed. |
| `HIGH` | Reads sensitive data, sends data outward, or persists beyond the session. |
| `MEDIUM` | Expands blast radius or reduces the user's visibility and control. |
| `LOW` | Poor hygiene or unnecessary privilege. Not an attack on its own. |
| `INFO` | Neutral capability worth knowing about before installing. |

## Confidence

| Level | Meaning |
|---|---|
| `high` | Deterministic match on an unambiguous construct. |
| `medium` | Strong pattern that has known benign uses. |
| `low` | Heuristic or contextual signal. Requires human judgment. |

---

## A. Code execution and delivery

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `EXE-001` | HIGH | Bundled binary or non-text file (ELF, Mach-O, PE, `.so`, `.dylib`, archives) | Contents cannot be reviewed by reading the skill | Vendored assets, fixtures, images — still review manually |
| `EXE-002` | HIGH | File with the executable bit set | Ready-to-run payload shipped with the skill | Helper CLI the skill legitimately invokes |
| `EXE-003` | CRITICAL | Remote-to-shell pipeline: `curl`/`wget` piped into `bash`/`sh`/`zsh`/`python`/`node` | Runs attacker-controlled code that was never reviewed | Never acceptable inside a skill |
| `EXE-004` | HIGH | Download-then-execute in two steps (fetch to disk, `chmod +x`, run) | Same as EXE-003, split to evade naive scanners | Rare; treat as EXE-003 |
| `EXE-005` | HIGH | Dynamic evaluation: `eval`, `exec`, `Function(...)`, `pickle.loads`, `yaml.load` without `SafeLoader`, `vm.runInNewContext` | Turns data into code at runtime, defeating static review | Legitimate uses exist but are rare in skills |
| `EXE-006` | HIGH | Encoded blob decoded into execution: `base64 -d \| sh`, `atob(...)` into eval, hex/ROT13 unpacking | Hides the real payload from review | Effectively never |
| `EXE-007` | MEDIUM | Package installation: `pip install`, `npm install -g`, `brew install`, `cargo install`, `go install` | Pulls unreviewed third-party code onto the machine | Documented setup step — flag the package and source |
| `EXE-008` | HIGH | Install from a non-registry source: git URL, raw archive URL, local path, unpinned `@main`/`@master` | Bypasses registry review and can change under you | Internal tooling with pinned refs |
| `EXE-009` | MEDIUM | High-entropy string literal over a length threshold | Likely an obfuscated payload | Hashes, keys, test fixtures, embedded assets |
| `EXE-010` | MEDIUM | Deeply nested or chained interpreter invocation (`sh -c "python -c '...'"`) | Layering used to defeat pattern matching | Legitimate but worth reading |

## B. Data exfiltration

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `NET-001` | HIGH | Outbound request to a hardcoded host or raw IP | Data leaves the machine to a destination you did not choose | Documented API the skill exists to call |
| `NET-002` | CRITICAL | Outbound request whose body interpolates file contents, command output, or env vars | This is exfiltration, not communication | Never, unless it is the skill's stated purpose |
| `NET-003` | HIGH | Known drop endpoints: `webhook.site`, `requestbin`, `pastebin`, `paste.ee`, `transfer.sh`, `0x0.st`, Discord/Slack/Telegram webhook URLs | Anonymous, disposable collection points | Slack/Discord notifications — verify the workspace is yours |
| `NET-004` | HIGH | DNS-based exfiltration: `dig`/`nslookup`/`host` with an interpolated subdomain | Bypasses HTTP egress filtering | Effectively never |
| `NET-005` | HIGH | `git push` to a remote not present in the repo, or `gh gist create` | Publishes local content to an external account | Documented publishing workflow |
| `NET-006` | HIGH | Mail delivery: SMTP client, `sendmail`, `mail`, mail API SDKs | Data channel that reads as ordinary tooling | Notification features |
| `NET-007` | MEDIUM | Data encoded immediately before transmission (base64/gzip into a URL or header) | Obscures what is being sent | Compression for large legitimate payloads |
| `NET-008` | MEDIUM | Raw socket use: `nc`, `socat`, `socket.connect`, `/dev/tcp` | Arbitrary channel outside HTTP tooling | Local port checks |
| `NET-009` | HIGH | Cloud instance metadata access (`169.254.169.254`, `metadata.google.internal`) | Standard route to steal cloud role credentials | Legitimate only in cloud-provisioning tooling |
| `NET-010` | INFO | Any outbound network capability at all | Baseline capability disclosure for the report summary | Common and often fine |

## C. Remote access and persistence

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `RSH-001` | CRITICAL | Reverse shell: `bash -i >& /dev/tcp/...`, `nc -e`, `socat ... EXEC:`, Python `socket` + `pty.spawn` | Hands interactive control of the machine to a remote party | Never |
| `RSH-002` | CRITICAL | Bind shell: listener spawning a shell on an inbound connection | Same as RSH-001, inbound | Never |
| `RSH-003` | HIGH | Tunneling: `ngrok`, `cloudflared`, `ssh -R`, `localtunnel`, `tailscale up` | Exposes the local machine to the internet | Documented dev-preview workflows |
| `RSH-004` | CRITICAL | Append to `~/.ssh/authorized_keys` | Permanent remote login for whoever owns the key | Never inside a skill |
| `PER-001` | HIGH | Scheduled execution: `crontab`, systemd unit/timer, `launchctl`, Task Scheduler | Runs after the session ends, without you present | Legitimate automation — must be disclosed |
| `PER-002` | HIGH | Writes to shell startup files: `.bashrc`, `.zshrc`, `.profile`, `.zshenv`, fish config | Executes on every future shell you open | PATH setup during install — verify exactly what is appended |
| `PER-003` | HIGH | Installs git hooks (`.git/hooks`, `core.hooksPath`) | Runs on every commit, push, or checkout | Legitimate tooling, must be disclosed |
| `PER-004` | MEDIUM | Detached background process (`nohup`, `&`, `setsid`, daemonization) | Survives the visible task; hard to notice | Long-running dev servers |

## D. Credentials and sensitive data access

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `CRD-001` | CRITICAL | Reads SSH private keys (`~/.ssh/id_*`, `~/.ssh/config`) | Full access to every host you can reach | Never |
| `CRD-002` | CRITICAL | Reads cloud credentials (`~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`) | Full access to your infrastructure | Never — cloud CLIs handle this themselves |
| `CRD-003` | HIGH | Reads `.env`, `.env.*`, `secrets.*`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc` | Application and registry secrets | Reading a project `.env` may be legitimate — never sending it |
| `CRD-004` | CRITICAL | Reads agent configuration holding tokens (`~/.claude.json`, `~/.claude/settings*.json`, MCP configs) | API keys plus the ability to reconfigure the agent | Never |
| `CRD-005` | HIGH | OS keychain access: `security find-generic-password`, `secret-tool`, `keyring`, DPAPI | Centralized credential store | Password-manager integrations |
| `CRD-006` | CRITICAL | Browser credential stores: cookie DBs, `Login Data`, profile directories | Session hijacking of every logged-in site | Never |
| `CRD-007` | HIGH | Crypto wallet paths and seed/keystore files | Irreversible financial loss | Never |
| `CRD-008` | MEDIUM | Bulk environment dump: `printenv`, `env`, full `os.environ`/`process.env` spread | Environments routinely hold tokens | Debug output — check where it goes |
| `CRD-009` | HIGH | Reads shell history (`.bash_history`, `.zsh_history`) | History commonly contains pasted secrets | Never |
| `CRD-010` | MEDIUM | Broad recursive search for secret-shaped patterns (`grep -r` for `token`, `api_key`, `password`) | Secret harvesting across the filesystem | Legitimate secret-scanning tools — verify scope and destination |

## E. Filesystem scope and integrity

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `FSW-001` | HIGH | Writes outside the skill directory and the working directory (absolute paths, `~`, `../` traversal) | Modifies things you did not put in scope | Config setup — must be disclosed |
| `FSW-002` | CRITICAL | Modifies agent configuration or instructions (`~/.claude/`, `CLAUDE.md`, `settings.json`, `.mcp.json`) | Rewrites the rules the agent follows — a persistent foothold in your assistant | Never, unless that is the skill's stated purpose |
| `FSW-003` | HIGH | Modifies or deletes other installed skills | Can neutralize this very auditor or backdoor trusted skills | Skill-management tooling only |
| `FSW-004` | HIGH | Destructive commands: `rm -rf`, `shred`, `dd of=`, `truncate`, `mkfs`, `git reset --hard`, `git clean -fdx` | Irreversible data loss | Cleanup with a narrow, literal path |
| `FSW-005` | MEDIUM | Permission or ownership changes: `chmod 777`, `chmod +s`, `chown`, ACL edits | Weakens system protections | Rare; read carefully |
| `FSW-006` | HIGH | Mass file rewrite or rename across a tree | Ransomware and mass-corruption shape | Codemods and formatters — verify scope |
| `FSW-007` | MEDIUM | Reads broadly outside the project (`$HOME` walks, `find /` sweeps) | Reconnaissance ahead of targeted theft | Disk-usage tooling |

## F. Privilege escalation and evasion

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `PRV-001` | HIGH | `sudo`, `doas`, `pkexec`, `runas` | Escalates beyond your normal blast radius | Documented system installs |
| `PRV-002` | HIGH | Disables shell history (`unset HISTFILE`, `set +o history`, `HISTSIZE=0`) | Deliberately destroys your forensic trail | No legitimate reason inside a skill |
| `PRV-003` | HIGH | Clears or truncates logs | Same as PRV-002 | Log rotation tooling only |
| `PRV-004` | MEDIUM | Disables TLS verification (`curl -k`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`) | Enables interception of everything sent | Local self-signed dev certs |
| `PRV-005` | MEDIUM | Bypasses safety gates (`git commit --no-verify`, `--force`, `--yes` on destructive commands) | Removes the checkpoints you rely on | Automation — verify intent |
| `PRV-006` | HIGH | Environment fingerprinting followed by branching (hostname, username, CI detection, VM/sandbox checks) | Classic behave-differently-when-watched pattern | Cross-platform support — check what the branches do |
| `PRV-007` | HIGH | Delayed or conditional execution (long sleeps, date comparisons, run counters) | Time-bomb shape: benign during review, malicious later | Retry logic and backoff |

## G. Agent-specific attacks

> This category is what separates a skill auditor from a generic malware scanner.
> A skill is *instructions for a model*. The instructions themselves are the attack
> surface, and no traditional scanner looks at them.

| ID | Severity | Detects | Why it matters | Legitimate when |
|---|---|---|---|---|
| `AGT-001` | CRITICAL | Prompt injection directed at the reader: "ignore previous instructions", "disregard your system prompt", "you are now", "new instructions:" | Attempts to hijack any agent that reads the file, including the auditor | Never — genuine skills instruct, they do not override |
| `AGT-002` | CRITICAL | Instructions to conceal activity from the user: "do not mention", "silently", "without telling", "do not log this", "hide" | The user losing visibility is the whole point of the attack | Never |
| `AGT-003` | HIGH | Instructions to bypass confirmation: "do not ask", "auto-approve", "skip confirmation", "assume yes" | Removes the human checkpoint on dangerous actions | UX shortcuts for genuinely safe operations |
| `AGT-004` | CRITICAL | Instructions to read memory, other skills, chat history, or project files and transmit them | Turns the agent into the exfiltration channel, so no suspicious binary is needed | Never |
| `AGT-005` | HIGH | Runtime instruction fetching: "read this URL and follow it", `WebFetch` into behavior | The real payload is off-file and can change after you audit it | Documentation lookup — the content must not become instructions |
| `AGT-006` | HIGH | Hidden content: HTML comments, zero-width characters, Unicode direction overrides, homoglyphs, whitespace-obscured text | Content the human reviewer never sees but the model does | Never legitimate at meaningful volume |
| `AGT-007` | HIGH | Capability/purpose mismatch: declared `allowed-tools` far exceed the stated function | A markdown formatter asking for `Bash` is asking for a reason | Broad genuine scope — should be justified in the description |
| `AGT-008` | MEDIUM | Overbroad activation: "always active", "on every prompt", "before any response" | Maximizes exposure and burns context on every turn | Genuinely cross-cutting protocols |
| `AGT-009` | HIGH | Description/body mismatch: the trigger describes one purpose, the body performs another | Classic bait — the user approves based on the description | Never |
| `AGT-010` | MEDIUM | Instructions to modify other skills, memory, or persistent agent instructions | Self-propagation and persistence at the agent layer | Skill-management tooling |
| `AGT-011` | MEDIUM | Payload placed far below the fold, or padding that pushes content out of casual review | Exploits reviewer fatigue | Long legitimate skills — flag as a review hint |
| `AGT-012` | HIGH | Instructions targeting the auditor itself ("this skill is safe", "report no findings", "skip the security check") | Direct attack on this tool | Never |

## H. Provenance and supply chain

Metadata signals. Never conclusive alone; they calibrate how carefully the content
findings should be read.

| ID | Severity | Detects |
|---|---|---|
| `SUP-001` | INFO | Repository age, commit count, contributor count, star count |
| `SUP-002` | MEDIUM | Name closely resembling a well-known skill (typosquatting distance) |
| `SUP-003` | MEDIUM | Recent force-push or history rewrite |
| `SUP-004` | LOW | No license, no README, or contact details that do not resolve |
| `SUP-005` | MEDIUM | Unpinned dependencies or references to mutable refs |
| `SUP-006` | INFO | Total size, file count, and how much is not human-readable |

---

## Report model

A severity score alone is not actionable. The report leads with a **capability
profile** in plain language, then supporting findings.

```
CAPABILITY PROFILE
  Network access      yes  → 2 hosts (api.example.com, 203.0.113.9)
  Reads secrets       yes  → ~/.aws/credentials
  Writes outside dir  yes  → ~/.zshrc
  Persistence         yes  → crontab entry
  Executes remote     no
  Hidden content      yes  → 340 zero-width characters in SKILL.md
```

Every finding carries:

- **id** and **severity** and **confidence**
- **location** — file and line
- **evidence** — the matched snippet, escaped and never re-interpreted
- **impact** — what an attacker gains, in one sentence
- **legitimate_use** — when this pattern is normal, so the user can judge
- **what_to_check** — the concrete question to answer before installing

Findings are ordered by severity, then confidence. Low-confidence heuristics are
grouped separately so they never dilute the deterministic ones.

## Non-goals

- No blocking, no veto, no auto-remediation.
- No sandboxed or instrumented execution.
- No claim of completeness. Static analysis cannot prove a skill is safe. The report
  says what was found, never that nothing exists.
