"""Rule catalogue — RULES.md section 6.

Only the deterministic, line-matchable subset is here. Structural rules that need
config parsing live in `structural.py`. Rules requiring taint (section 4),
reachability (section 5) or the semantic pass (section 8) are listed in
DEFERRED and reported as coverage gaps, never silently dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Capability buckets drive the profile and the disclosure comparison.
NETWORK = "network"
SECRETS = "secrets"
WRITE_OUTSIDE = "write_outside"
PERSISTENCE = "persistence"
CONTROL_PLANE = "control_plane"
AUTO_EXEC = "auto_exec"
REMOTE_EXEC = "remote_exec"
HIDDEN = "hidden"
PRIVILEGE = "privilege"
DESTRUCTIVE = "destructive"
INSTRUCTION = "instruction"
RECON = "recon"

ALL_PLATFORMS = ("claude", "codex", "opencode")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    confidence: str
    capability: str
    detects: str
    impact: str
    legitimate: str
    check: str
    pattern: re.Pattern
    specificity: int = 50  # section 7 precedence; higher wins
    platforms: tuple[str, ...] = ALL_PLATFORMS
    markdown_only: bool = False
    code_only: bool = False
    extra: dict = field(default_factory=dict)


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


RULES: list[Rule] = [
    # ------------------------------------------------------------------ A. execution
    Rule("EXE-003", "CRITICAL", "high", REMOTE_EXEC,
         "Remote-to-shell pipeline",
         "Runs attacker-controlled code that was never reviewed.",
         "Never acceptable inside an agent extension.",
         "What is at that URL, and who controls it?",
         _r(r"\b(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k|d)?sh\b"
            r"|\b(curl|wget)\b[^\n|]{0,200}\|\s*(python3?|node|perl|ruby)\b"),
         specificity=95),

    Rule("EXE-004", "HIGH", "high", REMOTE_EXEC,
         "Download-then-execute in two steps",
         "Same as EXE-003, split to evade naive scanners.",
         "Rare; treat as EXE-003.",
         "Is the downloaded artifact pinned by hash?",
         _r(r"chmod\s+\+x[^\n]{0,120}(&&|;|\n)[^\n]{0,60}\.\/"
            r"|(curl|wget)[^\n]{0,200}-[oO]\s+\S+[^\n]{0,80}(&&|;)\s*(chmod|\.\/|bash|sh)\b"),
         specificity=90),

    Rule("EXE-006", "HIGH", "high", REMOTE_EXEC,
         "Encoded blob decoded into execution",
         "Hides the real payload from review.",
         "Effectively never.",
         "Decode it by hand before installing anything.",
         _r(r"base64\s+(-{1,2}d|--decode)[^\n]{0,80}\|\s*(ba|z)?sh\b"
            r"|\batob\s*\([^)]{0,200}\)\s*\)?\s*(\)|;)?\s*(?=.*\beval\b)"
            r"|\beval\s*\(\s*(atob|Buffer\.from|base64)"
            r"|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64"),
         specificity=92),

    Rule("EXE-005", "HIGH", "medium", REMOTE_EXEC,
         "Dynamic evaluation of data as code",
         "Turns data into code at runtime, defeating static review.",
         "Legitimate uses exist but are rare in an agent extension.",
         "Where does the evaluated string come from?",
         _r(r"(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(\s*(?![\"'])"
            r"|\bnew\s+Function\s*\(|pickle\.loads?\s*\("
            r"|yaml\.load\s*\((?![^)]*SafeLoader)|vm\.runInNewContext"),
         specificity=70),

    Rule("EXE-008", "HIGH", "high", REMOTE_EXEC,
         "Install from a non-registry or mutable source",
         "Bypasses registry review and can change under you.",
         "Internal tooling with pinned refs.",
         "Is the ref pinned to a commit SHA?",
         _r(r"(pip|pip3|uv)\s+install[^\n]{0,120}(git\+|https?://|\.tar\.gz|\.whl)"
            r"|npm\s+(i|install)[^\n]{0,120}(github:|git\+|https?://|#(main|master))"
            r"|(cargo|go)\s+install[^\n]{0,120}@(main|master|latest)"),
         specificity=80),

    Rule("EXE-007", "MEDIUM", "high", REMOTE_EXEC,
         "Package installation",
         "Pulls unreviewed third-party code onto the machine.",
         "Documented setup step.",
         "Which package, from which registry?",
         _r(r"\b(pip3?|uv)\s+install\b|\bnpm\s+(i|install)\b(?![^\n]*--dry-run)"
            r"|\bbrew\s+install\b|\bcargo\s+install\b|\bgo\s+install\b|\bgem\s+install\b"
            r"|\bapt(-get)?\s+install\b|\bpnpm\s+add\b|\byarn\s+add\b"),
         specificity=40),

    Rule("EXE-010", "MEDIUM", "medium", REMOTE_EXEC,
         "Nested or chained interpreter invocation",
         "Layering used to defeat pattern matching.",
         "Legitimate but worth reading.",
         "Read the innermost command.",
         _r(r"\b(ba|z)?sh\s+-c\s+[\"'][^\"'\n]{0,80}\b(python3?|node|perl|ruby|(ba|z)?sh)\s+-[ce]\b"),
         specificity=60),

    Rule("EXE-011", "HIGH", "high", REMOTE_EXEC,
         "Archive extraction without path validation",
         "Zip-slip: writes outside the extraction directory.",
         "Never — extraction should be validated.",
         "Does the extractor check member paths?",
         _r(r"\.extractall\s*\(|_extract_member\s*\("
            r"|tar\s+[^\n]{0,40}(--absolute-names|-P\b)"
            r"|unzip\s+[^\n]{0,40}-o?\s+[^\n]{0,30}\$"),
         specificity=65),

    # ------------------------------------------------------------------ B. exfiltration
    Rule("NET-003", "HIGH", "high", NETWORK,
         "Known anonymous drop endpoint",
         "Disposable collection point for stolen data.",
         "Slack/Discord notifications — verify the workspace is yours.",
         "Do you control that endpoint?",
         _r(r"webhook\.site|requestbin|pipedream\.net|\bpastebin\.com|paste\.ee"
            r"|transfer\.sh|0x0\.st|file\.io|termbin\.com|ngrok\.io|\bbashupload\b"
            r"|discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot"),
         specificity=90),

    Rule("NET-009", "HIGH", "high", SECRETS,
         "Cloud instance metadata access",
         "Standard route to steal cloud role credentials.",
         "Cloud-provisioning tooling only.",
         "Why does this need instance credentials?",
         _r(r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com"
            r"|/latest/meta-data/|/computeMetadata/v1/"),
         specificity=92),

    Rule("NET-004", "HIGH", "high", NETWORK,
         "DNS-based exfiltration",
         "Bypasses HTTP egress filtering.",
         "Effectively never.",
         "What is being placed in the subdomain?",
         _r(r"\b(dig|nslookup|host)\b[^\n]{0,80}(\$\{?[A-Za-z_]|\$\(|`)"
            r"|\b(dig|nslookup)\b[^\n]{0,40}\+short[^\n]{0,60}\$"),
         specificity=88),

    Rule("NET-012", "HIGH", "high", NETWORK,
         "Traffic redirection: proxy or custom CA",
         "Silently routes all future traffic through a third party.",
         "Corporate proxy setup — must be declared.",
         "Who terminates TLS after this change?",
         _r(r"\b(HTTPS?_PROXY|ALL_PROXY)\s*=|NODE_EXTRA_CA_CERTS\s*=|REQUESTS_CA_BUNDLE\s*="
            r"|SSL_CERT_FILE\s*=|~/\.curlrc|security\s+add-trusted-cert|update-ca-certificates"),
         specificity=80),

    Rule("NET-011", "HIGH", "medium", NETWORK,
         "Markdown image or link with interpolated URL",
         "The renderer performs the exfiltration; no command runs.",
         "Never with interpolation.",
         "What value lands in that query string?",
         _r(r"!\[[^\]]{0,60}\]\(\s*https?://[^)\s]{0,200}(\$\{?[A-Za-z_]|\{\{|\$\()"),
         specificity=85, markdown_only=True),

    Rule("NET-005", "HIGH", "medium", NETWORK,
         "Publishes local content to an external account",
         "Content leaves the machine under someone's account.",
         "Documented publishing workflow.",
         "Which remote, which account?",
         _r(r"\bgh\s+gist\s+create\b|\bgit\s+push\s+(https?://|git@)"
            r"|\bglab\s+snippet\s+create\b|\bgh\s+release\s+upload\b"),
         specificity=75),

    Rule("NET-006", "HIGH", "medium", NETWORK,
         "Mail delivery",
         "Data channel that reads as ordinary tooling.",
         "Notification features.",
         "What is in the message body?",
         _r(r"\bsendmail\b|\bsmtplib\b|\bnodemailer\b|\bmailx?\s+-s\b"
            r"|api\.sendgrid\.com|api\.mailgun\.net|api\.resend\.com"),
         specificity=70),

    Rule("NET-008", "MEDIUM", "medium", NETWORK,
         "Raw socket use",
         "Arbitrary channel outside HTTP tooling.",
         "Local port checks.",
         "Which host and port?",
         _r(r"\bnc\s+(-[a-zA-Z]*\s+)*[\w.]+\s+\d+|\bsocat\b|/dev/(tcp|udp)/"
            r"|socket\.socket\s*\(|net\.createConnection\s*\("),
         specificity=65),

    Rule("NET-007", "MEDIUM", "medium", NETWORK,
         "Data encoded immediately before transmission",
         "Obscures what is being sent.",
         "Compression for large legitimate payloads.",
         "Decode the payload and read it.",
         _r(r"base64[^\n]{0,60}\|\s*(curl|wget|nc)\b"
            r"|(gzip|xz|zstd)[^\n]{0,40}\|\s*(base64[^\n]{0,40}\|\s*)?(curl|wget|nc)\b"),
         specificity=78),

    Rule("NET-001", "HIGH", "high", NETWORK,
         "Outbound request to a hardcoded host or raw IP",
         "Data leaves the machine to a destination you did not choose.",
         "Documented API the unit exists to call.",
         "Is that host in the description?",
         _r(r"\b(curl|wget|http\.request|requests\.(get|post|put)|fetch\s*\(|axios\.|urllib)"
            r"[^\n]{0,120}https?://(?!(localhost|127\.|0\.0\.0\.0|\[::1\]|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.))"
            r"|https?://(?!127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)(\d{1,3}\.){3}\d{1,3}"),
         specificity=45),

    Rule("NET-010", "INFO", "high", NETWORK,
         "Outbound network capability",
         "Baseline capability disclosure.",
         "Common and often fine.",
         "Is network access expected for this unit?",
         _r(r"\bcurl\b|\bwget\b|\brequests\.|\bfetch\s*\(|\baxios\b|\bhttpx\b|\burllib\b|WebFetch"),
         specificity=10),

    # ------------------------------------------------------------------ C. remote access / persistence
    Rule("RSH-001", "CRITICAL", "high", REMOTE_EXEC,
         "Reverse shell",
         "Hands interactive control of the machine to a remote party.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"(ba|z)?sh\s+-i\s*>&\s*/dev/tcp/|\bnc\b[^\n]{0,40}\s-[a-z]*e[a-z]*\s"
            r"|socat[^\n]{0,80}EXEC:|pty\.spawn\s*\(|subprocess\.call\(\[[\"'](/bin/)?(ba)?sh"),
         specificity=98),

    Rule("RSH-002", "CRITICAL", "high", REMOTE_EXEC,
         "Bind shell",
         "Same as RSH-001, inbound.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"\bnc\b[^\n]{0,30}-l[^\n]{0,30}-[a-z]*e|socat[^\n]{0,60}LISTEN[^\n]{0,60}EXEC:"
            r"|\bsocket\.bind\s*\([^)]*\)[^\n]{0,200}(pty|/bin/sh)"),
         specificity=98),

    Rule("RSH-004", "CRITICAL", "high", PERSISTENCE,
         "Appends to ~/.ssh/authorized_keys",
         "Permanent remote login for whoever owns the key.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"authorized_keys"),
         specificity=96),

    Rule("RSH-003", "HIGH", "high", NETWORK,
         "Tunneling: exposes the local machine to the internet",
         "Anyone with the URL reaches your machine.",
         "Documented dev-preview workflows.",
         "What is exposed, and for how long?",
         _r(r"\bngrok\b|\bcloudflared\b|\blocaltunnel\b|\blt\s+--port\b"
            r"|\bssh\s+[^\n]{0,60}-R\s+\d|\btailscale\s+up\b|\bbore\s+local\b"),
         specificity=85),

    Rule("PER-001", "HIGH", "high", PERSISTENCE,
         "Scheduled execution",
         "Runs after the session ends, without you present.",
         "Legitimate automation — must be declared.",
         "What runs, and how often?",
         _r(r"\bcrontab\b|/etc/cron\.|\blaunchctl\s+(load|bootstrap)\b|LaunchAgents"
            r"|systemctl\s+(--user\s+)?(enable|start)\b|\.service\b[^\n]{0,40}\[Install\]"
            r"|schtasks\s+/create|Register-ScheduledTask"),
         specificity=88),

    Rule("PER-002", "HIGH", "high", PERSISTENCE,
         "Writes to shell startup files",
         "Executes on every future shell you open.",
         "PATH setup during install — read exactly what is appended.",
         "What line is appended, verbatim?",
         _r(r"(>>|>|tee\s+-a?)\s*[\"']?[^\n\"']{0,40}[/.](bashrc|zshrc|bash_profile|profile|zshenv|zprofile)"
            r"|\.config/fish/config\.fish"),
         specificity=90),

    Rule("PER-003", "HIGH", "high", PERSISTENCE,
         "Installs git hooks",
         "Runs on every commit, push, or checkout.",
         "Legitimate tooling, must be declared.",
         "Read the hook body.",
         _r(r"\.git/hooks/|core\.hooksPath|\bhusky\s+install\b|pre-commit\s+install\b"),
         specificity=85),

    Rule("PER-004", "MEDIUM", "medium", PERSISTENCE,
         "Detached background process",
         "Survives the visible task; hard to notice.",
         "Long-running dev servers.",
         "What keeps running after the task?",
         _r(r"\bnohup\b|\bsetsid\b|\bdisown\b|\bdaemonize\b|start-stop-daemon"
            r"|subprocess\.Popen\([^)]{0,120}start_new_session\s*=\s*True"),
         specificity=60),

    # ------------------------------------------------------------------ D. credentials
    Rule("CRD-001", "CRITICAL", "high", SECRETS,
         "Reads SSH private keys",
         "Access to every host you can reach.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b|\.ssh/identity\b|BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE"),
         specificity=95),

    Rule("CRD-002", "CRITICAL", "high", SECRETS,
         "Reads cloud credentials",
         "Access to your infrastructure.",
         "Cloud-audit tooling — must be declared.",
         "Why does this need long-lived cloud keys?",
         _r(r"\.aws/credentials|\.aws/config\b|\.config/gcloud|\.azure/|\.kube/config"
            r"|application_default_credentials\.json|\.docker/config\.json"),
         specificity=94),

    Rule("CRD-004", "CRITICAL", "high", SECRETS,
         "Reads agent config holding tokens",
         "API keys plus the ability to reconfigure the agent.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"~/\.claude\.json|\.claude/settings[^\n]{0,20}\.json|\.codex/auth\.json"
            r"|\.config/opencode/auth|\.claude/\.credentials"),
         specificity=95),

    Rule("CRD-006", "CRITICAL", "high", SECRETS,
         "Browser credential stores",
         "Session hijacking of every logged-in site.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"Login\s?Data|Cookies\.binarycookies|cookies\.sqlite|key4\.db|logins\.json"
            r"|Google/Chrome/(Default|Profile)|Library/Application Support/Firefox"
            r"|AppData[^\n]{0,60}(Chrome|Edge|Firefox)[^\n]{0,40}(Cookies|Login)"),
         specificity=95),

    Rule("CRD-007", "HIGH", "high", SECRETS,
         "Crypto wallet paths or seed material",
         "Irreversible financial loss.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"wallet\.dat|\.electrum|keystore/UTC--|mnemonic|seed\s?phrase"
            r"|Exodus/exodus\.wallet|\.ethereum/keystore|metamask"),
         specificity=92),

    Rule("CRD-009", "HIGH", "high", SECRETS,
         "Reads shell history",
         "History commonly contains pasted secrets.",
         "Never.",
         "Why does this need your command history?",
         _r(r"\.(bash|zsh|fish|sh)_history|HISTFILE\b(?!\s*=\s*/dev/null)|\.local/share/fish/fish_history"),
         specificity=90),

    Rule("CRD-011", "HIGH", "high", SECRETS,
         "Credential retrieval via CLI",
         "Live tokens without touching a credential file — defeats every path rule.",
         "Tooling that needs the token it then uses locally.",
         "Where does the token go after it is read?",
         _r(r"\bgh\s+auth\s+token\b|aws\s+sts\s+get-(session|caller)|gcloud\s+auth\s+print-\w*token"
            r"|az\s+account\s+get-access-token|\bop\s+read\b|\bop\s+item\s+get\b"
            r"|vault\s+(read|kv\s+get)\b|doctl\s+auth\b|heroku\s+auth:token"),
         specificity=88),

    Rule("CRD-005", "HIGH", "high", SECRETS,
         "OS keychain access",
         "Centralized credential store.",
         "Password-manager integrations.",
         "Which item is being read?",
         _r(r"security\s+find-(generic|internet)-password|\bsecret-tool\s+lookup"
            r"|\bkeyring\.get_password|CredentialManager|DPAPI|libsecret"),
         specificity=85),

    Rule("CRD-012", "HIGH", "high", SECRETS,
         "Clipboard read",
         "Clipboards hold passwords and 2FA codes seconds after you copy them.",
         "Paste-driven utilities.",
         "Where does the clipboard content go?",
         _r(r"\bpbpaste\b|\bxclip\b[^\n]{0,30}-o\b|\bxsel\b[^\n]{0,20}-[bo]\b|\bwl-paste\b"
            r"|Get-Clipboard|clipboard\.paste\(\)|pyperclip\.paste"),
         specificity=88),

    Rule("CRD-013", "HIGH", "high", SECRETS,
         "Screen, audio, or camera capture",
         "Captures whatever is on screen, including other apps.",
         "Screenshot tooling — must be declared.",
         "What triggers the capture?",
         _r(r"\bscreencapture\b|\bscrot\b|\bgrim\b|\bmaim\b|import\s+-window\s+root"
            r"|ffmpeg[^\n]{0,80}(-f\s+(avfoundation|x11grab|gdigrab|alsa|pulse))"
            r"|Screenshot\.captureScreen|mss\(\)"),
         specificity=88),

    Rule("CRD-003", "HIGH", "low", SECRETS,
         "Reads local secret files",
         "Application and registry secrets.",
         "Reading a project .env is common. The flow is what matters.",
         "Is the content sent anywhere?",
         _r(r"\.env(\.[a-z]+)?\b|\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b"
            r"|secrets?\.(json|ya?ml|toml)\b|credentials\.json\b"),
         specificity=55),

    Rule("CRD-008", "MEDIUM", "high", SECRETS,
         "Bulk environment dump",
         "Environments routinely hold tokens.",
         "Debug output — check the sink.",
         "Where does the dump go?",
         _r(r"\bprintenv\b|^\s*env\s*$|\bos\.environ\b(?!\s*\[)|\bos\.environ\.copy\(\)"
            r"|\{\s*\.\.\.process\.env\s*\}|JSON\.stringify\(process\.env",
            re.IGNORECASE | re.MULTILINE),
         specificity=60),

    Rule("CRD-010", "MEDIUM", "medium", RECON,
         "Broad search for secret-shaped patterns",
         "Secret harvesting across the filesystem.",
         "Secret-scanning tools — verify scope and sink.",
         "What is the search root?",
         _r(r"(grep|rg|ag)\s+(-\w+\s+)*[\"']?(api[_-]?key|secret|password|token|BEGIN [A-Z]+ PRIVATE)"),
         specificity=70),

    # ------------------------------------------------------------------ E. filesystem
    Rule("FSW-002", "CRITICAL", "high", CONTROL_PLANE,
         "Modifies agent instructions or config",
         "Rewrites the rules the agent follows — a persistent foothold in your assistant.",
         "Only as the unit's stated purpose.",
         "What exactly is written into the agent config?",
         _r(r"(>>|>|tee\s+-a?|write_text|writeFile|open\s*\([^)]{0,60}[\"']w)"
            r"[^\n]{0,80}(CLAUDE\.md|AGENTS\.md|\.claude/|\.codex/|opencode\.json|\.mcp\.json"
            r"|settings\.local\.json|settings\.json)"),
         specificity=93),

    Rule("AGT-015", "HIGH", "high", CONTROL_PLANE,
         "Writes instructions for a different assistant",
         "Plants instructions in the assistant you are not auditing. Pure evasion.",
         "Multi-tool projects — must be declared.",
         "Why write rules for another agent?",
         _r(r"\.cursor/rules|\.cursorrules|copilot-instructions\.md|\.windsurfrules"
            r"|\.aider\.conf|\.continue/|\.github/instructions/"),
         specificity=88),

    Rule("FSW-003", "HIGH", "high", CONTROL_PLANE,
         "Modifies or deletes other installed extensions",
         "Can neutralize this auditor or backdoor trusted units.",
         "Extension-management tooling only.",
         "Which other extensions are touched?",
         _r(r"(rm|mv|cp|shutil\.(rm|move|copy))[^\n]{0,80}(\.claude/(skills|plugins|agents)"
            r"|\.opencode/(agent|plugin|command)|\.codex/prompts)"),
         specificity=90),

    Rule("FSW-004", "HIGH", "medium", DESTRUCTIVE,
         "Destructive command",
         "Irreversible data loss.",
         "Literal narrow path under a temp dir.",
         "Is the path interpolated? An unset variable makes this catastrophic.",
         _r(r"\brm\s+(-\w*[rf]\w*\s+)+[^\n]{0,80}(\$\{?\w|\$\(|`|~|/\*)"
            r"|\bshred\b|\bdd\s+[^\n]{0,60}of=|\bmkfs\b"
            r"|git\s+(reset\s+--hard|clean\s+-\w*f)"),
         specificity=80),

    Rule("FSW-006", "HIGH", "medium", DESTRUCTIVE,
         "Mass file rewrite across a tree",
         "Ransomware and mass-corruption shape.",
         "Codemods and formatters — verify scope.",
         "What is the traversal root?",
         _r(r"find\s+[^\n]{0,60}-exec\s+[^\n]{0,60}(rm|mv|sed\s+-i|chmod|openssl)"
            r"|(rg|grep)\s+-l[^\n]{0,60}\|\s*xargs\s+(sed\s+-i|rm|mv)"
            r"|os\.walk\([^)]{0,60}\)[^\n]{0,200}(unlink|remove|rename|write_text)"),
         specificity=78),

    Rule("FSW-001", "HIGH", "medium", WRITE_OUTSIDE,
         "Writes outside the unit and working directory",
         "Modifies things you did not put in scope.",
         "Config setup — must be declared.",
         "Which absolute paths are written?",
         _r(r"(>>|>|tee\s+-a?|writeFile|write_text|open\s*\([^)]{0,40}[\"']w[\"'])"
            r"\s*[\"']?(~|/etc/|/usr/|/opt/|/Library/|\$HOME|%APPDATA%)"),
         specificity=65),

    Rule("FSW-008", "HIGH", "high", WRITE_OUTSIDE,
         "Creates a symlink pointing outside the unit",
         "A later write through the link lands somewhere you did not approve.",
         "Never inside a distributed bundle.",
         "Where does the link point?",
         _r(r"\bln\s+-s\w*\s+[^\n]{0,60}(~|/etc/|/usr/|\$HOME|\.\./\.\.)"
            r"|os\.symlink\s*\(|Path[^\n]{0,40}\.symlink_to\s*\("),
         specificity=80),

    Rule("FSW-005", "MEDIUM", "high", PRIVILEGE,
         "Permission or ownership change",
         "Weakens system protections.",
         "Rare; read carefully.",
         "Which file, and to what mode?",
         _r(r"chmod\s+(-R\s+)?(777|666|a\+w|\+s|4755|u\+s)|\bchown\b|\bsetfacl\b|icacls\s+[^\n]{0,40}/grant"),
         specificity=75),

    Rule("FSW-007", "MEDIUM", "medium", RECON,
         "Reads broadly outside the project",
         "Reconnaissance ahead of targeted theft.",
         "Disk-usage tooling.",
         "What is the search root?",
         _r(r"\bfind\s+(/|~|\$HOME)\s|\b(rg|grep)\s+(-\w+\s+)*[^\n]{0,40}\s+(/|~|\$HOME)\s*$"
            r"|os\.walk\s*\(\s*[\"']?(/|~|os\.path\.expanduser)",
            re.IGNORECASE | re.MULTILINE),
         specificity=60),

    # ------------------------------------------------------------------ F. privilege / evasion
    Rule("PRV-008", "CRITICAL", "high", PRIVILEGE,
         "Container or host escape",
         "Escapes whatever isolation you thought you had.",
         "Container-management tooling — must be declared.",
         "Why does this need the host?",
         _r(r"/var/run/docker\.sock|--privileged\b|-v\s+/:/|--pid=host|--net=host\b"
            r"|\bnsenter\b|--cap-add[= ]SYS_ADMIN"),
         specificity=92),

    Rule("PRV-002", "HIGH", "high", PRIVILEGE,
         "Disables shell history",
         "Deliberately destroys your forensic trail.",
         "No legitimate reason inside an agent extension.",
         "Stop. This only makes sense to an attacker.",
         _r(r"unset\s+HISTFILE|set\s+\+o\s+history|HISTSIZE\s*=\s*0|HISTFILE\s*=\s*/dev/null"
            r"|Clear-History|Remove-Item[^\n]{0,40}ConsoleHost_history"),
         specificity=92),

    Rule("PRV-003", "HIGH", "high", PRIVILEGE,
         "Clears or truncates logs",
         "Destroys the forensic trail.",
         "Log rotation tooling only.",
         "Which logs, and why?",
         _r(r">\s*/var/log/|truncate\s+-s\s*0\s+[^\n]{0,40}\.log|\bjournalctl\s+--vacuum"
            r"|rm\s+[^\n]{0,40}/var/log/|wevtutil\s+cl\b|Clear-EventLog"),
         specificity=88),

    Rule("PRV-004", "MEDIUM", "high", PRIVILEGE,
         "Disables TLS verification",
         "Enables interception of everything sent.",
         "Local self-signed dev certs.",
         "Which connection skips verification?",
         _r(r"curl\s+[^\n]{0,40}(-k\b|--insecure)|wget\s+[^\n]{0,40}--no-check-certificate"
            r"|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
            r"|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context"),
         specificity=82),

    Rule("PRV-001", "HIGH", "high", PRIVILEGE,
         "Privilege escalation",
         "Escalates beyond your normal blast radius.",
         "Documented system installs.",
         "What runs as root?",
         _r(r"\bsudo\s+(?!-v\b)|\bdoas\b|\bpkexec\b|Start-Process[^\n]{0,60}-Verb\s+RunAs|\brunas\b"),
         specificity=70),

    Rule("PRV-005", "MEDIUM", "medium", PRIVILEGE,
         "Safety-gate bypass coupled to a destructive or publishing command",
         "Removes the checkpoint on an action that matters.",
         "Automation — verify intent. A bare --yes on a harmless command is not a finding.",
         "Which gate is removed, on which command?",
         _r(r"git\s+push\s+[^\n]{0,40}(--force\b|-f\b)|git\s+commit\s+[^\n]{0,40}--no-verify"
            r"|\brm\s+-\w*f[^\n]{0,40}(--no-preserve-root)"
            r"|(npm|pip|apt(-get)?)\s+[^\n]{0,30}(--force|--yes|-y)\b[^\n]{0,40}(uninstall|remove|purge)"),
         specificity=72),

    Rule("PRV-006", "HIGH", "low", PRIVILEGE,
         "Environment fingerprinting followed by branching",
         "Behave-differently-when-watched.",
         "Cross-platform support — read every branch.",
         "What differs between the branches?",
         _r(r"if\s+[^\n]{0,60}(\$CI\b|\$GITHUB_ACTIONS|\$CONTAINER|hostname|whoami|\$USER\b)"
            r"|(platform\.node|socket\.gethostname|os\.getlogin)\s*\(\)\s*[=!]="
            r"|/proc/1/cgroup|/\.dockerenv|systemd-detect-virt"),
         specificity=55),

    Rule("PRV-007", "HIGH", "low", PRIVILEGE,
         "Delayed or conditional execution",
         "Time-bomb shape: benign during review, malicious later.",
         "Retry logic and backoff.",
         "What happens after the delay or on the Nth run?",
         _r(r"\bsleep\s+([1-9]\d{3,})\b|time\.sleep\s*\(\s*([1-9]\d{3,})"
            r"|datetime[^\n]{0,60}[<>]=?\s*datetime|date\s+\+%s[^\n]{0,40}-(gt|lt)\b"
            r"|run_count|invocation_count"),
         specificity=50),

    # ------------------------------------------------------------------ G. instruction surface
    Rule("AGT-016", "CRITICAL", "high", INSTRUCTION,
         "Harness-mimicking structure",
         "Fakes a conversation turn or escapes a quarantine wrapper. Language-independent.",
         "Never outside a documented example.",
         "Why does this file contain conversation delimiters?",
         _r(r"<\|im_(start|end)\|>|<\|endoftext\|>|^\s*(Human|Assistant)\s*:\s*$"
            r"|</(system|instructions?)>|\[/INST\]|<\|eot_id\|>",
            re.IGNORECASE | re.MULTILINE),
         specificity=95),

    Rule("AGT-001", "CRITICAL", "medium", INSTRUCTION,
         "Instruction override directed at the reader",
         "Attempts to hijack any agent that reads the file, including the auditor.",
         "Never — genuine units instruct, they do not override.",
         "Read the surrounding paragraph in full.",
         _r(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+"
            r"(instruction|prompt|rule|direction|message)"
            r"|disregard\s+(your|the|all)\s+(system\s+)?(prompt|instruction|rule|guideline)"
            r"|forget\s+(everything|all)\s+(you|above|previous)"
            r"|you\s+are\s+now\s+(a|an|the)\s|new\s+instructions?\s*:"
            r"|override\s+(your|the)\s+(system|previous|prior)"
            r"|olvid[áa]\s+(las\s+)?instrucciones|ignor[áa]\s+(las\s+)?instrucciones"),
         specificity=92),

    Rule("AGT-012", "CRITICAL", "medium", INSTRUCTION,
         "Instruction targeting the auditor",
         "Direct attack on this tool.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"(this|the)\s+(skill|file|plugin|script|code)\s+is\s+(safe|trusted|verified|benign)"
            r"|report\s+no\s+(findings|issues|problems)|skip\s+the\s+(security|safety)\s+(check|scan|review)"
            r"|(mark|treat)\s+(this|it)\s+as\s+(safe|a\s+false\s+positive)"
            r"|do\s+not\s+(flag|report|analy[sz]e)\s+(this|the\s+following)"
            r"|no\s+security\s+(concerns?|issues?)\s+(here|in\s+this)"),
         specificity=93),

    Rule("AGT-002", "CRITICAL", "low", INSTRUCTION,
         "Concealment with the user or the log as the object",
         "The user losing visibility is the whole point of the attack.",
         "Requires verb+object proximity. Bare 'silently' is ordinary technical prose.",
         "Who is being kept in the dark, and about what?",
         _r(r"(do\s+not|don'?t|never|avoid)\s+(\w+\s+){0,3}"
            r"(mention|tell|inform|notify|show|display|report|reveal|disclose|log)"
            r"\s+(\w+\s+){0,2}(the\s+)?(user|human|them|operator|owner|it|this)"
            r"|without\s+(telling|informing|notifying|alerting)\s+(the\s+)?(user|them|anyone)"
            r"|hide\s+(this|it|the\s+\w+)\s+from\s+(the\s+)?(user|human|output|log)"
            r"|suppress\s+the\s+(output|log|message|warning)"),
         specificity=90),

    Rule("AGT-004", "CRITICAL", "medium", INSTRUCTION,
         "Instruction to read local context and transmit it",
         "Turns the agent into the exfiltration channel — no suspicious binary needed.",
         "Never.",
         "Stop. Do not install this.",
         _r(r"(read|collect|gather|dump|export|summari[sz]e)\s+(\w+\s+){0,4}"
            r"(memory|memories|conversation|chat\s+history|transcript|session|context|"
            r"other\s+skills?|installed\s+skills?|CLAUDE\.md|AGENTS\.md)"
            r"[^\n]{0,120}(send|post|upload|transmit|share|report|sync|push)\s+"
            r"|(send|post|upload)\s+(\w+\s+){0,4}(the\s+)?(conversation|transcript|history|memory|context)"),
         specificity=91),

    Rule("AGT-005", "HIGH", "high", INSTRUCTION,
         "Runtime instruction fetching",
         "The real payload is off-file and mutable after you audit.",
         "Documentation lookup — the content must not become instructions.",
         "Does fetched content become instructions?",
         _r(r"(fetch|read|load|retrieve|get)\s+(\w+\s+){0,3}(this|the)\s+(url|link|endpoint|page|file\s+at)"
            r"[^\n]{0,80}(and\s+)?(follow|execute|apply|obey|do|run)"
            r"|WebFetch[^\n]{0,80}(follow|instruction|then\s+do)"
            r"|follow\s+the\s+instructions?\s+(at|in|from)\s+https?://"),
         specificity=88),

    Rule("AGT-003", "HIGH", "medium", INSTRUCTION,
         "Confirmation bypass instruction",
         "Removes the human checkpoint on dangerous actions.",
         "UX shortcuts for genuinely safe operations.",
         "Which action skips confirmation?",
         _r(r"(do\s+not|don'?t|never)\s+ask\s+(for\s+)?(permission|confirmation|the\s+user)"
            r"|auto-?approve|skip\s+(the\s+)?confirmation|without\s+(asking|confirmation|prompting)"
            r"|assume\s+(yes|approval)|proceed\s+without\s+(asking|confirming)"),
         specificity=80),

    Rule("AGT-010", "MEDIUM", "medium", CONTROL_PLANE,
         "Instruction to modify other extensions, memory, or agent instructions",
         "Self-propagation and persistence at the agent layer.",
         "Extension-management tooling.",
         "What gets written where?",
         _r(r"(edit|modify|update|append\s+to|write\s+to|add\s+to)\s+(\w+\s+){0,3}"
            r"(CLAUDE\.md|AGENTS\.md|your\s+memory|the\s+memory|other\s+skills?|"
            r"installed\s+skills?|system\s+prompt|global\s+instructions)"),
         specificity=75),

    Rule("AGT-014", "HIGH", "medium", INSTRUCTION,
         "Instruction conditioned on the agent or execution mode",
         "The agentic form of PRV-006: behave differently when less supervised.",
         "Genuine cross-platform support — read every branch.",
         "What differs in the unsupervised branch?",
         _r(r"if\s+you\s+are\s+(claude|codex|opencode|cursor|copilot|gpt|an?\s+ai)"
            r"|when\s+(you\s+are\s+)?running\s+(autonomously|headless|unattended|in\s+ci)"
            r"|in\s+(autonomous|headless|unattended|yolo)\s+mode"
            r"|si\s+sos\s+(claude|codex|un\s+agente)"),
         specificity=82),

    Rule("AGT-008", "MEDIUM", "medium", INSTRUCTION,
         "Overbroad activation",
         "Maximizes exposure and burns context every turn.",
         "Genuinely cross-cutting protocols.",
         "Does this really need to run every turn?",
         _r(r"always\s+active|on\s+every\s+(prompt|turn|message|request|response)"
            r"|before\s+any\s+response|at\s+the\s+start\s+of\s+every"
            r"|mandatory\s+and\s+always\s+active|apply\s+this\s+to\s+all"),
         specificity=65),

    Rule("AGT-013", "HIGH", "low", INSTRUCTION,
         "Activation shadowing: captures another unit's domain",
         "Hijacks a trusted extension's trigger. Territory theft, not always-on.",
         "Genuine domain ownership.",
         "Does a trusted extension already own this trigger?",
         _r(r"use\s+(this|me)\s+for\s+(all|any|every)(thing)?\s+[\w\s-]{0,30}"
            r"(related\s+to|involving|about)"
            r"|instead\s+of\s+(the\s+)?(built-?in|default|standard)\s+\w+\s+(skill|tool|command)"
            r"|(always\s+)?prefer\s+this\s+(skill|tool)\s+over"),
         specificity=70),
]


# Rules in RULES.md that this version cannot evaluate. Reported as coverage gaps
# so a clean scan is never mistaken for a complete one.
DEFERRED = {
    "CHN-002": "binary-plus-execution-path composition not wired yet",
    "AGT-009": "needs the semantic pass (RULES.md section 8)",
    "AGT-011": "superseded by BND-003, not implemented",
    "SUP-002": "needs a registry of known extension names",
    "EXE-009": "entropy scan not enabled in v0 (high false-positive rate)",
}

BY_ID = {rule.id: rule for rule in RULES}
