"""The disclosure axis — RULES.md section 2.4.

Compares an observed capability against what the unit says about itself. This is
self-reported and therefore gameable, but a lying description is visible to the
human, which is the point. The report prints the description verbatim.
"""

from __future__ import annotations

import re

from . import rules as R

# Strong terms name the capability. Weak terms gesture at it without naming it —
# "syncs your environment" for reading .env.
_KEYWORDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    R.NETWORK: (
        ("http", "api", "url", "endpoint", "webhook", "network", "request",
         "upload", "download", "fetch", "remote", "server", "cloud", "post to"),
        ("sync", "publish", "share", "send", "notify", "report", "integrat", "connect"),
    ),
    R.SECRETS: (
        ("credential", "secret", "token", "api key", "password", "keychain",
         "auth", ".env", "wallet", "cookie", "clipboard", "screenshot"),
        ("environment", "config", "profile", "login", "session", "identity"),
    ),
    R.WRITE_OUTSIDE: (
        ("writes to", "installs to", "home directory", "global config", "dotfile"),
        ("install", "setup", "configure", "bootstrap", "initiali"),
    ),
    R.PERSISTENCE: (
        ("cron", "schedul", "background", "daemon", "startup", "persist",
         "git hook", "always running"),
        ("automat", "watch", "monitor", "continuous"),
    ),
    R.CONTROL_PLANE: (
        ("hook", "mcp", "subagent", "permission", "agent config", "settings.json",
         "claude.md", "agents.md", "slash command"),
        ("plugin", "extension", "tool", "configure", "manage"),
    ),
    R.AUTO_EXEC: (
        ("postinstall", "direnv", "envrc", "runs on install", "runs automatically"),
        ("install", "setup", "build"),
    ),
    R.REMOTE_EXEC: (
        ("executes", "runs a script", "binary", "shell command", "subprocess",
         "installs packages"),
        ("run", "execute", "script", "command", "cli", "build", "compile"),
    ),
    R.PRIVILEGE: (
        ("sudo", "root", "privileg", "administrator", "container", "docker"),
        ("system", "install", "permission"),
    ),
    R.DESTRUCTIVE: (
        ("delete", "remove", "clean", "reset", "wipe", "prune"),
        ("manage", "maintain", "tidy", "organi"),
    ),
    R.RECON: (
        ("scan", "search", "index", "audit", "inventory", "walk"),
        ("analy", "review", "inspect", "find", "look"),
    ),
    R.HIDDEN: ((), ()),
    R.INSTRUCTION: ((), ()),
}


def classify_disclosure(capability: str, description: str) -> str:
    """declared | euphemistic | undeclared."""
    if not description:
        return "undeclared"

    strong, weak = _KEYWORDS.get(capability, ((), ()))
    if not strong and not weak:
        # Hidden content and instruction-surface findings are never "declared".
        # Nobody documents a prompt injection.
        return "undeclared"

    text = re.sub(r"\s+", " ", description.lower())
    if any(term in text for term in strong):
        return "declared"
    if any(term in text for term in weak):
        return "euphemistic"
    return "undeclared"
