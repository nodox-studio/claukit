#!/usr/bin/env python3
"""
ClauKit Guard — PreToolUse security hook
Blocks dangerous commands, sensitive file access, and supply-chain attacks.
Pure Python stdlib — no external dependencies.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import re
import sys
import urllib.request
import urllib.error

# ── Sensitive paths ────────────────────────────────────────────────────────────

HOME = os.path.expanduser("~")

SENSITIVE_PATHS = [
    f"{HOME}/.ssh/",
    f"{HOME}/.aws/",
    f"{HOME}/.gnupg/",
    f"{HOME}/.netrc",
    f"{HOME}/.pypirc",
    f"{HOME}/.docker/config.json",
    f"{HOME}/.config/gcloud/",
    "/etc/shadow",
    "/etc/sudoers",
]

# Files matched by basename anywhere in the tree. Audience-novel coverage:
# .env* and SSH private keys are touched by designers / vibe coders daily,
# whereas the absolute paths above (e.g. ~/.ssh/) almost never appear in
# their workflows. Both lists run, so a path under ~/.ssh/ still gets caught.
SENSITIVE_FILENAMES = [
    ".env",
    ".env.local", ".env.production", ".env.development", ".env.staging", ".env.test",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pgpass",
    "credentials.json",         # Google Cloud, Firebase, others
    "terraform.tfvars",         # Terraform secrets file
    "terraform.tfvars.json",    # JSON variant
]

# Files matched by extension (lowercased). Covers private keys and key bundles.
# Public-cert formats (.crt, .cer, .csr) are intentionally NOT blocked — they're
# not secrets. .pfx is the Windows variant of .p12.
SENSITIVE_EXTENSIONS = [
    ".pem",   # PEM-encoded private keys and certs
    ".key",   # RSA / EC private keys (Laravel app.key also legitimately blocked)
    ".p12",   # PKCS#12 bundle (certificate + private key)
    ".pfx",   # PKCS#12 Windows variant
]

# ── Known IOCs ─────────────────────────────────────────────────────────────────

EXFILTRATION_SERVICES = [
    "transfer.sh", "webhook.site", "requestbin.com", "pipedream.net",
    "hookbin.com", "beeceptor.com", "ngrok.io", "ngrok.com",
    "serveo.net", "localhost.run", "burpcollaborator.net",
    "interactsh.com", "canarytokens.com", "oast.fun", "oast.me",
]

MALICIOUS_DOMAINS = [
    "giftshop.club",   # Postmark MCP incident, Sept 2025
]

SENSITIVE_ENV_VARS = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN",
    "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN", "DATABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY", "SENDGRID_API_KEY",
]

# ── Dangerous command patterns ─────────────────────────────────────────────────

RCE_PIPE_PATTERNS = [
    r"(curl|wget)\s+\S+\s*\|\s*(bash|sh|python3?|perl|ruby|node)",
    r"base64\s+-d\s*\|\s*(bash|sh|python3?|perl)",
    r"eval\s*\$\(",
    r"python3?\s+-c\s+['\"].*exec\(",
]

# Deferred execution: download-to-tmp then run in same chain.
# Catches the common bypass `curl URL -o /tmp/x && bash /tmp/x` that the simple
# pipe pattern above does not see because the two stages are split.
DEFERRED_EXEC_PATTERNS = [
    # eval $(curl ...) or eval "$(wget ...)"
    r"eval\s+[\"']?\$\(\s*(curl|wget|fetch)\b",
    # source/. of remote-fetched temp file
    r"\b(source|\.)\s+(/tmp|/var/tmp|\$TMPDIR)/",
    # curl/wget redirected to /tmp/... AND bash/sh of /tmp/... in same chain
    r"(curl|wget)\b[^|;]*?(\s>\s*|\s-[oO]\s+)(/tmp|/var/tmp|\$TMPDIR|~?/\.cache)/\S+.{0,200}(&&|;|\|\|).{0,200}\b(bash|sh|chmod\s+\S*x[^\n]*?(/tmp|/var/tmp))",
]

REVERSE_SHELL_PATTERNS = [
    r"bash\s+-i\s+>&\s*/dev/tcp/",
    r"nc\s+(-e|-c)\s+/bin/(sh|bash)",
    r"ncat\s+.*--exec",
    r"mkfifo\b.{0,80}\bnc\b",
    r"/dev/tcp/.+/bin/(sh|bash)",
]

# ── SQLi patterns ─────────────────────────────────────────────────────────────

# String concatenation into SQL queries — detects insecure query building in code.
# Each `.*` is bounded to {0,256} chars; combined with the SQLI_MAX_LEN cap on
# the input below, that keeps regex evaluation linear even on hostile input.
SQLI_MAX_LEN = 8192  # only scan the first 8KB of any candidate string

SQLI_PATTERNS = [
    # Python: cursor.execute("SELECT..." + var) or f"SELECT...{var}"
    r'execute\s*\(\s*[f"\'`].{0,256}SELECT.{0,256}(WHERE|AND|OR).{0,256}(\+\s*\w|\{)',
    r'execute\s*\(\s*[f"\'`].{0,256}INSERT.{0,256}(VALUES).{0,256}(\+\s*\w|\{)',
    r'execute\s*\(\s*[f"\'`].{0,256}UPDATE.{0,256}(SET).{0,256}(\+\s*\w|\{)',
    r'execute\s*\(\s*[f"\'`].{0,256}DELETE.{0,256}(WHERE).{0,256}(\+\s*\w|\{)',
    # Node/JS: db.query("SELECT..." + req. or db.query(`SELECT...${req.
    r'(query|raw)\s*\(\s*[`"\'].{0,256}SELECT.{0,256}(\+\s*req\.|\$\{req\.)',
    r'(query|raw)\s*\(\s*[`"\'].{0,256}INSERT.{0,256}(\+\s*req\.|\$\{req\.)',
    r'(query|raw)\s*\(\s*[`"\'].{0,256}UPDATE.{0,256}(\+\s*req\.|\$\{req\.)',
    r'(query|raw)\s*\(\s*[`"\'].{0,256}DELETE.{0,256}(\+\s*req\.|\$\{req\.)',
]

# ── Typosquatting ──────────────────────────────────────────────────────────────

POPULAR_NPM_PACKAGES = [
    "react", "react-dom", "lodash", "express", "axios", "moment",
    "webpack", "typescript", "eslint", "prettier", "jest", "vitest",
    "next", "nuxt", "vue", "angular", "gatsby", "remix",
    "tailwindcss", "prisma", "zod", "trpc", "drizzle",
    "dotenv", "cors", "body-parser", "nodemon", "ts-node",
]

POPULAR_PYPI_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "pydantic", "pytest", "boto3", "pillow",
    "scipy", "matplotlib", "tensorflow", "torch", "transformers",
    "openai", "anthropic", "langchain", "httpx", "aiohttp",
]

# ── OSV API ────────────────────────────────────────────────────────────────────

OSV_API = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 3  # seconds — fail open on timeout

def query_osv(name: str, ecosystem: str, version: str | None = None) -> list:
    """
    Query OSV database for known CVEs.
    Returns list of vuln IDs, empty list if safe or on network error (fail open).

    With version → returns CVEs affecting that specific version.
    Without version → returns ALL known CVEs for the package (history).
    """
    # Test harness escape hatch — skip all network when CLAUKIT_OFFLINE=1.
    if os.environ.get("CLAUKIT_OFFLINE") == "1":
        return []

    body = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    payload = json.dumps(body).encode()

    req = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return [v["id"] for v in data.get("vulns", [])]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError) as e:
        # Fail-open is intentional (network must not block UX), but log so the
        # user can see when CVE checks were silently skipped.
        _log_event(
            "WARN",
            _CTX.get("tool", ""),
            f"OSV query failed for {ecosystem}:{name} ({type(e).__name__}) — fail-open",
            _CTX.get("cmd", ""),
        )
        return []


# ── Helpers ────────────────────────────────────────────────────────────────────

# ── User level ────────────────────────────────────────────────────────────────

def _read_user_level() -> int:
    """Read user level from ~/.claude/claukit-profile.md. Returns 1/2/3."""
    profile = os.path.join(HOME, ".claude", "claukit-profile.md")
    try:
        content = open(profile).read()
        m = re.search(r"^level:\s*(\w+)", content, re.MULTILINE)
        if m:
            return {"beginner": 1, "intermediate": 2, "advanced": 3}.get(m.group(1), 1)
    except OSError:
        pass
    return 1  # safe default


USER_LEVEL = _read_user_level()

# ── Shannon entropy ────────────────────────────────────────────────────────────

# Calibrated against real samples:
# - English base64 / JWT:    ~4.4–5.1  → safe
# - True random base64 64c:  ~5.3      → suspicious
# - True random base64 128c: ~5.5      → very suspicious
# Threshold 5.2 + len>60 + network sink catches obfuscated payloads with low false-positive rate
ENTROPY_THRESHOLD_SHORT = 5.4   # for tokens 30–60 chars (very selective)
ENTROPY_THRESHOLD_LONG  = 5.2   # for tokens >60 chars (catches longer payloads)
ENTROPY_MIN_LEN         = 30    # ignore short tokens (UUIDs ~4.1, safely below)
ENTROPY_MAX_TOKENS      = 10    # cap to defend against pathological inputs

# Network/exec sinks that make a high-entropy string dangerous
ENTROPY_SINKS = re.compile(
    r"\b(eval|curl|wget|nc|ncat|socat|bash|sh|python3?|node|perl|ruby)\b",
    re.IGNORECASE,
)

def _shannon(s: str) -> float:
    n = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _entropy_message(token: str, score: float, sink: str) -> str:
    if USER_LEVEL == 3:
        return (
            f"[ENTROPY_ALERT] Shannon={score:.2f} | token='{token[:20]}…' "
            f"| sink={sink} | likely obfuscated payload or embedded key"
        )
    elif USER_LEVEL == 2:
        return (
            f"Se detectó una cadena de alta entropía ({score:.1f} bits/char) "
            f"enviada a `{sink}`. Esto suele ser una técnica de ofuscación de malware "
            f"o una clave embebida. Si es legítimo, muévelo a una variable de entorno."
        )
    else:
        return (
            "He bloqueado un comando que intentaba ejecutar código oculto o cifrado "
            "de forma insegura. Si necesitas usar datos cifrados, "
            "guárdalos en una variable de entorno (.env)."
        )


_CTX = {"tool": "", "cmd": ""}  # populated by main(), used by deny() for audit log


def _log_event(label: str, tool: str, message: str, cmd: str = "") -> None:
    """Append a forensic entry. Best-effort: never fail on log error."""
    try:
        log_dir = os.path.join(HOME, ".claude")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "claukit-guard.log")
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        # Truncate long commands and strip newlines so each entry stays one line
        cmd_safe = (cmd or "").replace("\n", " ").replace("\r", " ")[:200]
        line = f"{stamp}  {label:<5s}  tool={tool or '-'}  reason={message!r}  cmd={cmd_safe!r}\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def _audit_log(tool: str, reason: str, cmd: str) -> None:
    """Block event — kept as a thin wrapper for backwards compat."""
    _log_event("BLOCK", tool, reason, cmd)


def deny(reason: str) -> None:
    _audit_log(_CTX.get("tool", ""), reason, _CTX.get("cmd", ""))
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"ClauKit Guard: {reason}",
        }
    }))
    sys.exit(0)


def ask(reason: str) -> None:
    """Surface the decision to the user as a permission prompt, not a hard block.
    Used when severity is warning-level (e.g. historical CVE without a pinned version).
    """
    _log_event("ASK", _CTX.get("tool", ""), reason, _CTX.get("cmd", ""))
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"ClauKit Guard: {reason}",
        }
    }))
    sys.exit(0)


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    if a == b:
        return 0
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        row = [i + 1]
        for j, cb in enumerate(b):
            row.append(min(dp[j] + (ca != cb), dp[j + 1] + 1, row[j] + 1))
        dp = row
    return dp[len(b)]


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_path(path: str) -> None:
    if not path:
        return
    expanded = os.path.expanduser(path)
    for blocked in SENSITIVE_PATHS:
        if expanded.startswith(blocked):
            deny(f"blocked access to sensitive path: {path}")
    basename = os.path.basename(expanded)
    for blocked in SENSITIVE_FILENAMES:
        if basename == blocked:
            deny(f"blocked access to sensitive file: {path}")
    _, ext = os.path.splitext(basename.lower())
    if ext in SENSITIVE_EXTENSIONS:
        deny(f"blocked access to sensitive file ({ext}): {path}")


def check_bash(cmd: str) -> None:
    if not cmd:
        return

    # Known malicious and exfiltration domains
    for domain in MALICIOUS_DOMAINS + EXFILTRATION_SERVICES:
        if domain in cmd:
            deny(f"blocked connection to suspicious service: {domain}")

    # RCE via pipe — point the user at the verified-pipe-install pattern
    # (SECURITY-PATTERNS.md §8) instead of just saying "no". Educational deny
    # is more useful than a flat block, especially when the user hit this by
    # following a vendor's "curl URL | bash" install instructions.
    for pattern in RCE_PIPE_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            deny(
                "blocked remote code execution pattern (pipe to shell). "
                "Download to a tempfile, verify, then run. See: "
                "github.com/nodox-studio/claukit/blob/main/SECURITY-PATTERNS.md#8"
            )

    # Deferred execution: download to /tmp then run in same chain
    for pattern in DEFERRED_EXEC_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            deny(
                "blocked deferred remote-code execution (download → execute). "
                "Use a verified install pattern: "
                "github.com/nodox-studio/claukit/blob/main/SECURITY-PATTERNS.md#8"
            )

    # Reverse shells
    for pattern in REVERSE_SHELL_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            deny("blocked reverse shell pattern")

    # Sensitive env vars being exfiltrated
    for var in SENSITIVE_ENV_VARS:
        if var in cmd and re.search(r"\b(curl|wget|nc|socat|http)\b", cmd, re.IGNORECASE):
            deny(f"blocked potential exfiltration of {var}")

    # Entropy — high-entropy token + network/exec sink = obfuscated payload
    # Bounded {30,512} + first-N cap defends against ReDoS / pathological inputs.
    sink_match = ENTROPY_SINKS.search(cmd)
    if sink_match:
        sink = sink_match.group(1)
        token_re = r"[A-Za-z0-9+/=_-]{%d,512}" % ENTROPY_MIN_LEN
        for token in re.findall(token_re, cmd)[:ENTROPY_MAX_TOKENS]:
            score = _shannon(token)
            threshold = ENTROPY_THRESHOLD_LONG if len(token) > 60 else ENTROPY_THRESHOLD_SHORT
            if score >= threshold:
                deny(_entropy_message(token, score, sink))

    # SQLi — string concatenation into SQL queries (bounded scan)
    sqli_input = cmd[:SQLI_MAX_LEN]
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, sqli_input, re.IGNORECASE | re.DOTALL):
            deny(
                "blocked SQL query built with string concatenation — "
                "use parameterized queries or an ORM instead."
            )

    # Cap how many install tokens we validate per command — defends against
    # `npm install pkg1 pkg2 … pkg9999` pathological inputs.
    INSTALL_MAX_PKGS = 20

    # npm / pnpm / yarn / bun install — validate every package, not only the
    # first. Earlier `re.search` only captured one match, so a typosquat in
    # `npm install lodash react fake-pkg` slipped through.
    npm_verb = re.search(
        r"\b(npm\s+install|pnpm\s+add|yarn\s+add|bun\s+add)\b",
        cmd, re.IGNORECASE,
    )
    if npm_verb:
        rest = cmd[npm_verb.end():]
        rest = re.split(r";|&&|\|\||\|", rest, maxsplit=1)[0]
        for token in rest.split()[:INSTALL_MAX_PKGS]:
            if not token or token.startswith("-"):
                continue
            name, _, version = token.partition("@")
            name = name.lower()
            if name and not name.startswith("@"):
                check_npm_package(name, version or None)

    # pip install — same treatment. Handles version specifiers per token
    # (requests==2.28.0, requests>=2.0, requests[security]==1.0).
    pip_verb = re.search(r"\bpip3?\s+install\b", cmd, re.IGNORECASE)
    if pip_verb:
        rest = cmd[pip_verb.end():]
        rest = re.split(r";|&&|\|\||\|", rest, maxsplit=1)[0]
        for token in rest.split()[:INSTALL_MAX_PKGS]:
            if not token or token.startswith("-"):
                continue
            name = re.split(r"[=<>!]", token)[0].strip().lower()
            version_match = re.search(r"==\s*([\w.]+)", token)
            version = version_match.group(1) if version_match else None
            if name:
                check_pypi_package(name, version)


def check_npm_package(name: str, version: str | None) -> None:
    # Typosquatting check
    for popular in POPULAR_NPM_PACKAGES:
        if name == popular:
            break
        if len(name) > 3 and _levenshtein(name, popular) == 1:
            deny(
                f"'{name}' looks like a typosquat of '{popular}'. "
                f"Verify at npmjs.com/package/{popular} before installing."
            )

    # OSV check — version pinned → hard deny on hit; unpinned → ask if history exists.
    if version:
        cves = query_osv(name, "npm", version)
        if cves:
            deny(
                f"'{name}@{version}' has known vulnerabilities: {', '.join(cves[:5])}. "
                f"Check https://osv.dev/list?q={name} for details."
            )
    else:
        history = query_osv(name, "npm")
        if history:
            ask(
                f"'{name}' has {len(history)} historical CVE(s) — installing without "
                f"a pinned version means picking whatever npm serves today. "
                f"Examples: {', '.join(history[:3])}. Pin a known-safe version "
                f"(e.g. {name}@<version>) to remove this warning."
            )


def check_pypi_package(name: str, version: str | None) -> None:
    # Typosquatting check
    for popular in POPULAR_PYPI_PACKAGES:
        if name == popular:
            break
        if len(name) > 3 and _levenshtein(name, popular) == 1:
            deny(
                f"'{name}' looks like a typosquat of '{popular}'. "
                f"Verify at pypi.org/project/{popular} before installing."
            )

    # OSV check — version pinned → hard deny on hit; unpinned → ask if history exists.
    if version:
        cves = query_osv(name, "PyPI", version)
        if cves:
            deny(
                f"'{name}=={version}' has known vulnerabilities: {', '.join(cves[:5])}. "
                f"Check https://osv.dev/list?q={name} for details."
            )
    else:
        history = query_osv(name, "PyPI")
        if history:
            ask(
                f"'{name}' has {len(history)} historical CVE(s) — installing without "
                f"a pinned version means picking whatever pip serves today. "
                f"Examples: {', '.join(history[:3])}. Pin a known-safe version "
                f"(e.g. {name}=={version or '<version>'}) to remove this warning."
            )


def check_write_content(content: str) -> None:
    """Check code being written by Claude for SQLi patterns."""
    if not content:
        return
    scan = content[:SQLI_MAX_LEN]
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, scan, re.IGNORECASE | re.DOTALL):
            deny(
                "blocked writing SQL query with string concatenation — "
                "use parameterized queries or an ORM instead."
            )


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError, EOFError):
        sys.exit(0)

    tool = data.get("tool_name", "")
    inp = data.get("tool_input", {})

    # Populate context for audit log
    _CTX["tool"] = tool
    if tool == "Bash":
        _CTX["cmd"] = inp.get("command", "")
        check_bash(inp.get("command", ""))

    elif tool == "Write":
        _CTX["cmd"] = inp.get("file_path", "")
        check_path(inp.get("file_path", ""))
        check_write_content(inp.get("content", ""))

    elif tool == "Edit":
        _CTX["cmd"] = inp.get("file_path", "")
        check_path(inp.get("file_path", ""))
        check_write_content(inp.get("new_string", ""))

    elif tool == "MultiEdit":
        fp = inp.get("file_path", "")
        _CTX["cmd"] = fp
        check_path(fp)
        for edit in inp.get("edits", []) or []:
            check_write_content(edit.get("new_string", ""))

    elif tool == "NotebookEdit":
        nb = inp.get("notebook_path", "")
        _CTX["cmd"] = nb
        check_path(nb)
        check_write_content(inp.get("new_source", ""))

    elif tool == "Read":
        _CTX["cmd"] = inp.get("file_path", "")
        check_path(inp.get("file_path", ""))

    sys.exit(0)


if __name__ == "__main__":
    main()
