# Security Policy

ClauKit is a security-oriented toolkit. We take vulnerabilities in our own code seriously and welcome responsible disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

The `main` branch always reflects the latest supported state.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, use one of these private channels:

1. **Preferred — GitHub Security Advisories**
   [Open a private advisory](https://github.com/nodox-studio/claukit/security/advisories/new)

2. **Secondary — Email**
   `somos@nodox.studio` — please use the subject line `[SECURITY] ClauKit: <short description>`

When reporting, include if possible:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof-of-concept
- The version, commit hash, or `main` if applicable
- Your assessment of severity (if you have one)
- Whether you'd like to be credited in the fix announcement

## What to Expect

- **Acknowledgement** within **72 hours** of your report.
- **Initial assessment** within **7 days** — severity, scope, and remediation plan.
- **Fix and disclosure** coordinated with you. We aim to publish a fix within 30 days for high-severity issues.
- We will not pursue legal action against good-faith researchers who follow this policy.

## Scope

In scope:

- `install.sh` and any code it executes
- `hooks/claukit-guard.py` (PreToolUse hook logic and bypass paths)
- `commands/*.md` (slash command instructions, especially `/lock-claude` and `/unlock-claude`)
- `statusline.sh`
- The installer's modifications to `~/.claude/`

Out of scope:

- Vulnerabilities in upstream dependencies (Claude Code, Obsidian, RTK, Bun, npm, pnpm) — please report those to the respective projects.
- Issues that require physical access to the user's machine.
- Self-inflicted misconfiguration (e.g., the user manually disables `/guard` and then encounters an issue blocked by it).
- Social engineering of the user outside of what `claukit-guard.py` claims to detect.

## Hall of Fame

Researchers who report valid vulnerabilities will be credited here (with their consent) once the fix is public.

_None yet._
