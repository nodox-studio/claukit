# Changelog

All notable changes to ClauKit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-12

### Added

- Initial release as a Claude Code plugin.
- `hooks/claukit-guard.py` — PreToolUse hook covering Bash, Read, Write, Edit, MultiEdit, NotebookEdit. Blocks sensitive paths, supply-chain attacks, exfiltration targets, and dangerous content writes.
- `hooks/git-safety.sh` — PreToolUse hook covering Bash. Blocks `git push --force`, `git reset --hard`, `git branch -D` on protected branches, and `git clean -f`.
- `docs/SECURITY-PATTERNS.md` — Hook shipping protocol §9: fail-closed on crash, Python ≥3.7 / Bash ≥3.2, ≥1 crash-case test per hook file.
- 57 tests across `tests/guard.test.sh` (25), `tests/guard-e2e.test.sh` (6), and `tests/git-safety.test.sh` (26).

### Notes

This is a fresh start. Earlier `v1.x` releases distributed as a bash installer have been retired — they predated Claude Code's official plugin format and required manual `settings.json` patching. The plugin format provides declarative install, versioned updates, and clean uninstall via `/plugin` natively.
