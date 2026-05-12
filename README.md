# ClauKit

Security hooks for Claude Code. Blocks dangerous commands, sensitive file access, force-pushes, and supply-chain attacks before they execute.

Fail-closed on crash. Curated threat catalog. Pure stdlib — no runtime dependencies beyond `python3` and `jq`.

## What it blocks

**Supply chain (Bash)**
- `npm install` / `pnpm add` / `yarn add` of known-malicious or typosquatted packages (hard `deny`)
- `pip install` / `uv add` of pypi packages with known compromises (hard `deny`)
- Pinned versions affected by a known CVE — checked against OSV (hard `deny`)
- Unpinned installs of packages with historical CVE records — soft `ask` to nudge pinning
- `curl ... | sh` and similar pipe-to-shell patterns from untrusted hosts

**Sensitive paths (Read / Write / Edit / MultiEdit / NotebookEdit)**
- `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.netrc`, `~/.pypirc`, `~/.docker/config.json`, `~/.config/gcloud/`, `/etc/shadow`, `/etc/sudoers`
- Any `.env*`, SSH private keys, `.npmrc`, `.pgpass`, `credentials.json`, `terraform.tfvars*` matched by basename anywhere in the tree
- Any file with extension `.pem`, `.key`, `.p12`, `.pfx` (private keys and PKCS#12 bundles). Public-cert formats `.crt` / `.cer` / `.csr` intentionally remain allowed — they are not secrets.

**Git footguns (Bash)**
- `git push --force` / `-f` (allows `--force-with-lease`, the safe variant)
- `git reset --hard`
- `git branch -D main` / `master`
- `git clean -f` / `-fd`

**Exfiltration (Bash)**
- Outbound to `transfer.sh`, `webhook.site`, `ngrok.io`, and known C2 hosts
- Known IOCs from real incidents (Postmark MCP, etc.)

## Decision tiers

Each rule returns one of three outcomes — borrowed from the underlying Claude Code hook protocol:

| Outcome | When | Effect |
|---|---|---|
| `allow` (silent) | No rule matched | Tool call proceeds normally |
| `ask` | Soft warning (e.g. unpinned package has historical CVEs) | Claude Code prompts the user — proceed if intentional, decline otherwise |
| `deny` | Hard block (typosquats, sensitive paths, known affected versions, footguns) | Tool call is rejected with a `permissionDecisionReason` explaining what triggered it |

## Install

```bash
# Add the Nodox Studio marketplace
/plugin marketplace add nodox-studio/claukit

# Install the plugin
/plugin install claukit@nodox-studio
```

The hooks are active immediately. No `settings.json` patching, no installer script, no manual steps.

## Verify

After install, run `/plugin list` and confirm `claukit` is enabled. Then try a benign block to confirm the hook fires:

```
Run "git push --force origin main"
```

Claude should refuse with a `permissionDecisionReason` from `git-safety.sh`. If it doesn't, the hooks aren't loading — see [troubleshooting](#troubleshooting).

## Requirements

- Claude Code with `/plugin` support
- `python3` ≥ 3.7 (uses `from __future__ import annotations` for forward-compat with PEP 604 syntax)
- `jq` (used by `git-safety.sh` for JSON parsing — exits silently if missing, so the hook is defense-in-depth, not the only line)

## Design principles

1. **Fail-closed on crash.** A guard that crashes silently is worse than no guard — it gives false confidence. If the Python script throws or the bash script errors, the tool call is denied with a clear reason.
2. **Curated, not heuristic.** The threat catalog lists real IOCs from real incidents (Postmark, typosquats of `request`, `colors`, etc.). No fuzzy ML, no false-positive theatre.
3. **No state.** Hooks read stdin, decide, exit. No log files in your home, no telemetry, no network unless explicitly checking a package registry.
4. **One responsibility per file.** `claukit-guard.py` handles paths + supply chain + content scanning. `git-safety.sh` handles git footguns. Each is auditable in one read.

## Threat catalog

See [`docs/SECURITY-PATTERNS.md`](docs/SECURITY-PATTERNS.md) for the full hook shipping protocol and the rules each detector enforces.

## Environment variables

| Variable | Effect |
|---|---|
| `CLAUKIT_OFFLINE=1` | Skip all OSV network queries. Useful in air-gapped environments or to make CI runs deterministic. Local detection rules (typosquats, sensitive paths, git footguns) still run. |

## Troubleshooting

Hooks not firing:
```bash
/plugin list                          # is claukit enabled?
claude plugin validate ~/Code/claukit # is the manifest valid?
/reload-plugins                       # force reload after a manifest edit
```

Verify the hook scripts run cleanly outside Claude:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"}}' \
  | ~/.claude/plugins/cache/<...>/claukit/hooks/git-safety.sh
```

A `deny` JSON response confirms the hook is functional.

## License

MIT — see [LICENSE](LICENSE).

## Security policy

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.
