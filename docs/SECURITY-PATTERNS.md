# Security Patterns

Defensive patterns hardened in `claukit-app` during the v1.1.0 audit cycle. Each one is in production here — the code blocks are the real implementation, not pseudo-code. Use them as-is or adapt them to your stack.

These are deliberately stack-agnostic where possible (bash + Python in our case, but the principles travel).

> **Why these patterns exist.** Each came out of a concrete finding in our P0/P1/P2/P3 audit (commits `68c00ba`, `6219703`, `9383ac6`). What's documented here are the bugs and bypasses we actually had — not theoretical risks.

---

## Index

1. [Audit log every privileged decision](#1-audit-log-every-privileged-decision)
2. [Bound your regexes — every one of them](#2-bound-your-regexes--every-one-of-them)
3. [Pre-action snapshot + EXIT trap = a free undo](#3-pre-action-snapshot--exit-trap--a-free-undo)
4. [Idempotent + TOCTOU-safe config edits](#4-idempotent--toctou-safe-config-edits)
5. [Structured event logging with labels](#5-structured-event-logging-with-labels)
6. [`set -u` + `pipefail` without `-e`](#6-set--u--pipefail-without--e)
7. [Validate input, then build commands as arrays](#7-validate-input-then-build-commands-as-arrays)
8. [Don't `curl URL | bash` — verify, then execute](#8-dont-curl-url--bash--verify-then-execute)

---

## 1. Audit log every privileged decision

**The bug we had:** `/lock-claude` and `/unlock-claude` modified `~/.claude/settings.json` silently. If a malicious MCP or prompt injection convinced Claude to call `/unlock-claude`, the deny rules would be removed without any forensic trail. Same on `claukit-guard.py` — it would block dangerous commands but leave no record an attacker could be analyzed against.

**The pattern:** every command/hook/script that takes a privileged action appends a one-line, append-only event to a log file in `~/.claude/`. Best-effort: a logging error must never prevent the security action.

**Bash version (used in `lock-claude.md` / `unlock-claude.md`):**

```bash
log=$(python3 -c "import os; print(os.path.expanduser('~/.claude/claukit-security.log'))")
python3 -c "
import datetime, sys
stamp = datetime.datetime.now().isoformat(timespec='seconds')
with open('$log', 'a') as f:
    f.write(f'{stamp}  UNLOCK  removed={sys.argv[1]}\n')
" "$removed_rules" 2>/dev/null || true
```

**Python version (used in `claukit-guard.py`):**

```python
def _log_event(label: str, tool: str, message: str, cmd: str = "") -> None:
    """Append a forensic entry. Best-effort: never fail on log error."""
    try:
        log_dir = os.path.join(HOME, ".claude")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "claukit-guard.log")
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        cmd_safe = (cmd or "").replace("\n", " ").replace("\r", " ")[:200]
        line = f"{stamp}  {label:<5s}  tool={tool or '-'}  reason={message!r}  cmd={cmd_safe!r}\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass
```

**When to apply:**

- Any hook that grants/denies access (PreToolUse, PostToolUse).
- Any script that modifies `~/.claude/`, `settings.json`, or other config the user is unlikely to inspect frequently.
- Any flow where a future "what happened?" question is plausible. If you can imagine being asked "why did Claude run X yesterday?", log it.

**What to keep out:** never log the full command if it could contain secrets. Truncate (`cmd[:200]` here), strip newlines, and never log values from `tool_input` you haven't classified.

---

## 2. Bound your regexes — every one of them

**The bug we had:** `claukit-guard.py` used `[A-Za-z0-9+/=_-]{30,}` to detect high-entropy tokens. No upper bound. A pathological input — say, a 50 KB single-token command — would cause `re.findall` to scan the whole thing in one match. With `re.findall` returning a single huge string, the subsequent `_shannon()` call iterates char-by-char. The hook stalls. Effectively a DoS against the security layer.

**The pattern:** every regex has both a lower and upper repetition bound, and `re.findall` results are capped before iteration.

```python
ENTROPY_MIN_LEN    = 30   # ignore short tokens (UUIDs ~4.1, safely below)
ENTROPY_MAX_TOKENS = 10   # cap to defend against pathological inputs

token_re = r"[A-Za-z0-9+/=_-]{%d,512}" % ENTROPY_MIN_LEN
for token in re.findall(token_re, cmd)[:ENTROPY_MAX_TOKENS]:
    score = _shannon(token)
    # …
```

**Why both:** the `{30,512}` bound caps the size of any single match. The `[:10]` cap caps the *number* of matches. Either alone leaves a hole — a 10 GB input could still produce millions of small matches.

**When to apply:**

- Every regex over user-controlled input. No exceptions.
- Every regex inside a hook or pre-flight check (latency budget = nothing).
- Every regex inside a parser that runs at scale.

**Verification:** add a unit test with a pathological input. We have one — a 50 KB single-token command — and it returns in <200 ms.

---

## 3. Pre-action snapshot + EXIT trap = a free undo

**The bug we had:** `install.sh` modifies `~/.claude/` in many places. If it fails halfway (network drop during a `curl`, user Ctrl-C, or a logic bug), the user is left with a partially-modified config with no obvious way back.

**The pattern:** snapshot the target before any write, set a `trap on_exit EXIT`, and on non-zero exit, surface the rollback command. On success, surface the cleanup command.

```bash
# Snapshot before any write
BACKUP_DIR=""
if [ -d "$TARGET" ]; then
  BACKUP_DIR="$TARGET.backup-$(date +%Y%m%d-%H%M%S)"
  if cp -a "$TARGET" "$BACKUP_DIR" 2>/dev/null; then
    echo "Backup: $BACKUP_DIR"
  else
    BACKUP_DIR=""  # never reference a backup that wasn't created
  fi
fi

on_install_exit() {
  local exit_code=$?
  if [ $exit_code -ne 0 ] && [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    echo "Install interrupted (exit $exit_code)."
    echo "To roll back: rm -rf \"$TARGET\" && mv \"$BACKUP_DIR\" \"$TARGET\""
  fi
}
trap on_install_exit EXIT
```

At the end (success path), show the path so the user can clean up:

```bash
if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
  echo "Pre-install snapshot: $BACKUP_DIR"
  echo "Once you've confirmed everything works: rm -rf \"$BACKUP_DIR\""
fi
```

**Important nuances:**

- **Never auto-restore.** The user might have started other work in the target between the snapshot and the failure. Auto-restore could destroy that. Show the command, don't run it.
- **`cp -a`, not `cp -r`.** Preserves modes, timestamps, symlinks.
- **Reset `BACKUP_DIR=""` if the snapshot fails.** Otherwise the trap will reference a directory that doesn't exist.

---

## 4. Idempotent + TOCTOU-safe config edits

**The bug we had:** the `.npmrc` hardener checked `grep -q "ignore-scripts=true"` — which matched `ignore-scripts=false` because the substring `true` appeared in `false`. Even after fixing that, two more issues remained: between the check and the write, another process could create the file (TOCTOU); and re-running the installer would append duplicate lines because the check was looking for the literal substring, not "is the line already there?".

**The pattern:** anchor the regex, ensure trailing newline, and re-check immediately before the write so the same script can run twice without producing duplicates.

```bash
NPMRC_FILE="$HOME/.npmrc"

# Anchored regex — `ignore-scripts=false` no longer matches.
# Tolerate optional whitespace around the `=`.
if [ -f "$NPMRC_FILE" ] && grep -qE "^ignore-scripts[[:space:]]*=[[:space:]]*true" "$NPMRC_FILE" 2>/dev/null; then
  echo "already set"
else
  # Ensure trailing newline so the append doesn't merge with a previous line
  if [ -f "$NPMRC_FILE" ] && [ -s "$NPMRC_FILE" ] && [ "$(tail -c 1 "$NPMRC_FILE" 2>/dev/null)" != "" ]; then
    printf '\n' >> "$NPMRC_FILE"
  fi
  # Re-check between previous test and write — defends against a concurrent edit
  if ! grep -qE "^ignore-scripts[[:space:]]*=[[:space:]]*true" "$NPMRC_FILE" 2>/dev/null; then
    echo "ignore-scripts=true" >> "$NPMRC_FILE"
  fi
fi
```

**When to apply:** any time you edit a config file the user might also be editing, any time the script may run twice (idempotency), and any time the regex could false-positive on a substring (anchor it).

---

## 5. Structured event logging with labels

**The bug we had:** when our OSV vulnerability lookup failed (network down, API rate-limited), the guard fell through with `return []` — a "fail open" that we'd kept on purpose for UX, but which was completely silent. After enough fail-opens, a typosquat could slip through and we'd never know.

**The pattern:** a single logger that takes a label parameter (`BLOCK`, `WARN`, `INFO`), so future event types don't require a new writer. Fail-open *with visibility* beats fail-open silent.

```python
def _log_event(label: str, tool: str, message: str, cmd: str = "") -> None:
    """Append a forensic entry. Best-effort: never fail on log error."""
    # … (see pattern 1 for the body)

def _audit_log(tool: str, reason: str, cmd: str) -> None:
    """Block event — thin wrapper for backwards compat."""
    _log_event("BLOCK", tool, reason, cmd)

# In the OSV failure path:
except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError) as e:
    _log_event(
        "WARN",
        _CTX.get("tool", ""),
        f"OSV query failed for {ecosystem}:{name} ({type(e).__name__}) — fail-open",
        _CTX.get("cmd", ""),
    )
    return []  # fail-open is intentional, but no longer silent
```

**Why labels matter:** the same log file holds every event. `grep BLOCK` for blocks, `grep WARN` for warnings. A future `INFO` (e.g., "user explicitly approved this") doesn't need a new file.

---

## 6. `set -u` + `pipefail` without `-e`

**The bug we had:** the original `statusline.sh` had no `set` flags. Any silent failure (a missing `jq` filter match, a broken network call to RTK) would leave variables unset and produce a partially-rendered status line. We tried `set -euo pipefail` and immediately broke the script — `jq -r '.field // "?"'` is *intended* to fall through silently, and `grep -oE` lookups *intentionally* don't always match.

**The pattern:** turn on `-u` (catches typos in variable names) and `pipefail` (surfaces failures buried in pipes). Leave `-e` off where the script intentionally tolerates command failure.

```bash
#!/bin/bash
# Note: -e is intentionally omitted. The script tolerates individual jq/grep
# failures by relying on `// "?"` and `// 0` defaults inside jq filters and
# uses many `grep -oE` lookups that may legitimately not match. -u catches
# typos in variable names; pipefail surfaces failures buried in pipelines.
set -u
set -o pipefail

# Guard variables that might legitimately be unset:
if [ -n "${TMUX:-}" ]; then
  # …
fi
```

**Decision tree:**

- The script is supposed to be airtight (every step must succeed) → `set -euo pipefail`.
- The script is a chain of best-effort operations with sane defaults → `set -uo pipefail`. Document the choice in a comment near the `set` line.
- The script is a one-liner exploration → none, but use `${VAR:-}` everywhere.

**Don't blindly add `-e` and call it a security improvement.** It can mask bugs by silently exiting before the cleanup logic runs.

---

## 7. Validate input, then build commands as arrays

**The bug we had:** the installer asked the user for an Obsidian vault name and path, then passed them straight into `claude mcp add "$VAULT_NAME" --env "OBSIDIAN_VAULT_PATH=$VAULT_PATH" …`. If the vault name contained `--env BAD=x`, those tokens could be re-interpreted as flags by `claude mcp add`. If the vault path contained a glob character or a relative path, traversal was possible.

**The pattern:** two layers of defense. Validate the input shape with a strict regex (or `case`); then build the command as an array so no value can be re-parsed as a flag.

```bash
# 1. Validate the name with a strict regex
if [[ ! "$VAULT_NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "Invalid vault name (use letters, digits, _ or - only)"
  continue
fi

# 2. Validate the path structurally with `case` — must be absolute or ~/-prefixed
case "$VAULT_PATH" in
  /*|"$HOME"/*|"~/"*) ;;  # OK
  *)
    echo "Path must be absolute (start with / or ~/)"
    continue
    ;;
esac

# 3. Build the command as an array — values containing whitespace, `--env`,
# or `--` cannot be reinterpreted as flags by the downstream parser
mcp_args=(
  "$VAULT_NAME"
  --env "OBSIDIAN_VAULT_PATH=$VAULT_PATH"
  --env "OBSIDIAN_API_TOKEN=$VAULT_TOKEN"
  --env "OBSIDIAN_API_PORT=27123"
  --
  npx -y @huangyihe/obsidian-mcp
)

claude mcp add "${mcp_args[@]}"
```

**Why both validation *and* arrays?** Arrays prevent re-parsing as flags but don't stop a perfectly-quoted-but-malicious value from reaching the downstream tool. Validation rejects malicious values before they get there. Defense in depth.

**When to apply:**

- Any time user input becomes part of an `exec`-style call.
- Any time the downstream tool has a `--` argument separator (the array form is what makes `--` work).
- When you display the equivalent command to the user (so the example doesn't teach a worse pattern). In the fallback display, quote variables: `claude mcp add '${VAULT_NAME}' …`.

---

## 8. Don't `curl URL | bash` — verify, then execute

**The bug we had:** `install.sh` itself, in v1.0.0, did this:

```bash
curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/master/install.sh | bash
curl -fsSL https://bun.sh/install | bash
```

Two RCE-shaped statements inside our own installer — the same pattern we tell users to avoid. Any MITM, partial download, or upstream tamper would have run arbitrary code on the user's machine, and we'd have shipped it ourselves.

**The pattern:** download to a tempfile, compute the hash, refuse on mismatch, execute the file. Three steps where there used to be one.

```bash
# Replaces direct `curl URL | bash`. Defends against MITM, partial downloads,
# and mid-stream tampering. Args: <url> [expected_sha256]
verified_pipe_install() {
  local url="$1" expected_sha="${2:-}"
  local tmpfile actual_sha sha_cmd
  tmpfile=$(mktemp -t claukit_install.XXXXXX) || { echo "  ✗ mktemp failed"; return 1; }
  trap 'rm -f "$tmpfile"' RETURN

  if ! curl -fsSL --max-time 60 "$url" -o "$tmpfile"; then
    echo "  ✗ Download failed: $url"
    return 1
  fi
  if [ ! -s "$tmpfile" ]; then
    echo "  ✗ Empty download from $url"
    return 1
  fi

  if command -v shasum &>/dev/null; then sha_cmd="shasum -a 256"
  elif command -v sha256sum &>/dev/null; then sha_cmd="sha256sum"
  else sha_cmd=""; fi

  if [ -n "$sha_cmd" ]; then
    actual_sha=$($sha_cmd "$tmpfile" | cut -d' ' -f1)
    if [ -n "$expected_sha" ] && [ "$actual_sha" != "$expected_sha" ]; then
      echo "  ✗ SHA256 mismatch — refusing to execute"
      echo "    expected: $expected_sha"
      echo "    got:      $actual_sha"
      return 1
    fi
    [ -z "$expected_sha" ] && echo "  sha256: $actual_sha"
  fi

  bash "$tmpfile"
}

# Use:
verified_pipe_install "https://raw.githubusercontent.com/rtk-ai/rtk/master/install.sh"
```

**Three modes of operation, one helper:**

- **No expected SHA passed:** download, compute the hash, log it, execute. The hash in the log is your forensic record — if the upstream is later compromised, you can compare.
- **Expected SHA passed:** download, compute the hash, refuse to execute on mismatch. Use this when you've pinned a commit and verified the binary once.
- **No `shasum` / `sha256sum` available:** download, skip the hash, execute. Still safer than the pipe form because the file is on disk and the script can be inspected if something looks wrong.

**Why this is better than `curl … | bash`:**

- The download is **complete** before execution begins. A network drop mid-pipe can leave a half-finished script that bash starts running before the rest arrives.
- The file is on disk. If something looks wrong, `cat $tmpfile` shows what would have run.
- The hash is computable. Even without a pinned expected value, logging the observed hash creates a forensic trail.
- The trap removes the tempfile on return regardless of success or failure.

**When to apply:** any time you're tempted to write `curl … | bash`. Including, especially, when "everyone does it" — `bun.sh/install`, `rtk-ai`, `pnpm`, `rustup`. Convenience for them, your machine for you.

ClauKit Guard blocks the unverified pipe pattern in user code (see `hooks/claukit-guard.py`). When it fires, the deny message links here so the user gets both the "no" and the "do this instead".

---

## How these patterns are tested

Each pattern came with at least one test case that locked in the fix:

| Pattern | Test |
|---|---|
| Audit log | Manual: trigger a block, verify a line appears in `~/.claude/claukit-guard.log` |
| Bounded regex | A 50 KB pathological input completes the hook in <200 ms (vs. seconds before) |
| Snapshot + trap | Manual: kill `install.sh` mid-run, verify the rollback command appears |
| Idempotent edits | Run the same installer twice; `.npmrc` ends with one line, not two |
| Labels | `grep BLOCK ~/.claude/claukit-guard.log` returns blocks, `grep WARN` returns OSV failures |
| Defensive flags | E2E render of `statusline.sh` produces a complete status bar even with partial input |
| Validate + array | A vault name like `vault --env BAD=x` is rejected by the regex; a relative path `../../etc/passwd` is rejected by the `case` |
| Verified pipe install | Download with a known-bad upstream produces an SHA mismatch and aborts; download with no expected SHA logs the observed hash for later comparison |

Add at least one test before declaring a pattern adopted.

---

*This guide consolidates eight Features Backlog entries into a single reference. Each pattern is in production in `claukit-app` v1.1.0.*
