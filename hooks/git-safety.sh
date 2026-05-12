#!/usr/bin/env bash
# git-safety.sh — PreToolUse hook that blocks dangerous git operations.
#
# Blocks:
#   - git push --force / -f       (allows --force-with-lease, the safe variant)
#   - git reset --hard
#   - git branch -D main / master
#   - git clean -f / -fd / --force
#
# Design notes:
#
#   The hook is fed the raw command string the model wants to run. Naive
#   substring matching (e.g. grep "--force") triggers false blocks when
#   --force appears inside a heredoc, comment, or echo. We resolve that by
#   stripping common prefixes (`cd ... &&`, `rtk proxy`, env vars) to obtain
#   an EFFECTIVE_CMD, and only enforce when the effective command actually
#   *starts* with the matching git subcommand.
#
# Fail-open: if jq is missing the hook exits 0 and lets the command run —
# the guard is defense-in-depth, not the only line of defense.

if ! command -v jq &>/dev/null; then
  exit 0
fi

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [ "$TOOL" != "Bash" ] || [ -z "$CMD" ]; then
  exit 0
fi

EFFECTIVE_CMD=$(echo "$CMD" | sed -E '
  s/^[[:space:]]*(cd[[:space:]][^&;|]*[[:space:]]*(&&|;)[[:space:]]*)+//
  s/^[[:space:]]*(rtk[[:space:]]+proxy[[:space:]]+)+//
  s/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)+//
')

deny() {
  jq -n --arg reason "$1" '{
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": $reason
    }
  }'
  exit 0
}

is_git_subcmd() {
  echo "$EFFECTIVE_CMD" | grep -qE "^git[[:space:]]+$1\b"
}

# git push --force / -f  (allow --force-with-lease)
if is_git_subcmd push; then
  if echo "$EFFECTIVE_CMD" | grep -qE '(^|[[:space:]])--force-with-lease(\b|=)'; then
    :
  elif echo "$EFFECTIVE_CMD" | grep -qE '(^|[[:space:]])(--force(\b|=)|-f\b)'; then
    deny "GIT SAFETY: blocked force push. Use --force-with-lease if truly needed."
  fi
fi

# git reset --hard
if is_git_subcmd reset; then
  if echo "$EFFECTIVE_CMD" | grep -qE '(^|[[:space:]])--hard\b'; then
    deny "GIT SAFETY: blocked git reset --hard. Stash or commit first."
  fi
fi

# git branch -D main / master
if is_git_subcmd branch; then
  if echo "$EFFECTIVE_CMD" | grep -qE '(^|[[:space:]])-D[[:space:]]+(main|master)\b'; then
    deny "GIT SAFETY: blocked deletion of main/master branch."
  fi
fi

# git clean -f / -fd / --force
if is_git_subcmd clean; then
  if echo "$EFFECTIVE_CMD" | grep -qE '(^|[[:space:]])(-f[a-zA-Z]*|--force)\b'; then
    deny "GIT SAFETY: blocked git clean -f. Review untracked files first."
  fi
fi

exit 0
