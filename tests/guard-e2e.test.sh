#!/usr/bin/env bash
# End-to-end test for ClauKit as a Claude Code plugin.
# Simulates the plugin-installed environment by exporting CLAUDE_PLUGIN_ROOT
# to this repo, then feeds each hook the JSON Claude Code would send.
# Validates: hooks are present and executable, hooks.json declares handlers,
# and the deny paths actually deny.

set -u
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$TEST_DIR/.." && pwd)"

# Simulate the plugin-installed environment.
export CLAUDE_PLUGIN_ROOT="$REPO"

PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf "  PASS  %s\n" "$1"; }
ko() { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"; }

command -v jq      >/dev/null || { echo "  SKIP  jq not installed";      exit 0; }
command -v python3 >/dev/null || { echo "  SKIP  python3 not installed"; exit 0; }

# Hooks present and executable
[ -x "$CLAUDE_PLUGIN_ROOT/hooks/git-safety.sh" ] \
  && ok "git-safety.sh exists and is executable" \
  || ko "git-safety.sh missing or not +x"

[ -r "$CLAUDE_PLUGIN_ROOT/hooks/claukit-guard.py" ] \
  && ok "claukit-guard.py exists and is readable" \
  || ko "claukit-guard.py missing"

# hooks.json declares PreToolUse handlers
hooks_json="$CLAUDE_PLUGIN_ROOT/hooks/hooks.json"
if [ -f "$hooks_json" ] && jq -e '.hooks.PreToolUse | length > 0' "$hooks_json" >/dev/null 2>&1; then
  ok "hooks.json declares PreToolUse handlers"
else
  ko "hooks.json missing or has no PreToolUse handlers"
fi

# Force-push gets denied end-to-end through git-safety.sh
out=$(jq -nc '{tool_name:"Bash",tool_input:{command:"git push --force origin main"}}' \
  | "$CLAUDE_PLUGIN_ROOT/hooks/git-safety.sh")
if echo "$out" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
  ok "force push denied through git-safety.sh"
else
  ko "force push not denied — got: $out"
fi

# Benign git command passes through
out=$(jq -nc '{tool_name:"Bash",tool_input:{command:"git status"}}' \
  | "$CLAUDE_PLUGIN_ROOT/hooks/git-safety.sh")
[ -z "$out" ] && ok "git status passes through git-safety.sh" \
              || ko "git status wrongly denied: $out"

# claukit-guard.py runs cleanly on benign input
out=$(jq -nc '{tool_name:"Bash",tool_input:{command:"echo hello"}}' \
  | python3 "$CLAUDE_PLUGIN_ROOT/hooks/claukit-guard.py" 2>&1)
rc=$?
[ "$rc" = "0" ] && ok "claukit-guard.py runs on benign input" \
                || ko "claukit-guard.py crashed (exit $rc): $out"

# Sensitive path Read gets denied
out=$(jq -nc --arg p "$HOME/.ssh/id_rsa" '{tool_name:"Read",tool_input:{file_path:$p}}' \
  | python3 "$CLAUDE_PLUGIN_ROOT/hooks/claukit-guard.py" 2>&1)
if echo "$out" | grep -q '"permissionDecision"[[:space:]]*:[[:space:]]*"deny"'; then
  ok "sensitive path Read denied through claukit-guard.py"
else
  ko "sensitive path Read not denied — got: $out"
fi

printf "\n%d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
