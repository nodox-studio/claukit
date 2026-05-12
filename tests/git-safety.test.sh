#!/usr/bin/env bash
# Smoke test for hooks/git-safety.sh — covers the four blocked git operations,
# prefix permutations (cd/rtk proxy/env), and pass-through paths.
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$TEST_DIR/../hooks/git-safety.sh"

PASS=0
FAIL=0

run_case() {
  local desc="$1" cmd="$2" expect="$3"
  local out
  out=$(jq -nc --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}' | "$HOOK")
  if [ -z "$out" ]; then
    actual=allow
  else
    actual=deny
  fi
  if [ "$actual" = "$expect" ]; then
    PASS=$((PASS+1))
    printf "  PASS  %s\n" "$desc"
  else
    FAIL=$((FAIL+1))
    printf "  FAIL  %s (expected %s, got %s)\n" "$desc" "$expect" "$actual"
    [ -n "$out" ] && printf "        %s\n" "$out"
  fi
}

run_case "force push plain"             'git push --force origin main'           deny
run_case "force push -f"                'git push -f'                            deny
run_case "force-with-lease allowed"     'git push --force-with-lease'            allow
run_case "force-with-lease=ref allowed" 'git push --force-with-lease=main:abc'   allow
run_case "force inside echo"            "echo 'tip: --force is dangerous'"       allow
run_case "reset hard blocked"           'git reset --hard HEAD~1'                deny
run_case "reset hard with branch"       'git reset --hard origin/main'           deny
run_case "reset soft allowed"           'git reset HEAD~1'                       allow
run_case "reset --soft allowed"         'git reset --soft HEAD~1'                allow
run_case "reset hard inside heredoc"    "cat <<'E'\ngit reset --hard\nE"         allow
run_case "branch -D main"               'git branch -D main'                     deny
run_case "branch -D master"             'git branch -D master'                   deny
run_case "branch -D feature"            'git branch -D feature/x'                allow
run_case "branch -D mainframe"          'git branch -D mainframe'                allow
run_case "clean -fd"                    'git clean -fd'                          deny
run_case "clean -f"                     'git clean -f'                           deny
run_case "clean --force"                'git clean --force'                      deny
run_case "clean -fdx"                   'git clean -fdx'                         deny
run_case "clean -n (dry run)"           'git clean -n'                           allow
run_case "clean -i (interactive)"       'git clean -i'                           allow
run_case "rtk proxy force push"         'rtk proxy git push --force'             deny
run_case "cd && force push"             'cd /tmp/x && git push --force'          deny
run_case "ENV=1 force push"             'FOO=1 git push --force'                 deny
run_case "force inside echo with cd"    "cd /tmp && echo 'git push --force tip'" allow

# tools other than Bash must pass through
out=$(jq -nc '{tool_name:"Read",tool_input:{command:"git push --force"}}' | "$HOOK")
if [ -z "$out" ]; then
  PASS=$((PASS+1))
  printf "  PASS  non-Bash tool ignored\n"
else
  FAIL=$((FAIL+1))
  printf "  FAIL  non-Bash tool got blocked\n"
fi

# empty input must pass
out=$(jq -nc '{tool_name:"Bash",tool_input:{command:""}}' | "$HOOK")
if [ -z "$out" ]; then
  PASS=$((PASS+1))
  printf "  PASS  empty command ignored\n"
else
  FAIL=$((FAIL+1))
  printf "  FAIL  empty command blocked\n"
fi

printf "\n%d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
