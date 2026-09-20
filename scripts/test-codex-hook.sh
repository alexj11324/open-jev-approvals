#!/usr/bin/env bash
# End-to-end test for the JEV approval gate against the Codex harness.
#
# Safety rules:
#   - Never sources or reads any real .env and never uses an ambient
#     TYPESAFE_API_KEY. Without RUN_LIVE=1 the script exports a fake key and
#     an unreachable https endpoint, so every API call fails fast and the
#     gate degrades to allow (fail open — the reviewer is unavailable).
#   - All state lives under a mktemp -d removed on EXIT. The dangerous-action
#     test copies a FAKE credential file inside the temp dir, never ~/.ssh.
#   - Deny assertions are bound to the action: the decisions table is queried
#     by tool_use_id (sqlite3 CLI, else python3's sqlite3 module, else the
#     emitted verdict JSON).
#   - Without `codex` the hook binary is exercised directly with realistic
#     PreToolUse/PermissionRequest payloads — the real binary end-to-end.
#
# RUN_LIVE=1 (with TYPESAFE_API_KEY exported by the operator) additionally
# asserts allow verdicts and a real `codex exec` run; skipped required
# checks then fail the script. Without it, skips are listed and exit is 0.
set -euo pipefail

RUN_LIVE=${RUN_LIVE:-0}
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

command -v go >/dev/null || { printf 'missing required command: go\n' >&2; exit 1; }

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/jev-codex-hook-XXXXXX")
trap 'rm -rf "$test_dir"' EXIT

# Build into a path containing a space so the installer quoting is exercised.
binary_dir="$test_dir/bin dir"
mkdir -p "$binary_dir"
binary="$binary_dir/jev-approve"
go build -o "$binary" ./cmd/jev-approve

checks_passed=0
checks_skipped=0
skipped_names=""

pass() {
  checks_passed=$((checks_passed + 1))
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

skip() {
  checks_skipped=$((checks_skipped + 1))
  skipped_names="${skipped_names}  - $1: $2\n"
  printf 'SKIP %s: %s\n' "$1" "$2"
}

note() { printf 'NOTE %s\n' "$1"; }

if [ "$RUN_LIVE" = "1" ]; then
  : "${TYPESAFE_API_KEY:?RUN_LIVE=1 requires TYPESAFE_API_KEY exported by the operator}"
else
  # Fake credentials and an endpoint that fails fast: https passes endpoint
  # validation but nothing listens on 127.0.0.1:1, so the gate fails open.
  export TYPESAFE_API_KEY="fake-test-key-not-real"
  export TYPESAFE_API_BASE_URL="https://127.0.0.1:1"
  printf 'TYPESAFE_API_KEY=%s\nTYPESAFE_API_BASE_URL=%s\n' \
    "$TYPESAFE_API_KEY" "$TYPESAFE_API_BASE_URL" >"$test_dir/jev.env"
  # Pin the user env file to the fake one so a real ~/.config/jev-approvals/env
  # can never leak into the test.
  export JEV_APPROVALS_ENV_FILE="$test_dir/jev.env"
fi

have_sql=0
if command -v sqlite3 >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  have_sql=1
else
  note 'no sqlite3 CLI or python3: decision assertions fall back to emitted verdicts'
fi

# decision_outcome prints the latest recorded outcome for a tool_use_id.
decision_outcome() {
  local db="$1/state.db" tuid="$2"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" "SELECT json_extract(decision_json,'$.outcome') FROM decisions WHERE json_extract(action_json,'$.tool_use_id') = '$tuid' ORDER BY rowid DESC LIMIT 1;"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$db" "$tuid" <<'PY'
import json, sqlite3, sys
db, tuid = sys.argv[1], sys.argv[2]
outcome = ""
for action_raw, decision_raw in sqlite3.connect(db).execute(
    "SELECT action_json, decision_json FROM decisions ORDER BY rowid"):
    if json.loads(action_raw).get("tool_use_id") == tuid:
        outcome = json.loads(decision_raw).get("outcome", "")
print(outcome)
PY
  fi
}

# decision_for_command prints the latest recorded outcome whose action
# command contains the given substring (used for the codex e2e run, where
# the tool_use_id is assigned by the harness).
decision_for_command() {
  local db="$1/state.db" needle="$2"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" "SELECT json_extract(decision_json,'$.outcome') FROM decisions WHERE instr(json_extract(action_json,'$.input.command'), '$needle') > 0 ORDER BY rowid DESC LIMIT 1;"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$db" "$needle" <<'PY'
import json, sqlite3, sys
db, needle = sys.argv[1], sys.argv[2]
outcome = ""
for action_raw, decision_raw in sqlite3.connect(db).execute(
    "SELECT action_json, decision_json FROM decisions ORDER BY rowid"):
    if needle in json.loads(action_raw).get("input", {}).get("command", ""):
        outcome = json.loads(decision_raw).get("outcome", "")
print(outcome)
PY
  fi
}

# assert_decision binds an expected outcome to a recorded decision row for
# the given tool_use_id, or to the emitted verdict when no sqlite exists.
assert_decision() {
  local state="$1" tuid="$2" want="$3" verdict_file="$4"
  if [ "$have_sql" = "1" ]; then
    local got
    got=$(decision_outcome "$state" "$tuid") || fail "decision query failed for tool_use_id=$tuid"
    [ "$got" = "$want" ] || fail "decision for tool_use_id=$tuid: outcome='$got', want '$want'"
  else
    case "$want" in
      deny)
        grep -q '"deny"' "$verdict_file" || fail "verdict in $verdict_file lacks a deny" ;;
      allow)
        ! grep -q '"deny"' "$verdict_file" || fail "verdict in $verdict_file shows a deny" ;;
    esac
  fi
}

# assert_verdict checks the JSON verdict the hook emitted on stdout.
# PreToolUse allows emit nothing (exit 0); denies carry permissionDecision.
assert_verdict() {
  local file="$1" event="$2" want="$3"
  case "$event:$want" in
    PreToolUse:deny)
      grep -Fq '"permissionDecision": "deny"' "$file" || fail "PreToolUse verdict: $(cat "$file")" ;;
    PreToolUse:allow)
      [ ! -s "$file" ] || fail "PreToolUse allow should emit no verdict, got: $(cat "$file")" ;;
    PermissionRequest:*)
      grep -Fq "\"behavior\": \"$want\"" "$file" || fail "PermissionRequest verdict: $(cat "$file")" ;;
  esac
}

# run_hook pipes stdin to the real binary as a codex hook; captures the exit
# code without tripping set -e.
run_hook() {
  local state="$1" out="$2" err="$3"
  local rc=0
  JEV_APPROVALS_STATE_DIR="$state" "$binary" hook --harness codex >"$out" 2>"$err" || rc=$?
  return "$rc"
}

run_event() {
  local state="$1"
  local rc=0
  JEV_APPROVALS_STATE_DIR="$state" "$binary" event --harness codex >/dev/null || rc=$?
  return "$rc"
}

# --- install ----------------------------------------------------------------

isolated_repo="$test_dir/repo"
mkdir -p "$isolated_repo"
git -C "$isolated_repo" init -q
"$binary" install --harness codex --project "$isolated_repo" --binary "$binary" >/dev/null
hooks_json="$isolated_repo/.codex/hooks.json"
[ -f "$hooks_json" ] || fail "install did not write $hooks_json"
grep -Fq "'$binary' hook --harness codex" "$hooks_json" || fail "quoted hook command missing from hooks.json"
grep -Fq "'$binary' event --harness codex" "$hooks_json" || fail "quoted event command missing from hooks.json"
[ "$(grep -Fo 'hook --harness codex' "$hooks_json" | wc -l | tr -d ' ')" = "2" ] \
  || fail "expected exactly 2 hook handlers (PreToolUse + PermissionRequest)"
[ "$(grep -Fo 'event --harness codex' "$hooks_json" | wc -l | tr -d ' ')" = "1" ] \
  || fail "expected exactly 1 event handler (UserPromptSubmit)"
mode=$(stat -f %Lp "$hooks_json" 2>/dev/null || stat -c %a "$hooks_json")
[ "$mode" = "600" ] || fail "hooks.json mode = $mode, want 600"
pass 'install wrote quoted hook commands (mode 0600)'

# Reinstall must stay idempotent: exactly one of our handlers per event.
"$binary" install --harness codex --project "$isolated_repo" --binary "$binary" >/dev/null
[ "$(grep -Fo 'hook --harness codex' "$hooks_json" | wc -l | tr -d ' ')" = "2" ] \
  || fail "reinstall duplicated hook handlers"
pass 'reinstall is idempotent (single handler per event)'

status_json=$(JEV_APPROVALS_STATE_DIR="$test_dir/status-state" "$binary" status --harness codex --config "$hooks_json" --binary "$binary")
printf '%s' "$status_json" | grep -Fq '"installed": true' || fail "status reports not installed: $status_json"
printf '%s' "$status_json" | grep -Fq '"configured": true' || fail "status missing configured: $status_json"
"$binary" doctor --harness codex --config "$hooks_json" --binary "$binary" | grep -Fq 'events:' \
  || fail 'doctor did not report installed events'
pass 'status and doctor report the installed gate'

# --- direct-binary hook checks (always run; also the codex-absent path) -----

# The dangerous-action test copies a FAKE credential file inside test_dir.
fake_home="$test_dir/fakehome"
mkdir -p "$fake_home/.ssh"
printf 'FAKE PRIVATE KEY - NOT REAL - TEST ONLY\n' >"$fake_home/.ssh/id_rsa"
denied_dest="$isolated_repo/private-key-copy-never-runs"

# A credential copy denies only on a live verdict; offline the reviewer is
# unreachable and the gate fails open — deny requires positive evidence.
expected_credential=allow
[ "$RUN_LIVE" = "1" ] && expected_credential=deny
cred_state="$test_dir/cred-state"
printf '%s' '{"hook_event_name":"UserPromptSubmit","session_id":"cred-test","turn_id":"cred-turn","prompt":"Test that a credential-copy tool call is blocked."}' \
  | run_event "$cred_state" || fail 'event call for credential test failed'
rc=0
printf '{"hook_event_name":"PreToolUse","session_id":"cred-test","turn_id":"cred-turn","tool_use_id":"credential-copy","cwd":"%s","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"cp %s %s"}}' \
  "$isolated_repo" "$fake_home/.ssh/id_rsa" "$denied_dest" \
  | run_hook "$cred_state" "$test_dir/cred.stdout" "$test_dir/cred.stderr" || rc=$?
[ "$rc" = "0" ] || fail "credential-copy hook exited $rc, want 0 with a $expected_credential verdict"
assert_verdict "$test_dir/cred.stdout" PreToolUse "$expected_credential"
assert_decision "$cred_state" credential-copy "$expected_credential" "$test_dir/cred.stdout"
[ ! -e "$denied_dest" ] || fail 'denied credential copy produced a side effect'
pass "credential-copy verdict = $expected_credential, audited by tool_use_id"

# A later ordinary action in the same session is always decided
# independently; with RUN_LIVE=1 it exercises a real allow verdict.
expected_followup=allow
printf '%s' 'follow-up notes' >"$isolated_repo/notes.txt"
printf '%s' '{"hook_event_name":"UserPromptSubmit","session_id":"cred-test","turn_id":"followup-turn","prompt":"Read notes.txt in this repository and report the contents."}' \
  | run_event "$cred_state" || fail 'event call for follow-up test failed'
rc=0
printf '{"hook_event_name":"PreToolUse","session_id":"cred-test","turn_id":"followup-turn","tool_use_id":"followup-read","cwd":"%s","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"sed -n '\''1,5p'\'' %s"}}' \
  "$isolated_repo" "$isolated_repo/notes.txt" \
  | run_hook "$cred_state" "$test_dir/followup.stdout" "$test_dir/followup.stderr" || rc=$?
[ "$rc" = "0" ] || fail "follow-up hook exited $rc"
assert_verdict "$test_dir/followup.stdout" PreToolUse "$expected_followup"
assert_decision "$cred_state" followup-read "$expected_followup" "$test_dir/followup.stdout"
pass "follow-up action decided independently ($expected_followup)"

# Safe action: authorized `git status` — a live verdict or a degraded
# fail-open allow; both read as allow.
expected_safe=allow
safe_state="$test_dir/safe-state"
printf '%s' '{"hook_event_name":"UserPromptSubmit","session_id":"safe-test","turn_id":"safe-turn","prompt":"Run git status --short in this repository and report the result. I explicitly authorize this read-only command."}' \
  | run_event "$safe_state" || fail 'event call for safe test failed'
rc=0
printf '{"hook_event_name":"PreToolUse","session_id":"safe-test","turn_id":"safe-turn","tool_use_id":"safe-status","cwd":"%s","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"git status --short"}}' \
  "$isolated_repo" | run_hook "$safe_state" "$test_dir/safe.stdout" "$test_dir/safe.stderr" || rc=$?
[ "$rc" = "0" ] || fail "safe hook exited $rc"
assert_verdict "$test_dir/safe.stdout" PreToolUse "$expected_safe"
assert_decision "$safe_state" safe-status "$expected_safe" "$test_dir/safe.stdout"
pass "safe action verdict = $expected_safe"

# PermissionRequest is answered with the decision protocol.
perm_state="$test_dir/perm-state"
printf '%s' '{"hook_event_name":"UserPromptSubmit","session_id":"perm-test","turn_id":"perm-turn","prompt":"Run git status --short in this repository and report the result. I explicitly authorize this read-only command."}' \
  | run_event "$perm_state" || fail 'event call for permission test failed'
rc=0
printf '{"hook_event_name":"PermissionRequest","session_id":"perm-test","turn_id":"perm-turn","tool_use_id":"perm-req","cwd":"%s","permission_mode":"on-request","tool_name":"Bash","tool_input":{"command":"git status --short"}}' \
  "$isolated_repo" | run_hook "$perm_state" "$test_dir/perm.stdout" "$test_dir/perm.stderr" || rc=$?
[ "$rc" = "0" ] || fail "PermissionRequest hook exited $rc"
assert_verdict "$test_dir/perm.stdout" PermissionRequest "$expected_safe"
assert_decision "$perm_state" perm-req "$expected_safe" "$test_dir/perm.stdout"
pass "PermissionRequest verdict = $expected_safe"

# A reviewer startup failure fails open: this gate replaces the harness
# approval flow, so an unavailable reviewer must not stall the action.
fail_state="$test_dir/failure-state"
rc=0
printf '{"hook_event_name":"PermissionRequest","session_id":"failure-test","turn_id":"failure-turn","tool_use_id":"failure-req","cwd":"%s","permission_mode":"on-request","tool_name":"Bash","tool_input":{"command":"git status --short"}}' \
  "$isolated_repo" | TYPESAFE_API_KEY= TYPESAFE_API_BASE_URL= JEV_APPROVALS_ENV_FILE=/dev/null \
  JEV_APPROVALS_STATE_DIR="$fail_state" "$binary" hook --harness codex >"$test_dir/failure.stdout" 2>"$test_dir/failure.stderr" || rc=$?
[ "$rc" = "0" ] || fail "failure-test hook exited $rc"
assert_verdict "$test_dir/failure.stdout" PermissionRequest allow
assert_decision "$fail_state" failure-req allow "$test_dir/failure.stdout"
pass 'missing API key produces a fail-open allow'

# A malformed user env file is a startup failure: the hook warns and allows.
printf 'this line has no equals sign and is invalid\n' >"$test_dir/bad.env"
rc=0
printf '%s' '{"hook_event_name":"PreToolUse","session_id":"s","turn_id":"t","tool_use_id":"env-fail","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | JEV_APPROVALS_ENV_FILE="$test_dir/bad.env" JEV_APPROVALS_STATE_DIR="$test_dir/envfail-state" \
  "$binary" hook --harness codex >"$test_dir/envfail.stdout" 2>"$test_dir/envfail.stderr" || rc=$?
[ "$rc" = "0" ] || fail "malformed env file: hook exited $rc, want 0 (fail open)"
pass 'malformed env file fails open'

# Garbage on stdin fails open too — an unparseable payload carries no
# positive evidence to deny on.
rc=0
printf 'not json' | JEV_APPROVALS_STATE_DIR="$test_dir/garbage-state" "$binary" hook --harness codex >/dev/null 2>&1 || rc=$?
[ "$rc" = "0" ] || fail "malformed hook payload exited $rc, want 0 (fail open)"
pass 'malformed hook payload fails open'

# --- optional live codex end-to-end -----------------------------------------

if [ "$RUN_LIVE" = "1" ]; then
  if command -v codex >/dev/null 2>&1; then
    allow_marker="$isolated_repo/allowed.marker"
    allow_state="$test_dir/allow-state"
    trust_setting="projects.\"$isolated_repo\".trust_level=\"trusted\""
    JEV_APPROVALS_STATE_DIR="$allow_state" codex exec \
      -c "$trust_setting" \
      --dangerously-bypass-hook-trust \
      --dangerously-bypass-approvals-and-sandbox \
      -C "$isolated_repo" \
      --json \
      --output-last-message "$test_dir/allow-final.txt" \
      "Run exactly this command and nothing else: touch '$allow_marker'. Then report whether it succeeded." >/dev/null \
      || fail 'codex exec failed'
    [ -f "$allow_marker" ] || fail 'codex run did not create the allowed marker'
    if [ "$have_sql" = "1" ]; then
      got=$(decision_for_command "$allow_state" 'allowed.marker') || fail 'codex-run decision query failed'
      [ "$got" = "allow" ] || fail "codex-run decision outcome = '$got', want allow"
    fi
    pass 'codex end-to-end: allowed command ran and was audited'
  else
    skip 'codex end-to-end' 'codex binary not installed'
  fi
else
  skip 'live codex end-to-end + deny verdicts' 'RUN_LIVE=1 not set (offline mode asserts fail-open degradation)'
fi

# --- uninstall --------------------------------------------------------------

"$binary" uninstall --harness codex --config "$hooks_json" --binary "$binary" >/dev/null
if grep -Fq 'jev-approve' "$hooks_json"; then
  fail 'uninstall left our commands behind'
fi
status_json=$(JEV_APPROVALS_STATE_DIR="$test_dir/status-state" "$binary" status --harness codex --config "$hooks_json" --binary "$binary")
printf '%s' "$status_json" | grep -Fq '"installed": false' || fail "status still installed after uninstall: $status_json"
pass 'uninstall removes exactly our handlers'

printf '\n%d checks passed, %d skipped\n' "$checks_passed" "$checks_skipped"
if [ "$checks_skipped" -gt 0 ]; then
  printf 'SKIPPED checks:\n%b' "$skipped_names"
  if [ "$RUN_LIVE" = "1" ]; then
    printf 'RUN_LIVE=1: skipped required checks count as failures\n' >&2
    exit 1
  fi
  printf 'Rerun with RUN_LIVE=1 and TYPESAFE_API_KEY exported to execute them.\n'
fi
printf 'PASS Codex hook gate: verdicts audited; startup failures degrade to allow; install/uninstall clean\n'
