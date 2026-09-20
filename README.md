# open-jev-approvals

An MIT-licensed JEV approval gate for Codex and Claude Code hooks.

It receives hook events plus tool and permission payloads, sends each
intercepted action to TypeSafe Jev, and composes the typed judgments through
a local policy. On Codex, it preserves the upstream split between
`PreToolUse` blocking and `PermissionRequest` decisions. JEV is the only
reviewer: every intercepted action ends in an explicit local `allow` or
`deny` — there is no third outcome.

The first release targets macOS and Linux. It leaves each harness's model,
provider, sandbox, and bypass mode untouched.

## Build

```bash
go build -o bin/jev-approve ./cmd/jev-approve
go test ./...
```

## Configuration

`TYPESAFE_API_KEY` is required for live reviews. The binary loads
credentials only from a **user-level** env file — a checked-out or working
`.env` inside a project is never read, so a repository cannot redirect the
approval endpoint or capture the key. The file uses `KEY=value` lines (see
`.env.example`) and resolves in this order:

1. `$JEV_APPROVALS_ENV_FILE` when set,
2. `$XDG_CONFIG_HOME/jev-approvals/env` when `XDG_CONFIG_HOME` is set,
3. `~/.config/jev-approvals/env` otherwise.

Environment variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | yes | TypeSafe API credential, sent as a bearer token |
| `TYPESAFE_API_BASE_URL` | no | endpoint override; must be `https`, no credentials/query/fragment (default `https://api.typesafe.ai/v1/systemone`) |
| `TYPESAFE_MODEL` | no | model override (default `jev-latest`); responses are still validated to a `jev-*` model |
| `JEV_APPROVALS_STATE_DIR` | no | directory holding `state.db` |
| `JEV_APPROVALS_ENV_FILE` | no | env-file path override |
| `XDG_STATE_HOME`, `XDG_CONFIG_HOME` | no | XDG base-directory overrides for state and config |

The audit database is SQLite at `$JEV_APPROVALS_STATE_DIR/state.db`, else
`$XDG_STATE_HOME/jev-approvals/state.db`, else
`~/.local/state/jev-approvals/state.db`. It stores recorded user prompts
(authorization evidence) and every decision with its assessment and policy
version. Tool payloads and prompts are redacted (`internal/sanitize`)
before they are sent to JEV and before they are written to the database.

## Commands

```
jev-approve hook --harness <codex|claude-code>     # called by harness hooks (PreToolUse / PermissionRequest)
jev-approve event --harness <codex|claude-code>    # called by UserPromptSubmit to record authorization
jev-approve install|uninstall|status|doctor        # manage per-project hooks
jev-approve probe                                   # harmless connectivity check against the JEV API
jev-approve test [--live] --harness <harness>      # offline adapter+policy check; --live also calls JEV
jev-approve inspect <review-id>                     # print a recorded decision
```

`hook` and `event` are invoked by the installed harness hooks, not by hand.
`doctor --live` verifies the configured JEV credential without executing a
harness tool call.

## Test the gate

```bash
# No network call: validates hook input plus allow, explicit-block, and credential-deny policy paths.
bin/jev-approve test --harness codex

# Also evaluates a complete approval state through the configured JEV API.
bin/jev-approve test --harness codex --live

# Runs real Codex CLI tool calls through the installed project hook.
scripts/test-codex-hook.sh

# Offline calibration set: labeled assessments through the binary policy.
go run ./eval
```

The test command never executes the tool payload it evaluates. A passing
live test proves that JEV returned valid typed answers and that the local
policy could compose them.

`scripts/test-codex-hook.sh` is the runtime acceptance test. It builds the
binary into a path containing a space, installs the hook into an isolated
temporary repository, and exercises install/idempotency/status/doctor/
uninstall plus real `PreToolUse` and `PermissionRequest` payloads against
the built binary. It never touches a real credential: it uses a fake API
key, an unreachable endpoint, and a fake `id_rsa` inside the temp dir, and
asserts that denied actions leave no filesystem side effects and that every
decision is audited against its `tool_use_id`. With `RUN_LIVE=1` and a real
`TYPESAFE_API_KEY` it additionally runs `codex exec` end to end and requires
live `allow` verdicts; without it the run is offline and asserts the
fail-closed denies.

## Install a hook

```bash
bin/jev-approve install --harness codex --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"

bin/jev-approve install --harness claude-code --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"
```

Hooks are installed **per project**: the installer edits
`<project>/.codex/hooks.json` for Codex or `<project>/.claude/settings.json`
for Claude Code. It adds a `UserPromptSubmit` hook (records authorization)
and an all-tool `PreToolUse` hook; for Codex it also adds an all-tool
`PermissionRequest` hook. It does not change the harness's permission mode,
sandbox, model, provider, or provider credentials. Codex project hooks
still require Codex trust before they execute.

Use `status`, `doctor`, `inspect <review-id>`, and `uninstall` with the
same `--harness`, `--project`, and `--binary` values.

## Decision behavior

Every supported local tool call is normalized into one action and sent to
JEV with the saved user messages, redacted tool input, and any verified
facts. A single TypeSafe request asks independent risk, authorization,
explicit-constraint, egress, credential-probing, security-weakening,
destructive-effect, untrusted-instruction, and scope questions. The local
`codex-guardian-v1` policy (`internal/policy`, mirrored by
`policy/codex-guardian-v1/policy.json`) owns the outcome:

- Outcomes are binary: `allow` or `deny`. Invalid model output, missing or
  invalid safety judgments, service failure, unverifiable authorization
  freshness, and audit failure all deny. No decision is delegated to Codex
  user approval, Guardian, or auto review.
- Confirmed (`>= 0.70`) explicit-constraint violations, malicious
  instructions, unauthorized persistent security weakening, and sensitive
  egress without authorization deny. Critical risk always denies.
- Confirmed credential probing or destructive effect escalates effective
  risk to `high`. High risk requires at least `medium` user authorization
  and a narrowly-scoped (`>= 0.70`) action.
- A hazard judgment below the threshold — including an uncertain `0.5` —
  does not by itself deny; only missing or invalid judgments fail closed.
- Choice confidences must be valid probabilities, but their values are not
  deny inputs — harmless low/medium ambiguity does not become a false block.
- A confirmed Codex `PreToolUse` denial returns the upstream
  `permissionDecision: deny` JSON shape; an allow exits `0` silently, as
  required by the upstream protocol. A Codex `PermissionRequest` always
  returns the upstream nested `decision.behavior` shape. Claude Code keeps
  exit `0` allow / exit `2` block.

The current Noul action threshold is `0.70` and is **uncalibrated** — no
validated dataset exists yet. Run and extend `eval/` before changing it.

## Codex source contract

The policy and output contracts are derived from upstream Codex at commit
`5c5308fc9a9ee789049d646ef11e5400384b9c6f`:

- [Guardian risk, authorization, evidence, and outcome rules](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy_template.md).
- [Default security policy for egress, credentials, persistent weakening, and destructive actions](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy.md).
- [Guardian's strict `allow`/`deny` assessment schema](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/ext/guardian-reviewer/src/assessment.rs).
- [`PreToolUse` and `PermissionRequest` wire formats](https://github.com/openai/codex/tree/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/hooks/src/events).

JEV replaces the reviewer while Codex transports and enforces the hook
verdict.

## Limitations

- The `action_probability` threshold is uncalibrated; the labeled set in
  `eval/` is a scaffold, not yet a validated dataset.
- Only `UserPromptSubmit`, `PreToolUse`, and (Codex) `PermissionRequest`
  are wired. `SessionStart`, `PostToolUse`, `SessionEnd`, and subagent
  lifecycle events are not yet consumed.
- `transcript_path` from hook payloads is not read; authorization comes
  solely from user prompts recorded through `UserPromptSubmit` in the same
  installation/harness/session/agent scope.
- Claude Code keeps its exit-code contract; this release does not replace
  its approval router.

## Scope boundary

Codex's hosted tools and `write_stdin` continuations do not re-enter its
local `PreToolUse` hook path. This project audits and gates the tool calls
that each harness actually delivers; it does not claim to enforce paths
that a harness does not expose to hooks.
