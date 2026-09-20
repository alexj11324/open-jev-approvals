# open-jev-approvals

An MIT-licensed, fail-closed JEV approval gate for Codex and Claude Code hooks.

It receives lifecycle events and `PreToolUse` payloads, sends every intercepted
tool action to TypeSafe Jev, composes the typed judgments through a local policy,
and returns exit `0` to allow or exit `2` to block.

The first release targets macOS and Linux. It leaves each harness's model,
provider, sandbox, and bypass mode untouched.

## Build

```bash
cp .env.example .env
# Set TYPESAFE_API_KEY in .env.
go build -o bin/jev-approve ./cmd/jev-approve
go test ./...
```

`jev-approve probe` makes a harmless TypeSafe API call. The binary loads a
simple project-local `.env` only when the relevant process environment variable
is absent; `.env` is ignored by Git.

## Test the gate

```bash
# No network call: validates Hook input plus allow, explicit-block, and credential-deny policy paths.
bin/jev-approve test --harness codex

# Also evaluates a complete approval state through the configured JEV API.
bin/jev-approve test --harness codex --live

# Runs real Codex CLI tool calls through the installed project hook.
scripts/test-codex-hook.sh
```

The test command never executes the tool payload it evaluates. A passing live
test proves that JEV returned valid typed answers and that the local policy
could compose them. It reports the observed outcome instead of treating an
uncertain outcome as a false success.

`scripts/test-codex-hook.sh` is the runtime acceptance test. It builds the
binary, creates an isolated temporary Git repository, installs a Codex hook
there, and runs a safe `touch` through `codex exec`. It then sends an exact
Codex `PreToolUse` credential-copy payload to the same binary and requires
`deny`, then submits a normal action in the same session and requires `allow`.
It requires an authenticated Codex CLI and a configured
`TYPESAFE_API_KEY`; all test targets are temporary paths under `/private/tmp`.

## Install a hook

```bash
bin/jev-approve install --harness codex --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"

bin/jev-approve install --harness claude-code --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"
```

The installer adds `UserPromptSubmit` and all-tool `PreToolUse` command hooks,
without changing the harness's permission mode, sandbox, model, provider, or
provider credentials. Codex project hooks still require Codex trust before they
will execute.

Use `status`, `doctor`, `inspect <review-id>`, and `uninstall` with the same
`--harness`, `--project`, and `--binary` values. `doctor --live` verifies the
configured JEV credential without executing a harness tool call.

## Decision behavior

Every supported local tool call is normalized into one action and sent to JEV
with the saved user messages, full tool input, and any verified facts. A single
TypeSafe request asks independent risk, authorization, egress, credential,
security-weakening, destructive-effect, adapter-provided untrusted-instruction,
scope, and evidence
questions. Local `codex-derived-v1` policy owns the outcome:

- `ALLOW` exits `0` with no output.
- `DENY`, `REVIEW_REQUIRED`, and service/audit failures exit `2` and explain
  the blocking reason on stderr.
- Critical risk, explicit-constraint violations, unauthorized sensitive egress,
  credential probing, and unauthorized persistent security weakening are denied.
- High-risk work requires high, sufficiently confident authorization and a
  narrow scope. Missing evidence and errors fail closed.

The current thresholds are intentionally marked uncalibrated: safety hazards
deny at `0.70`; low-risk evidence sufficiency permits at `0.60`; high-risk
authorization and risk confidence require `0.70`. Collect labeled approval
outcomes before changing them.

## Scope boundary

Codex's hosted tools and `write_stdin` continuations do not re-enter its local
`PreToolUse` Hook path. This project audits and gates the tool calls that each
harness actually delivers; it does not claim to enforce paths that a harness
does not expose to Hooks.
