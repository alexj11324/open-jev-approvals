# open-jev-approvals

An MIT-licensed JEV approval gate for Codex and Claude Code hooks.

It receives lifecycle events plus tool and permission payloads, sends each
intercepted action to TypeSafe Jev, and composes the typed judgments through a
local policy. On Codex, it preserves the upstream split between `PreToolUse`
blocking and `PermissionRequest` decisions. JEV is the only reviewer: every
intercepted action ends in an explicit local `allow` or `deny`.

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
Finally, it submits an exact `PermissionRequest` payload and requires a direct
JEV `allow` verdict. It requires an authenticated Codex CLI and a configured
`TYPESAFE_API_KEY`; its targets are disposable temporary paths.

## Install a hook

```bash
bin/jev-approve install --harness codex --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"

bin/jev-approve install --harness claude-code --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"
```

The installer adds `UserPromptSubmit` and all-tool `PreToolUse` command hooks.
For Codex it also adds an all-tool `PermissionRequest` hook. It does not change
the harness's permission mode, sandbox, model, provider, or provider
credentials. Codex project hooks still require Codex trust before they execute.

Use `status`, `doctor`, `inspect <review-id>`, and `uninstall` with the same
`--harness`, `--project`, and `--binary` values. `doctor --live` verifies the
configured JEV credential without executing a harness tool call.

## Decision behavior

Every supported local tool call is normalized into one action and sent to JEV
with the saved user messages, full tool input, and any verified facts. A single
TypeSafe request asks independent risk, authorization, egress, credential,
security-weakening, destructive-effect, adapter-provided untrusted-instruction,
and scope
questions. Local `codex-derived-v1` policy owns the outcome:

- A confirmed Codex `PreToolUse` denial returns the upstream
  `permissionDecision: deny` JSON shape. An allow returns successfully with no
  blocking output, as required by the upstream protocol.
- A Codex `PermissionRequest` always returns the upstream nested
  `decision.behavior` JSON shape with either `allow` or `deny`.
- Invalid model output, service failure, and audit failure deny. No decision is
  delegated to Codex user approval, Guardian, or auto review.
- Claude Code retains the exit `0` allow and exit `2` block behavior because
  this release does not replace its approval router.
- Critical risk, explicit-constraint violations, unauthorized sensitive egress,
  unauthorized credential probing, and unauthorized persistent security
  weakening are denied.
- Low- and medium-risk actions allow unless an explicit policy deny applies.
- High-risk work requires at least medium user authorization and a narrow
  scope. Critical risk always denies.
- Choice confidence is retained for audit but is not a deny condition. This
  avoids converting harmless low/medium ambiguity into a false block.

The current Noul action threshold is `0.70`. Collect labeled approval outcomes
before changing it.

## Codex source contract

The policy and output contracts are copied from upstream Codex at commit
`5c5308fc9a9ee789049d646ef11e5400384b9c6f`:

- [Guardian risk, authorization, evidence, and outcome rules](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy_template.md).
- [Default security policy for egress, credentials, persistent weakening, and destructive actions](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy.md).
- [Guardian's strict `allow`/`deny` assessment schema](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/ext/guardian-reviewer/src/assessment.rs).
- [`PreToolUse` and `PermissionRequest` wire formats](https://github.com/openai/codex/tree/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/hooks/src/events).

JEV replaces the reviewer while Codex transports and enforces the hook verdict.

## Scope boundary

Codex's hosted tools and `write_stdin` continuations do not re-enter its local
`PreToolUse` Hook path. This project audits and gates the tool calls that each
harness actually delivers; it does not claim to enforce paths that a harness
does not expose to Hooks.
