# open-jev-approvals

An MIT-licensed JEV approval gate for Codex and Claude Code hooks.

It receives lifecycle events and `PreToolUse` payloads, sends each intercepted
action to TypeSafe Jev, and uses the embedded Codex Auto/Guardian policy to
produce the sole `allow` or `deny` verdict.

The first release targets macOS and Linux. It leaves each harness's model,
provider, sandbox, and bypass mode untouched.

## Build

```bash
cp .env.example .env
# Set TYPESAFE_API_KEY in .env.
set -a; source .env; set +a
go build -o bin/jev-approve ./cmd/jev-approve
go test ./...
```

`jev-approve probe` makes a harmless TypeSafe API call. Credentials normally
come from the trusted process environment. To load a file, set
`JEV_APPROVALS_ENV_FILE` to its absolute path; the binary never loads `.env`
from the target repository's working directory. `.env` is ignored by Git.

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
Finally, it disables the reviewer API and requires fail-open `allow`. It requires
an authenticated Codex CLI and a configured `TYPESAFE_API_KEY`; its targets are
disposable temporary paths.

## Install a hook

```bash
bin/jev-approve install --harness codex --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"

bin/jev-approve install --harness claude-code --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"
```

The installer adds `UserPromptSubmit` and all-tool `PreToolUse` command hooks.
It does not change the harness's permission mode, sandbox, model, provider, or
provider credentials. Codex project hooks still require Codex trust before they
execute.

Use `status`, `doctor`, `inspect <review-id>`, and `uninstall` with the same
`--harness`, `--project`, and `--binary` values. `doctor --live` verifies the
configured JEV credential without executing a harness tool call.

## Decision behavior

Every supported local tool call is normalized into one action and sent to JEV
with the current-turn user messages and full tool input. The exact upstream
Guardian policy is included in state. One TypeSafe request asks only the fields
from Guardian's assessment contract: `risk_level`, `user_authorization`, and
`outcome`.

- A confirmed Codex `PreToolUse` denial returns the upstream
  `permissionDecision: deny` JSON shape. An allow returns successfully with no
  blocking output, as required by the upstream protocol.
- API absence, timeouts, invalid responses, state errors, audit errors, and
  verdict-output errors all fail open and allow the action.
- Claude Code retains the exit `0` allow and exit `2` block behavior because
  this release does not replace its approval router.
- Only an explicit `outcome: deny` produced under the embedded Guardian policy
  blocks. Choice confidence never creates a separate blocking condition.

## Codex source contract

The Guardian policy template and default security policy are copied byte-for-byte
from upstream Codex at commit
`5c5308fc9a9ee789049d646ef11e5400384b9c6f`:

- [Guardian risk, authorization, evidence, and outcome rules](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy_template.md).
- [Default security policy for egress, credentials, persistent weakening, and destructive actions](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy.md).
- [Guardian's strict `allow`/`deny` assessment schema](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/ext/guardian-reviewer/src/assessment.rs).
- [`PreToolUse` wire format](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/hooks/src/events/pre_tool_use.rs).

The embedded copies live in `internal/jev/guardian_policy_template.md` and
`internal/jev/guardian_policy.md`. The upstream assessment fields are mapped to
three independent JEV Choice questions: `risk_level`, `user_authorization`, and
`outcome`. JEV does not generate Guardian's free-form `rationale`, so the
adapter uses the same allow/deny rationale defaults as the upstream parser.
Codex transports and enforces the resulting hook verdict.

## Deliberate runtime differences

This project preserves the upstream policy text and assessment values through a
third-party Hook adapter. It is not the in-process Guardian reviewer:

- The Hook supplies the current `PreToolUse` payload and the current-turn user
  prompt captured by `UserPromptSubmit`. It does not expose Guardian's full
  transcript, retained developer instructions, verified prompt answers, or
  read-only investigation tools.
- The installer does not add a `PermissionRequest` handler. The intended Codex
  mode uses `PreToolUse` while native approvals and sandboxing are bypassed, so
  there is no second approval decision or native fallback.
- Upstream Guardian denies ordinary reviewer failures. This gate deliberately
  allows API, parsing, state, audit, timeout, and verdict-output failures. This
  fail-open rule is the adapter's explicit operating contract.

## Scope boundary

Codex's hosted tools and `write_stdin` continuations do not re-enter its local
`PreToolUse` Hook path. This project audits and gates the tool calls that each
harness actually delivers; it does not claim to enforce paths that a harness
does not expose to Hooks.
