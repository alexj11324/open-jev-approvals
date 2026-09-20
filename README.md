# open-jev-approvals

An MIT-licensed, fail-closed JEV approval gate for Codex and Claude Code hooks.

It receives lifecycle events and `PreToolUse` payloads, sends every intercepted
tool action to TypeSafe Jev, composes the typed judgments through a local policy,
and returns exit `0` to allow or exit `2` to block.

The first release targets macOS and Linux. It leaves each harness's model,
provider, sandbox, and bypass mode untouched.

## Status

The repository is being implemented as a small Go binary with shared adapters,
local SQLite state and audit records, and a direct TypeSafe HTTP client.
