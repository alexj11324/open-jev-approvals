# open-jev-approvals

English | [简体中文](README.zh-CN.md)

open-jev-approvals is an approval gate for Codex and Claude Code. Every tool
call the agent wants to make is intercepted by a hook, sent to TypeSafe Jev
for review, and either allowed or denied.

The project exists to provide an auto mode for people using third-party API
providers. The harness's built-in approval flow isn't available in that
setup, so this gate replaces it: Jev acts as the reviewer, and a small local
policy turns its judgments into a verdict. If Jev is unreachable or returns
something unusable, the call is allowed — the gate should not block your
work just because the reviewer is down. A deny always requires positive
evidence that the action is dangerous.

## How it works

For each intercepted tool call, Jev answers a fixed set of questions about
the action: how risky it is, whether the user authorized it, whether it
violates an explicit constraint, whether it sends data out, probes
credentials, weakens security, has destructive effects, follows a malicious
instruction, and whether its scope is narrow. Each answer comes back as a
probability.

The local policy (`policy/codex-guardian-v1`) combines those probabilities:

- A confirmed hazard — any probability at or above `0.70` — denies the
  call, even if the rest of the verdict is missing or malformed.
- A critical risk level always denies.
- High-risk actions additionally need at least `medium` user authorization
  and narrow scope.
- If the user's authorization changes while the review is in flight, the
  verdict is denied because it was computed against a stale state.
- Anything that prevents a real review — Jev down, timeouts, bad responses,
  a missing API key, a broken audit database — allows the call and marks
  the record `incomplete`.

Denies are recorded per call and don't affect later calls in the same
session.

The policy is derived from Codex Guardian (upstream commit `5c5308f`,
Apache-2.0) and reimplemented here.

## Install

```bash
go build -o bin/jev-approve ./cmd/jev-approve
bin/jev-approve install --harness codex --project /path/to/repo --binary "$(pwd)/bin/jev-approve"
```

Use `--harness claude-code` for Claude Code. The installer only touches the
hook entries it owns; other handlers in the same file are left alone, and
running it twice is safe.

## Configure

`TYPESAFE_API_KEY` is required. Put it in `~/.config/jev-approvals/env` as
`KEY=value` lines (see `.env.example`). A `.env` inside a project is never
read, so a repository can't redirect the approval endpoint or steal the
key. `$JEV_APPROVALS_ENV_FILE` overrides the location.

## Commands

```bash
jev-approve status    --harness codex --project <repo>  # is it installed and configured?
jev-approve doctor    --harness codex --project <repo>  # diagnose; --live pings Jev
jev-approve test      --harness codex                   # offline self-check; --live hits the API
jev-approve inspect   <review-id>                       # show one recorded decision
jev-approve uninstall --harness codex --project <repo>  # remove only our handlers
```

Every decision is stored in a local SQLite database with the action, the
verdict, the full Jev assessment, and the policy version, keyed by
`tool_use_id`. `inspect` dumps one record.

## Development

```bash
go build ./... && go test ./... && go test -race ./internal/...
go run ./eval                      # labeled policy cases
scripts/test-codex-hook.sh         # end-to-end acceptance; RUN_LIVE=1 for real Jev
```

## License

MIT
