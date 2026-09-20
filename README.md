# open-jev-approvals

English | [简体中文](README.zh-CN.md)

Approval gate for Claude Code.

When the agent is about to run a tool, a hook intercepts the call, TypeSafe
Jev reviews it, and a local policy returns `allow` or `deny`. Third-party
API setups usually cannot use the harness's own approval flow; this gate
is the auto mode for that case. Jev is the reviewer. The local policy is
the verdict. If Jev cannot produce one, the call is allowed — a deny needs
positive evidence that the action is dangerous.

It does not change the harness's model, provider, sandbox, or bypass
mode. The first release targets macOS and Linux.

## Install

```bash
go build -o bin/jev-approve ./cmd/jev-approve

bin/jev-approve install --harness claude-code --project /path/to/repo \
  --binary "$(pwd)/bin/jev-approve"
```

Hooks are per project (`<project>/.claude/settings.json`). The installer
writes only its own handlers — `UserPromptSubmit` (records the prompt as
authorization evidence) and `PreToolUse` (reviews the action). Other
handlers in the same file are left alone; running install twice is safe.

## Configure

Live reviews need `TYPESAFE_API_KEY` in a **user-level** env file. A
project `.env` is never read, so a checked-out repo cannot redirect the
approval endpoint or steal the key. Format is `KEY=value` lines; see
`.env.example`.

```
# ~/.config/jev-approvals/env
TYPESAFE_API_KEY=...
```

Lookup order: `$JEV_APPROVALS_ENV_FILE`, then
`$XDG_CONFIG_HOME/jev-approvals/env`, then
`~/.config/jev-approvals/env`.

| Variable | Required | Meaning |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | yes | TypeSafe API credential |
| `TYPESAFE_API_BASE_URL` | no | HTTPS endpoint; default `https://api.typesafe.ai/v1/systemone` |
| `TYPESAFE_MODEL` | no | Jev model; default `jev-latest`. Responses must still be `jev-*` |
| `JEV_APPROVALS_STATE_DIR` | no | directory for `state.db` |
| `JEV_APPROVALS_ENV_FILE` | no | env-file path override |

Decisions are stored in SQLite at `$JEV_APPROVALS_STATE_DIR/state.db`,
else `$XDG_STATE_HOME/jev-approvals/state.db`, else
`~/.local/state/jev-approvals/state.db`. Prompts and tool payloads are
redacted before they go to Jev or to disk.

## How decisions work

Each intercepted action is sent to Jev with the current-turn user
messages, the redacted tool input, and any verified facts. Jev answers a
fixed set of questions — risk, authorization, hazards, scope. The local
policy turns those answers into a binary verdict.

- Confirmed (`≥ 0.70`) constraint violation, malicious instruction,
  persistent security weakening, or unauthorized sensitive egress →
  **deny**, even if the rest of the verdict is unusable.
- Critical risk always denies.
- Credential probing and destructive effect raise effective risk to
  `high`. They do not deny on their own.
- High-risk work needs at least `medium` user authorization **and** a
  narrow scope.
- If authorization changes while the review is in flight, the verdict is
  denied.
- Jev down, timeout, bad response, missing API key, or a broken audit
  database → **allow**, recorded `incomplete`.
- A hazard below `0.70`, including an uncertain `0.5`, is not a deny by
  itself.
- Denies are per call. They do not taint later calls in the same
  session.

`0.70` is uncalibrated. Run and extend `eval/` before changing it.

Claude Code: exit `0` allows, exit `2` blocks.

## Commands

```
jev-approve install|uninstall|status|doctor [--live] --harness claude-code --project <repo>
jev-approve probe                            # connectivity check
jev-approve test [--live] --harness claude-code
jev-approve inspect <review-id>              # print one recorded decision
```

`hook` and `event` are invoked by the installed harness hooks, not by
hand.

## Limits

- Only `UserPromptSubmit` and `PreToolUse` are wired.
- Authorization comes from `UserPromptSubmit` in the same
  installation / harness / session / agent scope. `transcript_path` is
  unused.
- This gate only sees what the harness actually delivers to hooks.

## Development

```bash
go build ./... && go test ./... && go test -race ./internal/...
go run ./eval
```

## License

[MIT](LICENSE)
