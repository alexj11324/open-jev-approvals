# open-jev-approvals

[English](README.md) | 简体中文

给 Claude Code 用的审批门。

agent 要执行工具时，hook 会拦住这次调用，交给 TypeSafe Jev 审查，再由
本地政策给出 `allow` 或 `deny`。走第三方 API 时，harness 自带的审批往往
不可用，这个门就是那种场景下的 auto mode。Jev 负责审查，本地政策负责
裁决。Jev 给不出结论时放行——拒绝必须有「这个动作确实危险」的正面证据。

不改 harness 的模型、provider、sandbox 或 bypass 模式。当前面向 macOS
和 Linux。

## 安装

```bash
go build -o bin/jev-approve ./cmd/jev-approve

bin/jev-approve install --harness claude-code --project /path/to/repo \
  --binary "$(pwd)/bin/jev-approve"
```

Hooks 按项目安装（`<project>/.claude/settings.json`）。安装器只写自己的
handler：`UserPromptSubmit`（记下用户提示词，作为授权证据）和
`PreToolUse`（审查动作）。同一文件里的其他 handler 不会被碰，重复执行
也安全。

## 配置

真实审查需要 `TYPESAFE_API_KEY`，写在**用户级** env 文件里。项目目录
里的 `.env` 永远不会被读，这样仓库就没法把审批端点指到别处，也偷不走
key。格式是每行一条 `KEY=value`，见 `.env.example`。

```
# ~/.config/jev-approvals/env
TYPESAFE_API_KEY=...
```

查找顺序：`$JEV_APPROVALS_ENV_FILE`，然后
`$XDG_CONFIG_HOME/jev-approvals/env`，然后
`~/.config/jev-approvals/env`。

| 变量 | 必需 | 含义 |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | 是 | TypeSafe API 凭据 |
| `TYPESAFE_API_BASE_URL` | 否 | HTTPS 端点；默认 `https://api.typesafe.ai/v1/systemone` |
| `TYPESAFE_MODEL` | 否 | Jev 模型；默认 `jev-latest`。响应仍必须是 `jev-*` |
| `JEV_APPROVALS_STATE_DIR` | 否 | `state.db` 所在目录 |
| `JEV_APPROVALS_ENV_FILE` | 否 | env 文件路径覆盖 |

决策存在 SQLite：`$JEV_APPROVALS_STATE_DIR/state.db`，否则
`$XDG_STATE_HOME/jev-approvals/state.db`，否则
`~/.local/state/jev-approvals/state.db`。提示词和工具载荷在发给 Jev
或落盘之前都会脱敏。

## 裁决怎么算

每次拦截到的动作会连同当前 turn 的用户消息、脱敏后的工具输入、以及已
验证事实一起发给 Jev。Jev 回答一组固定问题：风险、授权、危害、范围。
本地政策把这些回答合成二元裁决。

- 确认的（`≥ 0.70`）约束违反、恶意指令、持久安全削弱、未授权敏感外发
  → **拒绝**，即使裁决其余部分没法用。
- critical 风险一律拒绝。
- 凭据探取和破坏性效果会把有效风险升到 `high`，本身并不直接拒绝。
- high 风险还要求至少 `medium` 用户授权，**并且**范围狭窄。
- 审查进行中用户授权变了 → 拒绝。
- Jev 挂了、超时、响应非法、缺 API key、审计库坏了 → **放行**，记录
  `incomplete`。
- 危害低于 `0.70`（包括不确定的 `0.5`）本身不会拒绝。
- 拒绝按单次调用记录，不会污染同一 session 里的后续调用。

`0.70` 尚未校准。改它之前先跑、再扩充 `eval/`。

Claude Code：exit `0` 放行，exit `2` 阻断。

## 命令

```
jev-approve install|uninstall|status|doctor [--live] --harness claude-code --project <repo>
jev-approve probe                            # 连通性检查
jev-approve test [--live] --harness claude-code
jev-approve inspect <review-id>              # 查看一条已记录的决策
```

`hook` 和 `event` 由已安装的 harness hooks 调用，不要手工跑。

## 限制

- 目前只接了 `UserPromptSubmit` 和 `PreToolUse`。
- 授权只来自同一 installation / harness / session / agent 范围内的
  `UserPromptSubmit`。`transcript_path` 未使用。
- 这个门只看 harness 实际交给 hooks 的调用。

## 开发

```bash
go build ./... && go test ./... && go test -race ./internal/...
go run ./eval
```

## 许可证

[MIT](LICENSE)
