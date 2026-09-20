# open-jev-approvals

[English](README.md) | 简体中文

open-jev-approvals 是给 Codex 和 Claude Code 用的审批门。agent 每次想执行
工具调用时，hook 会把这个动作拦下来发给 TypeSafe Jev 审查，然后要么放行，
要么拒绝。

这个项目的目的，是给走第三方 API 的用户提供一个 auto mode。在这种用法下
harness 自带的审批流程用不了，所以由这个门来代替：Jev 充当审查者，一个
小型的本地政策把它的判断组合成裁决。如果 Jev 连不上或者返回了没法用的
东西，这次调用会被放行——不应该因为审查服务挂了就卡住你的工作。拒绝
永远需要动作确实危险的正面证据。

## 工作原理

每次拦截到工具调用，Jev 会针对这个动作回答一组固定的问题：风险有多大、
用户是否授权了、是否违反显式约束、是否向外发送数据、是否在探取凭据、
是否削弱安全、是否有破坏性效果、是否来自恶意指令、范围是否狭窄。每个
答案以概率的形式返回。

本地政策（`policy/codex-guardian-v1`）把这些概率组合起来：

- 确认的危害——任何一个概率达到或超过 `0.70`——拒绝这次调用，即使
  裁决的其他部分缺失或格式不对。
- critical 风险等级永远拒绝。
- high 风险的动作还要求至少 `medium` 级别的用户授权，并且范围狭窄。
- 如果在审查进行期间用户授权发生了变化，这次裁决被拒绝，因为它是基于
  过期的状态算出来的。
- 任何导致无法完成真实审查的情况——Jev 挂了、超时、响应非法、缺 API
  key、审计数据库坏了——都会放行这次调用，并在记录里标记 `incomplete`。

拒绝是按单次调用记录的，不会影响同一 session 里的后续调用。

## 安装

```bash
go build -o bin/jev-approve ./cmd/jev-approve
bin/jev-approve install --harness codex --project /path/to/repo --binary "$(pwd)/bin/jev-approve"
```

Claude Code 用 `--harness claude-code`。安装器只动它自己的 hook 条目，
同一个文件里的其他 handler 不会被碰，重复执行也是安全的。

## 配置

必须配置 `TYPESAFE_API_KEY`。把它写进 `~/.config/jev-approvals/env`，
格式是 `KEY=value` 每行一条（参考 `.env.example`）。项目目录里的
`.env` 永远不会被读取，这样仓库就没法把审批端点指向别处或偷走 key。
`$JEV_APPROVALS_ENV_FILE` 可以改变这个文件的位置。

## 命令

```bash
jev-approve status    --harness codex --project <repo>  # 装了没、配好了没
jev-approve doctor    --harness codex --project <repo>  # 诊断；--live 实测 Jev
jev-approve test      --harness codex                   # 离线自检；--live 打真 API
jev-approve inspect   <review-id>                       # 查看一条已记录的决策
jev-approve uninstall --harness codex --project <repo>  # 只移除我们的 handler
```

每条决策都存在本地 SQLite 里，包含动作、裁决、完整的 Jev 评估和政策
版本，按 `tool_use_id` 索引。`inspect` 可以查看单条记录。

## 开发

```bash
go build ./... && go test ./... && go test -race ./internal/...
go run ./eval                      # 标注政策用例
scripts/test-codex-hook.sh         # 端到端验收；RUN_LIVE=1 走真实 Jev
```

## 许可证

MIT
