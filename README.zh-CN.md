# open-jev-approvals

[English](README.md) | 简体中文

一个 MIT 许可的 JEV 审批门，用于 Codex 和 Claude Code 的 hooks。

它接收 hook 事件与工具/权限载荷，把每个被拦截的动作发给 TypeSafe Jev，
再由本地政策把类型化判断组合成结论。在 Codex 上保留了上游
`PreToolUse` 阻断与 `PermissionRequest` 决策的分离。JEV 是唯一的评审者：
每个被拦截的动作最终只有两种结果——本地的 `allow` 或 `deny`，没有第三种。

首个版本面向 macOS 和 Linux。它不改变任何 harness 的模型、provider、
sandbox 或 bypass 模式。

## 构建

```bash
go build -o bin/jev-approve ./cmd/jev-approve
go test ./...
```

## 配置

真实评审需要 `TYPESAFE_API_KEY`。二进制只从**用户级** env 文件读取凭据
——项目里的 `.env` 永远不会被读取，因此仓库无法重定向审批端点或窃取
密钥。文件使用 `KEY=value` 行（见 `.env.example`），按以下顺序解析：

1. 设置了 `$JEV_APPROVALS_ENV_FILE` 时使用它；
2. 设置了 `$XDG_CONFIG_HOME` 时使用 `$XDG_CONFIG_HOME/jev-approvals/env`；
3. 否则使用 `~/.config/jev-approvals/env`。

环境变量：

| 变量 | 必需 | 含义 |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | 是 | TypeSafe API 凭据，以 bearer token 发送 |
| `TYPESAFE_API_BASE_URL` | 否 | 端点覆盖；必须为 `https`，不允许内嵌凭据/query/fragment（默认 `https://api.typesafe.ai/v1/systemone`） |
| `TYPESAFE_MODEL` | 否 | 模型覆盖（默认 `jev-latest`）；响应仍会被校验为 `jev-*` 模型 |
| `JEV_APPROVALS_STATE_DIR` | 否 | 存放 `state.db` 的目录 |
| `JEV_APPROVALS_ENV_FILE` | 否 | env 文件路径覆盖 |
| `XDG_STATE_HOME`、`XDG_CONFIG_HOME` | 否 | state 与 config 的 XDG 基目录覆盖 |

审计数据库为 SQLite，位于 `$JEV_APPROVALS_STATE_DIR/state.db`，否则
`$XDG_STATE_HOME/jev-approvals/state.db`，否则
`~/.local/state/jev-approvals/state.db`。它保存记录的用户提示词
（授权证据）以及每条决策及其 assessment 与政策版本。工具载荷和提示词在
发送给 JEV 之前、写入数据库之前都会经过脱敏（`internal/sanitize`）。

## 命令

```
jev-approve hook --harness <codex|claude-code>     # 由 harness hooks 调用（PreToolUse / PermissionRequest）
jev-approve event --harness <codex|claude-code>    # 由 UserPromptSubmit 调用以记录授权
jev-approve install|uninstall|status|doctor        # 管理每个项目的 hooks
jev-approve probe                                   # 对 JEV API 的无害连通性检查
jev-approve test [--live] --harness <harness>      # 离线 adapter+policy 检查；--live 同时调用 JEV
jev-approve inspect <review-id>                     # 打印一条已记录的决策
```

`hook` 与 `event` 由已安装的 harness hooks 调用，而不是手工执行。
`doctor --live` 校验配置的 JEV 凭据，不执行任何 harness 工具调用。

## 测试这个门

```bash
# 无网络调用：校验 hook 输入以及 allow、显式拒绝、凭据拒绝三条政策路径。
bin/jev-approve test --harness codex

# 同时让完整的审批 state 经过配置的 JEV API。
bin/jev-approve test --harness codex --live

# 真实运行时验收：构建二进制、隔离临时仓库、真实 hook 载荷。
scripts/test-codex-hook.sh

# 离线校准集：带标签的 assessment 经过二进制政策。
go run ./eval
```

`test` 命令从不执行它评估的工具载荷。通过的 live 测试证明 JEV 返回了
合法的类型化回答，并且本地政策能够组合它们。

`scripts/test-codex-hook.sh` 是运行时验收测试。它把二进制构建到一个
**包含空格**的路径里，把 hook 安装到隔离的临时仓库中，并对构建出的
二进制执行 install/幂等/status/doctor/uninstall 以及真实的
`PreToolUse` 与 `PermissionRequest` 载荷。它从不触碰真实凭据：使用假
API key、不可达端点和临时目录里的假 `id_rsa`，并断言被拒绝的动作没有
文件系统副作用、每条决策都按 `tool_use_id` 审计。设置 `RUN_LIVE=1` 并
提供真实 `TYPESAFE_API_KEY` 时，它还会用 `codex exec` 端到端运行并要求
live `allow`/`deny` 判定；不设置则离线运行并断言 fail-open 降级放行。

## 安装 hook

```bash
bin/jev-approve install --harness codex --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"

bin/jev-approve install --harness claude-code --project /path/to/target-project \
  --binary "$(pwd)/bin/jev-approve"
```

Hooks 按**项目**安装：安装器编辑 `<project>/.codex/hooks.json`（Codex）
或 `<project>/.claude/settings.json`（Claude Code）。它添加一个
`UserPromptSubmit` hook（记录授权）和一个全工具 `PreToolUse` hook；
对 Codex 还会添加全工具 `PermissionRequest` hook。它不改变 harness 的
权限模式、sandbox、模型、provider 或 provider 凭据。Codex 项目 hooks
仍需要 Codex 信任后才会执行。

用 `status`、`doctor`、`inspect <review-id>` 和 `uninstall` 配合相同的
`--harness`、`--project`、`--binary` 参数。

## 决策行为

每个受支持的本地工具调用都被归一化为一个 action，连同已保存的用户消息、
脱敏后的工具输入和已验证事实一起发给 JEV。一次 TypeSafe 请求提出相互
独立的风险、授权、显式约束、外发、凭据探取、安全削弱、破坏性效果、
不可信指令和范围问题。本地 `codex-guardian-v1` 政策（`internal/policy`，
由 `policy/codex-guardian-v1/policy.json` 镜像）决定结果：

- 结果是二元的：`allow` 或 `deny`。deny 需要正面证据——这个门**就是**
  harness 的 auto mode，所以审查层故障（JEV 不可达、裁决无效或不完整、
  授权新鲜度无法验证、审计库不可用）一律降级为 `allow`（记录
  `incomplete: true`），而不是卡住用户的工作。没有任何决策会下放给
  Codex 用户审批、Guardian 或自动评审。
- 确认的（`>= 0.70`）显式约束违反、恶意指令、未授权持久安全削弱、
  未授权敏感外发——拒绝，即使出现在不完整的部分裁决中。critical 风险
  一律拒绝。
- 确认的凭据探取或破坏性效果会把有效风险升级到 `high`。`high` 风险
  要求至少 `medium` 用户授权且动作范围狭窄（`>= 0.70`）。
- 低于阈值的危害判断——包括不确定的 `0.5`——本身不会拒绝；整体缺失
  或非法的裁决则 fail open。
- Choice 置信度必须是合法概率，但其数值不是拒绝依据——无害的
  低/中歧义不会变成误拦。
- 确认的 Codex `PreToolUse` 拒绝返回上游 `permissionDecision: deny`
  JSON 形态；allow 静默退出 `0`，符合上游协议要求。Codex
  `PermissionRequest` 始终返回上游嵌套 `decision.behavior` 形态。
  Claude Code 保持 exit `0` 放行 / exit `2` 阻断。

当前 Noul 动作阈值为 `0.70`，**尚未校准**——还没有经验证的数据集。
改动它之前请先运行并扩展 `eval/`。

## Codex 来源契约

政策与输出契约源自上游 Codex 的 commit
`5c5308fc9a9ee789049d646ef11e5400384b9c6f`：

- [Guardian 风险、授权、证据与结果规则](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy_template.md)。
- [外发、凭据、持久削弱与破坏性动作的默认安全政策](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/prompts/templates/guardian/policy.md)。
- [Guardian 严格的 `allow`/`deny` assessment schema](https://github.com/openai/codex/blob/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/ext/guardian-reviewer/src/assessment.rs)。
- [`PreToolUse` 与 `PermissionRequest` 线上格式](https://github.com/openai/codex/tree/5c5308fc9a9ee789049d646ef11e5400384b9c6f/codex-rs/hooks/src/events)。

JEV 替代评审者，而 Codex 负责传输与执行 hook 判定。

## 限制

- `action_probability` 阈值未校准；`eval/` 里的带标签集合是脚手架，
  尚不是经过验证的数据集。
- 只接线了 `UserPromptSubmit`、`PreToolUse` 和（Codex 的）
  `PermissionRequest`。`SessionStart`、`PostToolUse`、`SessionEnd` 和
  子 agent 生命周期事件尚未消费。
- hook 载荷里的 `transcript_path` 未被读取；授权仅来自同一
  installation/harness/session/agent 作用域内经 `UserPromptSubmit`
  记录的用户提示词。
- Claude Code 保持其 exit code 契约；本版本不替换它的审批路由。

## 边界声明

Codex 的托管工具和 `write_stdin` 续写不会重新进入它的本地
`PreToolUse` hook 路径。本项目审计并拦截的是各 harness 实际交付给
hooks 的工具调用；对 harness 不暴露给 hooks 的路径不做强制保证。
