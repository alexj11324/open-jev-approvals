# codex-derived-v1

This policy package preserves the externalized ideas needed for a Hook-based
approval gate: risk and authorization are separate, only user messages form
authorization, and tool payloads are evidence rather than permission.

It is not a copy of Codex Guardian. Jev cannot inspect the environment or call
read-only tools, so this implementation submits only the action, saved user
messages, and adapter-provided facts. When that state is insufficient or the
service or audit store fails, the Hook exits `2`.

The policy is implemented in `internal/policy`. Its thresholds are initial,
uncalibrated operating values and must be evaluated against labeled approvals
before a production rollout.
