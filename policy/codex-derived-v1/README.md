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

## Decision semantics

Risk and authorization are independent. Explicit user authorization can raise
the authorization level for the concrete action, target, parameters, and turn;
it does not lower the action's intrinsic risk or override hard safety hazards.

| Condition | Outcome |
| --- | --- |
| Confirmed explicit-constraint violation, credential probing, unauthorized sensitive egress, or persistent security weakening | `DENY` |
| Uncertain critical hazard | `REVIEW_REQUIRED` |
| Low-risk action with concrete tool input and no confirmed hazard | `ALLOW`, even when the general evidence-sufficiency judgment is uncertain |
| Medium/high-risk action with insufficient evidence | `REVIEW_REQUIRED` |
| High-risk action | Requires high, confident, narrowly scoped authorization |

The low-risk evidence rule prevents a broad uncertainty question from blocking
routine preparatory reads. It does not make Jev's risk classification a
deterministic security boundary. A production policy still needs a separately
verified reversibility/effect class for each tool action, with Jev contributing
semantic signals to that code-owned policy.
