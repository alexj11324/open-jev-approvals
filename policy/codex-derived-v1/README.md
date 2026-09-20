# codex-derived-v1

This policy package preserves the externalized ideas needed for a Hook-based
approval gate: risk and authorization are separate, only user messages form
authorization, and tool payloads are evidence rather than permission.

This is a TypeSafe/JEV implementation of Codex Guardian's published policy at
upstream commit `5c5308fc9a9ee789049d646ef11e5400384b9c6f`. Jev cannot call read-only
tools, so the adapter supplies the exact action, current-turn user messages, and
verified facts. JEV is the sole reviewer; the result is always `ALLOW` or
`DENY`.

The policy is implemented in `internal/policy`. Its thresholds are initial,
uncalibrated operating values and must be evaluated against labeled approvals
before a production rollout.

## Decision semantics

Risk and authorization are independent. Explicit user authorization can raise
the authorization level for the concrete action, target, parameters, and turn;
it does not lower the action's intrinsic risk or override hard safety hazards.

| Condition | Outcome |
| --- | --- |
| Confirmed explicit-constraint violation, unauthorized sensitive egress, malicious injection, or unauthorized persistent security weakening | `DENY` |
| Low or medium risk without an explicit deny rule | `ALLOW` |
| High risk | `ALLOW` only with at least medium authorization and narrow scope |
| Critical risk | `DENY` |
| Invalid response, unavailable service, or failed audit write | `DENY` |

Prior decisions are never authorization or precedent. Only current-turn trusted
user messages establish authorization. Model uncertainty does not create a
third outcome: low/medium ambiguity resolves the same way, while confirmed hard
hazards and critical risk deny.
