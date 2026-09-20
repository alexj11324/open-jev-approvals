# codex-derived-v1

This policy package preserves the externalized ideas needed for a Hook-based
approval gate: risk and authorization are separate, only user messages form
authorization, and tool payloads are evidence rather than permission.

This is a TypeSafe/JEV adapter for Codex Guardian's published policy at upstream
commit `5c5308fc9a9ee789049d646ef11e5400384b9c6f`. The policy template and default
policy are embedded byte-for-byte. The adapter supplies the Hook's tool name,
full tool input, working directory, action identity, and captured current-turn
user messages. JEV is the sole reviewer for those inputs.

The policy is implemented by JEV's `outcome` Choice. Local code does not add
thresholds or supplementary safety judgments.

## Decision semantics

Risk and authorization are independent. Explicit user authorization can raise
the authorization level for the concrete action, target, parameters, and turn;
it does not lower the action's intrinsic risk or override hard safety hazards.

| Condition | Outcome |
| --- | --- |
| JEV returns explicit Guardian `outcome = deny` | `DENY` |
| JEV returns explicit Guardian `outcome = allow` | `ALLOW` |
| API, parsing, state, audit, or output failure | `ALLOW` |

Prior decisions are never authorization or precedent. Only current-turn trusted
user messages establish authorization. Model uncertainty does not create a
third outcome or a local block.

The adapter does not receive Guardian's full in-process transcript or its
read-only investigation tools. It also intentionally differs from upstream on
failure handling: incomplete or unavailable review allows the action.
