# codex-guardian-v1

`codex-guardian-v1` is the active approval policy of this gate. It is a
fail-closed **binary** policy: every composed decision is exactly `allow` or
`deny`. There is no `review_required`, no deferred outcome, and no third
state anywhere in the pipeline — an unavailable reviewer, an invalid model
response, a missing safety judgment, a failed audit write, or unverifiable
authorization freshness all produce `deny`.

## Source of truth

The executable source of truth is `internal/policy/policy.go`
(`policy.Compose` + `policy.Document`). `policy.json` in this directory is
the checked-in, human-readable mirror of that code — same version string,
same `action_probability` threshold (`0.70`), same required question ids,
same deny rules in evaluation order. `internal/policy/policy_test.go`
asserts the two stay semantically identical, so a drift between code and
document fails the test suite.

## Inputs

One JEV assessment per intercepted action:

| Field | Type | Role |
| --- | --- | --- |
| `risk_level` | choice: `low`/`medium`/`high`/`critical` | intrinsic risk of the exact action |
| `user_authorization` | choice: `unknown`/`low`/`medium`/`high` | how directly current-turn user messages authorize this action |
| `risk_confidence`, `authorization_confidence` | probability | must be valid; the value itself is not a deny input |
| `narrowly_scoped` | noul probability | target/effect concretely bounded by user authorization |
| `violates_explicit_constraint`, `sensitive_egress`, `egress_authorized`, `credential_probing`, `persistent_security_weakening`, `destructive_effect`, `malicious_instruction` | noul probabilities | hazard judgments; `>= 0.70` counts as confirmed |

## Decision semantics

Deny rules fire in this order; the first match decides, otherwise `allow`:

1. A choice confidence is missing, NaN, or outside `[0, 1]` → `deny`.
2. Any required noul judgment is absent or invalid → `deny`.
3. `violates_explicit_constraint >= 0.70` → `deny`.
4. `malicious_instruction >= 0.70` → `deny`.
5. `persistent_security_weakening >= 0.70` → `deny`.
6. `sensitive_egress >= 0.70` while `egress_authorized < 0.70` → `deny`.
7. `risk_level == critical` → `deny`; an unrecognized risk level → `deny`.
8. Effective risk is raised to `high` when `credential_probing >= 0.70` or
   `destructive_effect >= 0.70`. High effective risk then requires
   `user_authorization` of `medium` or `high` **and**
   `narrowly_scoped >= 0.70`, else `deny`.
9. Everything else → `allow` (low/medium risk, or high risk that is
   authorized and narrowly scoped).

Threshold semantics matter: a hazard noul *below* `0.70` — including an
uncertain `0.5` — does **not** by itself deny. Only missing/invalid
judgments fail closed on uncertainty; ambiguous-but-valid probabilities are
treated as unconfirmed and flow through the risk/authorization checks.

## Changes vs the `codex-derived-v1` draft

- **Binary collapse.** The draft language still carried Guardian's
  three-outcome shape. `codex-guardian-v1` collapses composition to strictly
  `allow`/`deny`; every incomplete or unverifiable review resolves to `deny`
  instead of a deferred outcome.
- **`credential_probing` rescoped.** It now means extracting credentials or
  session material from an **unintended** source to perform an action after
  normal authentication failed. Routine use of a service's normal
  authentication flow for a user-requested action is explicitly *not*
  probing — the old conflation produced false denies on ordinary
  authenticated commands.
- **High-risk authorization relaxed.** High-risk actions now accept
  `medium` authorization (not only `high`) when the action is confirmed
  narrowly scoped (`narrowly_scoped >= 0.70`).
- **Escalation instead of outright deny.** `credential_probing` and
  `destructive_effect` raise effective risk to `high` rather than denying
  unconditionally, so an authorized, narrowly-scoped destructive action can
  still be allowed.
- **Versioned evidence.** Every recorded decision carries
  `policy_version: codex-guardian-v1` so an allow can be traced to this
  exact rule set.

## Calibration status

`action_probability = 0.70` is an initial, **uncalibrated** operating value
— there is no validated dataset yet. Run the labeled set in `eval/`
(`go run ./eval`) before changing the threshold, and record denominators per
expected outcome; see `eval/README.md`.
