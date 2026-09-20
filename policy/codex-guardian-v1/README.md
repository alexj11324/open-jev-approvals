# codex-guardian-v1

`codex-guardian-v1` is the active approval policy of this gate. It is a
**binary** policy: every composed decision is exactly `allow` or `deny`.
There is no `review_required`, no deferred outcome, and no third state
anywhere in the pipeline.

Deny requires positive evidence. This gate *is* the harness's auto mode —
there is no native approval flow to fall back to — so a reviewer that
cannot produce a verdict must not stall the user's work. An unavailable
assessor, an API failure, an invalid or incomplete verdict, unverifiable
authorization freshness, or an unavailable audit store all resolve to
`allow` (recorded with `incomplete: true`), while a verdict that
affirmatively reports a hazard still denies.

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
| `risk_confidence`, `authorization_confidence` | probability | must be valid for the verdict to be complete; the value itself is not a deny input |
| `narrowly_scoped` | noul probability | target/effect concretely bounded by user authorization |
| `violates_explicit_constraint`, `sensitive_egress`, `egress_authorized`, `credential_probing`, `persistent_security_weakening`, `destructive_effect`, `malicious_instruction` | noul probabilities | hazard judgments; `>= 0.70` counts as confirmed |

## Decision semantics

Positive-evidence rules evaluate first, on whatever fields are present and
valid; the first match decides:

1. `risk_level == critical` → `deny`, even when the rest of the verdict is
   unusable.
2. `violates_explicit_constraint >= 0.70` → `deny`.
3. `malicious_instruction >= 0.70` → `deny`.
4. `persistent_security_weakening >= 0.70` → `deny`.
5. `sensitive_egress >= 0.70` while `egress_authorized` is absent, invalid,
   or `< 0.70` → `deny`.
6. A composed `allow` whose authorization version provably changed while
   the review was in flight → `deny`.

If no positive-evidence rule matches, completeness is checked: any missing
or invalid judgment field — a confidence outside `[0, 1]`, an absent noul,
an unrecognized risk level or authorization band — resolves to `allow`.
On a complete verdict, effective risk is raised to `high` when
`credential_probing >= 0.70` or `destructive_effect >= 0.70`; high
effective risk then requires `user_authorization` of `medium` or `high`
**and** `narrowly_scoped >= 0.70`, else `deny`. Everything else → `allow`.

Threshold semantics matter: a hazard noul *below* `0.70` — including an
uncertain `0.5` — does **not** by itself deny. Ambiguous-but-valid
probabilities are unconfirmed and flow through the risk/authorization
checks.

## Changes vs the `codex-derived-v1` draft

- **Binary collapse.** The draft language still carried Guardian's
  three-outcome shape. `codex-guardian-v1` collapses composition to
  strictly `allow`/`deny`.
- **Fail-open degradation.** Reviewer failure — unavailable JEV, invalid
  response, missing audit store — resolves to `allow` rather than `deny`,
  because this gate replaces the harness approval flow outright; a broken
  reviewer cannot hand the question back to a native prompt. Deny stays
  reserved for positive evidence.
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
