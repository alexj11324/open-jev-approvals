# Tasks

## Current: policy hardening (wt/policy-meta)

- [x] `policy/codex-guardian-v1/policy.json` — executable policy document
  mirroring `internal/policy` exactly (version, `action_probability` 0.70,
  required question ids, ordered deny rules, uncalibrated-thresholds note).
- [x] `policy/codex-guardian-v1/README.md` — semantics + change history vs
  the `codex-derived-v1` draft.
- [x] `internal/policy/policy_test.go` — `Document()` ⇆ `policy.json` parity
  test; new binary-policy cases (missing noul → deny, invalid confidence →
  deny, high risk + medium auth + unscoped → deny, destructive escalation).
- [x] `.github/workflows/ci.yml` — build/vet/test/race on ubuntu + macOS
  (Go 1.27.x), gofmt gate, GOOS=windows cross-compile.
- [x] `eval/` — `main.go` runner, `cases.jsonl` (16 labeled cases),
  `README.md` with denominator guidance.
- [x] `README.md` — corrected env-file model (user-level env only), state db
  location, env var table, command list, limitations.
- [x] `tasks/lessons.md` — recorded failure modes and fixes.

## Follow-ups (not done here)

- [ ] Grow `eval/cases.jsonl` from real recorded `assessment_json` rows;
  calibrate `action_probability` with per-class denominators.
- [ ] Wire `SessionStart`/`PostToolUse`/`SessionEnd` and subagent lifecycle
  events if the harnesses expose them.
- [ ] Decide whether `transcript_path` should supplement authorization
  evidence (currently unused).
- [ ] Revisit the `credential_probing`/`destructive_effect` escalation once
  the calibration set has enough high-risk examples.

## Review

- Verified: `gofmt`, `go build ./...`, `go test -count=1 ./internal/policy/`,
  `go run ./eval` (see commit message / PR notes for tails).
