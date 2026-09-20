# Policy calibration set

This directory holds the labeled evaluation scaffold for the
`codex-guardian-v1` approval policy. It is intentionally **offline**: no JEV
API call is made. Each case feeds a fake assessment (in the exact shape
`internal/jev` decodes from a TypeSafe response) straight into
`policy.Compose` and compares the binary outcome with its label.

## Run

```bash
go run ./eval                 # uses eval/cases.jsonl
go run ./eval -cases path/to/other.jsonl
```

The runner prints one line per case and a summary, then exits non-zero if
any case disagrees with its label:

```
PASS low-risk-routine-allow                                  -> allow
FAIL high-risk-low-auth-deny                                 -> allow (want deny): ...
16/16 passed; false allows (expected deny): 0; false denies (expected allow): 0
```

## Case format (`cases.jsonl`)

One JSON object per line; blank lines and `#` comments are ignored.

```json
{"name": "unique-case-name", "expect": "allow|deny", "comment": "why", "assessment": { ... }}
```

`assessment` is a `contracts.Assessment`: `risk_level`, `risk_confidence`,
`authorization`, `authorization_confidence`, `narrowly_scoped`, and a `noul`
map keyed by the required question ids (see
`policy/codex-guardian-v1/policy.json`). Missing noul keys are legal input —
they exercise the fail-open degradation path and should be labeled `allow`
unless a present, valid field carries positive deny evidence.

## Denominators are required

Never report a single accuracy number. Always report:

- **Deny-labeled denominator**: of the cases labeled `deny`, how many denied
  (and how many **falsely allowed** — the dangerous direction for an
  approval gate).
- **Allow-labeled denominator**: of the cases labeled `allow`, how many
  allowed (and how many **falsely denied** — availability cost).

The runner prints both confusion counts. When growing the set, keep both
classes populated — a set that is 95% deny-labeled can make a broken
always-deny policy look good on raw accuracy.

## Calibrating `action_probability` (currently 0.70, uncalibrated)

1. Collect real JEV assessments: each `decisions` row in the state database
   stores `assessment_json`. Export them, label the correct outcome, and
   append them here as JSONL rows.
2. Run `go run ./eval` at the current threshold and record per-class
   denominators.
3. Re-run with a candidate threshold by editing `DefaultThresholds()` (or
   adding a `-threshold` flag) and compare false-allow vs false-deny trade
   offs. A false allow is strictly worse than a false deny for this gate.
4. Update `policy.json`, `DefaultThresholds()`, and the policy README
   together — `TestDocumentMatchesCheckedInPolicy` fails if they drift.
