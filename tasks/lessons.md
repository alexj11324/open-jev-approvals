# Lessons

Failure modes this project already hit, and the rule that prevents repeats.

## 1. Self-installation caused SQLITE_BUSY self-blocking

When the gate's own hooks were installed on the development project,
concurrent agent tool calls each spawned a `jev-approve hook` process that
opened the same `state.db`. Writers collided → `SQLITE_BUSY` → denied
reviews that blocked the agent itself.

**Fix:** `busy_timeout(5000)` pragma + `journal_mode(WAL)` +
`synchronous(NORMAL)` + `SetMaxOpenConns(1)` in `internal/storage.Open`, so
writers serialize deterministically instead of racing.

**Rule:** any state a hook writes must assume N concurrent processes; never
ship a SQLite open without busy timeout and WAL, and keep one pooled
connection per process.

## 2. Missing authorization scoping caused flaky denials

Early versions keyed saved user prompts loosely, so a prompt from another
session/agent could authorize (or fail to authorize) the current action →
nondeterministic denials and potential cross-session authorization bleed.

**Fix:** `storage.ScopeKey(installation_id, harness, session_id, agent_id)`
namespaces every prompt and decision; `AuthorizationVersion` snapshots the
scope and is re-checked after assessing so an allow never ships against
stale authorization.

**Rule:** authorization evidence is only valid inside its scope and its
version; both must travel with the action.

## 3. Project `.env` could redirect the approval endpoint

Loading `.env` from the working directory meant a checked-out repo could
set `TYPESAFE_API_BASE_URL`/`TYPESAFE_API_KEY` and send approval payloads —
including tool inputs — to an attacker-controlled endpoint.

**Fix:** credentials load only from a user-level env file
(`$JEV_APPROVALS_ENV_FILE` → `$XDG_CONFIG_HOME/jev-approvals/env` →
`~/.config/jev-approvals/env`). `TYPESAFE_API_BASE_URL` must be `https`
with no embedded credentials, query, or fragment; the HTTP client refuses
cross-origin redirects.

**Rule:** a reviewed project must never control where its own approval
request is sent. User-managed config only.

## 4. Old policy conflated normal auth with credential probing

The earlier `credential_probing` question treated any credential-path
access as probing, so routine commands through a service's normal auth flow
(e.g. `gh`, `ssh` to a known host) produced false denies.

**Fix:** the question now means extracting credentials/session material
from an **unintended** source to perform an action after normal
authentication failed; `credential_path_indicators` facts are evidence, and
normal auth flows for user-requested actions are explicitly false.
Confirmed probing escalates effective risk to `high` rather than denying
outright.

**Rule:** hazard questions must encode intent (unauthorized/unintended),
not just surface indicators like "touched a credential path".

## 5. Secrets were sent to JEV unredacted

Tool payloads and prompts were serialized into the JEV request and the
audit log verbatim — a denied `cat ~/.aws/credentials` still leaked the
secret to the reviewer API and the database.

**Fix:** `internal/sanitize` redacts secret *values* (private keys, bearer
tokens, AWS/GitHub/Slack key shapes, `key=value` secrets) while preserving
structure; `jev.Assess` redacts before serialization and
`storage.RecordDecision`/`RememberPrompt` redact before persisting.

**Rule:** redaction happens at the trust boundary — before any bytes leave
the process or hit disk — never "later in the pipeline".
