package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

func testScope(t *testing.T, store *Store, sessionID string) string {
	t.Helper()
	id, err := store.InstallationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ScopeKey(id, contracts.HarnessCodex, sessionID, "")
}

func TestUserPromptsScopesAuthorizationToCurrentTurn(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	scope := testScope(t, store, "session")
	if err := store.RememberPrompt(ctx, scope, "session", "dangerous-turn", "Commit the credential"); err != nil {
		t.Fatal(err)
	}
	if err := store.RememberPrompt(ctx, scope, "session", "normal-turn", "Check repository status"); err != nil {
		t.Fatal(err)
	}

	prompts, _, err := store.UserPrompts(ctx, scope, "normal-turn")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Check repository status" {
		t.Fatalf("normal turn prompts = %#v", prompts)
	}
}

func TestUserPromptsWithoutTurnIDUsesLatestTurn(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	scope := testScope(t, store, "legacy-session")
	if err := store.RememberPrompt(ctx, scope, "legacy-session", "turn-1", "Older prompt"); err != nil {
		t.Fatal(err)
	}
	if err := store.RememberPrompt(ctx, scope, "legacy-session", "turn-2", "Current prompt"); err != nil {
		t.Fatal(err)
	}

	prompts, _, err := store.UserPrompts(ctx, scope, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Current prompt" {
		t.Fatalf("latest turn prompts = %#v", prompts)
	}
}

func TestAuthorizationVersionAdvancesWithNewPrompts(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	scope := testScope(t, store, "session")
	_, version, err := store.UserPrompts(ctx, scope, "turn-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RememberPrompt(ctx, scope, "session", "turn-1", "First prompt"); err != nil {
		t.Fatal(err)
	}
	current, err := store.AuthorizationVersion(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if current == version {
		t.Fatalf("authorization version did not advance: %d", current)
	}
}

func TestScopesDoNotShareAuthorization(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	id, err := store.InstallationID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	codexScope := ScopeKey(id, contracts.HarnessCodex, "session", "")
	claudeScope := ScopeKey(id, contracts.HarnessClaudeCode, "session", "")
	if err := store.RememberPrompt(ctx, codexScope, "session", "turn", "codex prompt"); err != nil {
		t.Fatal(err)
	}
	prompts, _, err := store.UserPrompts(ctx, claudeScope, "turn")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 0 {
		t.Fatalf("claude-code scope leaked codex prompts: %#v", prompts)
	}
}

// TestOpenMigratesPreScopeSchema builds a database at the pre-scope schema —
// no scope/turn_id on user_prompts, no scope/assessment_json on decisions, no
// meta table — then runs Open and expects every column migration to land
// without losing the rows that were already there.
func TestOpenMigratesPreScopeSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE user_prompts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  prompt TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE decisions (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  action_json TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
INSERT INTO user_prompts(session_id, prompt, created_at)
  VALUES ('legacy-session', 'legacy prompt', '2024-01-01T00:00:00Z');
INSERT INTO decisions(id, session_id, action_json, decision_json, created_at)
  VALUES ('rev_old', 'legacy-session', '{}', '{}', '2024-01-01T00:00:00Z');`); err != nil {
		t.Fatalf("build legacy schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated database: %v", err)
	}
	defer store.Close()

	for _, tc := range []struct{ table, column string }{
		{"user_prompts", "scope"},
		{"user_prompts", "turn_id"},
		{"decisions", "scope"},
		{"decisions", "assessment_json"},
	} {
		var present bool
		if err := store.db.QueryRow(
			`SELECT COUNT(*) > 0 FROM pragma_table_info(?) WHERE name = ?`,
			tc.table, tc.column,
		).Scan(&present); err != nil {
			t.Fatalf("inspect %s.%s: %v", tc.table, tc.column, err)
		}
		if !present {
			t.Errorf("migration did not add %s.%s", tc.table, tc.column)
		}
	}

	var prompt string
	if err := store.db.QueryRow(`SELECT prompt FROM user_prompts`).Scan(&prompt); err != nil {
		t.Fatalf("read preserved prompt: %v", err)
	}
	if prompt != "legacy prompt" {
		t.Fatalf("prompt row was not preserved: %q", prompt)
	}
	var decisions int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&decisions); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	if decisions != 1 {
		t.Fatalf("decisions rows = %d, want 1", decisions)
	}

	var meta bool
	if err := store.db.QueryRow(
		`SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'meta'`,
	).Scan(&meta); err != nil {
		t.Fatalf("inspect meta table: %v", err)
	}
	if !meta {
		t.Fatal("migration did not create the meta table")
	}

	// The migrated store must be usable end to end: a scoped prompt and a
	// decision with an assessment both write cleanly.
	ctx := context.Background()
	scope := ScopeKey("inst", contracts.HarnessCodex, "legacy-session", "")
	if err := store.RememberPrompt(ctx, scope, "legacy-session", "turn", "new prompt"); err != nil {
		t.Fatalf("write into migrated user_prompts: %v", err)
	}
	if _, err := store.RecordDecision(ctx,
		contracts.Action{Scope: scope, SessionID: "legacy-session"},
		contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "post-migration"},
		&contracts.Assessment{RiskLevel: contracts.RiskLow},
	); err != nil {
		t.Fatalf("write into migrated decisions: %v", err)
	}
}

// TestRecordDecisionPersistsAssessment proves the inspect path can recover the
// JEV assessment later: the raw row must carry the serialized assessment.
func TestRecordDecisionPersistsAssessment(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	scope := testScope(t, store, "session")
	assessment := &contracts.Assessment{
		Model:          "test-model",
		RiskLevel:      contracts.RiskLow,
		RiskConfidence: 0.9,
		Noul:           map[string]float64{"malicious_instruction": 0.1},
	}
	action := contracts.Action{Scope: scope, SessionID: "session", ToolName: "bash", Kind: contracts.ActionShell}
	id, err := store.RecordDecision(ctx, action,
		contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "assessment recorded"},
		assessment)
	if err != nil {
		t.Fatal(err)
	}

	var raw sql.NullString
	if err := store.db.QueryRow(`SELECT assessment_json FROM decisions WHERE id = ?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !raw.Valid || !strings.Contains(raw.String, `"risk_level"`) {
		t.Fatalf("assessment_json missing serialized assessment: %q", raw.String)
	}

	decision, err := store.Decision(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != contracts.DecisionAllow || decision.ReviewID != id {
		t.Fatalf("Decision(%q) = %+v", id, decision)
	}
}
