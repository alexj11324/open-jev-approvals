package storage

import (
	"context"
	"path/filepath"
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
