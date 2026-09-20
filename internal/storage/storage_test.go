package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestUserPromptsScopesAuthorizationToCurrentTurn(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.RememberPrompt(ctx, "session", "dangerous-turn", "Commit the credential"); err != nil {
		t.Fatal(err)
	}
	if err := store.RememberPrompt(ctx, "session", "normal-turn", "Check repository status"); err != nil {
		t.Fatal(err)
	}

	prompts, err := store.UserPrompts(ctx, "session", "normal-turn")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Check repository status" {
		t.Fatalf("normal turn prompts = %#v", prompts)
	}
}

func TestUserPromptsWithoutTurnIDUsesLatestPrompt(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.RememberPrompt(ctx, "legacy-session", "", "Older prompt"); err != nil {
		t.Fatal(err)
	}
	if err := store.RememberPrompt(ctx, "legacy-session", "", "Current prompt"); err != nil {
		t.Fatal(err)
	}

	prompts, err := store.UserPrompts(ctx, "legacy-session", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Current prompt" {
		t.Fatalf("legacy prompts = %#v", prompts)
	}
}
