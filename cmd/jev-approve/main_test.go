package main

import (
	"context"
	"strings"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

func TestEventAcceptsInstalledHarnessArgumentAndStoresPrompt(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("JEV_APPROVALS_STATE_DIR", stateDir)

	code, err := runEvent(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","prompt":"Only run git status."}`),
	)
	if err != nil || code != 0 {
		t.Fatalf("runEvent() = (%d, %v), want (0, nil)", code, err)
	}

	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prompts, err := store.UserPrompts(context.Background(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Only run git status." {
		t.Fatalf("stored prompts = %#v", prompts)
	}
}
