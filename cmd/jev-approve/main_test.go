package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestLoadConfiguredDotEnvIgnoresTargetWorkingDirectory(t *testing.T) {
	t.Setenv("JEV_APPROVALS_ENV_FILE", "")
	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, ".env"), []byte("JEV_TARGET_DOTENV_SENTINEL=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(targetDir)
	previous, existed := os.LookupEnv("JEV_TARGET_DOTENV_SENTINEL")
	os.Unsetenv("JEV_TARGET_DOTENV_SENTINEL")
	t.Cleanup(func() {
		if existed {
			os.Setenv("JEV_TARGET_DOTENV_SENTINEL", previous)
			return
		}
		os.Unsetenv("JEV_TARGET_DOTENV_SENTINEL")
	})

	if err := loadConfiguredDotEnv(); err != nil {
		t.Fatal(err)
	}
	if _, exists := os.LookupEnv("JEV_TARGET_DOTENV_SENTINEL"); exists {
		t.Fatal("target working-directory .env was loaded")
	}
}

func TestLoadConfiguredDotEnvRequiresAbsolutePath(t *testing.T) {
	t.Setenv("JEV_APPROVALS_ENV_FILE", ".env")
	if err := loadConfiguredDotEnv(); err == nil {
		t.Fatal("loadConfiguredDotEnv() error = nil")
	}
}

func TestEventAcceptsInstalledHarnessArgumentAndStoresPrompt(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("JEV_APPROVALS_STATE_DIR", stateDir)

	code, err := runEvent(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","turn_id":"turn-1","prompt":"Only run git status."}`),
		&bytes.Buffer{},
	)
	if err != nil || code != 0 {
		t.Fatalf("runEvent() = (%d, %v), want (0, nil)", code, err)
	}

	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prompts, err := store.UserPrompts(context.Background(), "session-1", "turn-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || prompts[0] != "Only run git status." {
		t.Fatalf("stored prompts = %#v", prompts)
	}
}

func TestEventFailsOpenOnMalformedInput(t *testing.T) {
	var stderr bytes.Buffer
	code, err := runEvent(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":`),
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("runEvent() = (%d, %v), want (0, nil)", code, err)
	}
	if !strings.Contains(stderr.String(), "allowing action") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestEventFailsOpenOnCodexInputWithoutTurnID(t *testing.T) {
	var stderr bytes.Buffer
	code, err := runEvent(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","prompt":"Do not store me."}`),
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("runEvent() = (%d, %v), want (0, nil)", code, err)
	}
	if !strings.Contains(stderr.String(), "allowing action") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestHookFailsOpenOnMalformedInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := runHook(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":`),
		&stdout,
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("runHook() = (%d, %v), want (0, nil)", code, err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "allowing action") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunTestReportsDeterministicHookAndPolicyChecks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := run([]string{"test", "--harness", "codex"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("run(test) = (%d, %v), stderr = %q", code, err, stderr.String())
	}
	for _, expected := range []string{"PASS adapter", "PASS policy allow", "PASS policy block", "PASS policy credential deny", "SKIP live JEV"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("test output missing %q: %q", expected, stdout.String())
		}
	}
}

func TestWriteHookDecisionAllowsWithoutOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "scoped authorization"},
		&stdout,
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("writeHookDecision() = (%d, %v)", code, err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestWriteHookDecisionBlocksConfirmedCodexPreToolUseHazard(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "credential probing"},
		&stdout,
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("writeHookDecision() = (%d, %v)", code, err)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	hookOutput := output["hookSpecificOutput"].(map[string]any)
	if hookOutput["permissionDecision"] != "deny" || hookOutput["permissionDecisionReason"] != "credential probing" {
		t.Fatalf("output = %#v", output)
	}
}

func TestWriteHookDecisionFailsOpenWhenDenyVerdictCannotBeWritten(t *testing.T) {
	var stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "unsafe"},
		failingWriter{},
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("writeHookDecision() = (%d, %v), want (0, nil)", code, err)
	}
	if !strings.Contains(stderr.String(), "allowing action") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestWriteHookDecisionFailsOpenWithoutExplicitOutcome(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.Decision{},
		&stdout,
		&stderr,
	)
	if err != nil || code != 0 {
		t.Fatalf("writeHookDecision() = (%d, %v), want (0, nil)", code, err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "allowing action") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}
