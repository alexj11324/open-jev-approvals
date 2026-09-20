package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestEventAcceptsInstalledHarnessArgumentAndStoresPrompt(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("JEV_APPROVALS_STATE_DIR", stateDir)

	code, err := runEvent(
		[]string{"--harness", "codex"},
		strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","turn_id":"turn-1","prompt":"Only run git status."}`),
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

func TestWriteHookDecisionUsesCodexPermissionRequestProtocol(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.HookPermissionRequest,
		contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "scoped authorization"},
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
	decision := hookOutput["decision"].(map[string]any)
	if hookOutput["hookEventName"] != "PermissionRequest" || decision["behavior"] != "allow" {
		t.Fatalf("output = %#v", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestWriteHookDecisionDeniesFailedCodexPermissionRequest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.HookPermissionRequest,
		contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "review failed"},
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
	decision := hookOutput["decision"].(map[string]any)
	if decision["behavior"] != "deny" || decision["message"] != "review failed" {
		t.Fatalf("output = %#v", output)
	}
}

func TestWriteHookDecisionBlocksConfirmedCodexPreToolUseHazard(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.HookPreToolUse,
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

func TestWriteHookDecisionBlocksWhenVerdictCannotBeWritten(t *testing.T) {
	var stderr bytes.Buffer
	code, err := writeHookDecision(
		contracts.HarnessCodex,
		contracts.HookPermissionRequest,
		contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "safe"},
		failingWriter{},
		&stderr,
	)
	if err != nil || code != 2 {
		t.Fatalf("writeHookDecision() = (%d, %v), want (2, nil)", code, err)
	}
	if !strings.Contains(stderr.String(), "could not emit the required hook verdict") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
