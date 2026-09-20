package adapters

import (
	"encoding/json"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func TestNormalizeCodexBash(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-1",
  "turn_id":"turn-1",
  "tool_use_id":"tool-1",
  "cwd":"/workspace",
  "permission_mode":"bypassPermissions",
  "tool_name":"Bash",
  "tool_input":{"command":"git push origin main"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if action.Kind != contracts.ActionShell {
		t.Fatalf("Kind = %q, want %q", action.Kind, contracts.ActionShell)
	}
	if action.Input["command"] != "git push origin main" {
		t.Fatalf("command = %#v", action.Input["command"])
	}
	if action.SessionID != "session-1" || action.TurnID != "turn-1" {
		t.Fatalf("session context = %#v", action)
	}
}

func TestNormalizeClaudeEdit(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-2",
  "transcript_path":"/tmp/transcript.jsonl",
  "cwd":"/workspace",
  "permission_mode":"bypassPermissions",
  "tool_name":"Edit",
  "tool_use_id":"tool-2",
  "agent_id":"agent-7",
  "tool_input":{"file_path":"internal/policy/policy.go","old_string":"allow", "new_string":"deny"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if action.Kind != contracts.ActionFileMutation {
		t.Fatalf("Kind = %q, want %q", action.Kind, contracts.ActionFileMutation)
	}
	if action.AgentID != "agent-7" {
		t.Fatalf("AgentID = %q", action.AgentID)
	}
	if action.Input["file_path"] != "internal/policy/policy.go" {
		t.Fatalf("file path = %#v", action.Input["file_path"])
	}
}

func TestNormalizeCodexApplyPatchPreservesStructuredInput(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-patch",
  "turn_id":"turn-patch",
  "tool_use_id":"tool-patch",
  "cwd":"/workspace",
  "permission_mode":"bypassPermissions",
  "tool_name":"apply_patch",
  "tool_input":{"patch":"*** Begin Patch\n*** Add File: note.txt\n+hello\n*** End Patch"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if action.Kind != contracts.ActionFileMutation {
		t.Fatalf("Kind = %q, want %q", action.Kind, contracts.ActionFileMutation)
	}
	if action.Input["patch"] == "" {
		t.Fatalf("patch input was not preserved: %#v", action.Input)
	}
}

func TestNormalizePreservesLargeJSONNumber(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-4",
  "turn_id":"turn-4",
  "tool_name":"mcp__objects__get",
  "tool_input":{"object_id":9007199254740993}
}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := action.Input["object_id"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("object_id = %q", got)
	}
}

func TestNormalizeRejectsMissingToolInput(t *testing.T) {
	_, err := Normalize(contracts.HarnessCodex, []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))
	if err == nil {
		t.Fatal("Normalize() error = nil")
	}
}

func TestNormalizeRejectsWrongHookEvent(t *testing.T) {
	_, err := Normalize(contracts.HarnessCodex, []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"true"}}`))
	if err == nil {
		t.Fatal("Normalize() error = nil")
	}
}

func TestNormalizeRejectsCodexInputWithoutTurnID(t *testing.T) {
	_, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-1",
  "tool_use_id":"tool-1",
  "tool_name":"Bash",
  "tool_input":{"command":"git status"}
}`))
	if err == nil {
		t.Fatal("Normalize() error = nil")
	}
}
