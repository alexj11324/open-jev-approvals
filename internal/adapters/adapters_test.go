package adapters

import (
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func TestNormalizeCodexBash(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
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

func TestNormalizeShellMarksSSHPrivateKeyAsCredentialEvidence(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "session_id":"session-3",
  "tool_name":"Bash",
  "tool_input":{"command":"cp ~/.ssh/id_rsa /tmp/key-copy"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	indicators, ok := action.Facts["credential_path_indicators"].([]string)
	if !ok || len(indicators) != 1 || indicators[0] != "~/.ssh/id_rsa" {
		t.Fatalf("credential indicators = %#v", action.Facts)
	}
}
