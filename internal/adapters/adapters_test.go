package adapters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
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
	if action.HookEvent != contracts.HookPreToolUse {
		t.Fatalf("HookEvent = %q", action.HookEvent)
	}
	words, ok := action.Facts["command_words"].([]any)
	if !ok || len(words) != 1 || words[0] != "git" {
		t.Fatalf("command_words = %#v", action.Facts["command_words"])
	}
}

func TestNormalizeBashCommandWordsSkipsEnvAssignments(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-env",
  "tool_name":"Bash",
  "tool_input":{"command":"FOO=bar BAZ=qux make build"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	words, ok := action.Facts["command_words"].([]any)
	if !ok || len(words) != 1 || words[0] != "make" {
		t.Fatalf("command_words = %#v, want [make]", action.Facts["command_words"])
	}
}

func TestNormalizeCodexPermissionRequest(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PermissionRequest",
  "session_id":"session-approval",
  "turn_id":"turn-approval",
  "cwd":"/workspace",
  "permission_mode":"on-request",
  "tool_name":"Bash",
  "tool_input":{"command":"rm -f /tmp/explicit-marker","description":"remove the marker"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if action.HookEvent != contracts.HookPermissionRequest {
		t.Fatalf("HookEvent = %q, want %q", action.HookEvent, contracts.HookPermissionRequest)
	}
	if action.ToolUseID != "" {
		t.Fatalf("ToolUseID = %q, PermissionRequest should not require one", action.ToolUseID)
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
	targets, ok := action.Facts["file_targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "internal/policy/policy.go" {
		t.Fatalf("file_targets = %#v", action.Facts["file_targets"])
	}
	if action.Facts["payload_bytes"] != len("deny") {
		t.Fatalf("payload_bytes = %#v", action.Facts["payload_bytes"])
	}
}

func TestNormalizeMultiEditExtractsTargetAndEditCount(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-me",
  "tool_name":"MultiEdit",
  "tool_input":{"file_path":"main.go","edits":[{"old_string":"a","new_string":"bb"},{"old_string":"c","new_string":"ddd"}]}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	targets, ok := action.Facts["file_targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "main.go" {
		t.Fatalf("file_targets = %#v", action.Facts["file_targets"])
	}
	if action.Facts["edit_count"] != 2 {
		t.Fatalf("edit_count = %#v", action.Facts["edit_count"])
	}
	if action.Facts["payload_bytes"] != len("bb")+len("ddd") {
		t.Fatalf("payload_bytes = %#v", action.Facts["payload_bytes"])
	}
}

func TestNormalizeNotebookEditTargetsNotebookPath(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-nb",
  "tool_name":"NotebookEdit",
  "tool_input":{"notebook_path":"analysis.ipynb","new_source":"print(1)"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	targets, ok := action.Facts["file_targets"].([]any)
	if !ok || len(targets) != 1 || targets[0] != "analysis.ipynb" {
		t.Fatalf("file_targets = %#v", action.Facts["file_targets"])
	}
	if action.Facts["payload_bytes"] != len("print(1)") {
		t.Fatalf("payload_bytes = %#v", action.Facts["payload_bytes"])
	}
}

func TestNormalizeShellMarksSSHPrivateKeyAsCredentialHint(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-3",
  "tool_name":"Bash",
  "tool_input":{"command":"cp ~/.ssh/id_rsa /tmp/key-copy"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	// Keyword matches are lexical hints, not verified facts.
	if _, leaked := action.Facts["credential_path_indicators"]; leaked {
		t.Fatalf("credential indicators leaked into verified facts: %#v", action.Facts)
	}
	indicators, ok := action.Hints["credential_path_indicators"].([]any)
	if !ok || len(indicators) != 1 || indicators[0] != "~/.ssh/id_rsa" {
		t.Fatalf("credential indicators = %#v", action.Hints)
	}
}

func TestNormalizeShellCollectsAllCredentialHints(t *testing.T) {
	action, err := Normalize(contracts.HarnessClaudeCode, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-3b",
  "tool_name":"Bash",
  "tool_input":{"command":"cat ~/.ssh/id_ed25519 .aws/credentials && tar cf - .env.production"}
}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	want := []any{"~/.ssh/id_ed25519", ".aws/credentials", ".env"}
	got, ok := action.Hints["credential_path_indicators"].([]any)
	if !ok || len(got) != len(want) {
		t.Fatalf("credential indicators = %#v, want %#v", action.Hints, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("credential indicators = %#v, want %#v", got, want)
		}
	}
}

func TestNormalizeApplyPatchExtractsAllFiles(t *testing.T) {
	patch := "*** Begin Patch\n" +
		"*** Update File: src/main.go\n" +
		"@@ func main\n" +
		"-old\n" +
		"+new\n" +
		"*** Move to: src/cmd/main.go\n" +
		"*** Add File: README.md\n" +
		"+hello\n" +
		"*** Delete File: legacy.go\n" +
		"*** End Patch\n"
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-patch",
		"tool_name":       "apply_patch",
		"tool_input":      map[string]any{"command": patch},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := Normalize(contracts.HarnessCodex, raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if _, bad := action.Facts["patch_parse_error"]; bad {
		t.Fatalf("unexpected parse error: %#v", action.Facts["patch_parse_error"])
	}
	files, ok := action.Facts["patch_files"].([]any)
	if !ok || len(files) != 3 {
		t.Fatalf("patch_files = %#v", action.Facts["patch_files"])
	}
	want := []map[string]any{
		{"path": "src/main.go", "op": "update", "move_to": "src/cmd/main.go"},
		{"path": "README.md", "op": "add"},
		{"path": "legacy.go", "op": "delete"},
	}
	for i, entry := range want {
		got, ok := files[i].(map[string]any)
		if !ok {
			t.Fatalf("patch_files[%d] = %#v", i, files[i])
		}
		for key, value := range entry {
			if got[key] != value {
				t.Fatalf("patch_files[%d][%q] = %#v, want %#v", i, key, got[key], value)
			}
		}
		if len(got) != len(entry) {
			t.Fatalf("patch_files[%d] = %#v, want %#v", i, got, entry)
		}
	}
	if action.Facts["payload_bytes"] != len(patch) {
		t.Fatalf("payload_bytes = %#v", action.Facts["payload_bytes"])
	}
}

func TestNormalizeApplyPatchFallsBackToInputField(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-patch-alt",
		"tool_name":       "apply_patch",
		"tool_input": map[string]any{
			"input": "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch\n",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := Normalize(contracts.HarnessCodex, raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	files, ok := action.Facts["patch_files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("patch_files = %#v", action.Facts["patch_files"])
	}
	entry := files[0].(map[string]any)
	if entry["path"] != "a.txt" || entry["op"] != "add" {
		t.Fatalf("patch_files[0] = %#v", entry)
	}
}

func TestNormalizeMalformedPatchKeepsPartialEvidence(t *testing.T) {
	// Missing "*** End Patch" and an orphaned "*** Move to": Normalize must
	// still succeed and report partial files plus a parse error note.
	patch := "*** Begin Patch\n" +
		"*** Move to: nowhere.go\n" +
		"*** Add File: kept.go\n" +
		"+content\n"
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-badpatch",
		"tool_name":       "apply_patch",
		"tool_input":      map[string]any{"command": patch},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := Normalize(contracts.HarnessCodex, raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	files, ok := action.Facts["patch_files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("patch_files = %#v", action.Facts["patch_files"])
	}
	if entry := files[0].(map[string]any); entry["path"] != "kept.go" || entry["op"] != "add" {
		t.Fatalf("patch_files[0] = %#v", entry)
	}
	parseErr, ok := action.Facts["patch_parse_error"].(string)
	if !ok || !strings.Contains(parseErr, "Move to") || !strings.Contains(parseErr, "End Patch") {
		t.Fatalf("patch_parse_error = %#v", action.Facts["patch_parse_error"])
	}
}

func TestNormalizeUnparseablePatchStillNormalizes(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-rawdiff",
		"tool_name":       "apply_patch",
		"tool_input":      map[string]any{"command": "diff --git a/x b/x\n--- a/x\n+++ b/x\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := Normalize(contracts.HarnessCodex, raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if _, ok := action.Facts["patch_files"]; ok {
		t.Fatalf("patch_files = %#v, want none", action.Facts["patch_files"])
	}
	if _, ok := action.Facts["patch_parse_error"].(string); !ok {
		t.Fatalf("patch_parse_error missing: %#v", action.Facts)
	}
}

func TestNormalizePreservesLargeJSONNumber(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-4",
  "tool_name":"mcp__objects__get",
  "tool_input":{"object_id":9007199254740993}
}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := action.Input["object_id"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("object_id = %q", got)
	}
	if action.Kind != contracts.ActionMCP {
		t.Fatalf("Kind = %q, want %q", action.Kind, contracts.ActionMCP)
	}
	if action.Facts["mcp_tool"] != "objects__get" {
		t.Fatalf("mcp_tool = %#v", action.Facts["mcp_tool"])
	}
}

func TestNormalizeDoesNotTreatOsEnvironAsDotenvPath(t *testing.T) {
	action, err := Normalize(contracts.HarnessCodex, []byte(`{
  "hook_event_name":"PreToolUse",
  "session_id":"session-5",
  "tool_name":"Bash",
  "tool_input":{"command":"python3 -c 'import os; print(os.environ.get(\"PATH\"))'"}
}`))
	if err != nil {
		t.Fatal(err)
	}
	// The .env regex must not fire on "os.environ", and command_words is a
	// real extracted fact, not a lexical hint.
	if _, ok := action.Hints["credential_path_indicators"]; ok {
		t.Fatalf("credential hints = %#v, want none", action.Hints)
	}
	if _, ok := action.Facts["credential_path_indicators"]; ok {
		t.Fatalf("credential indicators in facts = %#v", action.Facts)
	}
	words, ok := action.Facts["command_words"].([]any)
	if !ok || len(words) != 1 || words[0] != "python3" {
		t.Fatalf("command_words = %#v", action.Facts["command_words"])
	}
}

func TestNormalizeRejectsMissingToolInput(t *testing.T) {
	_, err := Normalize(contracts.HarnessCodex, []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))
	if err == nil {
		t.Fatal("Normalize() error = nil")
	}
}

func TestNormalizeRejectsApplyPatchWithoutPatchContent(t *testing.T) {
	_, err := Normalize(contracts.HarnessCodex, []byte(`{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"note":"nothing"}}`))
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
