package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

type hookInput struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	TurnID         string          `json:"turn_id"`
	ToolUseID      string          `json:"tool_use_id"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	CWD            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
}

func Normalize(harness contracts.Harness, raw []byte) (contracts.Action, error) {
	var event hookInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return contracts.Action{}, fmt.Errorf("decode hook input: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return contracts.Action{}, err
	}
	hookEvent := contracts.HookEvent(event.HookEventName)
	if hookEvent != contracts.HookPreToolUse && hookEvent != contracts.HookPermissionRequest {
		return contracts.Action{}, fmt.Errorf("hook input event is %q, want PreToolUse or PermissionRequest", event.HookEventName)
	}
	if event.ToolName == "" {
		return contracts.Action{}, fmt.Errorf("hook input has no tool_name")
	}
	if len(event.ToolInput) == 0 || string(event.ToolInput) == "null" {
		return contracts.Action{}, fmt.Errorf("hook input has no tool_input")
	}
	input := map[string]any{}
	inputDecoder := json.NewDecoder(bytes.NewReader(event.ToolInput))
	inputDecoder.UseNumber()
	if err := inputDecoder.Decode(&input); err != nil {
		return contracts.Action{}, fmt.Errorf("decode tool_input: %w", err)
	}
	if err := validateInput(event.ToolName, input); err != nil {
		return contracts.Action{}, err
	}
	facts := actionFacts(event.ToolName, input)

	return contracts.Action{
		Harness:    harness,
		HookEvent:  hookEvent,
		SessionID:  event.SessionID,
		TurnID:     event.TurnID,
		ToolUseID:  event.ToolUseID,
		AgentID:    event.AgentID,
		AgentType:  event.AgentType,
		CWD:        event.CWD,
		Permission: event.PermissionMode,
		ToolName:   event.ToolName,
		Kind:       kindFor(event.ToolName),
		Input:      input,
		Facts:      facts,
	}, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("hook input contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing hook input: %w", err)
	}
	return nil
}

func validateInput(toolName string, input map[string]any) error {
	if input == nil {
		return fmt.Errorf("hook input tool_input must be an object")
	}
	if toolName == "Bash" || toolName == "PowerShell" || toolName == "apply_patch" {
		command, ok := input["command"].(string)
		if !ok || strings.TrimSpace(command) == "" {
			return fmt.Errorf("hook input for %s has no command", toolName)
		}
	}
	return nil
}

var dotenvPathPattern = regexp.MustCompile(`(?i)(^|[\s'"=/])\.env(?:\.[a-z0-9_-]+)?($|[\s'"/])`)

func actionFacts(toolName string, input map[string]any) map[string]any {
	if toolName != "Bash" && toolName != "PowerShell" {
		return nil
	}
	command, ok := input["command"].(string)
	if !ok {
		return nil
	}
	lower := strings.ToLower(command)
	for _, indicator := range []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", "private_key", "private-key"} {
		if strings.Contains(lower, indicator) {
			return map[string]any{"credential_path_indicators": []string{indicator}}
		}
	}
	if dotenvPathPattern.MatchString(lower) {
		return map[string]any{"credential_path_indicators": []string{".env"}}
	}
	return nil
}

func kindFor(toolName string) contracts.ActionKind {
	switch toolName {
	case "Bash", "PowerShell":
		return contracts.ActionShell
	case "apply_patch", "Edit", "Write", "MultiEdit", "NotebookEdit":
		return contracts.ActionFileMutation
	case "Read", "Glob", "Grep", "ListDirectory":
		return contracts.ActionFileRead
	case "WebFetch", "WebSearch":
		return contracts.ActionNetwork
	default:
		if strings.HasPrefix(toolName, "mcp__") {
			return contracts.ActionMCP
		}
		return contracts.ActionOther
	}
}
