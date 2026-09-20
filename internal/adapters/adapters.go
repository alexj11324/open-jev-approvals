package adapters

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

type hookInput struct {
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
	if err := json.Unmarshal(raw, &event); err != nil {
		return contracts.Action{}, fmt.Errorf("decode hook input: %w", err)
	}
	if event.ToolName == "" {
		return contracts.Action{}, fmt.Errorf("hook input has no tool_name")
	}
	if len(event.ToolInput) == 0 || string(event.ToolInput) == "null" {
		event.ToolInput = json.RawMessage(`{}`)
	}
	input := map[string]any{}
	if err := json.Unmarshal(event.ToolInput, &input); err != nil {
		return contracts.Action{}, fmt.Errorf("decode tool_input: %w", err)
	}
	facts := actionFacts(event.ToolName, input)

	return contracts.Action{
		Harness:    harness,
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

func actionFacts(toolName string, input map[string]any) map[string]any {
	if toolName != "Bash" && toolName != "PowerShell" {
		return nil
	}
	command, ok := input["command"].(string)
	if !ok {
		return nil
	}
	lower := strings.ToLower(command)
	for _, indicator := range []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".env", "private_key", "private-key"} {
		if strings.Contains(lower, indicator) {
			return map[string]any{"credential_path_indicators": []string{indicator}}
		}
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
