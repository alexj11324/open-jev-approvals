package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
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
	facts, hints := actionEvidence(event.ToolName, input)

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
		Hints:      hints,
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
	switch toolName {
	case "Bash", "PowerShell":
		command, ok := input["command"].(string)
		if !ok || strings.TrimSpace(command) == "" {
			return fmt.Errorf("hook input for %s has no command", toolName)
		}
	case "apply_patch":
		if _, ok := patchSource(input); !ok {
			return fmt.Errorf("hook input for %s has no patch content", toolName)
		}
	}
	return nil
}

// actionEvidence extracts deterministic evidence about the action and splits
// it into two channels:
//
//   - facts are verified facts parsed directly out of tool_input: target
//     paths, patch operations, the invoked executable, payload sizes. They
//     are presented to JEV as verified_facts and must never contain keyword
//     guesses.
//   - hints are lexical hints: substring/keyword signals that are cheap
//     leads for the reviewer but prove nothing by themselves (the matched
//     text could be an argument, a comment, or unrelated output). They are
//     presented to JEV as lexical_hints.
//
// Lists are emitted as []any so sanitize.RedactValue recurses into them.
func actionEvidence(toolName string, input map[string]any) (facts, hints map[string]any) {
	facts = map[string]any{}
	hints = map[string]any{}

	switch toolName {
	case "Bash", "PowerShell":
		if command, ok := input["command"].(string); ok {
			if words := commandWords(command); len(words) > 0 {
				facts["command_words"] = words
			}
			if indicators := findCredentialPathIndicators(command); len(indicators) > 0 {
				hints["credential_path_indicators"] = indicators
			}
		}
	case "apply_patch":
		if patch, ok := patchSource(input); ok {
			facts["payload_bytes"] = len(patch)
			files, parseErr := parsePatchFiles(patch)
			if len(files) > 0 {
				facts["patch_files"] = files
			}
			if parseErr != "" {
				facts["patch_parse_error"] = parseErr
			}
		}
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		if targets := fileTargets(toolName, input); len(targets) > 0 {
			facts["file_targets"] = targets
		}
		if size, ok := payloadBytes(toolName, input); ok {
			facts["payload_bytes"] = size
		}
		if toolName == "MultiEdit" {
			if edits, ok := input["edits"].([]any); ok {
				facts["edit_count"] = len(edits)
			}
		}
	}

	if strings.HasPrefix(toolName, "mcp__") {
		facts["mcp_tool"] = strings.TrimPrefix(toolName, "mcp__")
	}

	if len(facts) == 0 {
		facts = nil
	}
	if len(hints) == 0 {
		hints = nil
	}
	return facts, hints
}

// envAssignment matches a leading shell prefix of the form NAME=value.
var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// commandWords returns the first meaningful word of a shell command — the
// executable name — skipping leading VAR=value environment assignments.
// Deliberately minimal: this is not a shell parser.
func commandWords(command string) []any {
	for _, field := range strings.Fields(command) {
		if envAssignment.MatchString(field) {
			continue
		}
		return []any{field}
	}
	return nil
}

// credentialPathIndicators are substring signals only. A command matching
// one of them might touch credential material, but the match itself proves
// nothing, so they go to lexical_hints and never to verified_facts.
var credentialPathIndicators = []string{
	"~/.ssh/id_rsa", "~/.ssh/id_ed25519",
	".ssh/id_rsa", ".ssh/id_ed25519",
	".aws/credentials",
	"private_key", "private-key",
}

var dotenvPathPattern = regexp.MustCompile(`(?i)(^|[\s'"=/])\.env(?:\.[a-z0-9_-]+)?($|[\s'"/])`)

func findCredentialPathIndicators(command string) []any {
	lower := strings.ToLower(command)
	matched := map[string]bool{}
	for _, indicator := range credentialPathIndicators {
		if strings.Contains(lower, indicator) {
			matched[indicator] = true
		}
	}
	var out []any
	for _, indicator := range credentialPathIndicators {
		if !matched[indicator] {
			continue
		}
		// "~/.ssh/id_rsa" already contains ".ssh/id_rsa"; keep only the
		// more specific form so a single path is reported once.
		if strings.HasPrefix(indicator, ".ssh/") && matched["~/"+indicator] {
			continue
		}
		out = append(out, indicator)
	}
	if dotenvPathPattern.MatchString(lower) {
		out = append(out, ".env")
	}
	return out
}

// patchSource returns the patch body for apply_patch. Harnesses carry it
// under "command", "input", or "patch" — checked in that order.
func patchSource(input map[string]any) (string, bool) {
	for _, key := range []string{"command", "input", "patch"} {
		if value, ok := input[key].(string); ok && strings.TrimSpace(value) != "" {
			return value, true
		}
	}
	return "", false
}

// parsePatchFiles extracts every file entry from an apply_patch document:
//
//	*** Begin Patch
//	*** Add File: path      -> {path, op: "add"}
//	*** Update File: path   -> {path, op: "update"}
//	*** Move to: new_path   -> sets move_to on the preceding update entry
//	*** Delete File: path   -> {path, op: "delete"}
//	*** End Patch
//
// The parser never fails: a malformed document still returns whatever
// parsed, plus human-readable error notes for patch_parse_error.
func parsePatchFiles(patch string) ([]any, string) {
	var files []any
	var errs []string
	began := false
	ended := false
	for index, raw := range strings.Split(patch, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case line == "*** Begin Patch":
			began = true
		case line == "*** End Patch":
			ended = true
		case strings.HasPrefix(line, "*** Add File:"):
			files = appendPatchFile(files, &errs, index, line, "*** Add File:", "add")
		case strings.HasPrefix(line, "*** Update File:"):
			files = appendPatchFile(files, &errs, index, line, "*** Update File:", "update")
		case strings.HasPrefix(line, "*** Delete File:"):
			files = appendPatchFile(files, &errs, index, line, "*** Delete File:", "delete")
		case strings.HasPrefix(line, "*** Move to:"):
			target := strings.TrimSpace(strings.TrimPrefix(line, "*** Move to:"))
			last, ok := lastPatchFile(files)
			switch {
			case target == "":
				errs = append(errs, fmt.Sprintf("line %d: \"*** Move to\" has no path", index+1))
			case !ok:
				errs = append(errs, fmt.Sprintf("line %d: \"*** Move to\" without a preceding file entry", index+1))
			case last["op"] != "update":
				errs = append(errs, fmt.Sprintf("line %d: \"*** Move to\" follows a %s entry, want update", index+1, last["op"]))
			default:
				last["move_to"] = target
			}
		case strings.HasPrefix(line, "***"):
			errs = append(errs, fmt.Sprintf("line %d: unrecognized patch marker %q", index+1, line))
		}
		if ended {
			break
		}
	}
	if !began {
		errs = append(errs, "missing \"*** Begin Patch\" marker")
	}
	if began && !ended {
		errs = append(errs, "missing \"*** End Patch\" marker")
	}
	if len(files) == 0 {
		errs = append(errs, "no patch file entries found")
	}
	return files, strings.Join(errs, "; ")
}

func appendPatchFile(files []any, errs *[]string, index int, line, prefix, op string) []any {
	path := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if path == "" {
		*errs = append(*errs, fmt.Sprintf("line %d: %q has no file path", index+1, prefix))
		return files
	}
	return append(files, map[string]any{"path": path, "op": op})
}

func lastPatchFile(files []any) (map[string]any, bool) {
	if len(files) == 0 {
		return nil, false
	}
	entry, ok := files[len(files)-1].(map[string]any)
	return entry, ok
}

// fileTargets returns the real file paths a file-mutation tool would touch.
func fileTargets(toolName string, input map[string]any) []any {
	var path string
	if toolName == "NotebookEdit" {
		path, _ = input["notebook_path"].(string)
	} else {
		path, _ = input["file_path"].(string)
	}
	if path == "" {
		return nil
	}
	return []any{path}
}

// payloadBytes returns the size of the new content a file-mutation tool
// would write, when it is determinable from tool_input.
func payloadBytes(toolName string, input map[string]any) (int, bool) {
	switch toolName {
	case "Edit":
		if newString, ok := input["new_string"].(string); ok {
			return len(newString), true
		}
	case "Write":
		if content, ok := input["content"].(string); ok {
			return len(content), true
		}
	case "NotebookEdit":
		if newSource, ok := input["new_source"].(string); ok {
			return len(newSource), true
		}
	case "MultiEdit":
		edits, ok := input["edits"].([]any)
		if !ok {
			return 0, false
		}
		total := 0
		for _, edit := range edits {
			if entry, ok := edit.(map[string]any); ok {
				if newString, ok := entry["new_string"].(string); ok {
					total += len(newString)
				}
			}
		}
		return total, true
	}
	return 0, false
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
