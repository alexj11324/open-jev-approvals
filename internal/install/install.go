package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

// Status reports how the harness hook config matches this gate.
type Status struct {
	ConfigPath string `json:"config_path"`
	// Installed is true only when every expected event has one of our
	// handlers and the config parsed cleanly.
	Installed bool `json:"installed"`
	// Configured is true when the config file exists and is valid JSON —
	// the harness config is in place even if our hooks are missing.
	Configured bool     `json:"configured"`
	Events     []string `json:"events"`
	Missing    []string `json:"missing"`
	// Malformed is non-empty when the config file exists but is not valid
	// JSON. A malformed config is reported, never an error.
	Malformed string `json:"malformed,omitempty"`
}

func DefaultConfigPath(harness contracts.Harness, projectDir string) string {
	switch harness {
	case contracts.HarnessCodex:
		return filepath.Join(projectDir, ".codex", "hooks.json")
	case contracts.HarnessClaudeCode:
		return filepath.Join(projectDir, ".claude", "settings.json")
	default:
		return ""
	}
}

func Install(harness contracts.Harness, configPath, binary string) error {
	if binary == "" {
		return fmt.Errorf("binary path is required")
	}
	config, err := load(configPath)
	if err != nil {
		return err
	}
	hooks := ensureMap(config, "hooks")
	for _, event := range expectedEvents(harness) {
		matcher := "*"
		if event == "UserPromptSubmit" {
			matcher = ""
		}
		add(hooks, event, matcher, harness, binary)
	}
	return save(configPath, config)
}

func Uninstall(harness contracts.Harness, configPath, binary string) error {
	config, err := load(configPath)
	if err != nil {
		return err
	}
	hooks, ok := config["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	for event, raw := range hooks {
		groups, ok := raw.([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(groups))
		for _, rawGroup := range groups {
			group, ok := rawGroup.(map[string]any)
			if !ok {
				kept = append(kept, rawGroup)
				continue
			}
			handlers, _ := group["hooks"].([]any)
			keptHandlers := make([]any, 0, len(handlers))
			removed := false
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]any)
				command, _ := handler["command"].(string)
				if ok && isOursAnyEvent(command, binary, harness) {
					removed = true
					continue // drop only our handlers, keep foreign ones
				}
				keptHandlers = append(keptHandlers, rawHandler)
			}
			if removed {
				if len(keptHandlers) == 0 {
					continue // the group held only our handlers
				}
				group["hooks"] = keptHandlers
			}
			kept = append(kept, group)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	return save(configPath, config)
}

func Check(harness contracts.Harness, configPath, binary string) (Status, error) {
	status := Status{ConfigPath: configPath, Events: []string{}, Missing: []string{}}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			status.Missing = expectedEvents(harness)
			return status, nil
		}
		return Status{}, err
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		// A broken config must never crash status/doctor: report it.
		status.Malformed = fmt.Sprintf("parse %s as JSON: %v", configPath, err)
		status.Missing = expectedEvents(harness)
		return status, nil
	}
	status.Configured = true
	hooks, _ := config["hooks"].(map[string]any)
	for _, event := range expectedEvents(harness) {
		sub := eventSubcommand(harness, event)
		found := false
		groups, _ := hooks[event].([]any)
		for _, raw := range groups {
			if group, ok := raw.(map[string]any); ok && groupHasOurHandler(group, binary, sub) {
				found = true
				break
			}
		}
		if found {
			status.Events = append(status.Events, event)
		} else {
			status.Missing = append(status.Missing, event)
		}
	}
	status.Installed = status.Malformed == "" && len(status.Missing) == 0
	return status, nil
}

// expectedEvents lists the hook events this gate handles, in a stable order
// for deterministic status output.
func expectedEvents(harness contracts.Harness) []string {
	events := []string{"UserPromptSubmit", "PreToolUse"}
	if harness == contracts.HarnessCodex {
		events = append(events, "PermissionRequest")
	}
	return events
}

func expectedHooks(harness contracts.Harness, binary string) map[string]string {
	commands := make(map[string]string, 3)
	for _, event := range expectedEvents(harness) {
		commands[event] = shellQuote(binary) + " " + eventSubcommand(harness, event)
	}
	return commands
}

// eventSubcommand is the CLI tail our handler runs for a hook event:
// UserPromptSubmit is recorded via `event`; blocking decisions via `hook`.
func eventSubcommand(harness contracts.Harness, event string) string {
	if event == "UserPromptSubmit" {
		return "event --harness " + string(harness)
	}
	return "hook --harness " + string(harness)
}

// shellQuote renders s as a single-quoted POSIX shell string so a binary
// path containing spaces or quotes survives the harness's shell parsing:
// /a b/c -> '/a b/c'; a'b -> 'a'"'"'b'.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// isOurCommand reports whether a handler command belongs to this gate: it
// runs our subcommand and invokes a jev-approve binary — the configured path
// quoted or bare, or any path whose name contains jev-approve (a stale entry
// left behind after the binary moved or an older unquoted install).
func isOurCommand(command, binary, sub string) bool {
	if !strings.Contains(command, sub) {
		return false
	}
	if binary != "" &&
		(strings.Contains(command, shellQuote(binary)) || strings.Contains(command, binary)) {
		return true
	}
	return strings.Contains(command, "jev-approve")
}

// isOursAnyEvent reports whether a handler command is ours under either of
// this harness's subcommands. Uninstall uses it so our handlers are removed
// even if they were written under an unexpected event key.
func isOursAnyEvent(command, binary string, harness contracts.Harness) bool {
	return isOurCommand(command, binary, "hook --harness "+string(harness)) ||
		isOurCommand(command, binary, "event --harness "+string(harness))
}

// add installs or refreshes our handler for event: the first existing
// handler whose command is ours (exact match, stale path, or legacy unquoted
// form) is updated in place to the canonical quoted command and any further
// copies are dropped, so reinstalling after a move leaves exactly one of our
// handlers per event. Foreign handlers are never touched.
func add(hooks map[string]any, event, matcher string, harness contracts.Harness, binary string) {
	sub := eventSubcommand(harness, event)
	command := shellQuote(binary) + " " + sub
	groups, _ := hooks[event].([]any)
	if raw, exists := hooks[event]; exists {
		if _, isList := raw.([]any); !isList {
			groups = []any{raw} // preserve a foreign non-list entry
		}
	}
	kept := make([]any, 0, len(groups)+1)
	installed := false
	for _, rawGroup := range groups {
		group, ok := rawGroup.(map[string]any)
		if !ok {
			kept = append(kept, rawGroup)
			continue
		}
		handlers, _ := group["hooks"].([]any)
		keptHandlers := make([]any, 0, len(handlers))
		touched := false
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]any)
			handlerCommand, _ := handler["command"].(string)
			if !ok || !isOurCommand(handlerCommand, binary, sub) {
				keptHandlers = append(keptHandlers, rawHandler)
				continue
			}
			touched = true
			if installed {
				continue // duplicate of ours: drop it
			}
			handler["command"] = command // refresh in place to the quoted form
			installed = true
			keptHandlers = append(keptHandlers, handler)
		}
		if touched {
			if len(keptHandlers) == 0 {
				continue // group held only duplicate handlers of ours
			}
			group["hooks"] = keptHandlers
		}
		kept = append(kept, group)
	}
	if !installed {
		handler := map[string]any{"type": "command", "command": command, "timeout": 10, "statusMessage": "Reviewing tool action with Jev"}
		group := map[string]any{"hooks": []any{handler}}
		if matcher != "" {
			group["matcher"] = matcher
		}
		kept = append(kept, group)
	}
	hooks[event] = kept
}

func groupHasOurHandler(group map[string]any, binary, sub string) bool {
	handlers, _ := group["hooks"].([]any)
	for _, raw := range handlers {
		handler, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if command, _ := handler["command"].(string); isOurCommand(command, binary, sub) {
			return true
		}
	}
	return false
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok {
		return existing
	}
	created := map[string]any{}
	parent[key] = created
	return created
}

func load(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse %s as JSON: %w", path, err)
	}
	return config, nil
}

// save writes config atomically: a temp file in the same directory is
// written, fsynced, and renamed over the target so a crash can never leave a
// truncated config behind. The file is mode 0600.
func save(path string, config map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
