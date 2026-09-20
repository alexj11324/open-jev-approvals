package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

type Status struct {
	ConfigPath string `json:"config_path"`
	Installed  bool   `json:"installed"`
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
	for event, command := range expectedHooks(harness, binary) {
		matcher := "*"
		if event == "UserPromptSubmit" {
			matcher = ""
		}
		add(hooks, event, matcher, command)
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
	prefix := binary + " "
	for event, raw := range hooks {
		groups, ok := raw.([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(groups))
		for _, group := range groups {
			groupMap, ok := group.(map[string]any)
			if !ok || !groupUsesBinary(groupMap, prefix) {
				filtered = append(filtered, group)
				continue
			}
		}
		if len(filtered) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = filtered
		}
	}
	return save(configPath, config)
}

func Check(harness contracts.Harness, configPath, binary string) (Status, error) {
	config, err := load(configPath)
	if err != nil {
		return Status{}, err
	}
	hooks, _ := config["hooks"].(map[string]any)
	for event, command := range expectedHooks(harness, binary) {
		raw := hooks[event]
		groups, _ := raw.([]any)
		found := false
		for _, group := range groups {
			if groupMap, ok := group.(map[string]any); ok && groupHasCommand(groupMap, command) {
				found = true
				break
			}
		}
		if !found {
			return Status{ConfigPath: configPath, Installed: false}, nil
		}
	}
	return Status{ConfigPath: configPath, Installed: true}, nil
}

func expectedHooks(harness contracts.Harness, binary string) map[string]string {
	commands := map[string]string{
		"UserPromptSubmit": binary + " event --harness " + string(harness),
		"PreToolUse":       binary + " hook --harness " + string(harness),
	}
	if harness == contracts.HarnessCodex {
		commands["PermissionRequest"] = binary + " hook --harness " + string(harness)
	}
	return commands
}

func add(hooks map[string]any, event, matcher, command string) {
	groups, _ := hooks[event].([]any)
	for _, raw := range groups {
		if group, ok := raw.(map[string]any); ok && groupHasCommand(group, command) {
			return
		}
	}
	handler := map[string]any{"type": "command", "command": command, "timeout": 10, "statusMessage": "Reviewing tool action with Jev"}
	group := map[string]any{"hooks": []any{handler}}
	if matcher != "" {
		group["matcher"] = matcher
	}
	hooks[event] = append(groups, group)
}

func groupHasCommand(group map[string]any, command string) bool {
	handlers, _ := group["hooks"].([]any)
	for _, raw := range handlers {
		handler, _ := raw.(map[string]any)
		if handler["command"] == command {
			return true
		}
	}
	return false
}

func groupUsesBinary(group map[string]any, prefix string) bool {
	handlers, _ := group["hooks"].([]any)
	for _, raw := range handlers {
		handler, _ := raw.(map[string]any)
		command, _ := handler["command"].(string)
		if len(command) >= len(prefix) && command[:len(prefix)] == prefix {
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

func save(path string, config map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
