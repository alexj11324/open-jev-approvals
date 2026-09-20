package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

func readConfig(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func hookCommands(t *testing.T, config map[string]any, event string) []string {
	t.Helper()
	hooks, _ := config["hooks"].(map[string]any)
	groups, _ := hooks[event].([]any)
	var commands []string
	for _, rawGroup := range groups {
		group, _ := rawGroup.(map[string]any)
		handlers, _ := group["hooks"].([]any)
		for _, rawHandler := range handlers {
			handler, _ := rawHandler.(map[string]any)
			if command, ok := handler["command"].(string); ok {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func TestShellQuote(t *testing.T) {
	for input, want := range map[string]string{
		"/opt/jev-approve":         `'/opt/jev-approve'`,
		"/opt/dir with spaces/jev": `'/opt/dir with spaces/jev'`,
		"/opt/path'with'quote/jev": `'/opt/path'"'"'with'"'"'quote/jev'`,
		"":                         `''`,
	} {
		if got := shellQuote(input); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInstallIsIdempotentAndPreservesHarnessSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	binary := "/opt/jev-approve"
	if err := os.WriteFile(path, []byte(`{"permission_mode":"bypassPermissions","model_provider":"third-party","hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Install(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}
	if err := Install(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}

	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed {
		t.Fatalf("Check().Installed = false, status = %#v", status)
	}
	if !status.Configured || status.Malformed != "" {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Events) != 3 || len(status.Missing) != 0 {
		t.Fatalf("status events/missing = %#v", status)
	}

	config := readConfig(t, path)
	if got := hookCommands(t, config, "PreToolUse"); len(got) != 1 || got[0] != `'/opt/jev-approve' hook --harness codex` {
		t.Fatalf("PreToolUse commands = %#v", got)
	}
	if len(hookCommands(t, config, "PermissionRequest")) != 1 {
		t.Fatalf("PermissionRequest commands = %#v", hookCommands(t, config, "PermissionRequest"))
	}
	if got := hookCommands(t, config, "UserPromptSubmit"); len(got) != 1 || got[0] != `'/opt/jev-approve' event --harness codex` {
		t.Fatalf("UserPromptSubmit commands = %#v", got)
	}
	if config["permission_mode"] != "bypassPermissions" || config["model_provider"] != "third-party" {
		t.Fatalf("installer changed harness settings: %#v", config)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
}

func TestInstallQuotesBinaryPathWithSpaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	binary := "/opt/dir with spaces/jev-approve"
	if err := Install(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}
	config := readConfig(t, path)
	want := `'/opt/dir with spaces/jev-approve' hook --harness codex`
	if got := hookCommands(t, config, "PreToolUse"); len(got) != 1 || got[0] != want {
		t.Fatalf("PreToolUse commands = %#v, want %q", got, want)
	}
	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed {
		t.Fatalf("Check().Installed = false for quoted path, status = %#v", status)
	}
}

func TestCheckRequiresPermissionRequestForCodex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	binary := "/opt/jev-approve"
	legacy := `{"hooks":{"UserPromptSubmit":[{"hooks":[{"command":"/opt/jev-approve event --harness codex"}]}],"PreToolUse":[{"hooks":[{"command":"/opt/jev-approve hook --harness codex"}]}]}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed {
		t.Fatal("Check().Installed = true without PermissionRequest hook")
	}
	if len(status.Events) != 2 || len(status.Missing) != 1 || status.Missing[0] != "PermissionRequest" {
		t.Fatalf("status = %#v", status)
	}
}

func TestInstallUpgradesStaleHandlerInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// A stale unquoted handler at a different path plus a foreign handler in
	// the same group: install must refresh ours and keep the foreign one.
	stale := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/old/path/jev-approve hook --harness codex"},{"type":"command","command":"/usr/bin/foreign hook"}]}],"UserPromptSubmit":[{"hooks":[{"command":"/old/path/jev-approve event --harness codex"}]}],"PermissionRequest":[{"hooks":[{"command":"/old/path/jev-approve hook --harness codex"}]}]}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := "/new/bin/jev-approve"
	if err := Install(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}
	config := readConfig(t, path)
	got := hookCommands(t, config, "PreToolUse")
	want := []string{`'/new/bin/jev-approve' hook --harness codex`, "/usr/bin/foreign hook"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("PreToolUse commands = %#v, want %#v", got, want)
	}
	// Reinstall after another move must leave exactly one of our handlers.
	if err := Install(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}
	config = readConfig(t, path)
	if got := hookCommands(t, config, "PreToolUse"); len(got) != 2 {
		t.Fatalf("PreToolUse commands after reinstall = %#v", got)
	}
	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed {
		t.Fatalf("status = %#v", status)
	}
}

func TestUninstallRemovesOnlyOurHandlers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	binary := "/opt/jev-approve"
	config := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"'/opt/jev-approve' hook --harness codex"},{"type":"command","command":"/usr/bin/foreign hook"}]},{"matcher":"*","hooks":[{"type":"command","command":"/opt/jev-approve hook --harness codex"}]}],"UserPromptSubmit":[{"hooks":[{"command":"/opt/jev-approve event --harness codex"}]}],"PermissionRequest":[{"hooks":[{"command":"'/opt/jev-approve' hook --harness codex"}]}]}}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(contracts.HarnessCodex, path, binary); err != nil {
		t.Fatal(err)
	}
	after := readConfig(t, path)
	// The mixed group survives with only the foreign handler; the our-only
	// group is gone, and so are the events that had nothing else.
	if got := hookCommands(t, after, "PreToolUse"); len(got) != 1 || got[0] != "/usr/bin/foreign hook" {
		t.Fatalf("PreToolUse commands = %#v", got)
	}
	for _, event := range []string{"UserPromptSubmit", "PermissionRequest"} {
		if got := hookCommands(t, after, event); len(got) != 0 {
			t.Fatalf("%s commands = %#v", event, got)
		}
		if _, exists := after["hooks"].(map[string]any)[event]; exists {
			t.Fatalf("event %s should have been deleted", event)
		}
	}
	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed {
		t.Fatalf("status = %#v after uninstall", status)
	}
}

func TestCheckReportsMalformedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := Check(contracts.HarnessCodex, path, "/opt/jev-approve")
	if err != nil {
		t.Fatalf("Check must not error on malformed config: %v", err)
	}
	if status.Installed || status.Malformed == "" {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Missing) != 3 {
		t.Fatalf("status.Missing = %#v", status.Missing)
	}
}

func TestCheckReportsMissingConfig(t *testing.T) {
	status, err := Check(contracts.HarnessCodex, filepath.Join(t.TempDir(), "nope", "hooks.json"), "/opt/jev-approve")
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed || status.Configured || status.Malformed != "" {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Missing) != 3 {
		t.Fatalf("status.Missing = %#v", status.Missing)
	}
}

func TestIsOurCommand(t *testing.T) {
	for _, tc := range []struct {
		command, binary, sub string
		want                 bool
	}{
		{`'/opt/jev-approve' hook --harness codex`, "/opt/jev-approve", "hook --harness codex", true},
		{`/opt/jev-approve hook --harness codex`, "/opt/jev-approve", "hook --harness codex", true},
		{`/old/moved/jev-approve hook --harness codex`, "/opt/jev-approve", "hook --harness codex", true},
		{`'/opt/dir with spaces/jev-approve' hook --harness codex`, "/opt/dir with spaces/jev-approve", "hook --harness codex", true},
		{`'/opt/dir with spaces/jev-approve' hook --harness codex`, "/other/jev-approve", "hook --harness codex", true},
		{`/usr/bin/foreign hook --harness codex`, "/opt/jev-approve", "hook --harness codex", false},
		{`/opt/jev-approve event --harness codex`, "/opt/jev-approve", "hook --harness codex", false},
		{`/opt/jev-approve hook --harness claude-code`, "/opt/jev-approve", "hook --harness codex", false},
	} {
		if got := isOurCommand(tc.command, tc.binary, tc.sub); got != tc.want {
			t.Fatalf("isOurCommand(%q, %q, %q) = %v, want %v", tc.command, tc.binary, tc.sub, got, tc.want)
		}
	}
}

func TestInstallCreatesParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "hooks.json")
	if err := Install(contracts.HarnessClaudeCode, path, "/opt/jev-approve"); err != nil {
		t.Fatal(err)
	}
	status, err := Check(contracts.HarnessClaudeCode, path, "/opt/jev-approve")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || len(status.Events) != 2 {
		t.Fatalf("status = %#v", status)
	}
	if strings.Contains(status.ConfigPath, "hooks.json") == false {
		t.Fatalf("status.ConfigPath = %q", status.ConfigPath)
	}
}

func TestCheckRequiresEveryInstalledHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	binary := "/opt/jev-approve"
	legacy := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"/opt/jev-approve hook --harness codex"}]}]}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := Check(contracts.HarnessCodex, path, binary)
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed {
		t.Fatal("Check().Installed = true without UserPromptSubmit hook")
	}
}
