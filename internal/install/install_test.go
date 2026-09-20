package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

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
		t.Fatal("Check().Installed = false, want true")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	hooks := config["hooks"].(map[string]any)
	if len(hooks["PreToolUse"].([]any)) != 1 {
		t.Fatalf("PreToolUse hook groups = %#v", hooks["PreToolUse"])
	}
	if config["permission_mode"] != "bypassPermissions" || config["model_provider"] != "third-party" {
		t.Fatalf("installer changed harness settings: %#v", config)
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
