package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// UserEnvPath is the only file the gate loads credentials from at runtime:
// a user-managed location outside any project directory. A checked-out or
// working-directory .env must never be able to redirect the approval
// endpoint or capture the API key — when no user home can be resolved there
// is no fallback, because any relative default would be project-controlled.
func UserEnvPath() (string, error) {
	if configured := os.Getenv("JEV_APPROVALS_ENV_FILE"); configured != "" {
		return configured, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "jev-approvals", "env"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home for env file: %w", err)
	}
	return filepath.Join(home, ".config", "jev-approvals", "env"), nil
}

// LoadUserEnv loads the user-managed env file. A missing file is fine; a
// malformed file is an error so a broken credential file cannot silently
// fall back to defaults.
func LoadUserEnv() error {
	path, err := UserEnvPath()
	if err != nil {
		return err
	}
	return LoadDotEnv(path)
}
