package config

import (
	"os"
	"path/filepath"
)

// UserEnvPath is the only file the gate loads credentials from at runtime:
// a user-managed location outside any project directory. A checked-out or
// working-directory .env must never be able to redirect the approval
// endpoint or capture the API key.
func UserEnvPath() string {
	if configured := os.Getenv("JEV_APPROVALS_ENV_FILE"); configured != "" {
		return configured
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "jev-approvals", "env")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".jev-approvals", "env")
	}
	return filepath.Join(home, ".config", "jev-approvals", "env")
}

// LoadUserEnv loads the user-managed env file. A missing file is fine; a
// malformed file is an error so a broken credential file cannot silently
// fall back to defaults.
func LoadUserEnv() error {
	return LoadDotEnv(UserEnvPath())
}
