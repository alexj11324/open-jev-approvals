package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	_ "modernc.org/sqlite"
)

var secretPattern = regexp.MustCompile(`(?i)(apikey_[a-z0-9_]+|bearer\s+)[a-z0-9._-]+`)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func DefaultPath() string {
	if configured := os.Getenv("JEV_APPROVALS_STATE_DIR"); configured != "" {
		return filepath.Join(configured, "state.db")
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "jev-approvals", "state.db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".jev-approvals", "state.db")
	}
	return filepath.Join(home, ".local", "state", "jev-approvals", "state.db")
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) RememberPrompt(ctx context.Context, sessionID, turnID, prompt string) error {
	if sessionID == "" || prompt == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_prompts(session_id, turn_id, prompt, created_at) VALUES (?, ?, ?, ?)`, sessionID, turnID, redact(prompt), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) UserPrompts(ctx context.Context, sessionID, turnID string) ([]string, error) {
	if sessionID == "" || turnID == "" {
		return nil, nil
	}
	query := `SELECT prompt FROM user_prompts WHERE session_id = ? AND turn_id = ? ORDER BY id`
	args := []any{sessionID, turnID}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var prompts []string
	for rows.Next() {
		var prompt string
		if err := rows.Scan(&prompt); err != nil {
			return nil, err
		}
		prompts = append(prompts, prompt)
	}
	return prompts, rows.Err()
}

func (s *Store) RecordDecision(ctx context.Context, action contracts.Action, decision contracts.Decision) (string, error) {
	id, err := reviewID()
	if err != nil {
		return "", err
	}
	actionJSON, err := json.Marshal(redactAction(action))
	if err != nil {
		return "", err
	}
	decision.ReviewID = id
	decision.CreatedAt = time.Now().UTC()
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO decisions(id, session_id, action_json, decision_json, created_at) VALUES (?, ?, ?, ?, ?)`, id, action.SessionID, string(actionJSON), string(decisionJSON), decision.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) Decision(ctx context.Context, id string) (contracts.Decision, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT decision_json FROM decisions WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.Decision{}, fmt.Errorf("review %q not found", id)
	}
	if err != nil {
		return contracts.Decision{}, err
	}
	var decision contracts.Decision
	if err := json.Unmarshal([]byte(raw), &decision); err != nil {
		return contracts.Decision{}, err
	}
	return decision, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS user_prompts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  turn_id TEXT NOT NULL DEFAULT '',
  prompt TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  action_json TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("migrate state database: %w", err)
	}
	var hasTurnID bool
	if err := s.db.QueryRow(`SELECT COUNT(*) > 0 FROM pragma_table_info('user_prompts') WHERE name = 'turn_id'`).Scan(&hasTurnID); err != nil {
		return fmt.Errorf("inspect user prompt schema: %w", err)
	}
	if !hasTurnID {
		if _, err := s.db.Exec(`ALTER TABLE user_prompts ADD COLUMN turn_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add user prompt turn id: %w", err)
		}
	}
	return nil
}

func reviewID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "rev_" + hex.EncodeToString(bytes), nil
}

func redact(value string) string {
	return secretPattern.ReplaceAllStringFunc(value, func(match string) string {
		if strings.HasPrefix(strings.ToLower(match), "bearer ") {
			return "Bearer [redacted]"
		}
		return "apikey_[redacted]"
	})
}

func redactAction(action contracts.Action) contracts.Action {
	copy := action
	copy.UserMessages = make([]string, 0, len(action.UserMessages))
	for _, message := range action.UserMessages {
		copy.UserMessages = append(copy.UserMessages, redact(message))
	}
	copy.Input = redactValue(action.Input).(map[string]any)
	return copy
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case string:
		return redact(typed)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = redactValue(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = redactValue(child)
		}
		return out
	default:
		return value
	}
}
