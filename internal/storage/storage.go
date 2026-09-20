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
	"strings"
	"time"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
	"github.com/alexj11324/open-jev-approvals/internal/sanitize"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	// busy_timeout keeps concurrent hook invocations from failing with
	// SQLITE_BUSY on the audit write; WAL reduces reader/writer blocking;
	// a single pooled connection serializes writers deterministically.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
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

// ScopeKey namespaces authorization state so two harnesses, agents, or
// installations can never share prompts by accident.
func ScopeKey(installationID string, harness contracts.Harness, sessionID, agentID string) string {
	return strings.Join([]string{installationID, string(harness), sessionID, agentID}, "/")
}

// InstallationID returns a stable per-installation identifier, generated on
// first use and persisted in the meta table.
func (s *Store) InstallationID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'installation_id'`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	id = "inst_" + hex.EncodeToString(bytes)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES ('installation_id', ?)`, id); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) RememberPrompt(ctx context.Context, scope, sessionID, turnID, prompt string) error {
	if scope == "" || prompt == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_prompts(scope, session_id, turn_id, prompt, created_at) VALUES (?, ?, ?, ?, ?)`, scope, sessionID, turnID, sanitize.RedactString(prompt), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// UserPrompts returns the prompts recorded for a scope and the authorization
// version they were read at. With an empty turnID it returns the prompts of
// the latest turn only. The version lets callers detect authorization
// changes that land while a review is in flight.
func (s *Store) UserPrompts(ctx context.Context, scope, turnID string) ([]string, int64, error) {
	if scope == "" {
		return nil, 0, nil
	}
	query := `SELECT prompt FROM user_prompts WHERE scope = ? AND turn_id = ? ORDER BY id`
	args := []any{scope, turnID}
	if turnID == "" {
		query = `SELECT prompt FROM user_prompts WHERE scope = ? AND turn_id = (SELECT turn_id FROM user_prompts WHERE scope = ? ORDER BY id DESC LIMIT 1) ORDER BY id`
		args = []any{scope, scope}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var prompts []string
	for rows.Next() {
		var prompt string
		if err := rows.Scan(&prompt); err != nil {
			return nil, 0, err
		}
		prompts = append(prompts, prompt)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	version, err := s.AuthorizationVersion(ctx, scope)
	if err != nil {
		return nil, 0, err
	}
	return prompts, version, nil
}

// AuthorizationVersion is a monotonically increasing marker over the scope's
// authorization stream. Any new prompt (including a tighter constraint)
// moves it.
func (s *Store) AuthorizationVersion(ctx context.Context, scope string) (int64, error) {
	if scope == "" {
		return 0, nil
	}
	var version int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM user_prompts WHERE scope = ?`, scope).Scan(&version)
	return version, err
}

func (s *Store) RecordDecision(ctx context.Context, action contracts.Action, decision contracts.Decision, assessment *contracts.Assessment) (string, error) {
	id, err := reviewID()
	if err != nil {
		return "", err
	}
	actionJSON, err := json.Marshal(sanitize.RedactAction(action))
	if err != nil {
		return "", err
	}
	var assessmentJSON []byte
	if assessment != nil {
		assessmentJSON, err = json.Marshal(assessment)
		if err != nil {
			return "", err
		}
	}
	decision.ReviewID = id
	decision.CreatedAt = time.Now().UTC()
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO decisions(id, scope, session_id, action_json, decision_json, assessment_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, action.Scope, action.SessionID, string(actionJSON), string(decisionJSON), string(assessmentJSON), decision.CreatedAt.Format(time.RFC3339Nano))
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
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_prompts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL,
  turn_id TEXT NOT NULL DEFAULT '',
  prompt TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  action_json TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  assessment_json TEXT,
  created_at TEXT NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("migrate state database: %w", err)
	}
	for _, migration := range []struct{ table, column, ddl string }{
		{"user_prompts", "turn_id", `ALTER TABLE user_prompts ADD COLUMN turn_id TEXT NOT NULL DEFAULT ''`},
		{"user_prompts", "scope", `ALTER TABLE user_prompts ADD COLUMN scope TEXT NOT NULL DEFAULT ''`},
		{"decisions", "scope", `ALTER TABLE decisions ADD COLUMN scope TEXT NOT NULL DEFAULT ''`},
		{"decisions", "assessment_json", `ALTER TABLE decisions ADD COLUMN assessment_json TEXT`},
	} {
		var present bool
		inspect := fmt.Sprintf(`SELECT COUNT(*) > 0 FROM pragma_table_info('%s') WHERE name = ?`, migration.table)
		if err := s.db.QueryRow(inspect, migration.column).Scan(&present); err != nil {
			return fmt.Errorf("inspect %s schema: %w", migration.table, err)
		}
		if !present {
			if _, err := s.db.Exec(migration.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", migration.table, migration.column, err)
			}
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
