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

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	// busy_timeout keeps concurrent hook invocations from failing with
	// SQLITE_BUSY on the audit write; WAL reduces reader/writer blocking;
	// a single pooled connection serializes writers deterministically.
	// The pragmas are applied explicitly (not via DSN) so their order is
	// deterministic: busy_timeout must be set before the WAL transition.
	// The timeout stays under the harness's hook deadline so a locked
	// database degrades instead of being killed mid-verdict.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	// journal_mode(WAL) on a cold database needs an exclusive lock and can
	// return SQLITE_BUSY while another process finishes its own cold open,
	// so it is retried instead of trusting busy_timeout to cover it.
	if err := execWithBusyRetry(ctx, db, `PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL journal: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA synchronous = NORMAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set synchronous: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// execWithBusyRetry runs a single statement, retrying while SQLite reports a
// transient lock. Cold-open races — several hook processes creating the same
// database file at once — resolve within milliseconds once the first writer
// commits. The caller's context bounds the retry so a wedged database can
// never outlive the hook deadline.
func execWithBusyRetry(ctx context.Context, db *sql.DB, query string) error {
	for {
		_, err := db.ExecContext(ctx, query)
		if err == nil || !strings.Contains(err.Error(), "SQLITE_BUSY") && !strings.Contains(err.Error(), "database is locked") {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// DefaultPath resolves the state database location. There is deliberately
// no relative fallback: when no user home exists a project-relative default
// would let the reviewed repository own the audit store and the env search
// path.
func DefaultPath() (string, error) {
	if configured := os.Getenv("JEV_APPROVALS_STATE_DIR"); configured != "" {
		return filepath.Join(configured, "state.db"), nil
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "jev-approvals", "state.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home for state database: %w", err)
	}
	return filepath.Join(home, ".local", "state", "jev-approvals", "state.db"), nil
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
	// Two cold-open processes can race here: both read an empty meta table
	// and both insert. The loser keeps whichever id committed first.
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO meta(key, value) VALUES ('installation_id', ?)`, id); err != nil {
		return "", err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'installation_id'`).Scan(&id); err != nil {
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
// the latest turn only; when the latest turn id is itself empty (harnesses
// without turn ids), only the single newest prompt counts so authorization
// cannot accumulate across unrelated requests. Prompts and version are read
// inside one snapshot transaction so a concurrent prompt insert cannot pair
// stale prompts with a fresh version.
func (s *Store) UserPrompts(ctx context.Context, scope, turnID string) ([]string, int64, error) {
	if scope == "" {
		return nil, 0, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()

	var version int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM user_prompts WHERE scope = ?`, scope).Scan(&version); err != nil {
		return nil, 0, err
	}
	if turnID == "" {
		if err := tx.QueryRowContext(ctx, `SELECT turn_id FROM user_prompts WHERE scope = ? ORDER BY id DESC LIMIT 1`, scope).Scan(&turnID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, version, tx.Commit()
			}
			return nil, 0, err
		}
	}
	query := `SELECT prompt FROM user_prompts WHERE scope = ? AND turn_id = ? ORDER BY id`
	args := []any{scope, turnID}
	if turnID == "" {
		// No turn ids exist at all: "the latest turn" degenerates to the
		// newest prompt only.
		query = `SELECT prompt FROM user_prompts WHERE scope = ? AND turn_id = '' ORDER BY id DESC LIMIT 1`
		args = []any{scope}
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	var prompts []string
	for rows.Next() {
		var prompt string
		if err := rows.Scan(&prompt); err != nil {
			rows.Close()
			return nil, 0, err
		}
		prompts = append(prompts, prompt)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
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

// migrate runs schema setup inside one immediate transaction so several
// processes opening a cold database serialize instead of interleaving
// CREATE/ALTER statements. BEGIN IMMEDIATE is covered by busy_timeout, so
// the loser of the race simply waits for the winner to commit.
func (s *Store) migrate(ctx context.Context) error {
	if err := execWithBusyRetry(ctx, s.db, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			s.db.Exec(`ROLLBACK`)
		}
	}()
	_, err := s.db.ExecContext(ctx, `
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
		if err := s.db.QueryRowContext(ctx, inspect, migration.column).Scan(&present); err != nil {
			return fmt.Errorf("inspect %s schema: %w", migration.table, err)
		}
		if !present {
			if _, err := s.db.ExecContext(ctx, migration.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", migration.table, migration.column, err)
			}
		}
	}
	if _, err := s.db.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	committed = true
	return nil
}

func reviewID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "rev_" + hex.EncodeToString(bytes), nil
}
