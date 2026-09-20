package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

// TestConcurrentStoresShareOneDatabase opens two independent Store handles on
// the same database file — the shape of concurrent hook invocations racing the
// audit log — and hammers both with prompt and decision writes. WAL plus the
// busy_timeout pragma must absorb the writer contention: any SQLITE_BUSY or
// "database is locked" error is a fail-closed outage, so the test demands zero.
func TestConcurrentStoresShareOneDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	storeA, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer storeA.Close()
	storeB, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer storeB.Close()

	// The DSN pragma must actually take effect on the modernc driver: WAL is
	// what lets readers and the single writer proceed without blocking.
	var mode string
	if err := storeA.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}

	ctx := context.Background()
	scope := ScopeKey("inst", contracts.HarnessCodex, "shared-session", "")
	stores := []*Store{storeA, storeB}

	const writers = 32
	errs := make(chan error, writers*2)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := stores[i%len(stores)]
			if err := store.RememberPrompt(ctx, scope, "shared-session", fmt.Sprintf("turn-%d", i%4), fmt.Sprintf("prompt %d", i)); err != nil {
				errs <- fmt.Errorf("store %d remember prompt %d: %w", i%len(stores), i, err)
				return
			}
			action := contracts.Action{
				Harness:   contracts.HarnessCodex,
				SessionID: "shared-session",
				ToolName:  "bash",
				Kind:      contracts.ActionShell,
				Scope:     scope,
			}
			decision := contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "concurrency probe"}
			if _, err := store.RecordDecision(ctx, action, decision, nil); err != nil {
				errs <- fmt.Errorf("store %d record decision %d: %w", i%len(stores), i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent audit write failed: %v", err)
	}
}
