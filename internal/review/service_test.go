package review

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
	"github.com/alexj11324/open-jev-approvals/internal/policy"
	"github.com/alexj11324/open-jev-approvals/internal/storage"
)

type fakeAssessor struct {
	assess func(context.Context, contracts.Action) (contracts.Assessment, error)
}

func (f fakeAssessor) Assess(ctx context.Context, action contracts.Action) (contracts.Assessment, error) {
	return f.assess(ctx, action)
}

// cleanAssessment satisfies every Guardian gate: all required noul judgments
// present and low, egress authorized, low risk, high confidences, narrowly
// scoped above the action-probability threshold.
func cleanAssessment() contracts.Assessment {
	return contracts.Assessment{
		Model:             "test-model",
		RiskLevel:         contracts.RiskLow,
		RiskConfidence:    0.95,
		Authorization:     contracts.AuthorizationHigh,
		AuthorizationConf: 0.95,
		NarrowlyScoped:    0.9,
		Noul: map[string]float64{
			"violates_explicit_constraint":  0.05,
			"sensitive_egress":              0.05,
			"egress_authorized":             0.95,
			"credential_probing":            0.05,
			"persistent_security_weakening": 0.05,
			"destructive_effect":            0.05,
			"malicious_instruction":         0.05,
		},
	}
}

func openStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestReviewAllowsFreshAuthorizedAction(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	scope := storage.ScopeKey("inst", contracts.HarnessCodex, "s1", "")
	if err := store.RememberPrompt(ctx, scope, "s1", "t1", "list the repository files"); err != nil {
		t.Fatal(err)
	}
	version, err := store.AuthorizationVersion(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}

	action := contracts.Action{
		Harness:              contracts.HarnessCodex,
		SessionID:            "s1",
		ToolName:             "bash",
		Kind:                 contracts.ActionShell,
		Scope:                scope,
		AuthorizationVersion: version,
	}
	service := Service{
		Assessor: fakeAssessor{assess: func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return cleanAssessment(), nil
		}},
		Store:      store,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(ctx, action)
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Review outcome = %q (%s), want allow", decision.Outcome, decision.Reason)
	}
	if decision.ReviewID == "" {
		t.Fatal("allowed decision was not recorded: empty ReviewID")
	}
	persisted, err := store.Decision(ctx, decision.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Outcome != contracts.DecisionAllow {
		t.Fatalf("persisted decision = %q, want allow", persisted.Outcome)
	}
}

// TestReviewDeniesWhenAuthorizationMovesMidReview simulates the user adding a
// tighter constraint while JEV is assessing: the assessor writes a new prompt
// into the same scope, bumping AuthorizationVersion, and the allow that was
// computed against the old snapshot must not ship.
func TestReviewDeniesWhenAuthorizationMovesMidReview(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	scope := storage.ScopeKey("inst", contracts.HarnessCodex, "s1", "")
	if err := store.RememberPrompt(ctx, scope, "s1", "t1", "deploy the branch"); err != nil {
		t.Fatal(err)
	}
	version, err := store.AuthorizationVersion(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}

	action := contracts.Action{
		Harness:              contracts.HarnessCodex,
		SessionID:            "s1",
		ToolName:             "bash",
		Kind:                 contracts.ActionShell,
		Scope:                scope,
		AuthorizationVersion: version,
	}
	service := Service{
		Assessor: fakeAssessor{assess: func(ctx context.Context, a contracts.Action) (contracts.Assessment, error) {
			// Mid-review authorization change: a new prompt lands in the
			// same scope while the assessment is in flight.
			if err := store.RememberPrompt(ctx, a.Scope, a.SessionID, "t1", "do not push to production"); err != nil {
				return contracts.Assessment{}, err
			}
			return cleanAssessment(), nil
		}},
		Store:      store,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(ctx, action)
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Review outcome = %q, want deny", decision.Outcome)
	}
	if !strings.Contains(decision.Reason, "authorization changed") {
		t.Fatalf("deny reason %q does not mention authorization changed", decision.Reason)
	}
}

func TestReviewAllowsWhenScopeMissing(t *testing.T) {
	store := openStore(t)
	service := Service{
		Assessor: fakeAssessor{assess: func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return cleanAssessment(), nil
		}},
		Store:      store,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "s1",
		ToolName:  "bash",
		Kind:      contracts.ActionShell,
	})
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Review outcome = %q, want allow", decision.Outcome)
	}
	if !decision.Incomplete {
		t.Fatal("scope-less review must be marked incomplete")
	}
}

func TestReviewAllowsWhenAuditStoreMissing(t *testing.T) {
	service := Service{
		Assessor: fakeAssessor{assess: func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return cleanAssessment(), nil
		}},
		Store:      nil,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "s1",
		ToolName:  "bash",
		Kind:      contracts.ActionShell,
		Scope:     storage.ScopeKey("inst", contracts.HarnessCodex, "s1", ""),
	})
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Review outcome = %q, want allow", decision.Outcome)
	}
	if !strings.Contains(decision.Reason, "audit store") {
		t.Fatalf("allow reason %q does not mention the audit store", decision.Reason)
	}
}

// TestReviewDenySurvivesAuditStoreFailure proves a positive-evidence deny
// is not upgraded to allow when the audit trail cannot be recorded.
func TestReviewDenySurvivesAuditStoreFailure(t *testing.T) {
	service := Service{
		Assessor: fakeAssessor{assess: func(context.Context, contracts.Action) (contracts.Assessment, error) {
			assessment := cleanAssessment()
			assessment.RiskLevel = contracts.RiskCritical
			return assessment, nil
		}},
		Store:      nil,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(context.Background(), contracts.Action{
		Harness: contracts.HarnessCodex, SessionID: "s1", ToolName: "bash", Kind: contracts.ActionShell,
	})
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Review outcome = %q, want deny", decision.Outcome)
	}
}

func TestReviewAllowsWhenAssessorMissing(t *testing.T) {
	store := openStore(t)
	service := Service{
		Assessor:   nil,
		Store:      store,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "s1",
		ToolName:  "bash",
		Kind:      contracts.ActionShell,
		Scope:     storage.ScopeKey("inst", contracts.HarnessCodex, "s1", ""),
	})
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Review outcome = %q, want allow", decision.Outcome)
	}
	if !decision.Incomplete {
		t.Fatal("assessor-less review must be marked incomplete")
	}
}

func TestReviewAllowsWhenAssessorFails(t *testing.T) {
	store := openStore(t)
	service := Service{
		Assessor: fakeAssessor{assess: func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return contracts.Assessment{}, context.DeadlineExceeded
		}},
		Store:      store,
		Thresholds: policy.DefaultThresholds(),
	}

	decision := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "s1",
		ToolName:  "bash",
		Kind:      contracts.ActionShell,
		Scope:     storage.ScopeKey("inst", contracts.HarnessCodex, "s1", ""),
	})
	if decision.Outcome != contracts.DecisionAllow || !decision.Incomplete {
		t.Fatalf("Review outcome = %q incomplete=%v, want incomplete allow", decision.Outcome, decision.Incomplete)
	}
}
