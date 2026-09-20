package review

import (
	"context"
	"errors"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

type assessorFunc func(context.Context, contracts.Action) (contracts.Assessment, error)

func (f assessorFunc) Assess(ctx context.Context, action contracts.Action) (contracts.Assessment, error) {
	return f(ctx, action)
}

func TestReviewFailsOpenWhenAssessorFails(t *testing.T) {
	t.Setenv("JEV_APPROVALS_STATE_DIR", t.TempDir())
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	decision := Service{
		Assessor: assessorFunc(func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return contracts.Assessment{}, errors.New("model unavailable")
		}),
		Store: store,
	}.Review(context.Background(), contracts.Action{Harness: contracts.HarnessCodex, ToolName: "Bash", Input: map[string]any{"command": "git status"}})

	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestReviewFailsOpenWhenAuditWriteFails(t *testing.T) {
	t.Setenv("JEV_APPROVALS_STATE_DIR", t.TempDir())
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	decision := Service{
		Assessor: assessorFunc(func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return contracts.Assessment{
				RiskLevel:     contracts.RiskHigh,
				Authorization: contracts.AuthorizationLow,
				Outcome:       contracts.DecisionDeny,
			}, nil
		}),
		Store: store,
	}.Review(context.Background(), contracts.Action{Harness: contracts.HarnessCodex, ToolName: "Bash", Input: map[string]any{"command": "dangerous"}})

	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestReviewRecordsExplicitGuardianDenyMetadata(t *testing.T) {
	t.Setenv("JEV_APPROVALS_STATE_DIR", t.TempDir())
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	decision := Service{
		Assessor: assessorFunc(func(context.Context, contracts.Action) (contracts.Assessment, error) {
			return contracts.Assessment{
				Model:         "jev-test",
				RiskLevel:     contracts.RiskHigh,
				Authorization: contracts.AuthorizationLow,
				Outcome:       contracts.DecisionDeny,
				Rationale:     "The action exposes a credential without authorization.",
			}, nil
		}),
		Store: store,
	}.Review(context.Background(), contracts.Action{
		Harness:  contracts.HarnessCodex,
		ToolName: "Bash",
		Input:    map[string]any{"command": "copy credential"},
	})

	if decision.Outcome != contracts.DecisionDeny || decision.ReviewID == "" {
		t.Fatalf("decision = %#v", decision)
	}
	if decision.Model != "jev-test" || decision.RiskLevel != contracts.RiskHigh || decision.Authorization != contracts.AuthorizationLow {
		t.Fatalf("decision metadata = %#v", decision)
	}
	recorded, err := store.Decision(context.Background(), decision.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Outcome != contracts.DecisionDeny || recorded.Rationale != decision.Rationale || recorded.Model != "jev-test" {
		t.Fatalf("recorded decision = %#v", recorded)
	}
}

func TestReviewDenyDoesNotContaminateLaterAllow(t *testing.T) {
	t.Setenv("JEV_APPROVALS_STATE_DIR", t.TempDir())
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	assessments := []contracts.Assessment{
		{
			Model:         "jev-test",
			RiskLevel:     contracts.RiskCritical,
			Authorization: contracts.AuthorizationUnknown,
			Outcome:       contracts.DecisionDeny,
			Rationale:     "Sensitive data would leave for an untrusted destination.",
		},
		{
			Model:         "jev-test",
			RiskLevel:     contracts.RiskLow,
			Authorization: contracts.AuthorizationUnknown,
			Outcome:       contracts.DecisionAllow,
			Rationale:     "The follow-up is a read-only repository status check.",
		},
	}
	next := 0
	service := Service{
		Assessor: assessorFunc(func(context.Context, contracts.Action) (contracts.Assessment, error) {
			assessment := assessments[next]
			next++
			return assessment, nil
		}),
		Store: store,
	}
	first := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "same-session",
		TurnID:    "denied-turn",
		ToolName:  "Bash",
		Input:     map[string]any{"command": "send sensitive data"},
	})
	second := service.Review(context.Background(), contracts.Action{
		Harness:   contracts.HarnessCodex,
		SessionID: "same-session",
		TurnID:    "safe-turn",
		ToolName:  "Bash",
		Input:     map[string]any{"command": "git status --short"},
	})

	if first.Outcome != contracts.DecisionDeny {
		t.Fatalf("first outcome = %q, want deny", first.Outcome)
	}
	if second.Outcome != contracts.DecisionAllow {
		t.Fatalf("second outcome = %q, want allow; reason = %q", second.Outcome, second.Reason)
	}
	if first.ReviewID == "" || second.ReviewID == "" || first.ReviewID == second.ReviewID {
		t.Fatalf("review ids = %q, %q", first.ReviewID, second.ReviewID)
	}
}
