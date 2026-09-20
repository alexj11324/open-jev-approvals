package review

import (
	"context"
	"fmt"
	"time"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	"github.com/alexjiang/open-jev-approvals/internal/policy"
	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

type Assessor interface {
	Assess(context.Context, contracts.Action) (contracts.Assessment, error)
}

type Service struct {
	Assessor   Assessor
	Store      *storage.Store
	Thresholds policy.Thresholds
}

func (s Service) Review(ctx context.Context, action contracts.Action) contracts.Decision {
	if s.Assessor == nil {
		return s.record(ctx, action, contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "approval assessor is unavailable"})
	}
	assessment, err := s.Assessor.Assess(ctx, action)
	if err != nil {
		return s.record(ctx, action, contracts.Decision{Outcome: contracts.DecisionDeny, Reason: fmt.Sprintf("approval did not complete: %v", err)})
	}
	decision := policy.Compose(assessment, s.Thresholds)
	return s.record(ctx, action, decision)
}

func (s Service) record(ctx context.Context, action contracts.Action, decision contracts.Decision) contracts.Decision {
	decision.CreatedAt = time.Now().UTC()
	if s.Store == nil {
		return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "approval audit store is unavailable", CreatedAt: decision.CreatedAt}
	}
	id, err := s.Store.RecordDecision(ctx, action, decision)
	if err != nil {
		return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: fmt.Sprintf("approval audit write failed: %v", err), CreatedAt: decision.CreatedAt}
	}
	decision.ReviewID = id
	return decision
}
