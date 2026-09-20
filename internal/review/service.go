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
	Assessor Assessor
	Store    *storage.Store
}

func (s Service) Review(ctx context.Context, action contracts.Action) contracts.Decision {
	if s.Assessor == nil {
		return s.record(ctx, action, contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "approval assessor is unavailable; fail-open"})
	}
	assessment, err := s.Assessor.Assess(ctx, action)
	if err != nil {
		return s.record(ctx, action, contracts.Decision{Outcome: contracts.DecisionAllow, Reason: fmt.Sprintf("approval did not complete; fail-open: %v", err)})
	}
	decision := policy.Compose(assessment)
	return s.record(ctx, action, decision)
}

func (s Service) record(ctx context.Context, action contracts.Action, decision contracts.Decision) contracts.Decision {
	decision.CreatedAt = time.Now().UTC()
	if s.Store == nil {
		return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "approval audit store is unavailable; fail-open", CreatedAt: decision.CreatedAt}
	}
	id, err := s.Store.RecordDecision(ctx, action, decision)
	if err != nil {
		return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: fmt.Sprintf("approval audit write failed; fail-open: %v", err), CreatedAt: decision.CreatedAt}
	}
	decision.ReviewID = id
	return decision
}
