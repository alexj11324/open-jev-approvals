package review

import (
	"context"
	"fmt"
	"time"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
	"github.com/alexj11324/open-jev-approvals/internal/policy"
	"github.com/alexj11324/open-jev-approvals/internal/storage"
)

type Assessor interface {
	Assess(context.Context, contracts.Action) (contracts.Assessment, error)
}

type Service struct {
	Assessor   Assessor
	Store      *storage.Store
	Thresholds policy.Thresholds
}

// Review is fail-closed: an unavailable assessor, an API failure, an invalid
// model response, stale authorization, or a failed audit write all produce
// DecisionDeny. There is no intermediate "review later" outcome.
func (s Service) Review(ctx context.Context, action contracts.Action) contracts.Decision {
	var assessment *contracts.Assessment
	var decision contracts.Decision
	if s.Assessor == nil {
		decision = deny("approval assessor is unavailable")
	} else {
		result, err := s.Assessor.Assess(ctx, action)
		if err != nil {
			decision = deny(fmt.Sprintf("approval did not complete: %v", err))
		} else {
			assessment = &result
			decision = policy.Compose(result, s.Thresholds)
			if decision.Outcome == contracts.DecisionAllow {
				decision = s.verifyAuthorizationFresh(ctx, action)
			}
		}
	}
	return s.record(ctx, action, decision, assessment)
}

// verifyAuthorizationFresh refuses to ship an ALLOW that was computed against
// authorization state which moved while the review was in flight — for
// example a user adding "do not push" after the tool call was emitted.
// Missing scope or a failed freshness check deny the action: under the
// binary policy there is no third outcome to defer to.
func (s Service) verifyAuthorizationFresh(ctx context.Context, action contracts.Action) contracts.Decision {
	if action.Scope == "" {
		return contracts.Decision{
			Outcome:       contracts.DecisionDeny,
			Reason:        "authorization scope is unavailable; the review is incomplete",
			PolicyVersion: policy.Version,
			Incomplete:    true,
		}
	}
	current, err := s.Store.AuthorizationVersion(ctx, action.Scope)
	if err != nil {
		return contracts.Decision{
			Outcome:       contracts.DecisionDeny,
			Reason:        fmt.Sprintf("authorization freshness could not be verified: %v", err),
			PolicyVersion: policy.Version,
			Incomplete:    true,
		}
	}
	if current != action.AuthorizationVersion {
		return contracts.Decision{
			Outcome:       contracts.DecisionDeny,
			Reason:        "user authorization changed while the action was under review",
			PolicyVersion: policy.Version,
		}
	}
	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "JEV assessment satisfies the local " + policy.Version + " policy", PolicyVersion: policy.Version}
}

func (s Service) record(ctx context.Context, action contracts.Action, decision contracts.Decision, assessment *contracts.Assessment) contracts.Decision {
	decision.CreatedAt = time.Now().UTC()
	if decision.PolicyVersion == "" {
		decision.PolicyVersion = policy.Version
	}
	if s.Store == nil {
		return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: "approval audit store is unavailable", PolicyVersion: decision.PolicyVersion, CreatedAt: decision.CreatedAt}
	}
	id, err := s.Store.RecordDecision(ctx, action, decision, assessment)
	if err != nil {
		return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: fmt.Sprintf("approval audit write failed: %v", err), PolicyVersion: decision.PolicyVersion, CreatedAt: decision.CreatedAt}
	}
	decision.ReviewID = id
	return decision
}

func deny(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: reason, PolicyVersion: policy.Version}
}
