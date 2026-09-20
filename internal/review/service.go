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

// Review is fail-open on reviewer failure: this gate is the harness's auto
// mode, so when JEV cannot produce a verdict — unavailable assessor, API
// failure, invalid response, unavailable audit store — the action allows
// rather than stalling the user's work. Deny requires positive evidence: a
// complete verdict that trips the policy, or a confirmed authorization
// change that invalidates an allow computed mid-flight.
func (s Service) Review(ctx context.Context, action contracts.Action) contracts.Decision {
	var assessment *contracts.Assessment
	var decision contracts.Decision
	if s.Assessor == nil {
		decision = open("approval assessor is unavailable")
	} else {
		result, err := s.Assessor.Assess(ctx, action)
		if err != nil {
			decision = open(fmt.Sprintf("approval did not complete: %v", err))
		} else {
			assessment = &result
			decision = policy.Compose(result, s.Thresholds)
			if decision.Outcome == contracts.DecisionAllow && !decision.Incomplete {
				decision = s.verifyAuthorizationFresh(ctx, action, decision)
			}
		}
	}
	return s.record(ctx, action, decision, assessment)
}

// verifyAuthorizationFresh refuses to ship an ALLOW that was computed against
// authorization state which moved while the review was in flight — for
// example a user adding "do not push" after the tool call was emitted. That
// mismatch is positive evidence the verdict does not apply, so it denies;
// an inability to verify freshness is reviewer degradation and allows.
func (s Service) verifyAuthorizationFresh(ctx context.Context, action contracts.Action, decision contracts.Decision) contracts.Decision {
	if action.Scope == "" || s.Store == nil {
		return openOn(&decision, "authorization freshness could not be verified")
	}
	current, err := s.Store.AuthorizationVersion(ctx, action.Scope)
	if err != nil {
		return openOn(&decision, fmt.Sprintf("authorization freshness could not be verified: %v", err))
	}
	if current != action.AuthorizationVersion {
		return contracts.Decision{
			Outcome:       contracts.DecisionDeny,
			Reason:        "user authorization changed while the action was under review",
			PolicyVersion: policy.Version,
		}
	}
	return decision
}

// record persists the decision when an audit store is available. A failed
// audit write never overrides the decision: the outcome stands and the
// reason records the lost audit trail.
func (s Service) record(ctx context.Context, action contracts.Action, decision contracts.Decision, assessment *contracts.Assessment) contracts.Decision {
	decision.CreatedAt = time.Now().UTC()
	if decision.PolicyVersion == "" {
		decision.PolicyVersion = policy.Version
	}
	if s.Store == nil {
		return openOn(&decision, "approval audit store is unavailable")
	}
	id, err := s.Store.RecordDecision(ctx, action, decision, assessment)
	if err != nil {
		return openOn(&decision, fmt.Sprintf("approval audit write failed: %v", err))
	}
	decision.ReviewID = id
	return decision
}

func open(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: reason + "; reviewer unavailable", PolicyVersion: policy.Version, Incomplete: true}
}

// openOn converts a decision into a degraded allow, unless it already denies
// on positive evidence — a confirmed violation or stale authorization still
// denies even when the audit trail cannot be recorded.
func openOn(decision *contracts.Decision, reason string) contracts.Decision {
	if decision.Outcome == contracts.DecisionDeny {
		decision.Reason += "; " + reason
		return *decision
	}
	decision.Outcome = contracts.DecisionAllow
	decision.Reason += "; " + reason
	decision.Incomplete = true
	return *decision
}
