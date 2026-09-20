package policy

import (
	"fmt"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

// Compose applies the outcome emitted under Codex Guardian's embedded policy.
// Any malformed or missing outcome is fail-open; the assessor's parsing path
// normally converts that condition into an error before reaching this boundary.
func Compose(assessment contracts.Assessment) contracts.Decision {
	switch assessment.Outcome {
	case contracts.DecisionDeny:
		return contracts.Decision{
			Outcome:       contracts.DecisionDeny,
			RiskLevel:     assessment.RiskLevel,
			Authorization: assessment.Authorization,
			Rationale:     assessment.Rationale,
			Model:         assessment.Model,
			Reason: fmt.Sprintf(
				"JEV Guardian denied the action (risk: %s, authorization: %s): %s",
				assessment.RiskLevel,
				assessment.Authorization,
				assessment.Rationale,
			),
		}
	case contracts.DecisionAllow:
		return contracts.Decision{
			Outcome:       contracts.DecisionAllow,
			RiskLevel:     assessment.RiskLevel,
			Authorization: assessment.Authorization,
			Rationale:     assessment.Rationale,
			Model:         assessment.Model,
			Reason: fmt.Sprintf(
				"JEV Guardian allowed the action (risk: %s, authorization: %s): %s",
				assessment.RiskLevel,
				assessment.Authorization,
				assessment.Rationale,
			),
		}
	default:
		return contracts.Decision{
			Outcome: contracts.DecisionAllow,
			Reason:  "JEV Guardian returned no valid outcome; fail-open",
		}
	}
}
