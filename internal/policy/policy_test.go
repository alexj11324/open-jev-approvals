package policy

import (
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func TestComposeUsesGuardianAllowOutcome(t *testing.T) {
	decision := Compose(contracts.Assessment{
		RiskLevel:     contracts.RiskMedium,
		Authorization: contracts.AuthorizationUnknown,
		Outcome:       contracts.DecisionAllow,
	})
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow", decision.Outcome)
	}
}

func TestComposeUsesGuardianDenyOutcome(t *testing.T) {
	decision := Compose(contracts.Assessment{
		RiskLevel:     contracts.RiskHigh,
		Authorization: contracts.AuthorizationLow,
		Outcome:       contracts.DecisionDeny,
	})
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny", decision.Outcome)
	}
}

func TestComposeFailsOpenWithoutValidOutcome(t *testing.T) {
	decision := Compose(contracts.Assessment{})
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow", decision.Outcome)
	}
}
