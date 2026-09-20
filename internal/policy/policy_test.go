package policy

import (
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func safeAssessment() contracts.Assessment {
	return contracts.Assessment{
		RiskLevel:         contracts.RiskLow,
		RiskConfidence:    0.95,
		Authorization:     contracts.AuthorizationLow,
		AuthorizationConf: 0.95,
		NarrowlyScoped:    0.98,
		Noul: map[string]float64{
			"violates_explicit_constraint":  0.01,
			"sensitive_egress":              0.01,
			"egress_authorized":             0.99,
			"credential_probing":            0.01,
			"persistent_security_weakening": 0.01,
			"destructive_effect":            0.01,
			"malicious_instruction":         0.01,
		},
	}
}

func TestComposeAllowsLowRiskWithCompleteEvidence(t *testing.T) {
	decision := Compose(safeAssessment(), DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeDeniesCriticalAction(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskCritical
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny", decision.Outcome)
	}
}

func TestComposeDeniesUnsupportedRiskLevel(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskUnresolved
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny", decision.Outcome)
	}
}

func TestComposeAllowsMediumRisk(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskMedium
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow", decision.Outcome)
	}
}

func TestComposeDeniesUnauthorizedSensitiveEgress(t *testing.T) {
	assessment := safeAssessment()
	assessment.Noul["sensitive_egress"] = 0.99
	assessment.Noul["egress_authorized"] = 0.01
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny", decision.Outcome)
	}
}

func TestComposeDeniesCredentialProbingBeforeRiskConfidenceFallback(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskConfidence = 0.01
	assessment.Noul["credential_probing"] = 0.99
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeDeniesCredentialProbingBeforeAnUncertainConstraint(t *testing.T) {
	assessment := safeAssessment()
	assessment.Noul["violates_explicit_constraint"] = 0.5
	assessment.Noul["credential_probing"] = 0.99
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeAllowsLowRiskWhenNoConstraintIsConfirmed(t *testing.T) {
	assessment := safeAssessment()
	assessment.Noul["violates_explicit_constraint"] = 0.5
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeAllowsWithoutAffirmativeInjectionEvidence(t *testing.T) {
	assessment := safeAssessment()
	assessment.Noul["malicious_instruction"] = 0.5
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeAllowsLowRiskWhenAuthorizationBandsAreUncertain(t *testing.T) {
	assessment := safeAssessment()
	assessment.AuthorizationConf = 0.58
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeDeniesHighRiskWithoutMediumAuthorization(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskHigh
	assessment.Authorization = contracts.AuthorizationLow
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeAllowsScopedHighRiskWithMediumAuthorization(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskHigh
	assessment.Authorization = contracts.AuthorizationMedium
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}
