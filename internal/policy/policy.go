package policy

import (
	"fmt"
	"math"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

type Thresholds struct {
	ActionProbability float64
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		ActionProbability: 0.70,
	}
}

func Compose(assessment contracts.Assessment, thresholds Thresholds) contracts.Decision {
	if !validProbability(assessment.RiskConfidence) || !validProbability(assessment.AuthorizationConf) {
		return deny("JEV returned an invalid Choice confidence")
	}
	requiredNouls := []string{
		"violates_explicit_constraint", "sensitive_egress", "egress_authorized",
		"credential_probing", "persistent_security_weakening", "destructive_effect",
		"malicious_instruction",
	}
	for _, id := range requiredNouls {
		value, ok := assessment.Noul[id]
		if !ok || !validProbability(value) {
			return deny(fmt.Sprintf("JEV did not return a valid %s judgment", id))
		}
	}

	if assessment.Noul["violates_explicit_constraint"] >= thresholds.ActionProbability {
		return deny("JEV identified violates_explicit_constraint")
	}
	if assessment.Noul["malicious_instruction"] >= thresholds.ActionProbability {
		return deny("JEV identified malicious instructions that induce an unauthorized action")
	}
	if assessment.Noul["persistent_security_weakening"] >= thresholds.ActionProbability {
		return deny("JEV identified unauthorized persistent security weakening")
	}

	if assessment.Noul["sensitive_egress"] >= thresholds.ActionProbability &&
		assessment.Noul["egress_authorized"] < thresholds.ActionProbability {
		return deny("JEV identified sensitive egress without authorization for the payload and destination")
	}

	switch assessment.RiskLevel {
	case contracts.RiskLow, contracts.RiskMedium, contracts.RiskHigh:
	case contracts.RiskCritical:
		return deny("JEV classified the action as critical risk")
	default:
		return deny(fmt.Sprintf("JEV returned unsupported risk level %q", assessment.RiskLevel))
	}

	risk := assessment.RiskLevel
	if assessment.Noul["credential_probing"] >= thresholds.ActionProbability ||
		assessment.Noul["destructive_effect"] >= thresholds.ActionProbability {
		risk = contracts.RiskHigh
	}

	if risk == contracts.RiskHigh {
		if assessment.Authorization != contracts.AuthorizationMedium && assessment.Authorization != contracts.AuthorizationHigh {
			return deny("a high-risk action lacks at least medium user authorization")
		}
		if assessment.NarrowlyScoped < thresholds.ActionProbability {
			return deny("JEV could not verify that the high-risk action is narrowly scoped")
		}
	}

	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "JEV assessment satisfies the source-derived Guardian policy"}
}

func validProbability(value float64) bool { return !math.IsNaN(value) && value >= 0 && value <= 1 }

func deny(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: reason}
}
