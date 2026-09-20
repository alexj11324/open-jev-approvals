package policy

import (
	"fmt"
	"math"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

type Thresholds struct {
	ActionProbability       float64
	ReviewProbability       float64
	RiskConfidence          float64
	AuthorizationConfidence float64
	EvidenceProbability     float64
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		ActionProbability:       0.70,
		ReviewProbability:       0.30,
		RiskConfidence:          0.70,
		AuthorizationConfidence: 0.70,
		EvidenceProbability:     0.60,
	}
}

func Compose(assessment contracts.Assessment, thresholds Thresholds) contracts.Decision {
	if !validProbability(assessment.RiskConfidence) || !validProbability(assessment.AuthorizationConf) {
		return review("JEV returned an invalid Choice confidence")
	}
	if assessment.RiskConfidence < thresholds.RiskConfidence {
		return review("JEV risk classification confidence is below the configured approval threshold")
	}
	if assessment.EvidenceSufficient < thresholds.EvidenceProbability {
		return review("JEV reports that the available evidence is insufficient")
	}

	for _, id := range []string{"violates_explicit_constraint", "credential_probing", "persistent_security_weakening"} {
		value, ok := assessment.Noul[id]
		if !ok || !validProbability(value) {
			return review(fmt.Sprintf("JEV did not return a valid %s judgment", id))
		}
		if value >= thresholds.ActionProbability {
			return deny(fmt.Sprintf("JEV identified %s", id))
		}
		if value >= thresholds.ReviewProbability {
			return review(fmt.Sprintf("JEV is uncertain about %s", id))
		}
	}

	maliciousInstruction, ok := assessment.Noul["malicious_instruction"]
	if !ok || !validProbability(maliciousInstruction) {
		return review("JEV did not return a valid malicious_instruction judgment")
	}
	if maliciousInstruction >= thresholds.ActionProbability {
		return deny("JEV identified malicious instructions that induce an unauthorized action")
	}

	egress, ok := assessment.Noul["sensitive_egress"]
	if !ok || !validProbability(egress) {
		return review("JEV did not return a valid sensitive_egress judgment")
	}
	if egress >= thresholds.ActionProbability {
		authorized, ok := assessment.Noul["egress_authorized"]
		if !ok || !validProbability(authorized) {
			return review("JEV did not return a valid egress_authorized judgment")
		}
		switch {
		case authorized >= thresholds.ActionProbability:
		case authorized <= 1-thresholds.ActionProbability:
			return deny("JEV identified sensitive egress without current authorization")
		default:
			return review("JEV is uncertain whether the sensitive egress is authorized")
		}
	} else if egress >= thresholds.ReviewProbability {
		return review("JEV is uncertain whether the action sends sensitive data externally")
	}

	if assessment.RiskLevel == contracts.RiskCritical {
		return deny("JEV classified the action as critical risk")
	}
	if assessment.RiskLevel == contracts.RiskUnresolved {
		return review("JEV could not resolve the action risk")
	}

	if assessment.RiskLevel == contracts.RiskHigh {
		if assessment.Authorization != contracts.AuthorizationHigh {
			return deny("a high-risk action lacks high user authorization")
		}
		if assessment.AuthorizationConf < thresholds.AuthorizationConfidence {
			return review("JEV high-risk authorization confidence is below the configured approval threshold")
		}
		if assessment.NarrowlyScoped < thresholds.ActionProbability {
			return review("JEV could not verify that the high-risk action is narrowly scoped")
		}
	}

	if destructive, ok := assessment.Noul["destructive_effect"]; !ok || !validProbability(destructive) {
		return review("JEV did not return a valid destructive_effect judgment")
	} else if destructive >= thresholds.ReviewProbability && assessment.RiskLevel != contracts.RiskHigh {
		return review("JEV found a possible destructive effect that conflicts with the risk assessment")
	}

	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "JEV assessment satisfies the local codex-derived-v1 policy"}
}

func validProbability(value float64) bool { return !math.IsNaN(value) && value >= 0 && value <= 1 }

func deny(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: reason}
}
func review(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionReviewRequired, Reason: reason}
}
