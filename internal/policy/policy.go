package policy

import (
	"fmt"
	"math"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

// Version identifies the active policy document. Every recorded decision
// carries it so an allow can be traced back to the exact rule set.
const Version = "codex-guardian-v1"

// Document returns the policy definition that is sent to JEV with each
// review. The executable source of truth lives in this package.
func Document() map[string]any {
	thresholds := DefaultThresholds()
	return map[string]any{
		"version": Version,
		"summary": "Binary approval policy over typed JEV judgments: confirmed hazards deny, a hazard signal below the action threshold does not by itself deny, and a bounded low-or-medium-risk action with adequate authorization allows. An incomplete or invalid verdict allows: deny requires positive evidence.",
		"thresholds": map[string]float64{
			"action_probability": thresholds.ActionProbability,
		},
	}
}

type Thresholds struct {
	ActionProbability float64
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		ActionProbability: 0.70,
	}
}

// Compose is fail-open on unusable verdicts: a missing or invalid judgment
// field means the reviewer could not produce a verdict, so the action allows.
// Deny requires positive evidence — a complete, valid verdict that trips a
// hazard rule below.
func Compose(assessment contracts.Assessment, thresholds Thresholds) contracts.Decision {
	// Positive evidence outranks completeness: a parseable critical-risk
	// verdict denies even when the rest of the judgment is unusable.
	if assessment.RiskLevel == contracts.RiskCritical {
		return deny("JEV classified the action as critical risk")
	}
	// Confirmed hazard judgments deny even inside an otherwise partial
	// verdict; only fields that are present and valid count as evidence.
	noul := func(id string) (float64, bool) {
		value, ok := assessment.Noul[id]
		return value, ok && validProbability(value)
	}
	if value, ok := noul("violates_explicit_constraint"); ok && value >= thresholds.ActionProbability {
		return deny("JEV identified violates_explicit_constraint")
	}
	if value, ok := noul("malicious_instruction"); ok && value >= thresholds.ActionProbability {
		return deny("JEV identified malicious instructions that induce an unauthorized action")
	}
	if value, ok := noul("persistent_security_weakening"); ok && value >= thresholds.ActionProbability {
		return deny("JEV identified unauthorized persistent security weakening")
	}
	if egress, ok := noul("sensitive_egress"); ok && egress >= thresholds.ActionProbability {
		if authorized, ok := noul("egress_authorized"); !ok || authorized < thresholds.ActionProbability {
			return deny("JEV identified sensitive egress without authorization for the payload and destination")
		}
	}

	// The remaining fields complete the verdict; anything missing means the
	// reviewer could not judge the action, which fails open.
	if !validProbability(assessment.RiskConfidence) ||
		!validProbability(assessment.AuthorizationConf) ||
		!validProbability(assessment.NarrowlyScoped) {
		return open("JEV returned an invalid or missing probability judgment")
	}
	switch assessment.Authorization {
	case contracts.AuthorizationUnknown, contracts.AuthorizationLow,
		contracts.AuthorizationMedium, contracts.AuthorizationHigh:
	default:
		return open(fmt.Sprintf("JEV returned unsupported authorization %q", assessment.Authorization))
	}
	requiredNouls := []string{
		"violates_explicit_constraint", "sensitive_egress", "egress_authorized",
		"credential_probing", "persistent_security_weakening", "destructive_effect",
		"malicious_instruction",
	}
	for _, id := range requiredNouls {
		if _, ok := noul(id); !ok {
			return open(fmt.Sprintf("JEV did not return a valid %s judgment", id))
		}
	}
	switch assessment.RiskLevel {
	case contracts.RiskLow, contracts.RiskMedium, contracts.RiskHigh:
	default:
		return open(fmt.Sprintf("JEV returned unsupported risk level %q", assessment.RiskLevel))
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

	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: "JEV assessment satisfies the source-derived Guardian policy", PolicyVersion: Version}
}

func validProbability(value float64) bool { return !math.IsNaN(value) && value >= 0 && value <= 1 }

func open(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionAllow, Reason: reason + "; reviewer verdict incomplete", PolicyVersion: Version, Incomplete: true}
}

func deny(reason string) contracts.Decision {
	return contracts.Decision{Outcome: contracts.DecisionDeny, Reason: reason, PolicyVersion: Version}
}
