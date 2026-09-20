package policy

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
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

func TestComposeAllowsUnsupportedRiskLevel(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskUnresolved
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow", decision.Outcome)
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

func TestComposeDeniesHighRiskThatIsNotNarrowlyScoped(t *testing.T) {
	assessment := safeAssessment()
	assessment.RiskLevel = contracts.RiskHigh
	assessment.Authorization = contracts.AuthorizationMedium
	assessment.NarrowlyScoped = 0.4
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}
}

func TestComposeAllowsWhenRequiredNoulIsMissing(t *testing.T) {
	assessment := safeAssessment()
	delete(assessment.Noul, "malicious_instruction")
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionAllow || !decision.Incomplete {
		t.Fatalf("Outcome = %q incomplete=%v, want incomplete allow; reason = %q", decision.Outcome, decision.Incomplete, decision.Reason)
	}
}

// TestComposeDeniesConfirmedHazardInPartialVerdict proves positive evidence
// outranks completeness: a tripping hazard noul denies even when another
// required field is missing.
func TestComposeDeniesConfirmedHazardInPartialVerdict(t *testing.T) {
	assessment := safeAssessment()
	assessment.Noul["malicious_instruction"] = 0.9
	delete(assessment.Noul, "sensitive_egress")
	decision := Compose(assessment, DefaultThresholds())
	if decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}
}

// TestComposeDeniesCriticalInPartialVerdict proves a critical risk level
// denies even when no noul judgments arrived at all.
func TestComposeDeniesCriticalInPartialVerdict(t *testing.T) {
	assessment := contracts.Assessment{RiskLevel: contracts.RiskCritical}
	if decision := Compose(assessment, DefaultThresholds()); decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny", decision.Outcome)
	}
}

func TestComposeAllowsInvalidChoiceConfidence(t *testing.T) {
	for name, mutate := range map[string]func(*contracts.Assessment){
		"nan risk confidence":          func(a *contracts.Assessment) { a.RiskConfidence = math.NaN() },
		"out-of-range risk confidence": func(a *contracts.Assessment) { a.RiskConfidence = 1.5 },
		"negative auth confidence":     func(a *contracts.Assessment) { a.AuthorizationConf = -0.1 },
	} {
		assessment := safeAssessment()
		mutate(&assessment)
		decision := Compose(assessment, DefaultThresholds())
		if decision.Outcome != contracts.DecisionAllow {
			t.Fatalf("%s: Outcome = %q, want allow; reason = %q", name, decision.Outcome, decision.Reason)
		}
	}
}

func TestComposeEscalatesDestructiveEffectToHighRisk(t *testing.T) {
	// A confirmed destructive effect upgrades effective risk to high instead
	// of denying outright: with high authorization and narrow scope it can
	// still allow, but with weak authorization it must deny.
	assessment := safeAssessment()
	assessment.Noul["destructive_effect"] = 0.9
	assessment.Authorization = contracts.AuthorizationLow
	if decision := Compose(assessment, DefaultThresholds()); decision.Outcome != contracts.DecisionDeny {
		t.Fatalf("Outcome = %q, want deny; reason = %q", decision.Outcome, decision.Reason)
	}

	assessment.Authorization = contracts.AuthorizationHigh
	if decision := Compose(assessment, DefaultThresholds()); decision.Outcome != contracts.DecisionAllow {
		t.Fatalf("Outcome = %q, want allow; reason = %q", decision.Outcome, decision.Reason)
	}
}

// TestDocumentMatchesCheckedInPolicy keeps the in-code policy document and
// the checked-in policy/codex-guardian-v1/policy.json semantically identical.
func TestDocumentMatchesCheckedInPolicy(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "policy", "codex-guardian-v1", "policy.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checked-in policy document: %v", err)
	}
	var checkedIn struct {
		Version           string             `json:"version"`
		Summary           string             `json:"summary"`
		Thresholds        map[string]float64 `json:"thresholds"`
		RequiredQuestions []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"required_questions"`
		DenyRules []struct {
			ID      string `json:"id"`
			Outcome string `json:"outcome"`
		} `json:"deny_rules"`
		DefaultOutcome string `json:"default_outcome"`
	}
	if err := json.Unmarshal(data, &checkedIn); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	document := Document()
	if checkedIn.Version != document["version"] {
		t.Fatalf("version = %q, want %q", checkedIn.Version, document["version"])
	}
	if checkedIn.Summary != document["summary"] {
		t.Fatalf("summary drifted from Document():\njson: %q\ncode: %q", checkedIn.Summary, document["summary"])
	}
	thresholds, ok := document["thresholds"].(map[string]float64)
	if !ok {
		t.Fatalf("Document() thresholds has unexpected type %T", document["thresholds"])
	}
	if checkedIn.Thresholds["action_probability"] != thresholds["action_probability"] {
		t.Fatalf("action_probability = %v, want %v", checkedIn.Thresholds["action_probability"], thresholds["action_probability"])
	}

	// The question ids must match the set the JEV client asks and Compose
	// consumes, in the documented order.
	wantQuestions := []string{
		"risk_level", "user_authorization", "violates_explicit_constraint", "sensitive_egress",
		"egress_authorized", "credential_probing", "persistent_security_weakening", "destructive_effect",
		"malicious_instruction", "narrowly_scoped",
	}
	if len(checkedIn.RequiredQuestions) != len(wantQuestions) {
		t.Fatalf("required_questions has %d entries, want %d", len(checkedIn.RequiredQuestions), len(wantQuestions))
	}
	for i, want := range wantQuestions {
		if checkedIn.RequiredQuestions[i].ID != want {
			t.Fatalf("required_questions[%d].id = %q, want %q", i, checkedIn.RequiredQuestions[i].ID, want)
		}
	}
	if len(checkedIn.DenyRules) == 0 {
		t.Fatal("checked-in policy document has no deny rules")
	}
	for _, rule := range checkedIn.DenyRules {
		if rule.Outcome != "deny" {
			t.Fatalf("deny rule %q has outcome %q", rule.ID, rule.Outcome)
		}
	}
	if checkedIn.DefaultOutcome != "allow" {
		t.Fatalf("default_outcome = %q, want allow", checkedIn.DefaultOutcome)
	}
}
