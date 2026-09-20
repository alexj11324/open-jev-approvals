package jev

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func TestNewFromEnvRejectsNonHTTPSBaseURL(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "test-key")
	t.Setenv("TYPESAFE_API_BASE_URL", "http://attacker.example/review")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("NewFromEnv() error = nil")
	}
}

func TestRedirectRestrictedClientRejectsOriginChange(t *testing.T) {
	origin, err := url.Parse("https://api.typesafe.ai/v1/systemone")
	if err != nil {
		t.Fatal(err)
	}
	client := redirectRestrictedClient(&http.Client{}, origin)
	request, err := http.NewRequest(http.MethodGet, "https://attacker.example/review", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("CheckRedirect() error = nil")
	}
}

func TestRedirectRestrictedClientAllowsSameHTTPSOrigin(t *testing.T) {
	origin, err := url.Parse("https://api.typesafe.ai/v1/systemone")
	if err != nil {
		t.Fatal(err)
	}
	client := redirectRestrictedClient(&http.Client{}, origin)
	request, err := http.NewRequest(http.MethodGet, "https://api.typesafe.ai/v1/redirected", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err != nil {
		t.Fatalf("CheckRedirect() error = %v", err)
	}
}

func TestApprovalRequestHasIndependentSafetyQuestions(t *testing.T) {
	request := BuildApprovalRequest(contracts.Action{
		Harness:      contracts.HarnessCodex,
		SessionID:    "session-1",
		TurnID:       "turn-1",
		ToolUseID:    "tool-1",
		ToolName:     "Bash",
		Kind:         contracts.ActionShell,
		Input:        map[string]any{"command": "git status"},
		UserMessages: []string{"Inspect this repository."},
	})

	if request.Model != "jev-latest" {
		t.Fatalf("model = %q", request.Model)
	}
	for _, id := range RequiredQuestionIDs() {
		if _, ok := request.Questions[id]; !ok {
			t.Fatalf("missing question %q", id)
		}
	}
	if request.Questions["risk_level"].Type != "choice" {
		t.Fatalf("risk_level type = %q", request.Questions["risk_level"].Type)
	}
	if request.Questions["outcome"].Type != "choice" {
		t.Fatalf("outcome type = %q", request.Questions["outcome"].Type)
	}
	state := request.State.(map[string]any)
	policy, ok := state["guardian_policy"].(string)
	if !ok || !strings.Contains(policy, "# Outcome Policy") || strings.Contains(policy, "{{ tenant_policy_config }}") {
		t.Fatalf("guardian policy was not embedded: %q", policy)
	}
	authorization := state["user_authorization"].([]map[string]string)
	if len(authorization) != 1 || authorization[0]["role"] != "user" || authorization[0]["content"] != "Inspect this repository." {
		t.Fatalf("user_authorization = %#v", authorization)
	}
	action := state["current_action"].(map[string]any)
	if action["session_id"] != "session-1" || action["turn_id"] != "turn-1" || action["tool_use_id"] != "tool-1" {
		t.Fatalf("current_action identity = %#v", action)
	}
}

func TestAssessmentDefaultsOptionalGuardianFieldsFromOutcome(t *testing.T) {
	confidence := 1.0
	assessment, err := assessmentFromResponse(Response{
		Model: "jev-test",
		Answers: map[string]Answer{
			"outcome": {
				Type:          "choice",
				Choice:        "deny",
				Confidence:    &confidence,
				Probabilities: map[string]float64{"allow": 0, "deny": 1},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Outcome != contracts.DecisionDeny || assessment.RiskLevel != contracts.RiskHigh || assessment.Authorization != contracts.AuthorizationUnknown {
		t.Fatalf("assessment = %#v", assessment)
	}
	if assessment.Rationale != "Auto-review returned a deny decision without a rationale." {
		t.Fatalf("Rationale = %q", assessment.Rationale)
	}
}

func TestAssessmentRejectsOutcomeWithoutCompleteProbabilityDistribution(t *testing.T) {
	confidence := 1.0
	_, err := assessmentFromResponse(Response{
		Model: "jev-test",
		Answers: map[string]Answer{
			"outcome": {Type: "choice", Choice: "deny", Confidence: &confidence},
		},
	})
	if err == nil {
		t.Fatal("assessmentFromResponse() error = nil")
	}
}

func TestAssessmentRejectsOutcomeThatIsNotMostProbable(t *testing.T) {
	confidence := 0.2
	_, err := assessmentFromResponse(Response{
		Model: "jev-test",
		Answers: map[string]Answer{
			"outcome": {
				Type:          "choice",
				Choice:        "deny",
				Confidence:    &confidence,
				Probabilities: map[string]float64{"allow": 0.8, "deny": 0.2},
			},
		},
	})
	if err == nil {
		t.Fatal("assessmentFromResponse() error = nil")
	}
}
