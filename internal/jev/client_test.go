package jev

import (
	"testing"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

func TestApprovalRequestHasIndependentSafetyQuestions(t *testing.T) {
	request := BuildApprovalRequest(contracts.Action{
		Harness:  contracts.HarnessCodex,
		ToolName: "Bash",
		Kind:     contracts.ActionShell,
		Input:    map[string]any{"command": "git status"},
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
	if request.Questions["sensitive_egress"].Type != "noul" {
		t.Fatalf("sensitive_egress type = %q", request.Questions["sensitive_egress"].Type)
	}
}
