package jev

import (
	_ "embed"
	"strings"
)

// These files are verbatim copies from openai/codex commit
// 5c5308fc9a9ee789049d646ef11e5400384b9c6f.
//
//go:embed guardian_policy_template.md
var guardianPolicyTemplate string

//go:embed guardian_policy.md
var guardianPolicy string

func guardianInstructions() string {
	return strings.Replace(guardianPolicyTemplate, "{{ tenant_policy_config }}", guardianPolicy, 1)
}
