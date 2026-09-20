package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/alexj11324/open-jev-approvals/internal/adapters"
	"github.com/alexj11324/open-jev-approvals/internal/config"
	"github.com/alexj11324/open-jev-approvals/internal/contracts"
	installer "github.com/alexj11324/open-jev-approvals/internal/install"
	"github.com/alexj11324/open-jev-approvals/internal/jev"
	"github.com/alexj11324/open-jev-approvals/internal/policy"
	"github.com/alexj11324/open-jev-approvals/internal/review"
	"github.com/alexj11324/open-jev-approvals/internal/storage"
)

func main() {
	if err := config.LoadUserEnv(); err != nil {
		fmt.Fprintln(os.Stderr, "jev-approve:", err)
		// On interception paths a broken environment degrades to allow —
		// the reviewer is unavailable, not a reason to stall the action.
		if len(os.Args) <= 1 || (os.Args[1] != "hook" && os.Args[1] != "event") {
			os.Exit(1)
		}
	}
	code, err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jev-approve:", err)
	}
	os.Exit(code)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("usage: jev-approve <hook|event|probe|test|install|uninstall|status|doctor|inspect>")
	}
	switch args[0] {
	case "hook":
		return blocking(runHook(args[1:], stdin, stdout, stderr))
	case "event":
		return blocking(runEvent(args[1:], stdin))
	case "probe":
		return runProbe(stdout)
	case "test":
		return runTest(args[1:], stdout)
	case "install", "uninstall", "status", "doctor":
		return runManagement(args, stdout)
	case "inspect":
		return runInspect(args[1:], stdout)
	default:
		return 1, fmt.Errorf("unknown command %q", args[0])
	}
}

// blocking maps a hook/event result to the harness exit code. Errors are
// already rare here — every recoverable failure degrades to allow inside
// runHook/runEvent — so a remaining error means even the verdict could not
// be emitted, which stays blocking rather than silently allowing.
func blocking(code int, err error) (int, error) {
	if err != nil {
		return 2, err
	}
	return code, nil
}

// hookDeadline budgets the whole interception from process entry so a slow
// environment cannot push the JEV call past the harness's hook timeout.
const hookDeadline = 8 * time.Second

func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
	defer cancel()

	flags := flag.NewFlagSet("hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(stderr, "jev-approve: %v; reviewer unavailable\n", err)
		return 0, nil
	}
	harness, err := parseHarness(*harnessValue)
	if err != nil {
		fmt.Fprintf(stderr, "jev-approve: %v; reviewer unavailable\n", err)
		return 0, nil
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		fmt.Fprintf(stderr, "jev-approve: read hook input: %v; reviewer unavailable\n", err)
		return 0, nil
	}
	action, err := adapters.Normalize(harness, raw)
	if err != nil {
		// A PermissionRequest payload that cannot be parsed still needs an
		// explicit Codex verdict; anything else fails open silently.
		if harness == contracts.HarnessCodex && strings.Contains(string(raw), `"PermissionRequest"`) {
			return writeRequiredHookJSON(stdout, stderr, map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName": string(contracts.HookPermissionRequest),
					"decision":      map[string]any{"behavior": "allow"},
				},
			})
		}
		fmt.Fprintf(stderr, "jev-approve: parse hook input: %v; reviewer unavailable\n", err)
		return 0, nil
	}

	// Degraded reviewer paths still funnel through Review: a verdict that
	// positively denies must deny even when the audit store is gone.
	var store *storage.Store
	if s, err := storage.Open(storage.DefaultPath()); err == nil {
		store = s
		defer store.Close()
		if installationID, err := store.InstallationID(ctx); err == nil {
			action.Scope = storage.ScopeKey(installationID, harness, action.SessionID, action.AgentID)
			if messages, version, err := store.UserPrompts(ctx, action.Scope, action.TurnID); err == nil {
				action.UserMessages, action.AuthorizationVersion = messages, version
			} else {
				fmt.Fprintf(stderr, "jev-approve: load user authorization: %v; reviewer degraded\n", err)
			}
		} else {
			fmt.Fprintf(stderr, "jev-approve: resolve installation id: %v; reviewer degraded\n", err)
		}
	} else {
		fmt.Fprintf(stderr, "jev-approve: open audit store: %v; reviewer degraded\n", err)
	}
	client, err := jev.NewFromEnv()
	if err != nil {
		decision := review.Service{Store: store, Thresholds: policy.DefaultThresholds()}.Review(ctx, action)
		return writeHookDecision(harness, action.HookEvent, decision, stdout, stderr)
	}
	decision := review.Service{Assessor: client, Store: store, Thresholds: policy.DefaultThresholds()}.Review(ctx, action)
	return writeHookDecision(harness, action.HookEvent, decision, stdout, stderr)
}

func writeHookDecision(harness contracts.Harness, event contracts.HookEvent, decision contracts.Decision, stdout, stderr io.Writer) (int, error) {
	if harness != contracts.HarnessCodex {
		if decision.Outcome == contracts.DecisionAllow {
			return 0, nil
		}
		fmt.Fprintf(stderr, "JEV approval blocked: %s (review %s)\n", decision.Reason, decision.ReviewID)
		return 2, nil
	}

	switch event {
	case contracts.HookPreToolUse:
		if decision.Outcome == contracts.DecisionAllow {
			return 0, nil
		}
		return writeRequiredHookJSON(stdout, stderr, map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            string(contracts.HookPreToolUse),
				"permissionDecision":       "deny",
				"permissionDecisionReason": decision.Reason,
			},
		})
	case contracts.HookPermissionRequest:
		var hookDecision map[string]any
		if decision.Outcome == contracts.DecisionAllow {
			hookDecision = map[string]any{"behavior": "allow"}
		} else {
			hookDecision = map[string]any{"behavior": "deny", "message": decision.Reason}
		}
		return writeRequiredHookJSON(stdout, stderr, map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName": string(contracts.HookPermissionRequest),
				"decision":      hookDecision,
			},
		})
	default:
		return 2, fmt.Errorf("unsupported hook event %q", event)
	}
}

func writeRequiredHookJSON(stdout, stderr io.Writer, value any) (int, error) {
	if _, err := writeJSON(stdout, value); err != nil {
		fmt.Fprintf(stderr, "JEV approval denied: could not emit the required hook verdict: %v\n", err)
		return 2, nil
	}
	return 0, nil
}

func runEvent(args []string, stdin io.Reader) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
	defer cancel()

	flags := flag.NewFlagSet("event", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	if err := flags.Parse(args); err != nil {
		return 0, nil
	}
	harness, err := parseHarness(*harnessValue)
	if err != nil {
		return 0, nil
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return 0, nil
	}
	var event struct {
		HookEventName string `json:"hook_event_name"`
		SessionID     string `json:"session_id"`
		TurnID        string `json:"turn_id"`
		AgentID       string `json:"agent_id"`
		Prompt        string `json:"prompt"`
		UserPrompt    string `json:"user_prompt"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return 0, nil
	}
	if event.HookEventName != "UserPromptSubmit" {
		return 0, nil
	}
	prompt := event.Prompt
	if prompt == "" {
		prompt = event.UserPrompt
	}
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		return 0, nil
	}
	defer store.Close()
	installationID, err := store.InstallationID(ctx)
	if err != nil {
		return 0, nil
	}
	scope := storage.ScopeKey(installationID, harness, event.SessionID, event.AgentID)
	if err := store.RememberPrompt(ctx, scope, event.SessionID, event.TurnID, prompt); err != nil {
		return 0, nil
	}
	return 0, nil
}

func runProbe(stdout io.Writer) (int, error) {
	client, err := jev.NewFromEnv()
	if err != nil {
		return 1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	model, err := client.Probe(ctx)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(stdout, "JEV API reachable: %s\n", model)
	return 0, nil
}

func runTest(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	live := flags.Bool("live", false, "also call TypeSafe JEV")
	if err := flags.Parse(args); err != nil {
		return 1, err
	}
	harness, err := parseHarness(*harnessValue)
	if err != nil {
		return 1, err
	}

	action, err := adapters.Normalize(harness, hookTestFixture(harness))
	if err != nil {
		return 1, fmt.Errorf("adapter test failed: %w", err)
	}
	if action.Kind != contracts.ActionShell || action.Input["command"] != "git status --short" {
		return 1, errors.New("adapter test produced an unexpected normalized action")
	}
	fmt.Fprintln(stdout, "PASS adapter: PreToolUse input normalized")

	safe := testAssessment()
	if decision := policy.Compose(safe, policy.DefaultThresholds()); decision.Outcome != contracts.DecisionAllow {
		return 1, fmt.Errorf("policy allow test failed: %s", decision.Reason)
	}
	fmt.Fprintln(stdout, "PASS policy allow: bounded low-risk action is allowed")

	blocked := testAssessment()
	blocked.Noul["violates_explicit_constraint"] = 1
	if decision := policy.Compose(blocked, policy.DefaultThresholds()); decision.Outcome != contracts.DecisionDeny {
		return 1, fmt.Errorf("policy block test failed: %s", decision.Reason)
	}
	fmt.Fprintln(stdout, "PASS policy block: explicit user constraint is denied")

	credentialProbe := testAssessment()
	credentialProbe.RiskConfidence = 0.01
	credentialProbe.Noul["credential_probing"] = 1
	if decision := policy.Compose(credentialProbe, policy.DefaultThresholds()); decision.Outcome != contracts.DecisionDeny {
		return 1, fmt.Errorf("policy credential deny test failed: %s", decision.Reason)
	}
	fmt.Fprintln(stdout, "PASS policy credential deny: credential probing overrides an uncertain risk classification")

	if !*live {
		fmt.Fprintln(stdout, "SKIP live JEV: rerun with --live to verify the configured API")
		return 0, nil
	}
	client, err := jev.NewFromEnv()
	if err != nil {
		return 1, err
	}
	action.UserMessages = []string{"Run git status in this repository and report the result. Do not modify files or contact external services."}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assessment, err := client.Assess(ctx, action)
	if err != nil {
		return 1, fmt.Errorf("live JEV approval test failed: %w", err)
	}
	decision := policy.Compose(assessment, policy.DefaultThresholds())
	fmt.Fprintf(stdout, "PASS live JEV: model=%s outcome=%s\n", assessment.Model, decision.Outcome)
	return 0, nil
}

func hookTestFixture(harness contracts.Harness) []byte {
	return []byte(fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"test-session","turn_id":"test-turn","tool_use_id":"test-tool","cwd":"/workspace","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"git status --short"}%s}`,
		map[bool]string{true: `,"agent_id":"test-agent"`, false: ""}[harness == contracts.HarnessClaudeCode]))
}

func testAssessment() contracts.Assessment {
	return contracts.Assessment{
		RiskLevel:         contracts.RiskLow,
		RiskConfidence:    0.99,
		Authorization:     contracts.AuthorizationLow,
		AuthorizationConf: 0.99,
		NarrowlyScoped:    0.99,
		Noul: map[string]float64{
			"violates_explicit_constraint":  0,
			"sensitive_egress":              0,
			"egress_authorized":             1,
			"credential_probing":            0,
			"persistent_security_weakening": 0,
			"destructive_effect":            0,
			"malicious_instruction":         0,
		},
	}
}

func runManagement(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	configPath := flags.String("config", "", "hook config path")
	binary := flags.String("binary", "", "absolute jev-approve path")
	project := flags.String("project", "", "project directory")
	live := flags.Bool("live", false, "call the JEV API")
	if err := flags.Parse(args[1:]); err != nil {
		return 1, err
	}
	harness, err := parseHarness(*harnessValue)
	if err != nil {
		return 1, err
	}
	if *project == "" {
		*project, _ = os.Getwd()
	}
	if *configPath == "" {
		*configPath = installer.DefaultConfigPath(harness, *project)
	}
	if *binary == "" {
		*binary, _ = os.Executable()
	}
	switch args[0] {
	case "install":
		if err := installer.Install(harness, *configPath, *binary); err != nil {
			return 1, err
		}
		fmt.Fprintf(stdout, "installed %s hooks in %s\n", harness, *configPath)
	case "uninstall":
		if err := installer.Uninstall(harness, *configPath, *binary); err != nil {
			return 1, err
		}
		fmt.Fprintf(stdout, "uninstalled %s hooks from %s\n", harness, *configPath)
	case "status":
		status, err := installer.Check(harness, *configPath, *binary)
		if err != nil {
			return 1, err
		}
		return writeJSON(stdout, status)
	case "doctor":
		status, err := installer.Check(harness, *configPath, *binary)
		if err != nil {
			return 1, err
		}
		if !status.Installed || status.Malformed != "" {
			return 1, fmt.Errorf("JEV hooks are not installed in %s", status.ConfigPath)
		}
		if *live {
			return runProbe(stdout)
		}
		fmt.Fprintf(stdout, "JEV hooks found in %s (events: %s); run doctor --live to verify the API.\n",
			status.ConfigPath, strings.Join(status.Events, ", "))
	}
	return 0, nil
}

func runInspect(args []string, stdout io.Writer) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: jev-approve inspect <review-id>")
	}
	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		return 1, err
	}
	defer store.Close()
	decision, err := store.Decision(context.Background(), args[0])
	if err != nil {
		return 1, err
	}
	return writeJSON(stdout, decision)
}

func writeJSON(writer io.Writer, value any) (int, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return 1, err
	}
	_, err = fmt.Fprintln(writer, string(data))
	return 0, err
}
func parseHarness(value string) (contracts.Harness, error) {
	harness := contracts.Harness(value)
	if harness != contracts.HarnessCodex && harness != contracts.HarnessClaudeCode {
		return "", fmt.Errorf("--harness must be codex or claude-code")
	}
	return harness, nil
}
