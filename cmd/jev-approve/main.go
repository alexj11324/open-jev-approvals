package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alexjiang/open-jev-approvals/internal/adapters"
	"github.com/alexjiang/open-jev-approvals/internal/config"
	"github.com/alexjiang/open-jev-approvals/internal/contracts"
	installer "github.com/alexjiang/open-jev-approvals/internal/install"
	"github.com/alexjiang/open-jev-approvals/internal/jev"
	"github.com/alexjiang/open-jev-approvals/internal/policy"
	"github.com/alexjiang/open-jev-approvals/internal/review"
	"github.com/alexjiang/open-jev-approvals/internal/storage"
)

func main() {
	if err := config.LoadDotEnv(".env"); err != nil {
		fmt.Fprintln(os.Stderr, "jev-approve:", err)
		os.Exit(1)
	}
	code, err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jev-approve:", err)
	}
	os.Exit(code)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("usage: jev-approve <hook|event|probe|install|uninstall|status|doctor|inspect>")
	}
	switch args[0] {
	case "hook":
		return runHook(args[1:], stdin, stderr)
	case "event":
		return runEvent(args[1:], stdin)
	case "probe":
		return runProbe(stdout)
	case "install", "uninstall", "status", "doctor":
		return runManagement(args, stdout)
	case "inspect":
		return runInspect(args[1:], stdout)
	default:
		return 1, fmt.Errorf("unknown command %q", args[0])
	}
}

func runHook(args []string, stdin io.Reader, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	harness, err := parseHarness(*harnessValue)
	if err != nil {
		return 2, err
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return 2, err
	}
	action, err := adapters.Normalize(harness, raw)
	if err != nil {
		return 2, err
	}

	store, err := storage.Open(storage.DefaultPath())
	if err != nil {
		return 2, err
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action.UserMessages, err = store.UserPrompts(ctx, action.SessionID)
	if err != nil {
		return 2, fmt.Errorf("load user authorization: %w", err)
	}
	client, err := jev.NewFromEnv()
	if err != nil {
		decision := review.Service{Store: store, Thresholds: policy.DefaultThresholds()}.Review(ctx, action)
		fmt.Fprintf(stderr, "JEV approval blocked: %s (review %s)\n", decision.Reason, decision.ReviewID)
		return 2, nil
	}
	decision := review.Service{Assessor: client, Store: store, Thresholds: policy.DefaultThresholds()}.Review(ctx, action)
	if decision.Outcome == contracts.DecisionAllow {
		return 0, nil
	}
	fmt.Fprintf(stderr, "JEV approval blocked: %s (review %s)\n", decision.Reason, decision.ReviewID)
	return 2, nil
}

func runEvent(args []string, stdin io.Reader) (int, error) {
	flags := flag.NewFlagSet("event", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessValue := flags.String("harness", "", "codex or claude-code")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if _, err := parseHarness(*harnessValue); err != nil {
		return 2, err
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return 2, err
	}
	var event struct {
		HookEventName string `json:"hook_event_name"`
		SessionID     string `json:"session_id"`
		Prompt        string `json:"prompt"`
		UserPrompt    string `json:"user_prompt"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return 0, err
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
		return 2, err
	}
	defer store.Close()
	if err := store.RememberPrompt(context.Background(), event.SessionID, prompt); err != nil {
		return 2, err
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
		if !status.Installed {
			return 1, fmt.Errorf("JEV hooks are not installed in %s", status.ConfigPath)
		}
		if *live {
			return runProbe(stdout)
		}
		fmt.Fprintf(stdout, "JEV hooks found in %s; run doctor --live to verify the API.\n", status.ConfigPath)
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
