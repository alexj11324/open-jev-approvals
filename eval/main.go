// Command eval runs the labeled calibration set in cases.jsonl through
// policy.Compose and reports per-case results plus confusion counts split by
// expected outcome. It exits non-zero when any case disagrees with its label.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
	"github.com/alexj11324/open-jev-approvals/internal/policy"
)

// evalCase is one labeled calibration row: a fake JEV assessment in the same
// shape the client decodes, plus the outcome the binary policy must produce.
type evalCase struct {
	Name       string               `json:"name"`
	Expect     string               `json:"expect"`
	Assessment contracts.Assessment `json:"assessment"`
	Comment    string               `json:"comment,omitempty"`
}

func defaultCasesPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "cases.jsonl"
	}
	return filepath.Join(filepath.Dir(file), "cases.jsonl")
}

func main() {
	casesPath := flag.String("cases", defaultCasesPath(), "path to the JSONL calibration set")
	flag.Parse()
	if err := run(*casesPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run(path string, out io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var total, passed, falseAllows, falseDenies int
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var evalCase evalCase
		if err := json.Unmarshal([]byte(raw), &evalCase); err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if evalCase.Expect != string(contracts.DecisionAllow) && evalCase.Expect != string(contracts.DecisionDeny) {
			return fmt.Errorf("%s:%d: expect must be allow or deny, got %q", path, line, evalCase.Expect)
		}
		total++
		decision := policy.Compose(evalCase.Assessment, policy.DefaultThresholds())
		got := string(decision.Outcome)
		if got == evalCase.Expect {
			passed++
			fmt.Fprintf(out, "PASS %-58s -> %s\n", evalCase.Name, got)
			continue
		}
		if evalCase.Expect == string(contracts.DecisionDeny) {
			falseAllows++
		} else {
			falseDenies++
		}
		fmt.Fprintf(out, "FAIL %-58s -> %s (want %s): %s\n", evalCase.Name, got, evalCase.Expect, decision.Reason)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	fmt.Fprintf(out, "%d/%d passed; false allows (expected deny): %d; false denies (expected allow): %d\n",
		passed, total, falseAllows, falseDenies)
	if total == 0 {
		return fmt.Errorf("%s contained no cases", path)
	}
	if passed != total {
		return fmt.Errorf("%d case(s) disagreed with their labels", total-passed)
	}
	return nil
}
