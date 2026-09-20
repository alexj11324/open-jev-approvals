// Package sanitize removes secret values from data before it leaves the
// process (sent to the JEV API) and before it is written to the audit store.
// Redaction keeps semantics: which key/path/flag held the secret stays
// visible, only the value is replaced by a typed marker.
package sanitize

import (
	"regexp"
	"strings"

	"github.com/alexj11324/open-jev-approvals/internal/contracts"
)

// rule order matters: multi-line blocks first, then well-known token shapes,
// then generic key=value secrets.
var rules = []struct {
	pattern *regexp.Regexp
	replace string
}{
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`), "[REDACTED:private-key]"},
	{regexp.MustCompile(`(?i)bearer[ \t]+[a-z0-9._~+/=-]{8,}`), "Bearer [REDACTED:token]"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED:aws-access-key]"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), "[REDACTED:github-pat]"},
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), "[REDACTED:github-token]"},
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "[REDACTED:slack-token]"},
	{regexp.MustCompile(`(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), "[REDACTED:api-key]"},
	{regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "[REDACTED:api-key]"},
	{regexp.MustCompile(`apikey_[a-z0-9_]+`), "apikey_[REDACTED]"},
	{keyValuePattern, "${1}${2}${3}[REDACTED:value]"},
}

// Matches secret-looking assignments: --token=abc, "api_key": "abc",
// password: abc, secret = abc. The key name and separator are preserved so a
// reviewer can still see which field carried the secret.
var keyValuePattern = regexp.MustCompile(
	`(?i)\b(password|passwd|pwd|secret|secret[_-]?key|token|access[_-]?token|auth[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential)\b(["']?)` +
		`(\s*(?:=|:=|:|"=>|=>)\s*)` +
		`("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[^\s,;&'")}\]]+)`,
)

// RedactString returns the input with every recognized secret value replaced
// by a typed marker. Surrounding structure (flag names, paths, endpoints,
// operations) is preserved.
func RedactString(value string) string {
	for _, rule := range rules {
		value = rule.pattern.ReplaceAllString(value, rule.replace)
	}
	return value
}

// sensitiveKeyPattern names map keys whose scalar values are secrets by
// position, not by shape — `{"api_key": "ordinary-looking-value"}` must
// redact even when the value matches no token pattern.
var sensitiveKeyPattern = regexp.MustCompile(
	`(?i)^(password|passwd|pwd|secret|secret[_-]?key|token|access[_-]?token|auth[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|authorization|x[_-]?api[_-]?key)$`,
)

// RedactValue deep-redacts decoded JSON values. Scalars under a sensitive
// map key are replaced outright; everything else is recursed into so token
// shapes and key=value assignments inside strings still redact.
func RedactValue(value any) any {
	return redactValue(value, "")
}

func redactValue(value any, key string) any {
	if key != "" && sensitiveKeyPattern.MatchString(key) {
		switch value.(type) {
		case map[string]any, []any:
			// Structured payloads under a sensitive key still recurse —
			// their children may hold both secrets and ordinary fields.
		default:
			return "[REDACTED:value]"
		}
	}
	switch typed := value.(type) {
	case string:
		return RedactString(typed)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for childKey, child := range typed {
			out[childKey] = redactValue(child, childKey)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = RedactValue(child)
		}
		return out
	default:
		return value
	}
}

// RedactAction returns a copy of the action with user messages, tool input,
// facts, and lexical hints redacted. Metadata (tool name, paths in dedicated
// fields, identifiers) is preserved.
func RedactAction(action contracts.Action) contracts.Action {
	redacted := action
	redacted.UserMessages = make([]string, 0, len(action.UserMessages))
	for _, message := range action.UserMessages {
		redacted.UserMessages = append(redacted.UserMessages, RedactString(message))
	}
	if action.Input != nil {
		if input, ok := RedactValue(action.Input).(map[string]any); ok {
			redacted.Input = input
		}
	}
	if action.Facts != nil {
		if facts, ok := RedactValue(action.Facts).(map[string]any); ok {
			redacted.Facts = facts
		}
	}
	if action.Hints != nil {
		if hints, ok := RedactValue(action.Hints).(map[string]any); ok {
			redacted.Hints = hints
		}
	}
	return redacted
}

// ErrorMessage renders an untrusted error body (for example a remote API
// error response that may echo our request) safe to show: redacted and
// truncated.
func ErrorMessage(body []byte, limit int) string {
	message := strings.TrimSpace(RedactString(string(body)))
	if limit > 0 && len(message) > limit {
		return message[:limit] + "…"
	}
	return message
}
