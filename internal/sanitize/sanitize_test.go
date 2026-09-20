package sanitize

import (
	"strings"
	"testing"
)

func TestRedactValueRedactsScalarUnderSensitiveKey(t *testing.T) {
	input := map[string]any{
		"api_key":    "ordinary-looking-value",
		"nested":     map[string]any{"client_secret": "also-ordinary", "note": "keep me"},
		"parameters": map[string]any{"url": "https://example.com"},
	}
	out := RedactValue(input).(map[string]any)
	if out["api_key"] != "[REDACTED:value]" {
		t.Fatalf("api_key = %v, want redacted", out["api_key"])
	}
	nested := out["nested"].(map[string]any)
	if nested["client_secret"] != "[REDACTED:value]" {
		t.Fatalf("client_secret = %v, want redacted", nested["client_secret"])
	}
	if nested["note"] != "keep me" {
		t.Fatalf("note = %v, want preserved", nested["note"])
	}
	if url := out["parameters"].(map[string]any)["url"]; url != "https://example.com" {
		t.Fatalf("url = %v, want preserved", url)
	}
}

func TestRedactStringCoversTokenShapesAndKeyValues(t *testing.T) {
	cases := map[string]string{
		"sk_live_abcdefghijklmnop":       "[REDACTED",
		"AKIAIOSFODNN7EXAMPLE":           "[REDACTED:aws-access-key]",
		"--token=hunter2hunter2":         "--token=[REDACTED:value]",
		`"password": "correct horse"`:    `"password": [REDACTED:value]`,
		"Authorization: Bearer abcdef12": "Bearer [REDACTED:token]",
	}
	for input, want := range cases {
		if got := RedactString(input); !strings.Contains(got, want) {
			t.Fatalf("RedactString(%q) = %q, want substring %q", input, got, want)
		}
	}
}
