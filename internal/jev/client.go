package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alexjiang/open-jev-approvals/internal/contracts"
)

const defaultBaseURL = "https://api.typesafe.ai/v1/systemone"

type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

type Request struct {
	State     any                 `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   *Usage            `json:"usage"`
}

type Client struct {
	APIKey     string
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

func NewFromEnv() (*Client, error) {
	key := os.Getenv("TYPESAFE_API_KEY")
	if key == "" {
		return nil, errors.New("TYPESAFE_API_KEY is not set")
	}
	baseURL := os.Getenv("TYPESAFE_API_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if _, err := validatedBaseURL(baseURL); err != nil {
		return nil, err
	}
	model := os.Getenv("TYPESAFE_MODEL")
	if model == "" {
		model = "jev-latest"
	}
	return &Client{APIKey: key, BaseURL: baseURL, Model: model, HTTPClient: &http.Client{Timeout: 5 * time.Second}}, nil
}

func (c *Client) Assess(ctx context.Context, action contracts.Action) (contracts.Assessment, error) {
	request := BuildApprovalRequest(action)
	request.Model = c.Model
	response, err := c.evaluate(ctx, request)
	if err != nil {
		return contracts.Assessment{}, err
	}
	return assessmentFromResponse(response)
}

func (c *Client) Probe(ctx context.Context) (string, error) {
	response, err := c.evaluate(ctx, Request{
		Model: c.Model,
		State: map[string]string{"probe": "This is a harmless API connectivity check. It has no side effect."},
		Questions: map[string]Question{
			"has_no_side_effect": {
				Type: "noul", Instructions: "Does `probe` explicitly describe an action with no side effect?",
				Criteria: map[string]string{"true": "The text explicitly says it has no side effect.", "false": "The text describes an action with a side effect."},
			},
		},
	})
	if err != nil {
		return "", err
	}
	answer, ok := response.Answers["has_no_side_effect"]
	if !ok || answer.Type != "noul" || answer.Noul == nil || !validProbability(*answer.Noul) {
		return "", errors.New("JEV probe response has no valid has_no_side_effect answer")
	}
	return response.Model, nil
}

func (c *Client) evaluate(ctx context.Context, request Request) (Response, error) {
	if c.APIKey == "" {
		return Response{}, errors.New("TYPESAFE_API_KEY is not set")
	}
	if c.BaseURL == "" {
		return Response{}, errors.New("TypeSafe API base URL is not set")
	}
	baseURL, err := validatedBaseURL(c.BaseURL)
	if err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf("encode JEV request: %w", err)
	}
	httpClient := redirectRestrictedClient(c.HTTPClient, baseURL)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("create JEV request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return Response{}, fmt.Errorf("call TypeSafe JEV: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20))
	if err != nil {
		return Response{}, fmt.Errorf("read TypeSafe JEV response: %w", err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return Response{}, fmt.Errorf("TypeSafe JEV returned HTTP %d: %s", httpResponse.StatusCode, safeError(responseBody))
	}
	var response Response
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return Response{}, fmt.Errorf("decode TypeSafe JEV response: %w", err)
	}
	if response.Model == "" || response.Answers == nil || response.Usage == nil {
		return Response{}, errors.New("TypeSafe JEV response is incomplete")
	}
	return response, nil
}

func validatedBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid TypeSafe API base URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("TypeSafe API base URL must be an HTTPS URL without user information")
	}
	return parsed, nil
}

func redirectRestrictedClient(source *http.Client, origin *url.URL) *http.Client {
	if source == nil {
		source = &http.Client{Timeout: 5 * time.Second}
	}
	client := *source
	previousCheck := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || !sameOrigin(request.URL, origin) {
			return errors.New("TypeSafe API redirect changed the trusted HTTPS origin")
		}
		if previousCheck != nil {
			return previousCheck(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 TypeSafe API redirects")
		}
		return nil
	}
	return &client
}

func sameOrigin(candidate, origin *url.URL) bool {
	return strings.EqualFold(candidate.Hostname(), origin.Hostname()) &&
		effectivePort(candidate) == effectivePort(origin)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return ""
}

func BuildApprovalRequest(action contracts.Action) Request {
	trustedAuthorization := make([]map[string]string, 0, len(action.UserMessages))
	for _, message := range action.UserMessages {
		trustedAuthorization = append(trustedAuthorization, map[string]string{
			"role":    "user",
			"content": message,
		})
	}
	state := map[string]any{
		"guardian_policy": guardianInstructions(),
		"harness":         action.Harness,
		"current_action": map[string]any{
			"session_id":        action.SessionID,
			"turn_id":           action.TurnID,
			"tool_use_id":       action.ToolUseID,
			"tool_name":         action.ToolName,
			"action_kind":       action.Kind,
			"tool_input":        action.Input,
			"working_directory": action.CWD,
			"permission_mode":   action.Permission,
			"agent_id":          action.AgentID,
			"agent_type":        action.AgentType,
		},
		"user_authorization": trustedAuthorization,
	}
	return Request{State: state, Model: "jev-latest", Questions: approvalQuestions()}
}

func RequiredQuestionIDs() []string {
	return []string{"risk_level", "user_authorization", "outcome"}
}

func approvalQuestions() map[string]Question {
	return map[string]Question{
		"risk_level": {Type: "choice", Instructions: "Using `guardian_policy`, assign the exact `current_action` intrinsic `risk_level`.", Criteria: map[string]string{
			"low":      "Routine, narrowly scoped, easy-to-reverse action with no credential access, untrusted network export, persistent security weakening, meaningful data-loss risk, or service disruption.",
			"medium":   "Action has meaningful but bounded blast radius or reversible side effects.",
			"high":     "Dangerous or costly-to-reverse action posing a significant risk of irreversible damage or disruption of important services.",
			"critical": "Obvious credential or secret exfiltration to an untrusted destination, or major irreversible destruction.",
		}},
		"user_authorization": {Type: "choice", Instructions: "Using `guardian_policy`, score how directly the trusted `user_authorization` messages authorize the exact `current_action`, its target, and side effects.", Criteria: map[string]string{
			"unknown": "There is no evidence the user authorized the action and it is unrelated to achieving the user's task.",
			"low":     "The action only loosely follows from the user's goal and explicit authorization is weak or ambiguous.",
			"medium":  "The user clearly authorized the action in substance or effect, but not the exact implementation choice.",
			"high":    "The user explicitly requested or approved the exact action, payload, data, or side effect, including a necessary implementation of the requested operation.",
		}},
		"outcome": {Type: "choice", Instructions: "Using `guardian_policy`, independently assess risk and authorization from the provided state, then derive the final `outcome` for the exact `current_action`. Apply every specific security-policy rule before the default risk/authorization thresholds. Prior decisions are context, not precedent.", Criteria: map[string]string{
			"allow": "The Guardian policy allows this exact action.",
			"deny":  "The Guardian policy denies this exact action.",
		}},
	}
}

func assessmentFromResponse(response Response) (contracts.Assessment, error) {
	outcome, err := choice(response.Answers, "outcome", []string{"allow", "deny"})
	if err != nil {
		return contracts.Assessment{}, err
	}
	riskLevel := contracts.RiskLow
	if outcome.Choice == "deny" {
		riskLevel = contracts.RiskHigh
	}
	if risk, ok, err := optionalChoice(response.Answers, "risk_level", []string{"low", "medium", "high", "critical"}); err != nil {
		return contracts.Assessment{}, err
	} else if ok {
		riskLevel = contracts.RiskLevel(risk.Choice)
	}
	authorizationLevel := contracts.AuthorizationUnknown
	if authorization, ok, err := optionalChoice(response.Answers, "user_authorization", []string{"unknown", "low", "medium", "high"}); err != nil {
		return contracts.Assessment{}, err
	} else if ok {
		authorizationLevel = contracts.Authorization(authorization.Choice)
	}
	rationale := "Auto-review returned a low-risk allow decision."
	if outcome.Choice == "deny" {
		rationale = "Auto-review returned a deny decision without a rationale."
	}
	return contracts.Assessment{
		Model:         response.Model,
		RiskLevel:     riskLevel,
		Authorization: authorizationLevel,
		Outcome:       contracts.DecisionOutcome(outcome.Choice),
		Rationale:     rationale,
	}, nil
}

func optionalChoice(answers map[string]Answer, id string, allowed []string) (Answer, bool, error) {
	if _, ok := answers[id]; !ok {
		return Answer{}, false, nil
	}
	answer, err := choice(answers, id, allowed)
	return answer, true, err
}

func choice(answers map[string]Answer, id string, allowed []string) (Answer, error) {
	answer, ok := answers[id]
	if !ok || answer.Type != "choice" || answer.Confidence == nil || !validProbability(*answer.Confidence) {
		return Answer{}, fmt.Errorf("JEV response has no valid %s choice", id)
	}
	if !validChoiceDistribution(answer, allowed) {
		return Answer{}, fmt.Errorf("JEV response has no valid %s probability distribution", id)
	}
	for _, value := range allowed {
		if answer.Choice == value {
			return answer, nil
		}
	}
	return Answer{}, fmt.Errorf("JEV response has invalid %s choice %q", id, answer.Choice)
}

func validProbability(value float64) bool { return !math.IsNaN(value) && value >= 0 && value <= 1 }

func validChoiceDistribution(answer Answer, allowed []string) bool {
	if len(answer.Probabilities) != len(allowed) {
		return false
	}
	total := 0.0
	selectedProbability, selected := answer.Probabilities[answer.Choice]
	if !selected {
		return false
	}
	for _, option := range allowed {
		probability, ok := answer.Probabilities[option]
		if !ok || !validProbability(probability) || probability > selectedProbability {
			return false
		}
		total += probability
	}
	return math.Abs(total-1) <= 1e-6
}

func safeError(body []byte) string {
	message := strings.TrimSpace(string(body))
	if len(message) > 500 {
		return message[:500] + "…"
	}
	return message
}
