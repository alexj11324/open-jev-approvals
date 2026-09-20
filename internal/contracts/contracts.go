package contracts

import "time"

type Harness string

const (
	HarnessCodex      Harness = "codex"
	HarnessClaudeCode Harness = "claude-code"
)

type HookEvent string

const (
	HookPreToolUse        HookEvent = "PreToolUse"
	HookPermissionRequest HookEvent = "PermissionRequest"
)

type ActionKind string

const (
	ActionShell        ActionKind = "shell_execution"
	ActionFileMutation ActionKind = "file_mutation"
	ActionFileRead     ActionKind = "file_read"
	ActionMCP          ActionKind = "mcp_invocation"
	ActionNetwork      ActionKind = "network_access"
	ActionOther        ActionKind = "other_tool"
)

type Action struct {
	Harness      Harness        `json:"harness"`
	HookEvent    HookEvent      `json:"hook_event_name"`
	SessionID    string         `json:"session_id"`
	TurnID       string         `json:"turn_id,omitempty"`
	ToolUseID    string         `json:"tool_use_id,omitempty"`
	AgentID      string         `json:"agent_id,omitempty"`
	AgentType    string         `json:"agent_type,omitempty"`
	CWD          string         `json:"cwd,omitempty"`
	Permission   string         `json:"permission_mode,omitempty"`
	ToolName     string         `json:"tool_name"`
	Kind         ActionKind     `json:"kind"`
	Input        map[string]any `json:"input"`
	UserMessages []string       `json:"user_messages,omitempty"`
	Facts        map[string]any `json:"facts,omitempty"`
	Hints        map[string]any `json:"lexical_hints,omitempty"`

	// Scope is the namespaced authorization bucket the action belongs to:
	// installation_id + harness + session_id + agent_id. Empty means the
	// caller could not establish a scope and the review is incomplete.
	Scope string `json:"scope,omitempty"`
	// AuthorizationVersion snapshots the authorization stream when
	// UserMessages were loaded. The review service re-reads the version
	// after assessing so an ALLOW never ships against stale authorization.
	AuthorizationVersion int64 `json:"authorization_version,omitempty"`
}

type RiskLevel string

const (
	RiskLow        RiskLevel = "low"
	RiskMedium     RiskLevel = "medium"
	RiskHigh       RiskLevel = "high"
	RiskCritical   RiskLevel = "critical"
	RiskUnresolved RiskLevel = "unresolved"
)

type Authorization string

const (
	AuthorizationUnknown Authorization = "unknown"
	AuthorizationLow     Authorization = "low"
	AuthorizationMedium  Authorization = "medium"
	AuthorizationHigh    Authorization = "high"
)

type Assessment struct {
	Model             string             `json:"model"`
	RiskLevel         RiskLevel          `json:"risk_level"`
	RiskConfidence    float64            `json:"risk_confidence"`
	Authorization     Authorization      `json:"authorization"`
	AuthorizationConf float64            `json:"authorization_confidence"`
	NarrowlyScoped    float64            `json:"narrowly_scoped"`
	Noul              map[string]float64 `json:"noul"`
}

type DecisionOutcome string

const (
	DecisionAllow DecisionOutcome = "allow"
	DecisionDeny  DecisionOutcome = "deny"
)

type Decision struct {
	ReviewID      string          `json:"review_id,omitempty"`
	Outcome       DecisionOutcome `json:"outcome"`
	Reason        string          `json:"reason"`
	PolicyVersion string          `json:"policy_version,omitempty"`
	// Incomplete marks a decision that could not observe required context
	// (missing authorization scope, unreadable transcript, malformed event).
	// Incomplete decisions are never valid evidence of a trusted review.
	Incomplete bool      `json:"incomplete,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
