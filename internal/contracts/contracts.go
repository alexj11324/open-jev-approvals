package contracts

import "time"

type Harness string

const (
	HarnessCodex      Harness = "codex"
	HarnessClaudeCode Harness = "claude-code"
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
	Model         string          `json:"model"`
	RiskLevel     RiskLevel       `json:"risk_level"`
	Authorization Authorization   `json:"user_authorization"`
	Outcome       DecisionOutcome `json:"outcome"`
	Rationale     string          `json:"rationale"`
}

type DecisionOutcome string

const (
	DecisionAllow DecisionOutcome = "allow"
	DecisionDeny  DecisionOutcome = "deny"
)

type Decision struct {
	ReviewID      string          `json:"review_id,omitempty"`
	Outcome       DecisionOutcome `json:"outcome"`
	RiskLevel     RiskLevel       `json:"risk_level,omitempty"`
	Authorization Authorization   `json:"user_authorization,omitempty"`
	Rationale     string          `json:"rationale,omitempty"`
	Model         string          `json:"model,omitempty"`
	Reason        string          `json:"reason"`
	CreatedAt     time.Time       `json:"created_at"`
}
