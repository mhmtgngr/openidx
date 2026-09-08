package governance

// The approval-chain shapes the live workflow reads.
//
// These types are all that survives internal/governance/request.go, a 676-line
// second implementation of the access-request workflow -- submit, approve,
// deny, cancel, manager resolution, notification hooks and an escalation sweep
// -- that no binary could reach. Found by tools/deadservice; deleted in the
// commit that added this file, along with request_approval_chains, the table
// only it wrote.
//
// The live workflow is internal/governance/workflows.go, which reads an
// ApprovalStep out of a policy's steps JSON and expands it into
// access_request_approvals rows (createApprovalRows). ApprovalChainConfig has
// no live producer today and is kept because the step shape it wraps is the
// same one the policy stores; a chain arriving from a policy is the intended
// path if anything ever configures escalation again.

// ApprovalStepType defines the type of approval step
type ApprovalStepType string

const (
	ApprovalStepTypeSpecificUser ApprovalStepType = "specific_user" // Specific user must approve
	ApprovalStepTypeRole         ApprovalStepType = "role"          // Any user with role must approve
	ApprovalStepTypeGroup        ApprovalStepType = "group"         // Any user in group must approve
	ApprovalStepTypeManager      ApprovalStepType = "manager"       // Resource owner's manager
	ApprovalStepTypeAuto         ApprovalStepType = "auto"          // Automatic approval based on conditions
)

// ApprovalStep represents a single step in an approval chain
type ApprovalStep struct {
	Order          int                    `json:"order"`                     // Step order (1-based)
	Type           ApprovalStepType       `json:"type"`                      // Type of approval required
	ApproverID     string                 `json:"approver_id,omitempty"`     // Specific user ID (for type=specific_user)
	RoleID         string                 `json:"role_id,omitempty"`         // Role ID (for type=role)
	GroupID        string                 `json:"group_id,omitempty"`        // Group ID (for type=group)
	MinApprovals   int                    `json:"min_approvals"`             // Minimum number of approvals needed (default: 1)
	TimeoutMinutes int                    `json:"timeout_minutes,omitempty"` // Step timeout in minutes
	Conditions     map[string]interface{} `json:"conditions,omitempty"`      // Auto-approval conditions

	// Legacy fields for backward compatibility
	StepOrder    int    `json:"step_order,omitempty"`
	ApproverType string `json:"approver_type,omitempty"` // "user", "role", "manager", "security_team"
	ApproverName string `json:"approver_name,omitempty"`
	Required     bool   `json:"required,omitempty"` // true = must approve, false = optional
}

// ApprovalChainConfig defines the approval workflow configuration
type ApprovalChainConfig struct {
	Steps              []ApprovalStep `json:"steps"`
	EscalateAfterHours int            `json:"escalate_after_hours"` // Default 24h
	EscalateTo         []string       `json:"escalate_to"`          // User IDs to escalate to
}
