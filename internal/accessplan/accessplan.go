// Package accessplan turns "open application X to group Y" into a plan an
// administrator can read before anything changes: whether it can be done,
// what it does, what is worth knowing first, and nothing else.
//
// It is pure. The caller gathers the facts and carries the plan out; the rules
// here decide, and no model does. The plan names every step, and each step is
// idempotent and has an undo, so approving one is never a leap.
package accessplan

// Resource kinds, as the applications table has them.
const KindPrivileged = "privileged"

// Fact thresholds.
const (
	// WideGroupShare is the share of the organization's people, in percent, a
	// group reaches before opening something to it counts as opening it widely.
	WideGroupShare = 50
	// WideGroupMinOrg is the smallest organization for which that share means
	// anything: in a team of six, half the people is three.
	WideGroupMinOrg = 10
)

// Facts is what the caller found out.
type Facts struct {
	ResourceFound   bool
	ResourceID      string
	ResourceName    string
	ResourceKind    string
	ResourceEnabled bool

	GroupFound   bool
	GroupID      string
	GroupName    string
	GroupMembers int

	// OrgUsers is how many enabled people the organization has.
	OrgUsers int
	// AlreadyGranted is whether the group is already assigned the resource.
	AlreadyGranted bool
}

// Status is the headline.
type Status string

const (
	// StatusReady means the plan can be approved.
	StatusReady Status = "ready"
	// StatusNoop means there is nothing to do: the group already has access.
	StatusNoop Status = "noop"
	// StatusBlocked means it cannot be done as asked.
	StatusBlocked Status = "blocked"
)

// Codes. The console words each; a test checks that it does.
const (
	BlockerNoResource = "RESOURCE_NOT_FOUND"
	BlockerNoGroup    = "GROUP_NOT_FOUND"
	BlockerDisabled   = "RESOURCE_DISABLED"

	NoteAlready = "ALREADY_GRANTED"

	RiskEmptyGroup = "EMPTY_GROUP"
	RiskWideGroup  = "WIDE_GROUP"
	RiskPrivileged = "PRIVILEGED_RESOURCE"
)

// AllCodes lists every code the rules can give.
var AllCodes = []string{BlockerNoResource, BlockerNoGroup, BlockerDisabled, NoteAlready,
	RiskEmptyGroup, RiskWideGroup, RiskPrivileged}

// ActionGrantGroup is the one step there is today: assign the group to the
// resource. Its undo is deleting that assignment, and only that.
const ActionGrantGroup = "grant_group_access"

// Step is one thing the plan does.
type Step struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	GroupID    string `json:"group_id"`
}

// Plan is what the rules make of the facts.
type Plan struct {
	Status   Status   `json:"status"`
	Blockers []string `json:"blockers"`
	// Notes are facts that are neither a block nor a risk.
	Notes []string `json:"notes"`
	// Risks are worth reading before approving; none stops the plan.
	Risks []string `json:"risks"`
	Steps []Step   `json:"steps"`
}

// PlanOpenAccess makes the plan for opening a resource to a group.
func PlanOpenAccess(f Facts) Plan {
	p := Plan{Blockers: []string{}, Notes: []string{}, Risks: []string{}, Steps: []Step{}}
	if !f.ResourceFound {
		p.Blockers = append(p.Blockers, BlockerNoResource)
	} else if !f.ResourceEnabled {
		p.Blockers = append(p.Blockers, BlockerDisabled)
	}
	if !f.GroupFound {
		p.Blockers = append(p.Blockers, BlockerNoGroup)
	}
	if len(p.Blockers) > 0 {
		p.Status = StatusBlocked
		return p
	}
	if f.AlreadyGranted {
		p.Status = StatusNoop
		p.Notes = append(p.Notes, NoteAlready)
		return p
	}
	if f.GroupMembers == 0 {
		p.Risks = append(p.Risks, RiskEmptyGroup)
	}
	if f.OrgUsers >= WideGroupMinOrg && f.GroupMembers*100 >= f.OrgUsers*WideGroupShare {
		p.Risks = append(p.Risks, RiskWideGroup)
	}
	if f.ResourceKind == KindPrivileged {
		p.Risks = append(p.Risks, RiskPrivileged)
	}
	p.Status = StatusReady
	p.Steps = append(p.Steps, Step{Action: ActionGrantGroup, ResourceID: f.ResourceID, GroupID: f.GroupID})
	return p
}
