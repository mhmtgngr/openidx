package abac

// THE VOCABULARY A POLICY CAN BE WRITTEN IN.
//
// An ABAC policy is a set of conditions over subject attributes, scoped to a
// resource type. Both halves are closed sets, and a policy that names something
// outside them cannot match: EvaluateCondition returns false for an attribute
// the subject does not carry, and Gate's query selects only
// `resource_type IN ($1, '*')` for the type an enforcement point actually asks
// about. Neither produces an error, a log line or a denial -- the policy simply
// never applies.
//
// That is worth naming because the ABAC page offered seven attributes and four
// resource types, and the sets overlapped the real ones by one attribute and
// two types. An administrator could pick "risk_score" or "ip_range" from a
// dropdown, save a policy, see it listed as enabled, and have it decide nothing
// for the life of the install. In enforce mode a DENY written that way permits
// exactly what it was written to stop, because Gate's composition is
// deny-wins-else-allow-else-allow.
//
// So the sets live here, next to the code that honours them, and
// internal/abac/vocabulary_test.go checks three things against them: that
// SubjectAttributes really produces these keys and no others, that the console's
// dropdowns offer nothing outside them, and that every resource type below is
// one some enforcement point asks about.

// SubjectAttributeKeys is every attribute SubjectAttributes puts on the map, and
// therefore every attribute a condition can be written against. See that
// function for where each comes from and why internal/identity's
// `Attributes map[string]string` is not among them.
var SubjectAttributeKeys = []string{
	"user_id",
	"username",
	"email",
	"department",
	"job_title",
	"employment_status",
	"enabled",
	"roles",
	"groups",
}

// The resource types an enforcement point asks about. Both gates authorize
// access to an APPLICATION -- internal/oauth at token issuance and
// internal/access at the proxy, each passing the application id as the resource
// id -- so "application" is the only concrete type any policy is ever evaluated
// for, and "*" is the wildcard Gate's query pairs with it.
//
// A policy scoped to anything else is never selected. The console offered
// "route" and "service"; no code has ever asked about either.
const (
	ResourceTypeApplication = "application"
	ResourceTypeAny         = "*"
)

// EvaluatedResourceTypes is what a policy may be scoped to. Adding to it means
// adding an enforcement point that asks about the new type -- the constant on
// its own authorizes nothing.
var EvaluatedResourceTypes = []string{ResourceTypeApplication, ResourceTypeAny}
