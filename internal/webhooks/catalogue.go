package webhooks

// The webhook event catalogue: every event type this product can deliver, in
// the order an operator should read them.
//
// WHY THIS IS A LIST AND NOT A CONSTANT BLOCK. A subscription form offered ten
// event types. Six of them had no publisher anywhere in the tree:
//
//	user.updated       only emitted from internal/identity/handler.go, a
//	group.updated      complete second user-and-group CRUD surface that no
//	                   router has ever mounted -- so the emitters ran nowhere.
//	user.locked        no line of this codebase has ever published it.
//	login.failed       the failed-login path wrote an audit record and nothing
//	                   else; the webhook was declared and never sent.
//	role.updated       an audit event of the same name exists; the webhook did
//	                   not.
//	policy.violated    declared for a decision no gate published.
//	review.completed   declared for a campaign completion nothing announced.
//
// An operator who subscribed an integration to "somebody left this group" or
// "an account was locked out" wired it up, saw the subscription listed, saw the
// delivery log stay empty, and had no way to tell a quiet week from a control
// that does not exist. That is the same defect as a switch that displays
// without enforcing, pointed outward at the systems downstream of this one.
//
// So the catalogue is the single place an event type is named, and
// catalogue_test.go holds it against the tree in BOTH directions: an entry with
// no publisher fails, and a Publish call naming something outside the catalogue
// fails too. An event nothing can send is not offered, and an event that is
// sent is offered.
const (
	EventUserCreated = "user.created"
	EventUserUpdated = "user.updated"
	EventUserDeleted = "user.deleted"
	EventUserLocked  = "user.locked"

	EventGroupCreated       = "group.created"
	EventGroupUpdated       = "group.updated"
	EventGroupDeleted       = "group.deleted"
	EventGroupMemberAdded   = "group.member_added"
	EventGroupMemberRemoved = "group.member_removed"

	EventRoleUpdated = "role.updated"

	EventLoginSuccess  = "login.success"
	EventLoginFailed   = "login.failed"
	EventLoginHighRisk = "login.high_risk"

	EventPolicyViolated  = "policy.violated"
	EventReviewCompleted = "review.completed"

	EventRefreshTokenReuse = "oauth.refresh_token.reuse_detected"
)

// EventType is one deliverable event, with the sentence an operator reads when
// choosing what to subscribe to.
type EventType struct {
	Type        string `json:"type"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// EventCatalogue is every event type this product publishes. Adding an entry
// without a publisher fails catalogue_test.go, which is the point: the list an
// operator subscribes from cannot drift ahead of the code that sends.
var EventCatalogue = []EventType{
	{EventUserCreated, "user", "A user account was created."},
	{EventUserUpdated, "user", "A user account's profile or status was changed."},
	{EventUserDeleted, "user", "A user account was deleted."},
	{EventUserLocked, "user", "A user account was locked out after too many failed sign-ins."},

	{EventGroupCreated, "group", "A group was created."},
	{EventGroupUpdated, "group", "A group's name, description or attributes were changed."},
	{EventGroupDeleted, "group", "A group was deleted."},
	{EventGroupMemberAdded, "group", "A user was added to a group, and may have gained access with it."},
	{EventGroupMemberRemoved, "group", "A user was removed from a group, and may have lost access with it."},

	{EventRoleUpdated, "role", "A role's definition or permissions were changed."},

	{EventLoginSuccess, "authentication", "A sign-in succeeded."},
	{EventLoginFailed, "authentication", "A sign-in was refused: wrong credentials, or an account that is locked or disabled."},
	{EventLoginHighRisk, "authentication", "A sign-in succeeded but scored above the high-risk threshold."},

	{EventPolicyViolated, "authorization", "An attribute-based access policy denied a request."},
	{EventReviewCompleted, "governance", "An access-certification campaign finished."},

	{EventRefreshTokenReuse, "security", "A refresh token was presented twice: the family was revoked."},
}

// KnownEventType reports whether t is in the catalogue. Subscriptions are
// checked against this so an operator cannot subscribe to an event that will
// never arrive.
func KnownEventType(t string) bool {
	for _, e := range EventCatalogue {
		if e.Type == t {
			return true
		}
	}
	return false
}
