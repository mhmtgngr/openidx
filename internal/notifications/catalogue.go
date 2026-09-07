package notifications

// The notification type catalogue: what this product actually sends, and
// therefore what a user can meaningfully switch off.
//
// WHY THIS EXISTS. The notification preferences page offered seven switches --
// access_request, security_alert, session_revoked, review_assigned,
// group_request, password_expiry and mfa_change -- and this product has never
// sent a notification of ANY of those types. The types it does send are the
// four below, and not one of them appeared on the page. So every switch on that
// page controlled a notification that does not exist, and every notification
// that does exist had no switch. Turning "security alerts" off changed nothing;
// turning it on added nothing.
//
// It was worse than a naming mismatch. isNotificationEnabled is consulted by
// CreateNotification, and four of the six senders never went through it: they
// ran `INSERT INTO notifications` directly, as a set-based write over every
// admin, every user in an org, or every user named by a finding. A preference
// that no writer reads is not a preference, however it is spelled.
//
// So: the catalogue is the one place a type is named, catalogue_test.go holds
// it against the tree in both directions, and every writer -- including the
// set-based ones -- now carries the preference predicate in its own statement,
// which the same test checks for.
const (
	// TypeAccessGranted: a PAM entry or an application was granted to this
	// user, directly or through a group.
	TypeAccessGranted = "access_granted"
	// TypeDeviceTrust: a device is awaiting trust approval (to administrators),
	// or a request was approved or rejected (to its owner).
	TypeDeviceTrust = "device_trust"
	// TypeSecurity: something about this account needs the user's attention --
	// today, an MFA enrolment reminder raised by a posture finding or an
	// identity recommendation.
	TypeSecurity = "security"
	// TypeBroadcast: an announcement an administrator sent to an audience.
	TypeBroadcast = "broadcast"
)

// PreferenceType is one switchable notification type, in the words the person
// choosing sees.
type PreferenceType struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Channels    []string `json:"channels"`
}

// TypeCatalogue is every notification type this product sends. An entry with no
// sender fails catalogue_test.go, which is the point: the switches a user is
// offered cannot drift ahead of the code that sends.
//
// Channels are the delivery routes a preference row can exist for. in_app is
// every type; push rides alongside in_app wherever ntfy is configured (see
// maybePush), so the two are offered together rather than separately promised.
var TypeCatalogue = []PreferenceType{
	{
		Type:        TypeAccessGranted,
		Title:       "Access granted",
		Description: "You were granted an application or a privileged credential.",
		Channels:    []string{"in_app", "push"},
	},
	{
		Type:        TypeDeviceTrust,
		Title:       "Device trust",
		Description: "A device is awaiting approval, or your request was decided.",
		Channels:    []string{"in_app", "push"},
	},
	{
		Type:        TypeSecurity,
		Title:       "Security reminders",
		Description: "Something about your account needs attention, such as enrolling a second factor.",
		Channels:    []string{"in_app", "push"},
	},
	{
		Type:        TypeBroadcast,
		Title:       "Announcements",
		Description: "Messages an administrator sent to everyone, a role or a group.",
		Channels:    []string{"in_app", "push"},
	},
}

// KnownType reports whether t is in the catalogue. A preference for anything
// else is refused rather than stored: a switch that can never fire is the
// defect this catalogue was written over.
func KnownType(t string) bool {
	for _, e := range TypeCatalogue {
		if e.Type == t {
			return true
		}
	}
	return false
}
