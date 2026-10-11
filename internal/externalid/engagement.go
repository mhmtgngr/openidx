package externalid

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// I13: a vendor that requires engagements (vendor_organizations.
// require_engagement, migration v234) has its external users reach, launch and
// ask for a target only inside a running engagement that covers it: open,
// started, not yet ended, naming the user (or naming nobody, which means every
// external user of the vendor) and listing the target.
var (
	ErrNoEngagement         = errors.New("your vendor organization works through engagements, and no running engagement covers this")
	ErrWindowPastEngagement = errors.New("the access window may not end after the engagement that covers it")
	ErrEngagementTargetType = errors.New("an engagement covers applications, PAM entries and devices; this kind of access is not available to your vendor organization")
	ErrEngagementNotFound   = errors.New("engagement not found")
	ErrEngagementClosed     = errors.New("this engagement is closed")
	ErrEngagementWindow     = errors.New("an engagement ends after it starts, and in the future")
	ErrEngagementTooLong    = errors.New("an engagement may last at most 365 days")
	ErrEngagementMember     = errors.New("an engagement's members are external users of its vendor organization")
	ErrEngagementNoTargets  = errors.New("an engagement needs at least one target")
	ErrEngagementBadTarget  = errors.New("an engagement target is an application, a PAM entry or an enrolled device of this organization")
	ErrEngagementTargetShut = errors.New("this target is not open to the vendor organization's closed list")
	ErrEngagementContract   = errors.New("the engagement may not end after the vendor's contract")
)

// EngagementTargetTypes are what an engagement can cover. A request or launch
// of any other type by a user whose vendor requires engagements is refused
// (ErrEngagementTargetType): a legacy network_service grant, a role, a group
// or a vault credential has no engagement to bound it.
var EngagementTargetTypes = map[string]bool{"application": true, "pam_entry": true, "device": true}

// engagementBoundTypes are the request and launch types I13 judges. A role is
// bounded by the role ceiling (I2) and a group by external_allowed (I3), and
// both by the account's end; I13 does not add to them.
var engagementBoundTypes = map[string]bool{
	"application": true, "pam_entry": true, "device": true, "network_service": true, "vault_credential": true,
}

// MaxEngagementDays bounds an engagement's length, as MaxAccountDays bounds
// the account.
const MaxEngagementDays = MaxAccountDays

// EngagementState is what I13 says about one user and one target.
type EngagementState struct {
	// External is whether the user is an external user with a vendor.
	External bool
	// Applies is whether the user is an external user of a vendor that
	// requires engagements.
	Applies bool
	// EngagementID and EndsAt name the running engagement that covers the
	// target, the one ending last; empty when none does. They are read for
	// every external user, whatever the vendor requires: some access (remote
	// support on a device) exists only through an engagement.
	EngagementID string
	EndsAt       *time.Time
}

// Covered reports whether a running engagement covers the target.
func (s EngagementState) Covered() bool { return s.EngagementID != "" }

// EngagementFor reads I13's state for userID and the target. The engagement's
// window is judged by the database clock, as appaccess judges an
// assignment's.
func EngagementFor(ctx context.Context, q Querier, orgID, userID, targetType, targetID string) (EngagementState, error) {
	var st EngagementState
	if orgID == "" || userID == "" {
		return st, errors.New("externalid: organization and user required")
	}
	var require bool
	var engagementID *string
	err := q.QueryRow(ctx, `
		SELECT v.require_engagement,
		       e.id::text, e.ends_at
		  FROM users u
		  JOIN vendor_organizations v ON v.id = u.vendor_org_id AND v.org_id = u.org_id
		  LEFT JOIN LATERAL (
		       SELECT e.id, e.ends_at
		         FROM vendor_engagements e
		         JOIN vendor_engagement_targets t ON t.engagement_id = e.id AND t.org_id = e.org_id
		        WHERE e.vendor_org_id = v.id AND e.org_id = v.org_id
		          AND e.status = 'open' AND e.starts_at <= NOW() AND e.ends_at > NOW()
		          AND (cardinality(e.member_user_ids) = 0 OR u.id = ANY (e.member_user_ids))
		          AND t.target_type = $3 AND t.target_id = $4
		        ORDER BY e.ends_at DESC
		        LIMIT 1) e ON true
		 WHERE u.id::text = $1 AND u.org_id = $2::uuid AND u.user_type = 'external'`,
		userID, orgID, targetType, targetID).Scan(&require, &engagementID, &st.EndsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EngagementState{}, nil
	}
	if err != nil {
		return EngagementState{}, err
	}
	st.External, st.Applies = true, require
	if engagementID != nil {
		st.EngagementID = *engagementID
	} else {
		st.EndsAt = nil
	}
	return st, nil
}

// CheckEngagement is I13 at a request or a launch: nil for an internal user,
// for a vendor that does not require engagements and for a type I13 does not
// judge. until, when given, is when the requested access would end; it may
// not pass the covering engagement's end.
//
// A window past the engagement is refused rather than shortened, for
// CheckWindow's reason: the approver approves the window the request names.
func CheckEngagement(ctx context.Context, q Querier, orgID, userID, targetType, targetID string, until *time.Time) error {
	if !engagementBoundTypes[targetType] {
		return nil
	}
	st, err := EngagementFor(ctx, q, orgID, userID, targetType, targetID)
	if err != nil {
		return err
	}
	if !st.Applies {
		return nil
	}
	if !EngagementTargetTypes[targetType] {
		return ErrEngagementTargetType
	}
	if !st.Covered() {
		return ErrNoEngagement
	}
	if until != nil && st.EndsAt != nil && until.After(*st.EndsAt) {
		return ErrWindowPastEngagement
	}
	return nil
}
