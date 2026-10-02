// Package externalid is the one place that knows what an external (vendor)
// user may hold.
//
// An external user is a row of users with user_type 'external' (migration
// v214): a person from a supplier, sponsored by an internal user, tied to a
// vendor organization, with an expiry. The database holds the invariant that
// makes such a row exist at all (I1: vendor, expiry and, while live, sponsor).
// This package holds the ones the database cannot: what the account may be
// given.
//
//   - I2, the role ceiling: the only role an external user may hold is "user".
//     Every console tier (auditor, operator, admin, super_admin,
//     compliance_reader) and every custom role is refused, and an external
//     user can neither receive a delegation nor approve anything.
//   - I3, no default assignment: an external user may join only a group an
//     administrator marked external_allowed.
//   - I1, the application half: an expiry in the future, within the
//     install's ceiling and the vendor's contract.
//   - I12: an external user cannot invite, create groups or extend their own
//     account.
//
// WHY A LEAF PACKAGE. Roles are written by identity, admin, governance,
// provisioning and SCIM; group memberships by identity, governance and
// directory sync; approvers are chosen in governance; tiers checked in access.
// None of those should import another, and a ceiling enforced in four of five
// writers is the shape of every grant defect this repository has fixed. Each
// writer asks here, against the row, so there is one predicate and no second
// place for the next writer to forget.
package externalid

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// User types.
const (
	TypeInternal = "internal"
	TypeExternal = "external"
	TypeService  = "service"
)

// Account statuses (the external lifecycle; internal users stay "active").
const (
	StatusInvited    = "invited"
	StatusPendingMFA = "pending_mfa"
	StatusActive     = "active"
	StatusSuspended  = "suspended"
	StatusExpired    = "expired"
	StatusDisabled   = "disabled"
)

// AllowedRole is the one role an external user may hold.
const AllowedRole = "user"

// Account lifetime bounds (decision D6 of the framework): an external account
// defaults to 90 days and may never be set beyond 365 from now.
const (
	DefaultAccountDays = 90
	MaxAccountDays     = 365
	// SponsorGraceDays is how long a suspended external user may be given a
	// new sponsor and reactivated (decision D5). After that the departure is
	// final and access needs a new invitation.
	SponsorGraceDays = 7
)

// Refusals. Each is a 4xx at an API, never a 500, and names the invariant.
var (
	ErrRoleCap            = errors.New("an external user may hold only the user role")
	ErrGroupNotExternal   = errors.New("this group is not open to external users")
	ErrExternalApprover   = errors.New("an external user cannot approve or be delegated authority")
	ErrExternalActor      = errors.New("an external user cannot do this")
	ErrExpiryRequired     = errors.New("an external user needs an account expiry")
	ErrExpiryPast         = errors.New("the account expiry must be in the future")
	ErrExpiryTooLong      = fmt.Errorf("the account expiry may be at most %d days away", MaxAccountDays)
	ErrExpiryContract     = errors.New("the account expiry may not pass the vendor's contract end")
	ErrVendorNotActive    = errors.New("the vendor organization is not active")
	ErrSponsorInvalid     = errors.New("the sponsor must be an enabled internal user of this organization")
	ErrTypeImmutable      = errors.New("a user type is fixed when the account is created")
	ErrGroupHasExternal   = errors.New("remove the external members before closing this group to external users")
	ErrIdentityIncomplete = errors.New("an external user needs a vendor organization, a sponsor and an account expiry")
	ErrAccountNotLive     = errors.New("this external account is suspended, expired or disabled and cannot be enabled")
)

// FromDB maps a refusal raised by the database guard (migration v214's
// external_identity_guard trigger and the users CHECK) to this package's
// error, or returns nil when err is not one. The writers that never call this
// package still meet the guard; this is how the ones that answer an API turn
// it into a 403 with a code rather than a 500.
func FromDB(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		return nil
	}
	switch pgErr.ConstraintName {
	case "external_role_cap":
		return ErrRoleCap
	case "external_group_not_allowed":
		return ErrGroupNotExternal
	case "external_cannot_approve":
		return ErrExternalApprover
	case "user_type_immutable":
		return ErrTypeImmutable
	case "external_group_has_members":
		return ErrGroupHasExternal
	case "users_external_identity_check", "user_invitations_external_check":
		return ErrIdentityIncomplete
	case "users_external_enabled_check":
		return ErrAccountNotLive
	}
	return nil
}

// Refusal returns the refusal err carries, from the database guard or from
// this package, or nil when err is something else.
func Refusal(err error) error {
	if err == nil {
		return nil
	}
	if r := FromDB(err); r != nil {
		return r
	}
	if IsRefusal(err) {
		return err
	}
	return nil
}

// Querier is satisfied by *pgxpool.Pool, database.ScopedPool and pgx.Tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Account is the external-identity half of a users row.
type Account struct {
	UserID        string
	Type          string
	Status        string
	VendorOrgID   string
	SponsorUserID string
	ExpiresAt     *time.Time
}

// External reports whether the account is an external user.
func (a Account) External() bool { return a.Type == TypeExternal }

// Load reads the account. A missing user is pgx.ErrNoRows, for the caller to
// answer as it answers a missing user today. orgID scopes the read; an empty
// orgID is refused rather than read across tenants.
func Load(ctx context.Context, q Querier, orgID, userID string) (Account, error) {
	if orgID == "" {
		return Account{}, errors.New("externalid: organization required")
	}
	a := Account{UserID: userID}
	err := q.QueryRow(ctx, `
		SELECT user_type, account_status, COALESCE(vendor_org_id::text, ''),
		       COALESCE(sponsor_user_id::text, ''), account_expires_at
		  FROM users WHERE id = $1::uuid AND org_id = $2::uuid`, userID, orgID).
		Scan(&a.Type, &a.Status, &a.VendorOrgID, &a.SponsorUserID, &a.ExpiresAt)
	return a, err
}

// IsExternal is Load for the callers that need only the type. A missing user
// is not external (the caller's own lookup reports it missing).
func IsExternal(ctx context.Context, q Querier, orgID, userID string) (bool, error) {
	if orgID == "" {
		return false, errors.New("externalid: organization required")
	}
	var userType string
	err := q.QueryRow(ctx, `SELECT user_type FROM users WHERE id = $1::uuid AND org_id = $2::uuid`, userID, orgID).Scan(&userType)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return userType == TypeExternal, nil
}

// RoleAllowed is the role ceiling as a pure predicate: for an external user,
// only AllowedRole. Role names compare case-insensitively, as the role tables
// store them as typed.
func RoleAllowed(userType, roleName string) bool {
	if userType != TypeExternal {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(roleName), AllowedRole)
}

// CheckRoleByName refuses a role above the ceiling for userID.
func CheckRoleByName(ctx context.Context, q Querier, orgID, userID, roleName string) error {
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil {
		return err
	}
	if ext && !RoleAllowed(TypeExternal, roleName) {
		return ErrRoleCap
	}
	return nil
}

// CheckRoleByID is CheckRoleByName for a writer that holds the role's id. A
// role id that does not resolve in orgID is left to the caller's own lookup.
func CheckRoleByID(ctx context.Context, q Querier, orgID, userID, roleID string) error {
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil || !ext {
		return err
	}
	var name string
	err = q.QueryRow(ctx, `SELECT name FROM roles WHERE id = $1::uuid AND org_id = $2::uuid`, roleID, orgID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !RoleAllowed(TypeExternal, name) {
		return ErrRoleCap
	}
	return nil
}

// CheckGroup refuses a group not marked external_allowed for an external
// userID. A group id that does not resolve in orgID is left to the caller.
func CheckGroup(ctx context.Context, q Querier, orgID, userID, groupID string) error {
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil || !ext {
		return err
	}
	var allowed bool
	err = q.QueryRow(ctx, `SELECT external_allowed FROM groups WHERE id = $1::uuid AND org_id = $2::uuid`, groupID, orgID).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowed {
		return ErrGroupNotExternal
	}
	return nil
}

// CheckActor refuses an action an external user may not take (I12: invite,
// create a group, extend an account, delegate; I2: approve). A caller that is
// not a user of orgID passes: the route's own authentication answers for it.
func CheckActor(ctx context.Context, q Querier, orgID, userID string) error {
	if userID == "" {
		return nil
	}
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil {
		return err
	}
	if ext {
		return ErrExternalActor
	}
	return nil
}

// ValidateExpiry is the application half of I1: an expiry in the future, at
// most MaxAccountDays away, and not past the vendor's contract end.
func ValidateExpiry(now time.Time, expires *time.Time, contractEnd *time.Time) error {
	if expires == nil {
		return ErrExpiryRequired
	}
	if !expires.After(now) {
		return ErrExpiryPast
	}
	if expires.After(now.AddDate(0, 0, MaxAccountDays)) {
		return ErrExpiryTooLong
	}
	if contractEnd != nil && expires.After(endOfDay(*contractEnd)) {
		return ErrExpiryContract
	}
	return nil
}

// endOfDay is the last instant of a contract's end date: a contract ending on
// the 30th covers the 30th.
func endOfDay(d time.Time) time.Time {
	y, m, day := d.UTC().Date()
	return time.Date(y, m, day, 23, 59, 59, 0, time.UTC)
}

// Vendor is what a writer needs of a vendor organization.
type Vendor struct {
	ID                   string
	Status               string
	ContractEnd          *time.Time
	AllowedEmailDomains  []string
	DefaultExpiryDays    int
	DefaultSponsorUserID string
}

// LoadVendor reads a vendor organization of orgID.
func LoadVendor(ctx context.Context, q Querier, orgID, vendorID string) (Vendor, error) {
	v := Vendor{ID: vendorID}
	err := q.QueryRow(ctx, `
		SELECT status, contract_end, allowed_email_domains, default_expiry_days,
		       COALESCE(default_sponsor_user_id::text, '')
		  FROM vendor_organizations WHERE id = $1::uuid AND org_id = $2::uuid`, vendorID, orgID).
		Scan(&v.Status, &v.ContractEnd, &v.AllowedEmailDomains, &v.DefaultExpiryDays, &v.DefaultSponsorUserID)
	return v, err
}

// EmailAllowed reports whether email's domain is on the vendor's list. An
// empty list allows any domain: the vendor record did not restrict it.
func (v Vendor) EmailAllowed(email string) bool {
	if len(v.AllowedEmailDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, d := range v.AllowedEmailDomains {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}

// CheckSponsor requires sponsorID to be an enabled, active internal user of
// orgID: an external user cannot sponsor (I2), and a disabled one cannot
// answer for anybody.
func CheckSponsor(ctx context.Context, q Querier, orgID, sponsorID string) error {
	if sponsorID == "" {
		return ErrSponsorInvalid
	}
	var userType, status string
	var enabled bool
	err := q.QueryRow(ctx, `
		SELECT user_type, account_status, COALESCE(enabled, false)
		  FROM users WHERE id = $1::uuid AND org_id = $2::uuid`, sponsorID, orgID).Scan(&userType, &status, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSponsorInvalid
	}
	if err != nil {
		return err
	}
	if userType != TypeInternal || status != StatusActive || !enabled {
		return ErrSponsorInvalid
	}
	return nil
}

// IsRefusal reports whether err is one of this package's refusals, which a
// handler answers with a 4xx rather than a 500.
func IsRefusal(err error) bool {
	for _, r := range []error{ErrRoleCap, ErrGroupNotExternal, ErrExternalApprover, ErrExternalActor,
		ErrExpiryRequired, ErrExpiryPast, ErrExpiryTooLong, ErrExpiryContract, ErrVendorNotActive, ErrSponsorInvalid,
		ErrTypeImmutable, ErrGroupHasExternal, ErrIdentityIncomplete, ErrAccountNotLive} {
		if errors.Is(err, r) {
			return true
		}
	}
	return false
}

// Code is the stable machine-readable code for a refusal.
func Code(err error) string {
	switch {
	case errors.Is(err, ErrRoleCap):
		return "external_role_cap"
	case errors.Is(err, ErrGroupNotExternal):
		return "external_group_not_allowed"
	case errors.Is(err, ErrExternalApprover):
		return "external_cannot_approve"
	case errors.Is(err, ErrExternalActor):
		return "external_not_permitted"
	case errors.Is(err, ErrExpiryRequired), errors.Is(err, ErrExpiryPast),
		errors.Is(err, ErrExpiryTooLong), errors.Is(err, ErrExpiryContract):
		return "external_expiry_invalid"
	case errors.Is(err, ErrVendorNotActive):
		return "vendor_not_active"
	case errors.Is(err, ErrSponsorInvalid):
		return "external_sponsor_invalid"
	case errors.Is(err, ErrTypeImmutable):
		return "user_type_immutable"
	case errors.Is(err, ErrGroupHasExternal):
		return "external_group_has_members"
	case errors.Is(err, ErrIdentityIncomplete):
		return "external_identity_incomplete"
	case errors.Is(err, ErrAccountNotLive):
		return "external_account_not_live"
	}
	return ""
}
