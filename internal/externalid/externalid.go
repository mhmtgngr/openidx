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
//   - I5 and I7, the PAM half: an external user is never handed a credential
//     (reveal, break-glass, an SSH certificate, cloud keys), and their session
//     is recorded, approved, on the overlay and hardened whatever the entry
//     says. The refusals and the session ceiling are here; the access service
//     applies them, since only it brokers sessions.
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

// MaxPamSession is the longest an external user's PAM session runs (I7): a
// working day. The access service's lifecycle sweep ends a session older than
// this, whatever grant it rides. It is a constant, as the account bounds above
// are, until the organization policy that section 7 of the framework describes
// exists to hold it.
const MaxPamSession = 8 * time.Hour

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
	ErrNotActivated       = errors.New("this external account has no second factor enrolled or is not active; nothing it holds takes effect until it is")
	ErrFactorNotAllowed   = errors.New("external users enroll an authenticator app, a passkey or a push device, not SMS, email or phone call")
	ErrEmailDomain        = errors.New("the email address is not in one of the vendor organization's allowed domains")
	ErrWindowRequired     = errors.New("an external user's access needs an end: give the request a duration")
	ErrWindowPastAccount  = errors.New("the access window may not end after the external user's account does")

	// I5 and I7 at the PAM paths.
	ErrRevealForbidden        = errors.New("an external user is never shown a credential: their session has it injected on the broker")
	ErrSSHCAForbidden         = errors.New("an external user is not issued SSH certificates: they connect through the recorded broker")
	ErrCloudJITForbidden      = errors.New("an external user is not issued cloud credentials: they connect through the recorded broker")
	ErrRecordingUnavailable   = errors.New("an external user's session is recorded, and this launch cannot record it")
	ErrBrokerIdentityRequired = errors.New("an external user's session needs its own broker identity: the shared broker token can open every connection on the broker")
)

// CheckWindow is invariant I8 at a request: an external user's access has an
// end, and it is not after the account's. until is when the requested access
// would end (nil for permanent). Nil for a user who is not external.
//
// A window past the account is refused, not shortened, for the reason the
// request ceiling is refused rather than shortened: an approver reads and
// approves the window the request names, and a grant that silently ends
// earlier is the same defect as one that ends later.
func CheckWindow(ctx context.Context, q Querier, orgID, userID string, until *time.Time) error {
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil || !ext {
		return err
	}
	if until == nil {
		return ErrWindowRequired
	}
	a, err := Load(ctx, q, orgID, userID)
	if err != nil {
		return err
	}
	if a.ExpiresAt != nil && until.After(*a.ExpiresAt) {
		return ErrWindowPastAccount
	}
	return nil
}

// StrongFactors are the second factors an external user may enroll and sign
// in with (decision D4): an authenticator app (TOTP), a passkey or security
// key (WebAuthn), and a push device. SMS, email and phone-call codes are not
// offered to an external user: they ride on accounts a supplier's helpdesk
// can be talked into moving, which is the attack this account type exists
// to resist.
var StrongFactors = []string{"totp", "webauthn", "push"}

// FactorAllowed reports whether userType may enroll or be challenged with
// method. Every method is allowed to a non-external user.
func FactorAllowed(userType, method string) bool {
	if userType != TypeExternal {
		return true
	}
	for _, f := range StrongFactors {
		if f == method {
			return true
		}
	}
	return false
}

// HasStrongFactor reports whether userID has a StrongFactors factor enrolled
// in orgID.
func HasStrongFactor(ctx context.Context, q Querier, orgID, userID string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = $1::uuid AND org_id = $2::uuid AND enabled)
		    OR EXISTS (SELECT 1 FROM mfa_webauthn WHERE user_id = $1::uuid AND org_id = $2::uuid)
		    OR EXISTS (SELECT 1 FROM mfa_push_devices WHERE user_id = $1::uuid AND org_id = $2::uuid AND COALESCE(enabled, true))`,
		userID, orgID).Scan(&ok)
	return ok, err
}

// CheckEffective is invariant I4: nothing an external user holds takes
// effect until the account is active and has a strong second factor. A
// request may be filed and approved before that; fulfilling it, and
// launching a privileged session, wait. Nil for a user who is not external.
//
// It is also I8 between the account's end and the sweep that records it: an
// account past its expiry is refused here while it still reads active.
func CheckEffective(ctx context.Context, q Querier, orgID, userID string) error {
	ext, err := IsExternal(ctx, q, orgID, userID)
	if err != nil || !ext {
		return err
	}
	a, err := Load(ctx, q, orgID, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !a.External() {
		return nil
	}
	if a.Status != StatusActive || (a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now())) {
		return ErrNotActivated
	}
	ok, err := HasStrongFactor(ctx, q, orgID, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotActivated
	}
	return nil
}

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
		ErrTypeImmutable, ErrGroupHasExternal, ErrIdentityIncomplete, ErrAccountNotLive, ErrNotActivated, ErrFactorNotAllowed, ErrEmailDomain,
		ErrWindowRequired, ErrWindowPastAccount, ErrRevealForbidden, ErrSSHCAForbidden, ErrCloudJITForbidden,
		ErrRecordingUnavailable, ErrBrokerIdentityRequired} {
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
	case errors.Is(err, ErrNotActivated):
		return "external_not_activated"
	case errors.Is(err, ErrFactorNotAllowed):
		return "external_factor_not_allowed"
	case errors.Is(err, ErrEmailDomain):
		return "external_email_domain"
	case errors.Is(err, ErrWindowRequired), errors.Is(err, ErrWindowPastAccount):
		return "external_window_invalid"
	case errors.Is(err, ErrRevealForbidden):
		return "external_reveal_forbidden"
	case errors.Is(err, ErrSSHCAForbidden):
		return "external_ssh_ca_forbidden"
	case errors.Is(err, ErrCloudJITForbidden):
		return "external_cloud_jit_forbidden"
	case errors.Is(err, ErrRecordingUnavailable):
		return "external_recording_unavailable"
	case errors.Is(err, ErrBrokerIdentityRequired):
		return "external_broker_identity_required"
	}
	return ""
}
