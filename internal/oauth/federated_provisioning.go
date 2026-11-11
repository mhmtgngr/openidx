package oauth

// PARTNER ORGANIZATIONS SIGNING IN THROUGH THEIR OWN IDENTITY PROVIDER.
//
// A person the provider vouches for whom OpenIDX does not know is
// provisioned when the provider's jit_policy says so (sso_federation.go,
// resolveFederatedUser step 3). The population decides what is created:
// an internal user, or an external (vendor) user of the partner
// organization the person belongs to. An external user carries a vendor, a
// sponsor and an expiry (invariant I1), and those come from the vendor
// record (migration 247): its default sponsor, its default expiry capped by
// the contract end and 365 days, and its default groups, of which only
// those open to external users are joined. The account starts in
// pending_mfa: an external user always proves an OpenIDX factor, and the
// sign-in hands it to the second-factor step (externalSignInNeedsMore).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/identity"
)

// federatedVendor is what provisioning needs of a vendor organization.
type federatedVendor struct {
	externalid.Vendor
	OnboardingMode  string
	SlidingExpiry   bool
	DefaultGroupIDs []string
	// Via says which rule picked the vendor: idp, domain or jit_policy.
	Via string
}

// errPartnerNotRegistered: no vendor organization claims the person.
var errPartnerNotRegistered = errors.New("no partner organization is registered for this person")

const federatedVendorSelect = `
	SELECT id::text, status, contract_end, allowed_email_domains, default_expiry_days,
	       COALESCE(default_sponsor_user_id::text, ''), onboarding_mode, sliding_expiry,
	       COALESCE(default_group_ids::text[], '{}')
	  FROM vendor_organizations`

func scanFederatedVendor(row pgx.Row) (*federatedVendor, error) {
	var v federatedVendor
	if err := row.Scan(&v.ID, &v.Status, &v.ContractEnd, &v.AllowedEmailDomains, &v.DefaultExpiryDays,
		&v.DefaultSponsorUserID, &v.OnboardingMode, &v.SlidingExpiry, &v.DefaultGroupIDs); err != nil {
		return nil, err
	}
	return &v, nil
}

// emailDomain is the lower-cased domain of email, or "".
func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// resolveVendorForClaims picks the vendor organization a federated external
// person belongs to, in order: (1) a vendor bound to this identity provider
// whose allowed domains admit the email (an empty list admits any), (2) a
// vendor that onboards by federation and lists the email's domain, (3) the
// IdP's jit_policy.vendor_org_id. A vendor that only takes invitations is
// never picked by (1) or (2). Closed vendors are not considered; a
// suspended one is returned, and the caller refuses it. idpID may be "" (a
// social login), which skips (1).
func (s *Service) resolveVendorForClaims(ctx context.Context, orgID, idpID string, policy identity.JITPolicy, email string) (*federatedVendor, error) {
	if idpID != "" {
		rows, err := s.db.Pool.Query(ctx, federatedVendorSelect+`
			 WHERE org_id = $1::uuid AND idp_id = $2::uuid AND status <> 'closed' AND onboarding_mode <> 'invitation'
			 ORDER BY created_at, id`, orgID, idpID)
		if err != nil {
			return nil, err
		}
		var picked *federatedVendor
		for rows.Next() {
			v, serr := scanFederatedVendor(rows)
			if serr != nil {
				rows.Close()
				return nil, serr
			}
			if picked == nil && v.EmailAllowed(email) {
				picked = v
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if picked != nil {
			picked.Via = "idp"
			return picked, nil
		}
	}
	if d := emailDomain(email); d != "" {
		v, err := scanFederatedVendor(s.db.Pool.QueryRow(ctx, federatedVendorSelect+`
			 WHERE org_id = $1::uuid AND status <> 'closed' AND onboarding_mode <> 'invitation'
			   AND EXISTS (SELECT 1 FROM unnest(allowed_email_domains) d WHERE lower(trim(d)) = $2)
			 ORDER BY created_at, id LIMIT 1`, orgID, d))
		if err == nil {
			v.Via = "domain"
			return v, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if policy.VendorOrgID != "" {
		v, err := scanFederatedVendor(s.db.Pool.QueryRow(ctx, federatedVendorSelect+`
			 WHERE org_id = $1::uuid AND id = $2::uuid AND status <> 'closed'`, orgID, policy.VendorOrgID))
		if err == nil {
			v.Via = "jit_policy"
			return v, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	return nil, errPartnerNotRegistered
}

// claimMatches reports whether the raw claim equals one of values. Numbers,
// booleans and lists are compared through their string form, so acct: 1
// and acct: "1" both match "1".
func claimMatches(raw map[string]interface{}, claim string, values []string) bool {
	v, ok := raw[claim]
	if !ok || v == nil {
		return false
	}
	var got []string
	switch t := v.(type) {
	case []interface{}:
		for _, e := range t {
			got = append(got, fmt.Sprint(e))
		}
	case []string:
		got = t
	case float64:
		got = []string{strings.TrimSuffix(fmt.Sprintf("%g", t), ".0")}
	default:
		got = []string{fmt.Sprint(t)}
	}
	for _, g := range got {
		for _, want := range values {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(want)) {
				return true
			}
		}
	}
	return false
}

// federatedPopulation decides whether a provisioned person is internal or
// external: the first population rule whose claim matches wins; otherwise an
// Entra B2B guest (#EXT# in preferred_username or upn) is external whatever
// the default says; otherwise the policy's default population.
func federatedPopulation(policy identity.JITPolicy, raw map[string]interface{}, preferredUsername, upn string) string {
	for _, r := range policy.PopulationRules {
		if r.Claim != "" && claimMatches(raw, r.Claim, r.Values) {
			if r.Population == identity.PopulationExternal {
				return identity.PopulationExternal
			}
			return identity.PopulationInternal
		}
	}
	if strings.Contains(strings.ToUpper(preferredUsername), "#EXT#") || strings.Contains(strings.ToUpper(upn), "#EXT#") {
		return identity.PopulationExternal
	}
	if policy.Population == identity.PopulationExternal {
		return identity.PopulationExternal
	}
	return identity.PopulationInternal
}

// federatedPerson is what provisioning knows of the person.
type federatedPerson struct {
	Email, Username, FirstName, LastName string
	EmailVerified                        bool
	// IdPID is the identity provider ("" for a social login); ExternalID is
	// the person's stable id there.
	IdPID, ExternalID string
}

// provisionFederatedExternal creates the external user of v for p. It
// returns the new user's id, or the refusal: a vendor that is not active
// (externalid.ErrVendorNotActive), an email outside its domains
// (ErrEmailDomain), a default sponsor who cannot sponsor (ErrSponsorInvalid)
// or an expiry the contract end does not allow (ErrExpiryContract).
func (s *Service) provisionFederatedExternal(ctx context.Context, orgID string, v *federatedVendor, p federatedPerson) (string, error) {
	if v.Status != "active" {
		return "", externalid.ErrVendorNotActive
	}
	if p.Email == "" || !v.EmailAllowed(p.Email) {
		return "", externalid.ErrEmailDomain
	}
	if err := externalid.CheckSponsor(ctx, s.db.Pool, orgID, v.DefaultSponsorUserID); err != nil {
		return "", err
	}
	now := time.Now()
	expires := externalid.ExpiryForVendor(now, v.DefaultExpiryDays, v.ContractEnd)
	if err := externalid.ValidateExpiry(now, &expires, v.ContractEnd); err != nil {
		return "", err
	}
	username := p.Username
	if username == "" {
		username = p.Email
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var uid string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled, email_verified,
		                   user_type, vendor_org_id, sponsor_user_id, account_expires_at, account_status,
		                   status_changed_at, source, idp_id, external_user_id)
		VALUES ($1::uuid, $2, $3, NULLIF($4, ''), NULLIF($5, ''), true, $6,
		        'external', $7::uuid, $8::uuid, $9, 'pending_mfa', NOW(), 'federated', NULLIF($10, '')::uuid, NULLIF($11, ''))
		RETURNING id::text`,
		orgID, username, p.Email, p.FirstName, p.LastName, p.EmailVerified,
		v.ID, v.DefaultSponsorUserID, expires, p.IdPID, p.ExternalID).Scan(&uid); err != nil {
		return "", err
	}
	// Default groups, only those open to external users (I3).
	tag, err := tx.Exec(ctx, `
		INSERT INTO group_memberships (user_id, group_id, org_id)
		SELECT $1::uuid, g.id, g.org_id FROM groups g
		 WHERE g.org_id = $2::uuid AND g.id = ANY($3::uuid[]) AND g.external_allowed
		ON CONFLICT DO NOTHING`, uid, orgID, v.DefaultGroupIDs)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	if skipped := int64(len(v.DefaultGroupIDs)) - tag.RowsAffected(); skipped > 0 {
		s.logger.Info("federated provisioning: default groups not open to external users were skipped",
			zap.String("vendor_org_id", v.ID), zap.Int64("skipped", skipped))
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.provisioned", "success", uid, "", uid, "user",
		map[string]interface{}{"vendor_org_id": v.ID, "via": v.Via, "source": "federated", "idp_id": p.IdPID,
			"sponsor_user_id": v.DefaultSponsorUserID, "account_expires_at": expires, "groups_joined": tag.RowsAffected()})
	return uid, nil
}

// slideFederatedExpiry moves a live external account's expiry forward on a
// successful federated sign-in when its vendor has sliding_expiry: to
// GREATEST(current, LEAST(now + default_expiry_days, end of contract day)),
// never beyond 365 days. Nothing happens for an internal user, a vendor
// without sliding expiry or one that is not active.
func (s *Service) slideFederatedExpiry(ctx context.Context, orgID, userID string) {
	var vendorID string
	var before, after time.Time
	err := s.db.Pool.QueryRow(ctx, `
		WITH v AS (
			SELECT vo.id, LEAST(NOW() + make_interval(days => LEAST(vo.default_expiry_days, $3)),
			                    COALESCE(vo.contract_end::timestamp AT TIME ZONE 'UTC' + interval '1 day' - interval '1 second', 'infinity'::timestamptz)) AS target
			  FROM vendor_organizations vo JOIN users u ON u.vendor_org_id = vo.id AND u.org_id = vo.org_id
			 WHERE u.id = $1::uuid AND u.org_id = $2::uuid AND vo.sliding_expiry AND vo.status = 'active'
		), old AS (
			SELECT account_expires_at FROM users WHERE id = $1::uuid AND org_id = $2::uuid
		)
		UPDATE users u SET account_expires_at = v.target, updated_at = NOW()
		  FROM v, old
		 WHERE u.id = $1::uuid AND u.org_id = $2::uuid AND u.user_type = 'external'
		   AND u.account_status IN ('active', 'pending_mfa') AND v.target > u.account_expires_at
		RETURNING v.id::text, old.account_expires_at, u.account_expires_at`, userID, orgID, externalid.MaxAccountDays).
		Scan(&vendorID, &before, &after)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		s.logger.Warn("federated sign-in: could not slide the account expiry", zap.String("user_id", userID), zap.Error(err))
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.expiry_slid", "success", userID, "", userID, "user",
		map[string]interface{}{"vendor_org_id": vendorID, "previous_expires_at": before, "account_expires_at": after})
}

// federatedExternalRefusal maps a provisioning error to the login page's
// reason and the audit detail.
func federatedExternalRefusal(err error) (reason, detail string) {
	switch {
	case errors.Is(err, errPartnerNotRegistered):
		return ssoErrPartnerNotRegistered, "partner_not_registered"
	case externalid.IsRefusal(err):
		return ssoErrPartnerNotRegistered, externalid.Code(err)
	default:
		return externalErrUnavailable, "provisioning_failed"
	}
}
