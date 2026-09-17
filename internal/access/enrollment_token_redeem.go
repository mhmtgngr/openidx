package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE TWO DOORS INTO THE FLEET HAD DIFFERENT LOCKS.
//
// An admin/MDM enrolment token (agent_enrollment_tokens) admits a device on two
// public routes: the agent's POST /agent/enroll (HandleEnroll) and the dark-mode
// POST /api/v1/access/enroll (Service.handleEnroll → validateEnrollmentToken).
// Each carried its own copy of the check, and the copies had drifted into
// mirror-image defects:
//
//   - the dark-mode copy read expires_at into an interface{} and never compared
//     it, so a token an administrator issued for 24 hours admitted a device for
//     ever;
//   - the agent copy compared expires_at but marked used_at with a Warn on
//     failure, so a one-time token that could not be spent was accepted anyway
//     and remained spendable;
//   - neither copy made the spend a claim: SELECT used_at, then UPDATE used_at,
//     with nothing between them, so two devices presenting the same one-time
//     token in the same instant were both enrolled.
//
// This is now the one redeemer both routes call. The decision is the UPDATE:
// `SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, and the row count is
// the verdict -- zero means another redemption got there first, or the token
// was already spent, and the caller is refused. A token that cannot be spent
// (the UPDATE fails) is not a token that may be used, so that error is returned
// rather than logged. Reusable (fleet/MDM bootstrap) tokens are never spent and
// are checked for revocation and expiry only.

// Since v197 the token table is per-tenant and belted. An agent redeeming a
// token arrives with no tenant -- no JWT, no subdomain the resolver can trust
// -- so the lookup runs under an explicit RLS bypass keyed by the token's
// SHA-256 (as v171 did for enrollment_sessions), and the tenant the token
// carries is handed back to the caller, who scopes everything after it.

// enrollTokenStore is the slice of *database.ScopedPool the redeemer needs.
type enrollTokenStore interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// redeemedEnrollmentToken is what a successful redemption hands the caller:
// which token it was, whom it was issued for, and whether it was spent.
type redeemedEnrollmentToken struct {
	ID        string
	CreatedBy string
	Reusable  bool
	// OrgID is the tenant the token was minted in, and therefore the tenant the
	// device enrols into (v197).
	OrgID string
}

// Refusals a caller may show the client. Anything else the redeemer returns
// is an infrastructure failure: the token was NOT redeemed and the caller
// must not proceed as if it had been.
var (
	errEnrollmentTokenUnknown = enrollError{"invalid enrollment token"}
	errEnrollmentTokenRevoked = enrollError{"enrollment token has been revoked"}
	errEnrollmentTokenExpired = enrollError{"enrollment token has expired"}
	errEnrollmentTokenUsed    = enrollError{"enrollment token has already been used"}
)

// redeemEnrollmentToken looks the presented token up by its hash, refuses it
// when unknown, revoked or expired, and -- unless the token is reusable --
// spends it exactly once. On success the token is spent (or reusable) and the
// caller may mint credentials against it.
func redeemEnrollmentToken(ctx context.Context, store enrollTokenStore, token string) (redeemedEnrollmentToken, error) {
	var (
		out       redeemedEnrollmentToken
		createdBy *string
		expiresAt time.Time
		revoked   bool
	)
	// The one pre-tenant read on this table: the presented token is the key,
	// and the row names the tenant.
	ctx = orgctx.WithBypassRLS(ctx)
	//orgscope:ignore public token redemption: keyed by the high-entropy token hash before any tenant is resolvable; the row's own org_id scopes everything after
	err := store.QueryRow(ctx, `
		SELECT id, created_by, expires_at, COALESCE(revoked, false), COALESCE(reusable, false), org_id::text
		FROM agent_enrollment_tokens
		WHERE token_hash = $1
	`, sha256Hex(token)).Scan(&out.ID, &createdBy, &expiresAt, &revoked, &out.Reusable, &out.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return redeemedEnrollmentToken{}, errEnrollmentTokenUnknown
	}
	if err != nil {
		return redeemedEnrollmentToken{}, fmt.Errorf("look up enrollment token: %w", err)
	}
	if createdBy != nil {
		out.CreatedBy = *createdBy
	}
	if revoked {
		return redeemedEnrollmentToken{}, errEnrollmentTokenRevoked
	}
	if !time.Now().UTC().Before(expiresAt) {
		return redeemedEnrollmentToken{}, errEnrollmentTokenExpired
	}
	if out.Reusable {
		return out, nil
	}

	// The spend is the claim. Two redemptions of the same one-time token race
	// to this statement and the database lets exactly one of them through.
	tag, err := store.Exec(ctx, `
		UPDATE agent_enrollment_tokens SET used_at = NOW()
		WHERE id = $1 AND org_id = $2 AND used_at IS NULL
	`, out.ID, out.OrgID)
	if err != nil {
		return redeemedEnrollmentToken{}, fmt.Errorf("spend enrollment token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return redeemedEnrollmentToken{}, errEnrollmentTokenUsed
	}
	return out, nil
}
