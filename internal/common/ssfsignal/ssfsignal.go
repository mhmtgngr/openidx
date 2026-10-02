// Package ssfsignal is how a path that severs an account, or changes what its
// token says, tells the SSF transmitter about it without being able to call
// it.
//
// The transmitter (internal/oauth, EmitCAEPEvent) lives in oauth-service and
// needs the issuer's signing key. The paths that disable or delete a user live
// in identity, directory and admin; the ones that give and take back a role or
// a group for a window live in governance. This package is the seam: such a
// path writes one row to ssf_pending_events (migration v196) with the database
// handle it already holds -- a transaction if it has one, the pool if not --
// and oauth-service's drainer turns the row into a signed SET for every stream
// in the tenant that asked for the event.
//
// WHY NOT THE OUTBOX. The outbox is drained by cmd/event-relay into NATS, and
// nats.enabled defaults false; it is also single-consumer by construction. A
// federated security signal placed behind an optional broker is one the
// default install never sends. See the v196 migration and the plan's 3.1 for
// the measurement behind that decision.
//
// This package imports no service and no signing code, so every severing path
// in the tree can import it without a cycle.
package ssfsignal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// The event types a producer may enqueue. They are spelled here rather than
// imported from internal/oauth so that a producer never has to import the
// transmitter; oauth asserts each spelling agrees with its own, and its
// drainer signs these and nothing else.
const (
	// AccountDisabled (RISC): the account is gone, or can no longer sign in
	// and does not come back. The default when a signal names no type.
	AccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	// SessionRevoked (CAEP): the subject's sessions were ended, and the
	// account may come back. A suspended external account is the case: a new
	// sponsor can reactivate it within the grace period (decision D5).
	SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	// TokenClaimsChange (CAEP): what a token issued for the subject says has
	// changed, because a role or a group they hold through an access request
	// began or ended. A producer names the subject and nothing else: the
	// drainer reads the claims' new values when it signs, from the same rows a
	// token is issued from, so a row cannot make the issuer assert a role.
	TokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
)

// Execer is the one method this package needs from a database handle.
// *pgxpool.Pool, pgx.Tx and the scoped pool wrapper all satisfy it, so a
// caller inside a transaction passes the transaction and the signal commits or
// rolls back with the sever.
type Execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// ErrNoTenant is returned for an empty org id. The transmitter refuses the
// same case for the same reason: an empty org used to mean "every tenant", and
// a security event about one tenant's user must never fan out to the others.
var ErrNoTenant = errors.New("ssfsignal: refusing to enqueue a signal without a tenant")

// ErrNoSubject is returned for an empty subject id: a signal about nobody.
var ErrNoSubject = errors.New("ssfsignal: refusing to enqueue a signal without a subject")

// Signal is one pending security event.
type Signal struct {
	OrgID        string
	EventType    string
	SubjectID    string
	SubjectEmail string // optional; the SET carries the id when this is empty
	Claims       map[string]any
}

// Enqueue writes the signal. It is a single INSERT and holds no state, so the
// atomicity a caller gets is exactly the atomicity of the handle it passes.
func Enqueue(ctx context.Context, exec Execer, sig Signal) error {
	if sig.OrgID == "" {
		return ErrNoTenant
	}
	if sig.SubjectID == "" {
		return ErrNoSubject
	}
	if sig.EventType == "" {
		sig.EventType = AccountDisabled
	}
	claims := sig.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("ssfsignal: marshal claims: %w", err)
	}
	_, err = exec.Exec(ctx, `
		INSERT INTO ssf_pending_events (org_id, event_type, subject_id, subject_email, claims)
		VALUES ($1, $2, $3, $4, $5)`,
		sig.OrgID, sig.EventType, sig.SubjectID, sig.SubjectEmail, body)
	if err != nil {
		// The subject and event type are caller-supplied and end up in the
		// caller's log line under a sanitised field; they do not belong in the
		// error text as well, where they would reach the log unsanitised.
		return fmt.Errorf("ssfsignal: enqueue: %w", err)
	}
	return nil
}
