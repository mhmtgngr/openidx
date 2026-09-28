// Package pamgrant ends a user's PAM entry surface: the standing and pending
// access a user holds on PAM entries, as opposed to the time-bound elevations
// internal/jitgrant ends. It is what the three severance paths call:
//
//   - the admin kill switch (internal/access/kill_switch.go), synchronously;
//   - the identity service's deprovisionUser, on the API disable and delete
//     paths;
//   - the access service's lifecycle sweep, the reconcile net for every other
//     way a user ends up disabled (SCIM, directory sync, lifecycle policies).
//
// Until this package existed none of the three touched any of it. The kill
// switch cut sessions, tokens, vault checkouts, elevations and Guacamole
// sessions and left the user holding every PAM connection grant they had,
// every launch approval already given to them, every exclusive lease, every
// temporary access link they had issued and every brokered SSH or cloud
// session -- and pamEntryAllowed reads pam_entry_grants at the moment of the
// call, so a severed user could open a new privileged session a second after
// the emergency control reported success.
//
// WHY A LEAF PACKAGE. The same reason internal/jitgrant is one: the three
// callers live in packages that must not import each other, and the last time
// a revocation lived unexported in one of them the other two wrote their own
// SQL against the wrong table. A write wired in here is wired in everywhere,
// and there is no second place for the next table to be forgotten.
//
// WHAT IS NOT HERE. The live PAM entry sessions on the broker. Ending one is a
// Guacamole API call only the access service can make, and its ledger row may
// be marked ended only once the broker no longer serves the session; that
// stays in internal/access, next to the Guacamole client. Grants held through
// a role or a group are also left alone: they belong to that principal, not to
// the user being severed.
package pamgrant

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is satisfied by both *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Counts reports what one pass ended, per table, so a caller can put the
// numbers on its response and in its audit event rather than a bare "done".
type Counts struct {
	// GrantsExpired is the user's own pam_entry_grants rows (principal_type
	// 'user') that were live and now carry expires_at = NOW().
	GrantsExpired int64
	// ApprovalsRevoked is the pending and approved pam_entry_access_requests
	// rows the user had: a given approval is a single-use ticket the user
	// could still spend, a pending one would be spent the moment an approver
	// said yes.
	ApprovalsRevoked int64
	// LeasesReleased is the user's active pam_active_checkouts rows, the
	// exclusive leases that block every other principal from an entry.
	LeasesReleased int64
	// TempLinksRevoked is the active temp_access_links rows the user issued:
	// access handed to somebody outside on a URL nobody signs in to, redeemed
	// as long as it is active whatever happens to its issuer.
	TempLinksRevoked int64
	// BrokeredEnded is the user's active brokered_sessions ledger rows. The
	// SSH certificates and cloud credentials those sessions issued cannot be
	// recalled and expire by their own TTL; a caller that reports this number
	// says so next to it.
	BrokeredEnded int64
}

// StepError names the write that failed. Every step is attempted whatever the
// earlier ones did: one table refusing must not leave the others live.
type StepError struct {
	Step string
	Err  error
}

func (e *StepError) Error() string { return e.Step + ": " + e.Err.Error() }
func (e *StepError) Unwrap() error { return e.Err }

// EndForUser ends one user's PAM entry surface in their organization. Every
// statement touches only still-live rows, so a repeat is a no-op that reports
// zeros.
func EndForUser(ctx context.Context, q Execer, userID, orgID string) (Counts, []error) {
	var c Counts
	var errs []error
	run := func(step string, dst *int64, sql string) {
		tag, err := q.Exec(ctx, sql, userID, orgID)
		if err != nil {
			errs = append(errs, &StepError{Step: step, Err: err})
			return
		}
		*dst = tag.RowsAffected()
	}
	run("expire_pam_entry_grants", &c.GrantsExpired,
		`UPDATE pam_entry_grants SET expires_at = NOW()
		  WHERE principal_type = 'user' AND principal_id = $1 AND org_id = $2
		    AND (expires_at IS NULL OR expires_at > NOW())`)
	run("revoke_pam_entry_approvals", &c.ApprovalsRevoked,
		`UPDATE pam_entry_access_requests SET status = 'revoked'
		  WHERE requester_id = $1 AND org_id = $2 AND status IN ('pending', 'approved')`)
	run("release_pam_entry_leases", &c.LeasesReleased,
		`UPDATE pam_active_checkouts SET status = 'revoked', released_at = NOW()
		  WHERE principal_id = $1 AND org_id = $2 AND status = 'active'`)
	run("revoke_temp_access_links", &c.TempLinksRevoked,
		`UPDATE temp_access_links SET status = 'revoked', updated_at = NOW()
		  WHERE created_by = $1 AND org_id = $2 AND status = 'active'`)
	run("end_brokered_sessions", &c.BrokeredEnded,
		`UPDATE brokered_sessions SET status = 'ended', ended_at = NOW()
		  WHERE user_id = $1 AND org_id = $2 AND status = 'active'`)
	return c, errs
}

// EndForDisabledUsers ends the PAM entry surface of every user who is disabled
// or no longer exists, across the install: the lifecycle sweep's reconcile
// net. A row whose user is gone has no organization context to run under,
// which is why each statement carries its own "no enabled user" predicate
// rather than a tenant term, the same shape the sweep's vault statements use.
func EndForDisabledUsers(ctx context.Context, q Execer) (Counts, []error) {
	var c Counts
	var errs []error
	run := func(step string, dst *int64, sql string) {
		tag, err := q.Exec(ctx, sql)
		if err != nil {
			errs = append(errs, &StepError{Step: step, Err: err})
			return
		}
		*dst = tag.RowsAffected()
	}
	run("expire_pam_entry_grants", &c.GrantsExpired,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown), same posture as internal/access/lifecycle_sweep.go
		`UPDATE pam_entry_grants g SET expires_at = NOW()
		  WHERE g.principal_type = 'user'
		    AND (g.expires_at IS NULL OR g.expires_at > NOW())
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id::text = g.principal_id AND u.enabled = true)`)
	run("revoke_pam_entry_approvals", &c.ApprovalsRevoked,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE pam_entry_access_requests r SET status = 'revoked'
		  WHERE r.status IN ('pending', 'approved')
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = r.requester_id AND u.enabled = true)`)
	run("release_pam_entry_leases", &c.LeasesReleased,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE pam_active_checkouts l SET status = 'revoked', released_at = NOW()
		  WHERE l.status = 'active'
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = l.principal_id AND u.enabled = true)`)
	run("revoke_temp_access_links", &c.TempLinksRevoked,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE temp_access_links t SET status = 'revoked', updated_at = NOW()
		  WHERE t.status = 'active'
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = t.created_by AND u.enabled = true)`)
	run("end_brokered_sessions", &c.BrokeredEnded,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE brokered_sessions b SET status = 'ended', ended_at = NOW()
		  WHERE b.status = 'active'
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = b.user_id AND u.enabled = true)`)
	return c, errs
}

// Total is the number of rows a pass ended, for a log line.
func (c Counts) Total() int64 {
	return c.GrantsExpired + c.ApprovalsRevoked + c.LeasesReleased + c.TempLinksRevoked + c.BrokeredEnded
}

// String is the log form.
func (c Counts) String() string {
	return fmt.Sprintf("grants=%d approvals=%d leases=%d temp_links=%d brokered=%d",
		c.GrantsExpired, c.ApprovalsRevoked, c.LeasesReleased, c.TempLinksRevoked, c.BrokeredEnded)
}
