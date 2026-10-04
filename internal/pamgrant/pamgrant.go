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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is satisfied by both *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Querier adds the read half, for the grant check.
type Querier interface {
	Execer
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Holds reports whether userID holds a live grant on entryID that carries
// action: directly, through one of roles (role names, as the token carries
// them), or through a group they belong to in orgID. An empty action asks for
// any action, which is whether the entry is visible to them at all.
//
// It is the one statement of the PAM grant check, read at the moment of the
// call: the access service's connect and reveal paths ask it, and governance
// asks it before it takes a request for an entry, so the two cannot disagree
// about who holds what. Every live row counts, so a standing grant and a
// request's grant on the same entry add up.
func Holds(ctx context.Context, q Querier, orgID, entryID, userID string, roles []string, action string) (bool, error) {
	if userID == "" || orgID == "" || entryID == "" {
		return false, nil
	}
	if roles == nil {
		roles = []string{}
	}
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pam_entry_grants g
			 WHERE g.org_id = $1 AND g.entry_id = $2
			   AND ($3 = '' OR $3 = ANY(g.actions))
			   AND (g.expires_at IS NULL OR g.expires_at > NOW())
			   AND ((g.principal_type = 'user' AND g.principal_id = $4)
			     OR (g.principal_type = 'role' AND g.principal_id = ANY($5))
			     OR (g.principal_type = 'group' AND g.principal_id IN (
			           SELECT gm.group_id::text FROM group_memberships gm
			            WHERE gm.user_id = $4::uuid AND gm.org_id = $1))))`,
		orgID, entryID, action, userID, roles).Scan(&ok)
	return ok, err
}

// Lister is satisfied by *pgxpool.Pool and pgx.Tx.
type Lister interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LapsedSession is a live PAM entry session that has to end, and why.
type LapsedSession struct {
	ID     string
	OrgID  string
	UserID string
	// Reason is "grant_ended" when the user no longer holds a grant to
	// connect to the entry, "moderation_ended" when the moderation that
	// admitted the session ended, "max_duration" when an external user's
	// session has run past its ceiling.
	Reason string
}

// LapsedSessions lists, across the install, up to limit live PAM entry
// sessions that have to end, oldest first. The access service ends them.
//
//   - grant_ended: the user no longer holds a live 'connect' grant on the
//     session's entry: the grant expired (a request's window closed), was
//     removed, or the role or group that carried it is no longer theirs. A
//     session lasts as long as the access that opened it.
//   - moderation_ended: a moderation admitted the session
//     (pam_entry_sessions.moderation_id, migration v221), and it is no
//     longer active: its moderator or its requester ended it, and the end
//     did not reach the broker. A moderated session runs only while it is
//     moderated.
//   - max_duration: the user is external and the session started more than
//     maxExternal ago (invariant I7 of the third-party access framework),
//     whatever grant it rides. A maxExternal of zero turns this off.
//
// The grant half is Holds asked of the session's user, with the roles read
// from user_roles the way a token's are (internal/oauth: the user's unexpired
// assignments in the org, by name, as a role grant names them), because the
// sweep has no token. Two kinds of session are not judged by it: one an
// administrator opened without a grant (admin_bypass names 'grant'), since no
// grant opened it, and one recorded before migration v217 (admin_bypass
// NULL), since whether a grant opened it is not known. The duration half
// judges every external session, those two kinds included. When more than one
// applies, the reason is the first of grant_ended, moderation_ended and
// max_duration.
func LapsedSessions(ctx context.Context, q Lister, maxExternal time.Duration, limit int) ([]LapsedSession, error) {
	rows, err := q.Query(ctx,
		//orgscope:ignore install-wide sweep of live PAM entry sessions; each grant, role, group and user is matched in the session's own org
		`SELECT id, org_id, user_id,
		        CASE WHEN lapsed THEN 'grant_ended' WHEN unmoderated THEN 'moderation_ended' ELSE 'max_duration' END
		   FROM (
		     SELECT s.id::text AS id, s.org_id::text AS org_id, s.user_id::text AS user_id, s.started_at,
		            (s.admin_bypass IS NOT NULL AND NOT ('grant' = ANY(s.admin_bypass))
		             AND NOT EXISTS (
		                   SELECT 1 FROM pam_entry_grants g
		                    WHERE g.org_id = s.org_id AND g.entry_id = s.entry_id
		                      AND 'connect' = ANY(g.actions)
		                      AND (g.expires_at IS NULL OR g.expires_at > NOW())
		                      AND ((g.principal_type = 'user' AND g.principal_id = s.user_id::text)
		                        OR (g.principal_type = 'role' AND g.principal_id IN (
		                              SELECT r.name FROM user_roles ur
		                                JOIN roles r ON r.id = ur.role_id
		                               WHERE ur.user_id = s.user_id AND ur.org_id = s.org_id
		                                 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())))
		                        OR (g.principal_type = 'group' AND g.principal_id IN (
		                              SELECT gm.group_id::text FROM group_memberships gm
		                               WHERE gm.user_id = s.user_id AND gm.org_id = s.org_id))))) AS lapsed,
		            (s.moderation_id IS NOT NULL
		             AND NOT EXISTS (SELECT 1 FROM guacamole_moderation_sessions m
		                              WHERE m.id = s.moderation_id AND m.org_id = s.org_id AND m.status = 'active')) AS unmoderated,
		            ($2::bigint > 0 AND s.started_at < NOW() - make_interval(secs => $2::bigint)
		             AND EXISTS (SELECT 1 FROM users u
		                          WHERE u.id = s.user_id AND u.org_id = s.org_id AND u.user_type = 'external')) AS overlong
		       FROM pam_entry_sessions s
		      WHERE s.status = 'active' AND s.user_id IS NOT NULL
		   ) judged
		  WHERE lapsed OR unmoderated OR overlong
		  ORDER BY started_at
		  LIMIT $1`, limit, int64(maxExternal/time.Second))
	if err != nil {
		return nil, fmt.Errorf("list PAM entry sessions that have to end: %w", err)
	}
	defer rows.Close()
	var out []LapsedSession
	for rows.Next() {
		var l LapsedSession
		if err := rows.Scan(&l.ID, &l.OrgID, &l.UserID, &l.Reason); err != nil {
			return nil, fmt.Errorf("scan a PAM entry session: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
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
	// ModerationsEnded is the pending and active moderations
	// (guacamole_moderation_sessions) the user asked for or moderates: a
	// moderation a moderator joined admits a session, and one whose moderator
	// was severed no longer has anyone watching. The lifecycle sweep then
	// ends the sessions they admitted (LapsedSessions, moderation_ended).
	ModerationsEnded int64
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
	run("end_moderations", &c.ModerationsEnded,
		`UPDATE guacamole_moderation_sessions SET status = 'ended', ended_at = NOW()
		  WHERE (requester_id::text = $1 OR moderator_id::text = $1) AND org_id = $2 AND status IN ('pending', 'active')`)
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
	run("end_moderations", &c.ModerationsEnded,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE guacamole_moderation_sessions m SET status = 'ended', ended_at = NOW()
		  WHERE m.status IN ('pending', 'active')
		    AND (NOT EXISTS (SELECT 1 FROM users u WHERE u.id = m.requester_id AND u.enabled = true)
		      OR (m.moderator_id IS NOT NULL
		          AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = m.moderator_id AND u.enabled = true)))`)
	return c, errs
}

// Total is the number of rows a pass ended, for a log line.
func (c Counts) Total() int64 {
	return c.GrantsExpired + c.ApprovalsRevoked + c.LeasesReleased + c.TempLinksRevoked + c.BrokeredEnded +
		c.ModerationsEnded
}

// String is the log form.
func (c Counts) String() string {
	return fmt.Sprintf("grants=%d approvals=%d leases=%d temp_links=%d brokered=%d moderations=%d",
		c.GrantsExpired, c.ApprovalsRevoked, c.LeasesReleased, c.TempLinksRevoked, c.BrokeredEnded, c.ModerationsEnded)
}
