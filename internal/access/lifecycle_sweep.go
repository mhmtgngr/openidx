// Package access — cross-pillar lifecycle enforcement sweep.
//
// The PAM counterpart to ziti_user_sync.go's runDeprovisionSweep: where that
// sweep tears down Ziti identities of disabled/deleted IAM users, this one
// tears down their live *privileged* access. Identity's deprovisionUser
// already revokes PAM state inline on the API disable path; this sweep is the
// reconcile net for every other way a user can end up disabled (SCIM
// deactivation, directory sync, lifecycle policies, direct DB changes) — and
// it is the only place that can terminate a live Guacamole session, because
// the Guacamole client lives in the access-service.
//
// Together the three enforcement layers make the IAM⇄PAM⇄Ziti relation hold
// under all paths:
//
//	disable via API   → identity deprovisionUser (inline, immediate)
//	any disable path  → this sweep (PAM, ≤1 tick) + ziti deprovision sweep (network, ≤1 tick)
//	admin kill switch → kill_switch.go (all pillars, synchronous)
package access

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/jitgrant"
	"github.com/openidx/openidx/internal/pamgrant"
	"github.com/openidx/openidx/internal/revocation"
)

// StartLifecycleEnforcement starts the background sweep. Interval should match
// the Ziti user-sync poller (30s) so both halves of the deprovision converge
// within one tick.
func (s *Service) StartLifecycleEnforcement(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.logger.Info("Cross-pillar lifecycle enforcement sweep started",
			zap.Duration("interval", interval))

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("Lifecycle enforcement sweep stopped")
				return
			case <-ticker.C:
				s.runLifecycleEnforcement(ctx)
			}
		}
	}()
}

// runLifecycleEnforcement revokes live PAM access held by users who are
// disabled or deleted. Idempotent: every statement only touches still-active
// rows, so repeat ticks (or replicas racing) are harmless.
func (s *Service) runLifecycleEnforcement(ctx context.Context) {
	// Vault checkouts whose principal is disabled or gone.
	if tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown), same posture as the ziti deprovision sweep
		`UPDATE vault_checkouts vc SET status = 'revoked', returned_at = NOW()
		  WHERE vc.status = 'active' AND vc.principal_id IS NOT NULL
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = vc.principal_id AND u.enabled = true)`); err != nil {
		s.logger.Warn("lifecycle sweep: vault checkout revocation failed", zap.Error(err))
	} else if n := tag.RowsAffected(); n > 0 {
		s.logger.Info("lifecycle sweep: revoked vault checkouts of disabled users", zap.Int64("count", n))
	}

	// Direct user vault grants of disabled/deleted principals.
	if tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`UPDATE vault_access_grants vg SET expires_at = NOW()
		  WHERE vg.principal_type = 'user'
		    AND (vg.expires_at IS NULL OR vg.expires_at > NOW())
		    AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = vg.principal_id AND u.enabled = true)`); err != nil {
		s.logger.Warn("lifecycle sweep: vault grant expiry failed", zap.Error(err))
	} else if n := tag.RowsAffected(); n > 0 {
		s.logger.Info("lifecycle sweep: expired vault grants of disabled users", zap.Int64("count", n))
	}

	// Time-bound elevations of disabled users. This used to update jit_grants,
	// which nothing in the product writes, so the sweep reconciled nothing.
	//
	// The elevations end here AND the tokens carrying them are cut below. The
	// sweep used to do only the first: it removed the assignment rows and
	// logged how many, so a user disabled by SCIM, a directory sync or a
	// lifecycle policy lost the row while the access token in their browser
	// kept naming the role -- and this sweep is the reconcile net precisely for
	// the disable paths that do NOT go through deprovisionUser, which does cut
	// tokens. The net caught the access and let the credential through.
	n, cutTokensFor, err := jitgrant.EndAllForDisabledUsers(ctx, s.db.Pool)
	if err != nil {
		s.logger.Warn("lifecycle sweep: ending elevations of disabled users failed",
			zap.Int64("ended_before_failure", n), zap.Error(err))
	} else if n > 0 {
		s.logger.Info("lifecycle sweep: ended time-bound elevations of disabled users", zap.Int64("count", n))
	}
	// Cut whatever was actually ended, including on the error path: a sweep
	// that failed part way through has still removed real access, and those
	// users are exactly the ones whose tokens must not outlive it. Redis cannot
	// join the statements above, so this runs after them, here at the call
	// site, rather than inside the shared revoke.
	for _, userID := range cutTokensFor {
		if s.redis == nil {
			// An install with no Redis still reconciles: the elevations above
			// are already gone, and refusing to run would leave them live in
			// the database as well as the token.
			break
		}
		if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
			s.logger.Warn("lifecycle sweep: failed to cut tokens of a disabled user whose elevation ended",
				zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
		}
	}

	// The PAM entry surface of disabled/deleted users: their own connection
	// grants, launch approvals, exclusive leases, issued temporary access
	// links and brokered-session ledger rows. The same five writes the kill
	// switch and deprovisionUser make, so a user disabled by SCIM, a directory
	// sync or a lifecycle policy loses them within one tick too.
	if pam, pamErrs := pamgrant.EndForDisabledUsers(ctx, s.db.Pool); len(pamErrs) > 0 {
		for _, err := range pamErrs {
			s.logger.Warn("lifecycle sweep: ending the PAM entry surface of disabled users failed", zap.Error(err))
		}
	} else if pam.Total() > 0 {
		s.logger.Info("lifecycle sweep: ended the PAM entry surface of disabled users", zap.Stringer("counts", pam))
	}
	s.endPamEntrySessionsOfDisabledUsers(ctx)
	s.endPamEntrySessionsPastTheirGrant(ctx)

	// Live privileged sessions of disabled/deleted users. Rows are marked
	// terminated only after Guacamole confirms the kill, so a configured-but-
	// unreachable Guacamole retries next tick instead of silently "succeeding".
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown)
		`SELECT gs.id, COALESCE(gs.guac_session_uuid, ''), gs.user_id
		   FROM guacamole_sessions gs
		   LEFT JOIN users u ON u.id = gs.user_id
		  WHERE gs.status = 'active' AND gs.user_id IS NOT NULL
		    AND (u.id IS NULL OR u.enabled = false)
		  LIMIT 20`)
	if err != nil {
		s.logger.Warn("lifecycle sweep: guacamole session query failed", zap.Error(err))
		return
	}
	type sess struct{ rowID, uuid, userID string }
	var doomed []sess
	for rows.Next() {
		var d sess
		if err := rows.Scan(&d.rowID, &d.uuid, &d.userID); err == nil {
			doomed = append(doomed, d)
		}
	}
	rows.Close()

	if len(doomed) == 0 {
		return
	}
	if s.guacamoleClient == nil {
		s.logger.Warn("lifecycle sweep: active privileged sessions belong to disabled users but Guacamole is not configured",
			zap.Int("count", len(doomed)))
		return
	}

	for _, d := range doomed {
		if d.uuid != "" {
			if err := s.guacamoleClient.TerminateSession(ctx, d.uuid); err != nil {
				s.logger.Warn("lifecycle sweep: guacamole terminate failed (will retry next tick)",
					zap.String("user_id", d.userID), zap.Error(err))
				continue
			}
		}
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore keyed by primary key resolved from the annotated install-wide sweep above
			`UPDATE guacamole_sessions SET status = 'terminated', ended_at = NOW()
			  WHERE id = $1 AND status = 'active'`, d.rowID); err != nil {
			s.logger.Warn("lifecycle sweep: session row update failed", zap.Error(err))
			continue
		}
		s.logger.Info("lifecycle sweep: terminated privileged session of disabled user",
			zap.String("user_id", d.userID))
	}
}

// endPamEntrySessionsOfDisabledUsers ends the live PAM entry sessions of
// disabled or deleted users through the same broker-honest path the kill
// switch uses (endUserPamEntrySessions): a ledger row is marked ended only
// once the broker no longer serves the session, so a configured-but-
// unreachable broker retries next tick rather than "succeeding" on paper.
// The sweep runs install-wide; each user's sessions are ended under that
// user's own organization.
func (s *Service) endPamEntrySessionsOfDisabledUsers(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep (disabled/deleted users -> PAM teardown); each session is ended under the org of its own row
		`SELECT DISTINCT ps.org_id::text, ps.user_id::text
		   FROM pam_entry_sessions ps
		   LEFT JOIN users u ON u.id = ps.user_id
		  WHERE ps.status = 'active' AND ps.user_id IS NOT NULL
		    AND (u.id IS NULL OR u.enabled = false)
		  LIMIT 20`)
	if err != nil {
		s.logger.Warn("lifecycle sweep: PAM entry session query failed", zap.Error(err))
		return
	}
	type owner struct{ orgID, userID string }
	var owners []owner
	for rows.Next() {
		var o owner
		if err := rows.Scan(&o.orgID, &o.userID); err == nil {
			owners = append(owners, o)
		}
	}
	rows.Close()
	for _, o := range owners {
		warn := func(step string, err error) {
			s.logger.Warn("lifecycle sweep: PAM entry session of disabled user not ended (will retry next tick)",
				zap.String("step", step), zap.String("user_id", logsafe.Clean(o.userID)), zap.Error(err))
		}
		if n := s.endUserPamEntrySessions(ctx, o.orgID, o.userID, warn); n > 0 {
			s.logger.Info("lifecycle sweep: ended PAM entry sessions of disabled user",
				zap.String("user_id", logsafe.Clean(o.userID)), zap.Int("count", n))
		}
	}
}

// endPamEntrySessionsPastTheirGrant ends the live PAM entry sessions whose user
// no longer holds the grant that let them connect: a request's window closed,
// an administrator removed the grant, or the role or group that carried it is
// no longer theirs (pamgrant.LapsedSessions). A session lasts as long as the
// access that opened it, which is what makes a four-hour request four hours
// rather than four hours to start a session that then runs on.
//
// The same broker-honest path as the kill switch: a row is marked ended only
// once the broker no longer serves the session, so an unreachable broker
// retries next tick. Without per-user broker identities the broker cannot tell
// whose session it is looking at, and every live session on the entry's
// connection ends with it, as at the kill switch; the warning says so. Each
// ended session is audited as pam.session_ended with reason grant_ended.
func (s *Service) endPamEntrySessionsPastTheirGrant(ctx context.Context) {
	lapsed, err := pamgrant.LapsedSessions(ctx, s.db.Pool, 200)
	if err != nil {
		s.logger.Warn("lifecycle sweep: listing PAM entry sessions past their grant failed", zap.Error(err))
		return
	}
	byOrg := map[string][]string{}
	userOf := map[string]string{}
	for _, l := range lapsed {
		byOrg[l.OrgID] = append(byOrg[l.OrgID], l.ID)
		userOf[l.ID] = l.UserID
	}
	for orgID, ids := range byOrg {
		octx := orgctx.With(ctx, orgctx.Org{ID: orgID})
		rows, err := s.db.Pool.Query(octx,
			`SELECT s.id, COALESCE(s.guac_connection_id, ''), COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, '')
			   FROM pam_entry_sessions s
			   JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
			  WHERE s.id = ANY($1::uuid[]) AND s.org_id = $2 AND s.status = 'active'`, ids, orgID)
		if err != nil {
			s.logger.Warn("lifecycle sweep: reading PAM entry sessions past their grant failed", zap.Error(err))
			continue
		}
		warn := func(step string, err error) {
			s.logger.Warn("lifecycle sweep: a PAM entry session past its grant was not ended (will retry next tick)",
				zap.String("step", step), zap.String("org_id", logsafe.Clean(orgID)), zap.Error(err))
		}
		for _, id := range s.endPamEntrySessionRows(octx, orgID, scanPamSessionRows(rows), warn) {
			s.logger.Info("lifecycle sweep: ended a PAM entry session past its grant",
				zap.String("session_id", id), zap.String("user_id", logsafe.Clean(userOf[id])))
			if s.auditService != nil {
				if err := s.auditService.RecordEvent(octx, "openidx", "pam.session_ended", "", userOf[id], "",
					map[string]interface{}{"session_id": id, "reason": "grant_ended"}); err != nil {
					s.logger.Warn("lifecycle sweep: could not audit an ended PAM entry session", zap.Error(err))
				}
			}
		}
	}
}
