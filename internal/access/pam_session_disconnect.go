// Package access — ending PAM entry sessions the broker no longer serves.
//
// A pam_entry_sessions row was marked ended only by an explicit end: the End
// button, the kill switch, a lapsed grant, a disabled user, the risk scorer, a
// moderation ending, the browser terminal closing. A user who closed the tab
// ended nothing, so the row stayed 'active' for ever. The reference install
// had 107 rows, every one 'active', the oldest four months old.
//
// reconcileDisconnectedPamSessions runs on the lifecycle tick. For each broker
// it lists the active connections ONCE; a ledger row the broker is serving is
// stamped broker_last_seen_at, and a row it has not served for
// pamDisconnectGrace (measured from the last sighting, or from started_at if
// it was never seen) is ended with reason 'disconnected', audited and
// published like every other end.
//
// It fails safe. A broker that is not configured, or whose listing fails,
// ends nothing on this tick: a network fault must not read as every session
// having gone. Rows with no broker connection (the browser terminal, a
// website launch) are not its business; their own paths end them.
//
// Matching is by connection id and, when the session has its own broker
// identity, by that username. A session launched under the shared broker
// account cannot be told from another user's on the same connection, so it
// counts as served while anyone is on that connection: the sweep then keeps
// a row open too long, never closes one too early.
package access

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// pamDisconnectGrace is how long a session may be absent from the broker
// before it counts as ended. It covers a browser that takes a while to open
// the connect URL and a reconnect after a short drop.
const pamDisconnectGrace = 10 * time.Minute

// pamDisconnectBatch bounds one tick's work; the oldest rows go first, so a
// backlog drains over successive ticks.
const pamDisconnectBatch = 500

type pamLiveRow struct {
	id, orgID, userID, connID, guacUser, reach string
	stale                                      bool
}

func (s *Service) reconcileDisconnectedPamSessions(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep; each row is stamped or ended under its own org
		`SELECT s.id::text, s.org_id::text, COALESCE(s.user_id::text, ''), s.guac_connection_id,
		        COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, ''),
		        COALESCE(s.broker_last_seen_at, s.started_at) < NOW() - make_interval(secs => $1)
		   FROM pam_entry_sessions s
		   JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		  WHERE s.status = 'active' AND COALESCE(s.guac_connection_id, '') <> ''
		  ORDER BY s.started_at
		  LIMIT $2`, pamDisconnectGrace.Seconds(), pamDisconnectBatch)
	if err != nil {
		s.logger.Warn("lifecycle sweep: listing live PAM entry sessions failed", zap.Error(err))
		return
	}
	var live []pamLiveRow
	for rows.Next() {
		var r pamLiveRow
		if err := rows.Scan(&r.id, &r.orgID, &r.userID, &r.connID, &r.guacUser, &r.reach, &r.stale); err == nil {
			live = append(live, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Warn("lifecycle sweep: reading live PAM entry sessions failed", zap.Error(err))
		return
	}
	if len(live) == 0 {
		return
	}

	// One listing per broker. nil means "unknown": nothing on it is ended.
	type served struct {
		byConnUser map[string]bool
		byConn     map[string]bool
	}
	listings := map[*GuacamoleClient]*served{}
	listingOf := func(b *GuacamoleClient) *served {
		if l, ok := listings[b]; ok {
			return l
		}
		active, err := b.ListActiveSessions(ctx)
		if err != nil {
			s.logger.Warn("lifecycle sweep: the broker's active sessions could not be listed; no session on it is ended this tick",
				zap.Error(err))
			listings[b] = nil
			return nil
		}
		l := &served{byConnUser: map[string]bool{}, byConn: map[string]bool{}}
		for _, a := range active {
			l.byConn[a.ConnectionIdentifier] = true
			l.byConnUser[a.ConnectionIdentifier+"\x00"+a.Username] = true
		}
		listings[b] = l
		return l
	}

	var seen []string
	ended := 0
	for _, r := range live {
		b := s.brokerFor(r.reach)
		if b == nil {
			continue
		}
		l := listingOf(b)
		if l == nil {
			continue
		}
		isServed := l.byConn[r.connID]
		if r.guacUser != "" {
			isServed = l.byConnUser[r.connID+"\x00"+r.guacUser]
		}
		if isServed {
			seen = append(seen, r.id)
			continue
		}
		if !r.stale {
			continue
		}
		octx := orgctx.With(ctx, orgctx.Org{ID: r.orgID})
		tag, err := s.db.Pool.Exec(octx,
			`UPDATE pam_entry_sessions SET status = 'ended', ended_at = COALESCE(broker_last_seen_at, NOW())
			  WHERE id = $1 AND org_id = $2 AND status = 'active'`, r.id, r.orgID)
		if err != nil {
			s.logger.Warn("lifecycle sweep: ending a disconnected PAM entry session failed",
				zap.String("session_id", r.id), zap.Error(err))
			continue
		}
		if tag.RowsAffected() == 0 {
			continue // ended by someone else since the listing
		}
		ended++
		s.pamSessionEnded(r.orgID, r.id, sessionEndDisconnected, "")
		if s.auditService != nil {
			if err := s.auditService.RecordEvent(octx, "openidx", "pam.session_ended", "", r.userID, "",
				map[string]interface{}{"session_id": r.id, "reason": sessionEndDisconnected}); err != nil {
				s.logger.Warn("lifecycle sweep: could not audit a disconnected PAM entry session", zap.Error(err))
			}
		}
	}
	if len(seen) > 0 {
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore keyed by primary keys read by the annotated install-wide sweep above
			`UPDATE pam_entry_sessions SET broker_last_seen_at = NOW()
			  WHERE id = ANY($1::uuid[]) AND status = 'active'`, seen); err != nil {
			s.logger.Warn("lifecycle sweep: stamping served PAM entry sessions failed", zap.Error(err))
		}
	}
	if ended > 0 {
		s.logger.Info("lifecycle sweep: ended PAM entry sessions the broker no longer serves",
			zap.Int("count", ended))
	}
}
