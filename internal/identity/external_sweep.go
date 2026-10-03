package identity

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// StartExternalAccountSweep starts the leader-gated sweep that ends the
// external (vendor) accounts the clock or a departure has ended: invariants I8
// and I9 of the third-party access framework. Admin-plane work, like the
// role-expiry sweep: it changes accounts across every org and signs nobody in.
func (s *Service) StartExternalAccountSweep(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("External account sweep started")
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "identity:external-accounts", 1*time.Minute, s.sweepExternalAccounts)
}

// externalSweepStep is one transition the sweep makes. sql moves the accounts
// it finds in one statement guarded by their state, and returns each one's
// id, org, previous status, sponsor and vendor.
type externalSweepStep struct {
	action string // audit action
	reason string // audit reason
	sql    string
}

// externalSweepSteps, in order. The account's end comes first, so an account
// past it is expired whatever else happened to it; a closed vendor comes
// before a departed sponsor, so its accounts go straight to disabled; a
// suspended vendor's accounts are suspended before the sponsor step looks.
//
// The routes that change an account sever it themselves. These are the
// transitions nobody makes by hand: the clock, a sponsor disabled by a writer
// that does not know about sponsorship (directory sync, a lifecycle policy, the
// kill switch), a vendor closed by a close that failed half-way, or suspended
// by an update whose accounts were not all reached.
var externalSweepSteps = []externalSweepStep{
	{
		// I8: the account's end.
		action: "external.expired",
		reason: "the account reached its expiry",
		sql: externalSweepMove("expired", `
			u.account_status IN ('invited', 'pending_mfa', 'active', 'suspended')
			AND u.account_expires_at <= NOW()`),
	},
	{
		// The vendor's closure, for an account the close route did not reach.
		action: "external.disabled",
		reason: "the vendor organization is closed",
		sql: externalSweepMove("disabled", `
			u.account_status IN ('invited', 'pending_mfa', 'active', 'suspended')
			AND EXISTS (SELECT 1 FROM vendor_organizations v
			             WHERE v.id = u.vendor_org_id AND v.org_id = u.org_id AND v.status = 'closed')`),
	},
	{
		// The vendor's suspension, for an account the update route did not
		// reach. Suspended, not disabled: the account comes back when the
		// vendor does.
		action: "external.suspended",
		reason: "the vendor organization is suspended",
		sql: externalSweepMove("suspended", `
			u.account_status IN ('invited', 'pending_mfa', 'active')
			AND EXISTS (SELECT 1 FROM vendor_organizations v
			             WHERE v.id = u.vendor_org_id AND v.org_id = u.org_id AND v.status = 'suspended')`),
	},
	{
		// An account that waits for its second factor after its invitation
		// stopped answering: the /mfa step reads that invitation, so the
		// account can never become active.
		action: "external.expired",
		reason: "the invitation lapsed before a second factor was enrolled",
		sql: externalSweepMove("expired", `
			u.account_status IN ('invited', 'pending_mfa')
			AND NOT EXISTS (SELECT 1 FROM user_invitations i
			                 WHERE i.org_id = u.org_id AND lower(i.email) = lower(u.email)
			                   AND i.user_type = 'external' AND i.status = 'accepted' AND i.expires_at > NOW())`),
	},
	{
		// I9: the sponsor is no longer an enabled, active internal user of the
		// org (externalid.CheckSponsor's rule). Suspended, not disabled
		// (decision D5): a new sponsor may take the account over within
		// SponsorGraceDays.
		action: "external.suspended",
		reason: "the sponsor is no longer an enabled internal user",
		sql: externalSweepMove("suspended", `
			u.account_status IN ('invited', 'pending_mfa', 'active')
			AND NOT EXISTS (SELECT 1 FROM users sp
			                 WHERE sp.id = u.sponsor_user_id AND sp.org_id = u.org_id
			                   AND sp.user_type = 'internal' AND sp.account_status = 'active'
			                   AND COALESCE(sp.enabled, false))`),
	},
	{
		// D5: nobody took the account over in time; the departure is final.
		// A suspension with no recorded time is past any grace. The window
		// does not run while the vendor is suspended, since nobody can
		// reactivate the account then; the vendor's reactivation restarts
		// it (restartVendorGrace).
		action: "external.disabled",
		reason: "not reactivated within the sponsor grace period",
		sql: externalSweepMove("disabled", `
			u.account_status = 'suspended'
			AND (u.status_changed_at IS NULL
			     OR u.status_changed_at <= NOW() - make_interval(days => `+strconv.Itoa(externalid.SponsorGraceDays)+`))
			AND NOT EXISTS (SELECT 1 FROM vendor_organizations v
			                 WHERE v.id = u.vendor_org_id AND v.org_id = u.org_id AND v.status = 'suspended')`),
	},
}

// externalSweepMove builds a step's statement: the external accounts matching
// where (over users u) move to status, unable to sign in.
func externalSweepMove(status, where string) string {
	return `
		WITH due AS (
			SELECT u.id, u.account_status, u.sponsor_user_id, u.vendor_org_id
			  FROM users u
			 WHERE u.user_type = 'external' AND ` + where + `
			 FOR UPDATE OF u
		)
		UPDATE users
		   SET account_status = '` + status + `', enabled = false, status_changed_at = NOW(), updated_at = NOW()
		  FROM due
		 WHERE users.id = due.id
		RETURNING users.id::text, users.org_id::text, due.account_status,
		          COALESCE(due.sponsor_user_id::text, ''), COALESCE(due.vendor_org_id::text, '')`
}

// externalSweepBatch bounds how many departed accounts one tick severs; the
// rest wait for the next.
const externalSweepBatch = 200

// sweepExternalAccounts makes each transition, then severs every account that
// is no longer live and has not been severed since its status last changed.
func (s *Service) sweepExternalAccounts(ctx context.Context) {
	if s.db == nil || s.db.Pool == nil {
		return
	}
	for _, step := range externalSweepSteps {
		s.runExternalSweepStep(ctx, step)
	}
	s.severDepartedExternals(ctx)
}

func (s *Service) runExternalSweepStep(ctx context.Context, step externalSweepStep) {
	//orgscope:ignore background sweep of external accounts across all orgs; each row's org is returned and audited
	rows, err := s.db.Pool.Query(ctx, step.sql)
	if err != nil {
		s.logger.Error("external account sweep step failed", zap.String("action", step.action),
			zap.String("reason", step.reason), zap.Error(err))
		return
	}
	type moved struct{ id, org, from, sponsor, vendor string }
	var done []moved
	for rows.Next() {
		var m moved
		if err := rows.Scan(&m.id, &m.org, &m.from, &m.sponsor, &m.vendor); err != nil {
			// The account has moved already; the sever step still finds it.
			s.logger.Error("external account moved but could not be read for the audit trail",
				zap.String("action", step.action), zap.Error(err))
			continue
		}
		done = append(done, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Error("the external account sweep's list is incomplete", zap.String("action", step.action), zap.Error(err))
	}
	for _, m := range done {
		details := map[string]interface{}{"reason": step.reason, "from": m.from, "vendor_org_id": m.vendor}
		if m.sponsor != "" {
			details["sponsor_user_id"] = m.sponsor
		}
		s.logAuditEvent(orgctx.With(ctx, orgctx.Org{ID: m.org}), "identity", "external_access", step.action, "success",
			"system", m.id, "user", details)
	}
	if len(done) > 0 {
		s.logger.Info("external accounts ended", zap.String("action", step.action),
			zap.String("reason", step.reason), zap.Int("count", len(done)))
	}
}

// severDepartedExternals severs (severExternal) each external account that
// cannot sign in and has not been severed since its status changed. The
// routes sever inline; this catches the sweep's own transitions and any sever
// an earlier attempt did not record.
func (s *Service) severDepartedExternals(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background sweep of external accounts across all orgs; each row's org scopes its severing
		`SELECT id::text, org_id::text, account_status FROM users
		  WHERE user_type = 'external' AND account_status IN ('suspended', 'expired', 'disabled')
		    AND (access_severed_at IS NULL OR access_severed_at < status_changed_at)
		  ORDER BY status_changed_at NULLS FIRST
		  LIMIT $1`, externalSweepBatch)
	if err != nil {
		s.logger.Error("could not list the external accounts to sever", zap.Error(err))
		return
	}
	type departed struct{ id, org, status string }
	var due []departed
	for rows.Next() {
		var d departed
		if err := rows.Scan(&d.id, &d.org, &d.status); err != nil {
			s.logger.Error("could not read an external account to sever", zap.Error(err))
			continue
		}
		due = append(due, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Error("the list of external accounts to sever is incomplete", zap.Error(err))
	}
	for _, d := range due {
		octx := orgctx.With(ctx, orgctx.Org{ID: d.org})
		if err := s.severExternal(octx, d.org, d.id, d.status); err != nil {
			s.logger.Warn("external account severed but not recorded; the next sweep repeats it",
				zap.String("user_id", logsafe.Clean(d.id)), zap.Error(err))
			continue
		}
		s.logAuditEvent(octx, "identity", "external_access", "external.access_severed", "success",
			"system", d.id, "user", map[string]interface{}{"status": d.status})
	}
}
