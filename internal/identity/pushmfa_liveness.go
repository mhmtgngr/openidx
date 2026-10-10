// Package identity - push device liveness and the dead-device sweep.
//
// A push device row used to live forever. A phone that was lost, wiped or
// replaced kept push on the user's list of factors and kept being sent every
// challenge, and a user whose only factor was that phone could not sign in at
// all: an administrator was locked out exactly this way, with the login
// offering push and nothing else.
//
// Three things follow from last_seen_at (migration v233):
//   - the login stops offering a long-unseen phone as the only way in
//     (AssessPushLiveness, read by internal/oauth's MFA evaluation);
//   - a sweep disables, never deletes, a device unseen for longer still
//     (StartPushDeviceSweep);
//   - the console shows an administrator when each device was last seen.
//
// None of it removes a second factor. A device the system disabled still
// counts as a factor the user has (PushLiveness.Suspended), so the login
// keeps asking for one and offers the fallbacks instead.
package identity

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Reasons recorded in mfa_push_devices.disabled_reason.
const (
	PushDisabledStale = "stale"
	PushDisabledAdmin = "admin"
)

// pushDeviceSeen returns when the device was last seen: LastSeenAt, else its
// last approval, else its registration.
func pushDeviceSeen(d PushMFADevice) time.Time {
	switch {
	case d.LastSeenAt != nil:
		return *d.LastSeenAt
	case d.LastUsedAt != nil:
		return *d.LastUsedAt
	default:
		return d.CreatedAt
	}
}

// PushLiveness is what a user's push devices say about push as a way in.
type PushLiveness struct {
	// Fresh counts enabled devices seen within the stale window.
	Fresh int
	// Stale counts enabled devices not seen within it. They are still sent a
	// challenge; they are just not the only thing offered.
	Stale int
	// Suspended counts devices the system disabled (sweep or administrator).
	// Push is not offered through them, but the user still has a second
	// factor: the login must keep asking for one.
	Suspended int
	// LastSeen is the most recent sighting of any of the devices above, nil
	// when there are none.
	LastSeen *time.Time
}

// Offerable reports whether a push challenge has an enabled device to go to.
func (l PushLiveness) Offerable() bool { return l.Fresh+l.Stale > 0 }

// Unseen reports whether the user has push (enabled or suspended) and no
// device of it has been seen within the window.
func (l PushLiveness) Unseen() bool { return l.Fresh == 0 && l.Stale+l.Suspended > 0 }

// AssessPushLiveness sorts a user's push devices by liveness at now. A device
// the user switched off themselves (disabled with no system mark) is ignored,
// as it always was.
func AssessPushLiveness(devices []PushMFADevice, now time.Time, staleAfter time.Duration) PushLiveness {
	var l PushLiveness
	for _, d := range devices {
		switch {
		case d.Enabled:
			if now.Sub(pushDeviceSeen(d)) > staleAfter {
				l.Stale++
			} else {
				l.Fresh++
			}
		case d.DisabledAt != nil:
			l.Suspended++
		default:
			continue
		}
		seen := pushDeviceSeen(d)
		if l.LastSeen == nil || seen.After(*l.LastSeen) {
			l.LastSeen = &seen
		}
	}
	return l
}

// PushDeviceStale reports whether an enabled device has gone unseen for longer
// than staleAfter.
func PushDeviceStale(d PushMFADevice, now time.Time, staleAfter time.Duration) bool {
	return now.Sub(pushDeviceSeen(d)) > staleAfter
}

// mostRecentlySeenEnabled returns the enabled device seen most recently, or
// nil when there is none.
func mostRecentlySeenEnabled(devices []PushMFADevice) *PushMFADevice {
	var best *PushMFADevice
	for i := range devices {
		d := &devices[i]
		if !d.Enabled {
			continue
		}
		if best == nil || pushDeviceSeen(*d).After(pushDeviceSeen(*best)) {
			best = d
		}
	}
	return best
}

// PushDeviceStaleAfter is the configured stale window (PUSH_DEVICE_STALE_DAYS,
// default 30 days).
func (s *Service) PushDeviceStaleAfter() time.Duration {
	if s.cfg == nil {
		return 30 * 24 * time.Hour
	}
	return s.cfg.PushMFA.StaleDeviceAfter()
}

// StartPushDeviceSweep starts the leader-gated sweep that disables push devices
// unseen for PUSH_DEVICE_DISABLE_DAYS. It changes devices across every org,
// so it runs bypassed, like the other admin-plane sweeps; each device's org is
// returned and carried on its audit event. A window of 0 leaves it off.
func (s *Service) StartPushDeviceSweep(ctx context.Context) {
	if s.cfg == nil || s.cfg.PushMFA.DisableDeviceAfter() <= 0 {
		s.logger.Info("Push device sweep not started: PUSH_DEVICE_DISABLE_DAYS is 0")
		return
	}
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Push device sweep started",
		zap.Duration("disable_after", s.cfg.PushMFA.DisableDeviceAfter()))
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "identity:push-device-sweep", 1*time.Hour, func(ctx context.Context) {
		if _, err := s.sweepStalePushDevices(ctx, time.Now(), s.cfg.PushMFA.DisableDeviceAfter()); err != nil {
			s.logger.Error("push device sweep failed", zap.Error(err))
		}
	})
}

// pushSweepBatch bounds how many devices one tick disables; the rest wait for
// the next.
const pushSweepBatch = 500

// sweptPushDevice is one device the sweep disabled.
type sweptPushDevice struct {
	ID, UserID, OrgID, Name, Platform string
	LastSeen                          time.Time
}

// sweepStalePushDevices disables every enabled push device unseen since
// now - disableAfter and writes one audit event per device. It is idempotent:
// a disabled device is not enabled, so a second run finds nothing. ctx must
// be bypassed (StartPushDeviceSweep does it).
func (s *Service) sweepStalePushDevices(ctx context.Context, now time.Time, disableAfter time.Duration) ([]sweptPushDevice, error) {
	if s.db == nil || s.db.Pool == nil || disableAfter <= 0 {
		return nil, nil
	}
	cutoff := now.Add(-disableAfter)
	//orgscope:ignore background sweep of push devices across all orgs; each row's org is returned and audited
	rows, err := s.db.Pool.Query(ctx, `
		WITH due AS (
			SELECT id FROM mfa_push_devices
			 WHERE COALESCE(enabled, false)
			   AND COALESCE(last_seen_at, last_used_at, created_at) < $1
			 ORDER BY COALESCE(last_seen_at, last_used_at, created_at)
			 LIMIT $2
			 FOR UPDATE SKIP LOCKED
		)
		UPDATE mfa_push_devices p
		   SET enabled = false, disabled_at = $3, disabled_reason = $4
		  FROM due
		 WHERE p.id = due.id AND COALESCE(p.enabled, false)
		RETURNING p.id::text, p.user_id::text, p.org_id::text, COALESCE(p.device_name, ''), p.platform,
		          COALESCE(p.last_seen_at, p.last_used_at, p.created_at)`,
		cutoff, pushSweepBatch, now, PushDisabledStale)
	if err != nil {
		return nil, err
	}
	var swept []sweptPushDevice
	for rows.Next() {
		var d sweptPushDevice
		if err := rows.Scan(&d.ID, &d.UserID, &d.OrgID, &d.Name, &d.Platform, &d.LastSeen); err != nil {
			s.logger.Error("push device disabled but could not be read for the audit trail", zap.Error(err))
			continue
		}
		swept = append(swept, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return swept, err
	}
	for _, d := range swept {
		s.logAuditEvent(orgctx.With(ctx, orgctx.Org{ID: d.OrgID}), "identity", "mfa", "push_device.disabled_stale", "success",
			"system", d.ID, "push_device", map[string]interface{}{
				"user_id":       d.UserID,
				"device_name":   d.Name,
				"platform":      d.Platform,
				"last_seen_at":  d.LastSeen.UTC().Format(time.RFC3339),
				"unseen_days":   int(now.Sub(d.LastSeen).Hours() / 24),
				"disable_after": int(disableAfter.Hours() / 24),
			})
	}
	if len(swept) > 0 {
		s.logger.Info("push devices disabled: not seen within the window",
			zap.Int("count", len(swept)), zap.Time("cutoff", cutoff))
	}
	return swept, nil
}

// disablePushDeviceForUser disables one of a user's push devices on an
// administrator's say-so, in the caller's org. It returns false when the
// device is not the user's (or not in the org).
func (s *Service) disablePushDeviceForUser(ctx context.Context, orgID, userID, deviceID string) (bool, error) {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE mfa_push_devices
		   SET enabled = false,
		       disabled_at = COALESCE(disabled_at, NOW()),
		       disabled_reason = COALESCE(disabled_reason, $4)
		 WHERE id = $1 AND user_id = $2 AND org_id = $3`,
		deviceID, userID, orgID, PushDisabledAdmin)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		s.logger.Info("push device not found for disable",
			logsafe.String("user_id", userID), logsafe.String("device_id", deviceID))
		return false, nil
	}
	return true, nil
}
