package access

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/risk"
)

// deviceTrusted reports whether the request's device is a trusted known_device.
// Trust is per-device: it matches the authoritative known_devices.trusted flag by
// (user_id, fingerprint), where the fingerprint is computed the same way the risk
// service writes it (sha256 of the IP's /24 subnet + User-Agent). Absence of a row,
// an untrusted row, or any error all yield false (a missing device is not trusted).
func (s *Service) deviceTrusted(ctx context.Context, userID, ip, userAgent string) bool {
	if userID == "" {
		return false
	}
	// Bypass RLS: forward-auth runs with no resolved org; the device is keyed by
	// the already-authenticated user_id (globally unique) + fingerprint.
	ctx = orgctx.WithBypassRLS(ctx)
	fp := risk.ComputeDeviceFingerprint(ip, userAgent)

	var trusted bool
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore proxy data-plane device-trust read; resolves the already-authenticated session user's device by user_id + fingerprint (user_id is globally unique)
		`SELECT trusted FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`,
		userID, fp).Scan(&trusted)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("device-trust lookup failed", zap.String("user_id", userID), zap.Error(err))
		}
		return false
	}
	return trusted
}

// ensureDeviceTrustRequest files a pending device-trust request for an untrusted
// device that attempted access, so an admin can approve it (which flips
// known_devices.trusted=true, after which deviceTrusted returns true). Best-effort:
// every error is logged and swallowed so it never blocks the proxied request.
// Idempotent — a device with an existing pending request is not re-filed.
func (s *Service) ensureDeviceTrustRequest(ctx context.Context, userID, ip, userAgent string) {
	if userID == "" {
		return
	}
	// Bypass RLS: forward-auth runs with no resolved org; keyed by the
	// already-authenticated user_id (globally unique) + fingerprint.
	ctx = orgctx.WithBypassRLS(ctx)
	fp := risk.ComputeDeviceFingerprint(ip, userAgent)

	// The device must already be registered (the login/risk path creates the
	// known_devices row). Pull its id + name for the request.
	var deviceID, deviceName string
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore proxy data-plane device-trust write; the already-authenticated session user's device by user_id + fingerprint
		`SELECT id, COALESCE(name,'') FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`,
		userID, fp).Scan(&deviceID, &deviceName)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("device-trust request: known_devices lookup failed", zap.String("user_id", userID), zap.Error(err))
		}
		return
	}

	// THE TENANT, AND WHY THIS FUNCTION HAD NEVER ONCE WORKED.
	//
	// v72 gave device_trust_requests an org_id and made it NOT NULL, with no
	// default. This INSERT was never updated. Since v72 it has failed on every
	// single call with
	//
	//	null value in column "org_id" ... violates not-null constraint (23502)
	//
	// and the error was logged at WARN and swallowed, because this whole
	// function is best-effort so it can never block the proxied request. So the
	// enforcement path refused an untrusted device, said it was filing a request
	// for an admin to approve, and filed nothing -- every time, on every
	// install, for as long as the column has existed. The identity-side writer
	// in internal/identity/device_trust_approval.go always wrote the tenant;
	// this one, the pair's other half, never did.
	//
	// Forward-auth carries no resolved org (hence the bypass above), so the
	// tenant comes from the already-authenticated user, which is exact: a user
	// belongs to exactly one organization. Without it the row would be filed
	// nowhere, and the approval queue is org-scoped on every read.
	var orgID string
	if err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore proxy data-plane device-trust write; resolves the already-authenticated session user's tenant (user_id is globally unique)
		`SELECT org_id::text FROM users WHERE id=$1`, userID).Scan(&orgID); err != nil || orgID == "" {
		s.logger.Warn("device-trust request: cannot resolve the user's organization; not filing",
			zap.String("user_id", userID), zap.Error(err))
		return
	}

	// Dedup: one pending request per (user, device), within the tenant.
	var exists int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT 1 FROM device_trust_requests
		 WHERE user_id=$1 AND device_fingerprint=$2 AND status='pending' AND org_id=$3 LIMIT 1`,
		userID, fp, orgID).Scan(&exists); err == nil {
		return // already pending
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Warn("device-trust request: dedup check failed", zap.String("user_id", userID), zap.Error(err))
		return
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO device_trust_requests
			(id, user_id, device_id, device_fingerprint, device_name, device_type,
			 ip_address, user_agent, justification, status, org_id, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 'unknown', $5, $6,
			'Untrusted device attempted access to a device-trust-protected resource', 'pending', $7, NOW())`,
		userID, deviceID, fp, deviceName, ip, userAgent, orgID); err != nil {
		s.logger.Warn("device-trust request: insert failed", zap.String("user_id", userID), zap.Error(err))
	}
}
