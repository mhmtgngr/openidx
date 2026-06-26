package access

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

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

	// Dedup: one pending request per (user, device).
	var exists int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT 1 FROM device_trust_requests WHERE user_id=$1 AND device_fingerprint=$2 AND status='pending' LIMIT 1`,
		userID, fp).Scan(&exists); err == nil {
		return // already pending
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Warn("device-trust request: dedup check failed", zap.String("user_id", userID), zap.Error(err))
		return
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO device_trust_requests
			(id, user_id, device_id, device_fingerprint, device_name, device_type,
			 ip_address, user_agent, justification, status, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 'unknown', $5, $6,
			'Untrusted device attempted access to a device-trust-protected resource', 'pending', NOW())`,
		userID, deviceID, fp, deviceName, ip, userAgent); err != nil {
		s.logger.Warn("device-trust request: insert failed", zap.String("user_id", userID), zap.Error(err))
	}
}
