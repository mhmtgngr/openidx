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
