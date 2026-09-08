package risk

import (
	"context"

	"go.uber.org/zap"
)

// factorCount runs one risk factor's count and says so when it cannot.
//
// WHY THIS EXISTS. Every factor in this engine is a one-row aggregate, and
// every one of them used to discard the Scan error. A one-row aggregate always
// returns exactly one row, so a failure there never means "there is nothing to
// count" -- it means the query did not run, and the destination keeps its zero.
// The engine then scores that zero as a measurement:
//
//	deviceCount  0 -> "Login from unrecognized device" (+10). Harsher.
//	countryCount 0 -> "First login from this country"  (+15). Harsher.
//	mfaCount     0 -> "No MFA method configured"       (+20). Harsher.
//	failedCount  0 -> no brute-force factor at all.     QUIETER.
//
// The last one is the reason this is not cosmetic: a failed count of recent
// failed logins removes the brute-force signal from the score entirely, and
// nothing anywhere said the factor had gone missing. This engine has already
// been caught running with a factor permanently at zero -- the WebAuthn count
// read a table no migration creates, so every user looked like they had no
// WebAuthn, for the life of the query.
//
// A factor that cannot be measured is still scored from the zero it is left
// with, because inventing a number would be worse. But it is logged with its
// name, so an engine running on fewer factors than it thinks is visible instead
// of quiet.
func (s *Service) factorCount(ctx context.Context, factor string, dest any, sql string, args ...any) {
	if err := s.db.Pool.QueryRow(ctx, sql, args...).Scan(dest); err != nil {
		s.logger.Warn("risk factor could not be measured; scoring it from zero",
			zap.String("factor", factor), zap.Error(err))
	}
}
