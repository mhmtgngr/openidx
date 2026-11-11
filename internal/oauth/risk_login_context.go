package oauth

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/identity"
)

// prevLoginLookup resolves the previous geolocated sign-in for a user.
type prevLoginLookup func(ctx context.Context, userID string, before time.Time) (ip string, lat, lon float64, at time.Time, ok bool)

// fillLoginHistory populates the history half of the adaptive-risk
// LoginContext (B7.4). Before this, FailedAttempts / LastLogin* were always
// zero, so the impossible-travel, new-location and failed-attempt checks in
// identity.AssessLoginRisk could never fire.
func (s *Service) fillLoginHistory(ctx context.Context, lc *identity.LoginContext, user *identity.User) {
	var lookup prevLoginLookup
	if s.riskService != nil {
		lookup = s.riskService.PreviousLoginLocation
	}
	populateLoginHistory(ctx, lc, user, lookup)
}

func populateLoginHistory(ctx context.Context, lc *identity.LoginContext, user *identity.User, lookup prevLoginLookup) {
	failed, lastLogin := user.RiskLoginStats()
	lc.FailedAttempts = failed
	if lastLogin == nil || lookup == nil {
		return
	}
	ip, lat, lon, at, ok := lookup(ctx, user.ID, *lastLogin)
	if !ok {
		return
	}
	t := at
	lc.LastLoginIP = ip
	lc.LastLoginLat = lat
	lc.LastLoginLon = lon
	lc.LastLoginTime = &t
}
