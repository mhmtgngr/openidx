package stepup

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/syssettings"
)

// MaxAge resolves the freshness window for this install.
//
// `security.reauth_interval` has existed in three places and been read by
// nothing: as a column on application_sso_settings (v63), as a field of the
// console's settings document, and as SessionPolicy.ReauthInterval, which
// getEffectiveSessionPolicy populates and no caller consults. It is the
// setting an operator would reasonably expect to control exactly this, so it
// is the setting this gate reads — a field with a reader at last, rather than
// a fourth name for the same idea.
//
// Precedence: the console setting when an operator has set one (> 0),
// otherwise the deployment default from STEPUP_MAX_AGE, otherwise
// DefaultMaxAge. A read failure falls back to the deployment default rather
// than to "no window": failing open on the window would turn an enabled gate
// into a gate that gates nothing, silently, which is the failure this whole
// change exists to stop.
//
// The window is install-wide because the settings document is
// (system_settings has no org_id by design — migration v034). The
// per-application override on application_sso_settings.reauth_interval is NOT
// read here and remains unread: this gate protects PAM launches and admin
// writes, which are not requests to an application, so there is no application
// whose override would apply. Saying that plainly is better than wiring a
// lookup that would have to invent which application a PAM launch belongs to.
func MaxAge(ctx context.Context, db *database.PostgresDB, deploymentDefault time.Duration) time.Duration {
	if deploymentDefault <= 0 {
		deploymentDefault = DefaultMaxAge
	}
	if db == nil || db.Pool == nil {
		return deploymentDefault
	}
	settings, err := syssettings.Load(ctx, db.Pool)
	if err != nil {
		return deploymentDefault
	}
	if settings.Security.ReauthInterval > 0 {
		return time.Duration(settings.Security.ReauthInterval) * time.Second
	}
	return deploymentDefault
}
