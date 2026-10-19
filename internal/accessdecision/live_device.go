package accessdecision

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// A WEB SIGN-IN OR A PRIVILEGED SESSION CAN ASK FOR A LIVE DEVICE TOO.
//
// The overlay already refuses a resource that requires a trusted device to
// anything but a compliant device identity that is reporting in. A browser
// sign-in to the same application (OIDC/SAML) and a privileged session
// launched from the console never asked: "device trust" there meant an
// admin-approved browser fingerprint or nothing, and an agent that had been
// stopped for a week changed neither.
//
// UserHasLiveDevice answers the question those paths can ask: does this
// person have at least one enrolled device that is active, compliant and has
// reported within the liveness timeout? It is a statement about the person,
// not about the browser: it does not prove the sign-in comes from that
// device. Binding the browser to the device is a later step; this one makes
// "no agent checking in, no access" true for the person.

// UserHasLiveDevice reports whether userID has an active, compliant device in
// orgID whose agent reported within timeout. A zero timeout drops the
// freshness requirement (the liveness rule is off).
func UserHasLiveDevice(ctx context.Context, db *database.PostgresDB, orgID, userID string, timeout time.Duration) (bool, error) {
	var ok bool
	err := db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM enrolled_agents
		   WHERE org_id = $1::uuid AND enrolled_by_user_id = $2::uuid
		     AND status = 'active' AND compliance_status = 'compliant'
		     AND ($3::bigint = 0 OR last_report_at > NOW() - make_interval(secs => $3::bigint)))`,
		orgID, userID, int64(timeout/time.Second)).Scan(&ok)
	return ok, err
}
