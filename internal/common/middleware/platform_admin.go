package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// INSTALL-WIDE SETTINGS NEED AN ADMINISTRATOR OF THE DEFAULT ORGANIZATION.
//
// Some configuration exists once per install rather than once per
// organization: the rows of system_settings (SMS delivery, the passwordless
// defaults, the OpenZiti controller connection, the BrowZer domain), the OAuth
// signing keys, the shared IP deny-list and error catalog, the platform TLS
// certificate and key, and the self-heal loop's controls. Changing one of them
// changes it for every organization on the install.
//
// The admin role cannot be what authorizes that. An organization's
// administrators grant it inside their own organization, so on a multi-tenant
// install the admin role says what a caller may do in one organization, while
// these settings decide things for all of them -- including where every
// organization's SMS one-time codes are delivered.
//
// An install administrator holds admin or super_admin in the install's default
// organization, DefaultOrgID, and two facts must both name that organization:
//
//   - The caller's own organization: users.org_id for the token's subject,
//     read from the database on every check. It is deliberately not the
//     organization the request resolved to -- a platform admin working inside
//     another tenant resolves to that tenant, and still administers the
//     install.
//   - The credential's organization, where the validator bound one (org_id in
//     the gin context): the token's signed org_id, or an API key's
//     organization. The roles come from the credential and hold in that
//     organization only, so an admin role granted anywhere else says nothing
//     about the default organization. A token is minted in its holder's own
//     organization, so the two facts agree unless the user has moved since;
//     the second is checked all the same.
//
// It is the canonical default organization, not DEFAULT_ORG_ID. That setting
// names the tenant resolver's fallback, the organization a request with no
// other tenant signal belongs to, and an operator who pointed it at a
// customer's organization would otherwise have made that customer's
// administrators administrators of the whole install.
//
// super_admin is tested the same way as admin: both are granted inside an
// organization, by that organization, so it is the organization and not the
// role that makes the holder an administrator of the install. A fresh install
// seeds only the admin role, and on a single-organization install every user
// belongs to the default organization, so its administrators keep managing
// these settings exactly as before.
//
// This is one of two rules the default organization carries, and the wider
// one. Crossing into another organization needs super_admin held in the
// default organization (IsPlatformAdmin, a platform admin); changing an
// install-wide setting needs admin or super_admin held there. Every platform
// admin is an install administrator, and an admin of the default organization
// who does not hold super_admin is an install administrator without being able
// to act in any other organization. RequirePlatformAdmin and
// PlatformAdminRequired keep the names they were published under.

// PlatformAdminRequired is the error a refused caller receives. The admin
// console recognises it and explains that the setting is install-wide, so it
// must not be reworded without changing the console to match.
const PlatformAdminRequired = "platform administrator required"

// errPlatformAdminNoDatabase is returned when the gate has no database to look
// the caller up in. It fails closed: a gate that cannot look cannot vouch.
var errPlatformAdminNoDatabase = errors.New("platform administrator check has no database")

// userOrgQuerier is the one method the lookup needs, as an interface so the
// decision can be tested without a database.
type userOrgQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// RequirePlatformAdmin admits only an install administrator, as defined above.
// Mount it after authentication, where "roles", "user_id" and "org_id" are set,
// and on every route that changes install-wide configuration or reads a secret
// stored there.
//
// It takes no default organization: the rule is held to DefaultOrgID whatever
// DEFAULT_ORG_ID says. db may be nil when the routes are registered only to be
// listed (the route-table tests do this); a request that reaches the gate then
// fails closed.
func RequirePlatformAdmin(db *database.PostgresDB, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(c *gin.Context) {
		// Resolved per request rather than when the route is registered:
		// services register their routes before every test has a pool, and a
		// nil *ScopedPool held in the interface would not compare equal to nil.
		var q userOrgQuerier
		if db != nil && db.Pool != nil {
			q = db.Pool
		}
		ok, err := isInstallAdministrator(c, q)
		if err != nil {
			logger.Error("could not decide whether the caller is an install administrator; refusing",
				logsafe.String("user_id", c.GetString("user_id")),
				logsafe.String("route", c.Request.Method+" "+c.FullPath()),
				zap.Error(err))
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "platform administrator check unavailable",
			})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": PlatformAdminRequired})
			return
		}
		c.Next()
	}
}

// IsInstallAdministrator is the decision RequirePlatformAdmin enforces, for a
// handler that answers every caller its gates admit but shows an install
// administrator more: the whole of something every organization shares, where
// anyone else sees their own organization's part of it. It returns an error
// only when it could not look, and a handler must then refuse rather than fall
// back to either view. db may be nil, as for RequirePlatformAdmin.
func IsInstallAdministrator(c *gin.Context, db *database.PostgresDB) (bool, error) {
	var q userOrgQuerier
	if db != nil && db.Pool != nil {
		q = db.Pool
	}
	return isInstallAdministrator(c, q)
}

// isInstallAdministrator is the decision behind RequirePlatformAdmin. It is not
// IsPlatformAdmin, which decides who may cross organizations; see the comment
// at the top of this file for how the two relate. It returns an error only when
// it could not look; every "no" is a (false, nil).
func isInstallAdministrator(c *gin.Context, q userOrgQuerier) (bool, error) {
	// The role test comes first and costs nothing: a caller who is not an
	// administrator anywhere is refused without a query.
	if !callerHoldsAdminRole(c) {
		return false, nil
	}
	// So does the credential's organization, when the validator bound one:
	// the roles just read hold in that organization and nowhere else.
	if v, bound := c.Get("org_id"); bound {
		if credentialOrg, _ := v.(string); credentialOrg != DefaultOrgID {
			return false, nil
		}
	}
	// A service account or a token whose subject is not a user id has no row
	// in users, and so no organization of its own.
	userID := c.GetString("user_id")
	if _, err := uuid.Parse(userID); err != nil {
		return false, nil
	}
	if q == nil {
		return false, errPlatformAdminNoDatabase
	}

	// users is behind the FORCE'd RLS belt, and the request's tenant scope is
	// the organization it resolved to -- which for a platform admin working in
	// another tenant is not their own, so a scoped read would find no row and
	// refuse them. The bypass is safe because the read is keyed by the
	// caller's own user id and returns only that user's organization.
	var orgID string
	err := q.QueryRow(orgctx.WithBypassRLS(c.Request.Context()),
		//orgscope:ignore platform-administrator check: reads the caller's own organization by their globally-unique user id, which must not depend on the tenant the request resolved to
		`SELECT org_id::text FROM users WHERE id = $1`, userID).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return orgID == DefaultOrgID, nil
}
