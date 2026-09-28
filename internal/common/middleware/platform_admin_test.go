package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The decision behind RequirePlatformAdmin, isInstallAdministrator, driven
// without a database: a fake users lookup answers with an organization, no
// row, or an error, and records whether it was asked at all and under which RLS
// scope. The same decision against a real Postgres, as a non-superuser under
// the FORCE'd belt, is in platform_admin_testdb_test.go.

const platformTestUser = "11111111-1111-1111-1111-111111111111"

type fakeUserOrgRow struct {
	org string
	err error
}

func (r fakeUserOrgRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.org
	return nil
}

// fakeUserOrgs answers the users lookup from a map; a missing id is no row.
type fakeUserOrgs struct {
	orgs     map[string]string
	err      error
	asked    int
	bypassed bool
}

func (f *fakeUserOrgs) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	f.asked++
	f.bypassed = orgctx.IsBypassRLS(ctx)
	if f.err != nil {
		return fakeUserOrgRow{err: f.err}
	}
	org, ok := f.orgs[args[0].(string)]
	if !ok {
		return fakeUserOrgRow{err: pgx.ErrNoRows}
	}
	return fakeUserOrgRow{org: org}
}

// decide runs isInstallAdministrator inside a real gin request, so the caller's
// roles, subject and -- when one is given -- credential organization are read
// from the context exactly as the middleware reads them.
func decide(t *testing.T, q userOrgQuerier, userID string, roles []string, credentialOrg ...string) (bool, error) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var (
		ok  bool
		err error
	)
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
		if roles != nil {
			c.Set("roles", roles)
		}
		if len(credentialOrg) > 0 {
			c.Set("org_id", credentialOrg[0])
		}
		ok, err = isInstallAdministrator(c, q)
		c.Status(http.StatusNoContent)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	return ok, err
}

func TestInstallAdministratorDecision(t *testing.T) {
	const otherOrg = "33333333-3333-3333-3333-333333333333"
	for _, tc := range []struct {
		name      string
		userID    string
		roles     []string
		orgs      map[string]string
		want      bool
		wantAsked bool
	}{
		{"an admin of the default organization is one", platformTestUser, []string{"admin"},
			map[string]string{platformTestUser: DefaultOrgID}, true, true},
		{"a super_admin of the default organization is one", platformTestUser, []string{"super_admin"},
			map[string]string{platformTestUser: DefaultOrgID}, true, true},
		{"an admin whose own organization is another is not", platformTestUser, []string{"admin"},
			map[string]string{platformTestUser: otherOrg}, false, true},
		{"a super_admin whose own organization is another is not", platformTestUser, []string{"admin", "super_admin"},
			map[string]string{platformTestUser: otherOrg}, false, true},
		{"a subject with no user row is not", platformTestUser, []string{"admin"},
			map[string]string{}, false, true},
		// Refused before any query: the role test is free and comes first.
		{"a plain user of the default organization is not", platformTestUser, []string{"user"},
			map[string]string{platformTestUser: DefaultOrgID}, false, false},
		{"a caller with no roles is not", platformTestUser, nil,
			map[string]string{platformTestUser: DefaultOrgID}, false, false},
		{"a service account is not", "", []string{"service_account"}, nil, false, false},
		{"a subject that is not a user id is not", "client:ci-bot", []string{"admin"}, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeUserOrgs{orgs: tc.orgs}
			got, err := decide(t, q, tc.userID, tc.roles)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("install administrator = %v, want %v", got, tc.want)
			}
			if asked := q.asked > 0; asked != tc.wantAsked {
				t.Errorf("users lookup asked = %v, want %v", asked, tc.wantAsked)
			}
			if q.asked > 0 && !q.bypassed {
				t.Error("the users lookup ran under the request's tenant scope; a platform admin " +
					"working in another tenant would find no row of their own and be refused")
			}
		})
	}
}

// The roles a credential carries hold in the organization it was issued in, so
// where the validator bound that organization it has to be the default one as
// well. A user whose own row is in the default organization but who presents a
// credential of another organization is refused, before any query; a bound
// organization that names nothing is a refusal too, not an absence. Whether
// DEFAULT_ORG_ID can move the rule is asked of each service that mounts the
// gate, which is where that setting is read: see
// TestTheFallbackOrganizationDoesNotChooseInstallAdministrators in
// internal/admin and the settings tests of identity and access.
func TestInstallAdministratorNeedsTheCredentialsOrganization(t *testing.T) {
	const otherOrg = "33333333-3333-3333-3333-333333333333"
	for _, tc := range []struct {
		name          string
		credentialOrg string
		want, asked   bool
	}{
		{"a credential of the default organization", DefaultOrgID, true, true},
		{"a credential of another organization", otherOrg, false, false},
		{"a credential that names no organization", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeUserOrgs{orgs: map[string]string{platformTestUser: DefaultOrgID}}
			got, err := decide(t, q, platformTestUser, []string{"admin"}, tc.credentialOrg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("install administrator = %v, want %v", got, tc.want)
			}
			if asked := q.asked > 0; asked != tc.asked {
				t.Errorf("users lookup asked = %v, want %v", asked, tc.asked)
			}
		})
	}
}

// A lookup that fails is an error, not a "no": the middleware answers 503 for
// it, and it must never answer 2xx.
func TestPlatformAdminLookupFailureIsAnError(t *testing.T) {
	q := &fakeUserOrgs{err: errors.New("connection refused")}
	ok, err := decide(t, q, platformTestUser, []string{"admin"})
	if ok || err == nil {
		t.Fatalf("got (%v, %v), want (false, error)", ok, err)
	}
}

// The exported decision, for handlers that show an install administrator more,
// fails the same way the middleware does when it has no database: a caller it
// cannot refuse on roles is an error, never a quiet "no" that a handler might
// read as the organization's view and never a "yes".
func TestIsInstallAdministratorWithoutADatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		roles   []string
		wantErr bool
	}{
		{"a plain user is not one, without a lookup", []string{"user"}, false},
		{"an admin cannot be decided", []string{"admin"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				ok  bool
				err error
			)
			r := gin.New()
			r.GET("/", func(c *gin.Context) {
				c.Set("user_id", platformTestUser)
				c.Set("roles", tc.roles)
				ok, err = IsInstallAdministrator(c, nil)
				c.Status(http.StatusNoContent)
			})
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			if ok || (err != nil) != tc.wantErr {
				t.Fatalf("got (%v, %v), want (false, error=%v)", ok, err, tc.wantErr)
			}
		})
	}
}

// The middleware itself, with no database behind it: every caller it cannot
// refuse on roles alone is refused because it cannot look, and nobody reaches
// the handler.
func TestRequirePlatformAdminWithoutADatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name      string
		roles     []string
		wantCode  int
		wantError string
	}{
		{"a plain user is refused on roles", []string{"user"}, http.StatusForbidden, PlatformAdminRequired},
		{"an admin is refused because nothing could be checked", []string{"admin"}, http.StatusServiceUnavailable, "platform administrator check unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("user_id", platformTestUser)
				c.Set("roles", tc.roles)
				c.Next()
			})
			r.PUT("/settings", RequirePlatformAdmin(nil, zap.NewNop()), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusOK)
			})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/settings", nil))
			if w.Code != tc.wantCode || reached {
				t.Fatalf("status %d (handler reached: %v), want %d and not reached", w.Code, reached, tc.wantCode)
			}
			var body map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if body["error"] != tc.wantError {
				t.Errorf("error = %q, want %q", body["error"], tc.wantError)
			}
		})
	}
}
