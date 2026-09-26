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

// The decision behind RequirePlatformAdmin, driven without a database: a fake
// users lookup answers with an organization, no row, or an error, and records
// whether it was asked at all and under which RLS scope. The same decision
// against a real Postgres, as a non-superuser under the FORCE'd belt, is in
// platform_admin_testdb_test.go.

const (
	platformTestUser  = "11111111-1111-1111-1111-111111111111"
	platformTestOther = "22222222-2222-2222-2222-222222222222"
)

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

// decide runs isPlatformAdmin inside a real gin request, so the caller's roles
// and subject are read from the context exactly as the middleware reads them.
func decide(t *testing.T, q userOrgQuerier, defaultOrg, userID string, roles []string) (bool, error) {
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
		ok, err = isPlatformAdmin(c, q, defaultOrg)
		c.Status(http.StatusNoContent)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	return ok, err
}

func TestPlatformAdminDecision(t *testing.T) {
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
			got, err := decide(t, q, DefaultOrgID, tc.userID, tc.roles)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("platform administrator = %v, want %v", got, tc.want)
			}
			if asked := q.asked > 0; asked != tc.wantAsked {
				t.Errorf("users lookup asked = %v, want %v", asked, tc.wantAsked)
			}
			if q.asked > 0 && !q.bypassed {
				t.Error("the users lookup ran under the request's tenant scope; a platform administrator " +
					"working in another tenant would find no row of their own and be refused")
			}
		})
	}
}

// DEFAULT_ORG_ID can name an organization other than the seeded one; the
// install's default organization is whichever one it names.
func TestPlatformAdminFollowsTheConfiguredDefaultOrganization(t *testing.T) {
	const configured = "44444444-4444-4444-4444-444444444444"
	q := &fakeUserOrgs{orgs: map[string]string{platformTestUser: configured, platformTestOther: DefaultOrgID}}

	if ok, err := decide(t, q, configured, platformTestUser, []string{"admin"}); err != nil || !ok {
		t.Errorf("an admin of the configured default organization: got (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := decide(t, q, configured, platformTestOther, []string{"admin"}); err != nil || ok {
		t.Errorf("an admin of the seeded organization, which DEFAULT_ORG_ID no longer names: got (%v, %v), want (false, nil)", ok, err)
	}
}

// A lookup that fails is an error, not a "no": the middleware answers 503 for
// it, and it must never answer 2xx.
func TestPlatformAdminLookupFailureIsAnError(t *testing.T) {
	q := &fakeUserOrgs{err: errors.New("connection refused")}
	ok, err := decide(t, q, DefaultOrgID, platformTestUser, []string{"admin"})
	if ok || err == nil {
		t.Fatalf("got (%v, %v), want (false, error)", ok, err)
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
			r.PUT("/settings", RequirePlatformAdmin(nil, "", zap.NewNop()), func(c *gin.Context) {
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
