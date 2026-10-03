package governance

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// openToSignedInUsers are the governance writes an ordinary signed-in user is
// meant to reach: their handlers decide who may do each (the requester, an
// approver of the request's step, the reviewer of a review, the access-proxy
// with the internal token on an evaluate route). Every other write runs the
// governance program itself and needs an administrator when OPA is not in the
// request path. A new write is gated unless it is added here, with its
// reason.
var openToSignedInUsers = map[string]string{
	"POST /api/v1/governance/requests":                           "a user files their own access request",
	"POST /api/v1/governance/requests/:id/approve":               "an approver of the request's step; the handler checks",
	"POST /api/v1/governance/requests/:id/deny":                  "an approver of the request's step; the handler checks",
	"POST /api/v1/governance/requests/:id/cancel":                "the requester; the handler checks",
	"POST /api/v1/governance/requests/:id/credential":            "the requester of a vault request; the handler checks",
	"POST /api/v1/governance/requests/:id/return":                "the requester of a vault request; the handler checks",
	"POST /api/v1/governance/reviews/:id/items/:itemId/decision": "the review's reviewer or an administrator; authorizeReviewDecision",
	"POST /api/v1/governance/reviews/:id/items/batch-decision":   "the review's reviewer or an administrator; authorizeReviewDecision",
	"POST /api/v1/governance/policies/:id/evaluate":              "a policy evaluation, also reached by the access-proxy with the internal token",
	"POST /api/v1/governance/abac-policies/evaluate":             "an ABAC evaluation, also reached by the access-proxy with the internal token",
}

// TestGovernanceProgramWritesNeedAnAdministratorWithoutOPA drives the REAL
// route table behind the REAL authentication middleware, with access tokens
// signed by a key the service trusts. Without OPA (the default), every
// governance write not on openToSignedInUsers answers a plain user, an
// operator and an auditor 403 admin_required, and lets an administrator and a
// super administrator through to its handler. With OPA on, the gate defers to
// the policy and lets the plain user through too. The open writes are not
// stopped by it.
func TestGovernanceProgramWritesNeedAnAdministratorWithoutOPA(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const issuer = "https://issuer.example.test"
	token := func(roles ...string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "11111111-0000-0000-0000-000000000001", "iss": issuer,
			"exp": time.Now().Add(time.Hour).Unix(), "client_id": "admin-console",
			"openidx_api": true, "org_id": "00000000-0000-0000-0000-000000000010",
			"roles": roles,
		})
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}
	engine := func(opa bool) *gin.Engine {
		svc := NewService(&database.PostgresDB{}, &database.RedisClient{},
			&config.Config{OAuthIssuer: issuer, EnableOPAAuthz: opa}, zap.NewNop())
		svc.jwksCachedKey = &key.PublicKey
		svc.jwksCacheExpiry = time.Now().Add(time.Hour)
		r := gin.New()
		r.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
		RegisterRoutes(r, svc)
		return r
	}
	gated := func(r *gin.Engine, method, path, bearer string) (bool, int) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		r.ServeHTTP(w, req)
		return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `"admin_required"`), w.Code
	}
	concrete := func(path string) string {
		parts := strings.Split(path, "/")
		for i, p := range parts {
			if strings.HasPrefix(p, ":") {
				parts[i] = "00000000-0000-0000-0000-0000000000aa"
			}
		}
		return strings.Join(parts, "/")
	}

	withoutOPA, withOPA := engine(false), engine(true)
	writes := 0
	for _, ri := range withoutOPA.Routes() {
		if ri.Method == http.MethodGet || !strings.HasPrefix(ri.Path, "/api/v1/governance/") {
			continue
		}
		key := ri.Method + " " + ri.Path
		path := concrete(ri.Path)
		if _, open := openToSignedInUsers[key]; open {
			if g, code := gated(withoutOPA, ri.Method, path, token("user")); g {
				t.Errorf("%s is open to signed-in users by design, and the admin gate stopped a plain user (%d)", key, code)
			}
			continue
		}
		writes++
		for _, roles := range [][]string{{"user"}, {"operator"}, {"auditor"}, {}} {
			if g, code := gated(withoutOPA, ri.Method, path, token(roles...)); !g {
				t.Errorf("without OPA, %s let a caller with roles %v past the admin gate (%d); a governance write "+
					"that is not on openToSignedInUsers needs an administrator", key, roles, code)
			}
		}
		for _, role := range []string{"admin", "super_admin"} {
			if g, code := gated(withoutOPA, ri.Method, path, token(role)); g {
				t.Errorf("without OPA, %s stopped an %s at the admin gate (%d)", key, role, code)
			}
		}
		if g, code := gated(withOPA, ri.Method, path, token("user")); g {
			t.Errorf("with OPA on, %s was decided by the admin gate rather than the policy (%d)", key, code)
		}
	}
	if writes < 15 {
		t.Fatalf("only %d gated governance writes were found; the census is not reading the route table", writes)
	}
	for key := range openToSignedInUsers {
		method, path, _ := strings.Cut(key, " ")
		found := false
		for _, ri := range withoutOPA.Routes() {
			if ri.Method == method && ri.Path == path {
				found = true
			}
		}
		if !found {
			t.Errorf("openToSignedInUsers names %s, which governance no longer serves; delete the line", key)
		}
	}
}

// openReadsToSignedInUsers are the governance reads an ordinary signed-in user
// is meant to reach; their handlers decide what each caller sees (their own
// requests, the requests they approve, the reviews they are the reviewer of).
var openReadsToSignedInUsers = map[string]string{
	"GET /api/v1/governance/requests":          "the caller's own requests, or all for an administrator; the handler pins",
	"GET /api/v1/governance/requests/:id":      "its requester, an approver, the external requester's sponsor, an administrator",
	"GET /api/v1/governance/my-approvals":      "the caller's own approval queue",
	"GET /api/v1/governance/reviews":           "access reviews, read by their reviewer",
	"GET /api/v1/governance/reviews/:id":       "access reviews, read by their reviewer",
	"GET /api/v1/governance/reviews/:id/items": "access reviews, read by their reviewer",
}

// TestGovernanceProgramReadsNeedAReaderWithoutOPA: without OPA, every
// governance read not on openReadsToSignedInUsers answers a plain user and a
// caller with no roles 403 reader_required, and lets an administrator, a super
// administrator, an operator and an auditor through; with OPA on it defers to
// the policy. The open reads are not stopped.
func TestGovernanceProgramReadsNeedAReaderWithoutOPA(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const issuer = "https://issuer.example.test"
	token := func(roles ...string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "11111111-0000-0000-0000-000000000001", "iss": issuer,
			"exp": time.Now().Add(time.Hour).Unix(), "client_id": "admin-console",
			"openidx_api": true, "org_id": "00000000-0000-0000-0000-000000000010",
			"roles": roles,
		})
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}
	engine := func(opa bool) *gin.Engine {
		svc := NewService(&database.PostgresDB{}, &database.RedisClient{},
			&config.Config{OAuthIssuer: issuer, EnableOPAAuthz: opa}, zap.NewNop())
		svc.jwksCachedKey = &key.PublicKey
		svc.jwksCacheExpiry = time.Now().Add(time.Hour)
		r := gin.New()
		r.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
		RegisterRoutes(r, svc)
		return r
	}
	refused := func(r *gin.Engine, path, bearer string) (bool, int) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		r.ServeHTTP(w, req)
		return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `"reader_required"`), w.Code
	}
	withoutOPA, withOPA := engine(false), engine(true)
	gatedReads := 0
	for _, ri := range withoutOPA.Routes() {
		if ri.Method != http.MethodGet || !strings.HasPrefix(ri.Path, "/api/v1/governance/") {
			continue
		}
		key := ri.Method + " " + ri.Path
		path := strings.ReplaceAll(ri.Path, ":id", "00000000-0000-0000-0000-0000000000aa")
		if _, open := openReadsToSignedInUsers[key]; open {
			if g, code := refused(withoutOPA, path, token("user")); g {
				t.Errorf("%s is open to signed-in users by design, and the reader gate stopped a plain user (%d)", key, code)
			}
			continue
		}
		gatedReads++
		for _, roles := range [][]string{{"user"}, {}} {
			if g, code := refused(withoutOPA, path, token(roles...)); !g {
				t.Errorf("without OPA, %s let a caller with roles %v read it (%d)", key, roles, code)
			}
		}
		for _, role := range []string{"admin", "super_admin", "operator", "auditor"} {
			if g, code := refused(withoutOPA, path, token(role)); g {
				t.Errorf("without OPA, %s refused an %s (%d)", key, role, code)
			}
		}
		if g, code := refused(withOPA, path, token("user")); g {
			t.Errorf("with OPA on, %s was decided by the reader gate rather than the policy (%d)", key, code)
		}
	}
	if gatedReads < 12 {
		t.Fatalf("only %d gated governance reads were found; the census is not reading the route table", gatedReads)
	}
	for key := range openReadsToSignedInUsers {
		method, path, _ := strings.Cut(key, " ")
		found := false
		for _, ri := range withoutOPA.Routes() {
			if ri.Method == method && ri.Path == path {
				found = true
			}
		}
		if !found {
			t.Errorf("openReadsToSignedInUsers names %s, which governance no longer serves; delete the line", key)
		}
	}
}
