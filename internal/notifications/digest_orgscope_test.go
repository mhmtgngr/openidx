package notifications

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The digest settings handlers, migration v163.
//
// notification_digests is the one table in this programme's register that was
// NOT reachable across tenants: both queries address it by user_id, and that
// user id is the caller's own, taken from their token. The tenant term v163
// adds is defence in depth behind the FORCE RLS belt, not a leak being closed —
// so what is worth asserting here is the direction of the failure, which is
// what the belt makes load-bearing: a request with no organization on its
// context must be refused rather than run unscoped.
//
// This package tests its guards with a nil pool, because they fire before any
// database access. Cross-tenant containment for this table is proved by
// TestRLSBeltTables in test/integration.
func TestDigestSettings_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := NewService(nil, zap.NewNop())

	for name, tc := range map[string]struct {
		handler gin.HandlerFunc
		method  string
		body    string
	}{
		"get":    {s.handleGetDigestSettings, "GET", ""},
		"update": {s.handleUpdateDigestSettings, "PUT", `{"digest_type":"daily","channel":"email","enabled":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(tc.method, "/notifications/digest",
				strings.NewReader(tc.body)).WithContext(context.Background()) // bare context
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("user_id", "11111111-1111-1111-1111-111111111111")

			tc.handler(c)

			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s. "+
					"The table is behind the FORCE RLS belt from v163, so an "+
					"unscoped read returns nothing and reads as \"you have no "+
					"digest settings\" — the wrong direction for a failure",
					name, w.Code, w.Body.String())
			}
		})
	}
}
