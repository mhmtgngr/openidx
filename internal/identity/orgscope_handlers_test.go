package identity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The invitation and email-verification endpoints are HTTP handlers,
// so the org-scoping contract is verified at the gin layer: with no
// org on the request context (the resolver never ran), each handler
// must bail out with an error status BEFORE touching the database.
// The service is built with a nil pool, so if a handler reached SQL it
// would panic — a clean non-200 response proves the org guard is the
// first thing each handler does.
func TestInvitationAndVerifyHandlers_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := NewService(nil, nil, nil, zap.NewNop())

	cases := []struct {
		name    string
		method  string
		path    string
		route   string
		handler gin.HandlerFunc
		body    string
		userID  string
	}{
		{"VerifyEmail", "POST", "/verify-email", "/verify-email", svc.handleVerifyEmail, `{"token":"t"}`, ""},
		{"ResendVerification", "POST", "/resend", "/resend", svc.handleResendVerification, ``, "u-1"},
		{"ListInvitations", "GET", "/invitations", "/invitations", svc.handleListInvitations, ``, "u-1"},
		{"CreateInvitation", "POST", "/invitations", "/invitations", svc.handleCreateInvitation, `{"email":"a@b.com"}`, "u-1"},
		{"DeleteInvitation", "DELETE", "/invitations/i-1", "/invitations/:id", svc.handleDeleteInvitation, ``, "u-1"},
		{"AcceptInvitation", "POST", "/invitations/tok/accept", "/invitations/:token/accept", svc.handleAcceptInvitation, `{"username":"u","password":"p"}`, ""},

		{"GetMyPrivacyConsents", "GET", "/me/consents", "/me/consents", svc.handleGetMyPrivacyConsents, ``, "u-1"},
		{"GrantPrivacyConsent", "POST", "/me/consents", "/me/consents", svc.handleGrantPrivacyConsent, `{"consent_type":"marketing"}`, "u-1"},
		{"RevokePrivacyConsent", "DELETE", "/me/consents/marketing", "/me/consents/:consentType", svc.handleRevokePrivacyConsent, ``, "u-1"},
		{"SubmitDSAR", "POST", "/me/dsar", "/me/dsar", svc.handleSubmitDSAR, `{"request_type":"export"}`, "u-1"},
		{"GetMyDSARs", "GET", "/me/dsars", "/me/dsars", svc.handleGetMyDSARs, ``, "u-1"},

		{"OffboardUser", "POST", "/users/u-1/offboard", "/users/:id/offboard", svc.handleOffboardUser, ``, "admin-1"},

		{"ListUserPATs", "GET", "/me/tokens", "/me/tokens", svc.handleListUserPATs, ``, "u-1"},
		{"CreateUserPAT", "POST", "/me/tokens", "/me/tokens", svc.handleCreateUserPAT, `{"name":"ci"}`, "u-1"},
		{"RevokeUserPAT", "DELETE", "/me/tokens/k-1", "/me/tokens/:id", svc.handleRevokeUserPAT, ``, "u-1"},
		{"ListUserConsents", "GET", "/me/consents-oauth", "/me/consents-oauth", svc.handleListUserConsents, ``, "u-1"},
		{"RevokeUserConsent", "DELETE", "/me/apps/c-1", "/me/apps/:client_id", svc.handleRevokeUserConsent, ``, "u-1"},
		{"GetMyIdentityLinks", "GET", "/me/identity-links", "/me/identity-links", svc.handleGetMyIdentityLinks, ``, "u-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				if tc.userID != "" {
					c.Set("user_id", tc.userID)
				}
				c.Next()
			})
			// No tenant-resolver middleware → no org on the context.
			r.Handle(tc.method, tc.route, tc.handler)

			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// If the org guard were missing, the handler would dereference
			// the nil pool and panic; ServeHTTP completing with a non-200
			// status is the proof that the guard fired first.
			r.ServeHTTP(w, req)

			if w.Code == http.StatusOK || w.Code == http.StatusCreated {
				t.Fatalf("%s: status = %d, want an error status (handler must refuse without an org)", tc.name, w.Code)
			}
		})
	}
}
