package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// THE POLICY WAS WRITTEN AGAINST A SUBJECT THE MIDDLEWARE DID NOT SUPPLY.
//
// OPAAuthz builds opa.Input.User from c.Get("roles") and c.Get("groups").
// authz.rego opens with `default allow := false` and grants on roles; it also
// has one rule on groups and a separation-of-duties deny on roles. Nothing
// anywhere called c.Set("groups"), and governance-service and
// provisioning-service -- two of the three services that mount OPAAuthz --
// never called c.Set("roles") either.
//
// These tests read the JSON OPA actually receives, from a stub policy server,
// because "the middleware sets a context key" is a claim about the middleware
// and what matters is the document the decision is taken on.

// captureOPA stands in for the policy server and records the input it is given.
func captureOPA(t *testing.T, allow bool) (*opa.Client, *opa.Input) {
	t.Helper()
	var got opa.Input
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input opa.Input `json:"input"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		got = body.Input
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allow": allow}}))
	}))
	t.Cleanup(srv.Close)
	return opa.NewClient(srv.URL, zap.NewNop()), &got
}

func TestTheSubjectOPASeesCarriesTheRolesAndGroupsFromTheToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client, got := captureOPA(t, true)

	r := gin.New()
	// Stand in for an authentication middleware: verified claims, then the one
	// binder every such middleware now calls.
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-1")
		BindSubjectClaims(c, map[string]interface{}{
			"roles":  []interface{}{"auditor", "operator"},
			"groups": []interface{}{"admin-group", "eng"},
		})
		c.Next()
	})
	r.Use(OPAAuthz(client, zap.NewNop(), false))
	r.GET("/api/v1/governance/policies", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/governance/policies", nil))
	require.Equal(t, http.StatusOK, w.Code)

	require.Equal(t, []string{"auditor", "operator"}, got.User.Roles,
		"every role-based rule in authz.rego is decided on this list")
	require.Equal(t, []string{"admin-group", "eng"}, got.User.Groups,
		"the admin-group rule could never fire while this was empty")
	require.Equal(t, "u-1", got.User.ID)
	require.True(t, got.User.Authenticated)
}

// A token with no groups claim must not turn into an empty-but-present list
// that reads as "this user is in no groups" when the question was never asked.
func TestATokenWithoutGroupsBindsNoGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client, got := captureOPA(t, true)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-2")
		BindSubjectClaims(c, map[string]interface{}{"roles": []interface{}{"admin"}})
		c.Next()
	})
	r.Use(OPAAuthz(client, zap.NewNop(), false))
	r.GET("/api/v1/admin/users", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/admin/users", nil))
	require.Equal(t, http.StatusOK, w.Code)

	require.Equal(t, []string{"admin"}, got.User.Roles)
	require.Empty(t, got.User.Groups)
}

// Claims that are not arrays must not panic or bind garbage: a token is
// attacker-influenced input at this layer even after signature verification.
func TestMalformedClaimsBindNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	BindSubjectClaims(c, map[string]interface{}{
		"roles":  "admin",
		"groups": map[string]interface{}{"a": 1},
	})
	_, hasRoles := c.Get("roles")
	_, hasGroups := c.Get("groups")
	require.False(t, hasRoles, "a string is not a role list")
	require.False(t, hasGroups, "an object is not a group list")
}

// Non-string array members are coerced rather than dropped, so a numeric or
// boolean entry cannot silently shorten the list the policy is decided on.
func TestNonStringClaimMembersAreKeptAsText(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	BindSubjectClaims(c, map[string]interface{}{"roles": []interface{}{"admin", 7, true}})
	roles, ok := c.Get("roles")
	require.True(t, ok)
	require.Equal(t, []string{"admin", "7", "true"}, roles)
}
