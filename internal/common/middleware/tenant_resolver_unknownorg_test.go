package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// unknownOrgID is a well-formed UUID that the fake lookup does not know, so both
// ByID and BySlug return ErrOrgNotFound for it.
const unknownOrgID = "99999999-9999-9999-9999-999999999999"

// TestTenantResolver_jwtClaim_unknownOrg_returns400 covers the tenant-isolation
// property that a JWT carrying an org_id the platform doesn't recognise (forged
// or stale) is REJECTED, not silently resolved to the default org.
func TestTenantResolver_jwtClaim_unknownOrg_returns400(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	setClaim := func(c *gin.Context) {
		c.Set("org_id", unknownOrgID)
		c.Next()
	}

	rec := runResolver(t, lookup, cfg, got, req, setClaim)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got.org != (orgctx.Org{}) {
		t.Fatalf("handler ran despite unknown JWT org: org=%+v", got.org)
	}
}

// TestTenantResolver_xOrgIDHeader_unknownOrg_returns400 covers the same rejection
// for the platform-admin X-Org-ID cross-org path: an unknown target org is a 400,
// never a silent default fallback.
func TestTenantResolver_xOrgIDHeader_unknownOrg_returns400(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           defaultOrgID,
		PlatformAdminPredicate: func(*gin.Context) bool { return true },
	}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-ID", unknownOrgID)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got.org != (orgctx.Org{}) {
		t.Fatalf("handler ran despite unknown X-Org-ID: org=%+v", got.org)
	}
}
