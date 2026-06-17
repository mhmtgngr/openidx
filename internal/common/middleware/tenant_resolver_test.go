package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	defaultOrgID = "00000000-0000-0000-0000-000000000010"
	acmeOrgID    = "11111111-2222-3333-4444-555555555555"
	bigcorpOrgID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// fakeLookup is a deterministic OrgLookup for tests. It panics if a
// call to ByID or BySlug surprises us (unknown values) instead of
// silently returning zero — keeps tests honest about what the
// middleware is doing.
type fakeLookup struct {
	mu     sync.Mutex
	byID   map[string]orgctx.Org
	bySlug map[string]orgctx.Org
	// fail, when non-nil, is returned from every lookup. Use to test
	// the 500 path.
	fail error
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{
		byID: map[string]orgctx.Org{
			defaultOrgID: {ID: defaultOrgID, Slug: "default"},
			acmeOrgID:    {ID: acmeOrgID, Slug: "acme"},
			bigcorpOrgID: {ID: bigcorpOrgID, Slug: "bigcorp"},
		},
		bySlug: map[string]orgctx.Org{
			"default": {ID: defaultOrgID, Slug: "default"},
			"acme":    {ID: acmeOrgID, Slug: "acme"},
			"bigcorp": {ID: bigcorpOrgID, Slug: "bigcorp"},
		},
	}
}

func (f *fakeLookup) ByID(_ context.Context, id string) (orgctx.Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return orgctx.Org{}, f.fail
	}
	if org, ok := f.byID[id]; ok {
		return org, nil
	}
	return orgctx.Org{}, ErrOrgNotFound
}

func (f *fakeLookup) BySlug(_ context.Context, slug string) (orgctx.Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return orgctx.Org{}, f.fail
	}
	if org, ok := f.bySlug[slug]; ok {
		return org, nil
	}
	return orgctx.Org{}, ErrOrgNotFound
}

// captureHandler is the terminal handler — it stores whatever org the
// resolver attached to ctx so the test can assert against it.
type capturedRequest struct {
	org             orgctx.Org
	orgErr          error
	isPlatformAdmin bool
}

func captureHandler(target *capturedRequest) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, err := orgctx.From(c.Request.Context())
		target.org = org
		target.orgErr = err
		target.isPlatformAdmin = orgctx.IsPlatformAdmin(c.Request.Context())
		c.Status(http.StatusOK)
	}
}

// runResolver wires the middleware up to a minimal gin engine and
// performs a single request. It returns the response recorder so
// tests can inspect status and body.
func runResolver(t *testing.T, lookup OrgLookup, cfg TenantResolverConfig, target *capturedRequest, req *http.Request, beforeResolver ...gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	for _, mw := range beforeResolver {
		r.Use(mw)
	}
	r.Use(TenantResolver(lookup, cfg))
	r.Any("/*any", captureHandler(target))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestTenantResolver_subdomainSlug_wins(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "acme")

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.orgErr != nil {
		t.Fatalf("orgctx.From err = %v", got.orgErr)
	}
	if got.org.ID != acmeOrgID || got.org.Slug != "acme" {
		t.Fatalf("got org = %+v, want acme(%s)", got.org, acmeOrgID)
	}
}

func TestTenantResolver_subdomainSlug_unknown_returns400(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "ghost-corp")

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// Handler must not have run.
	if got.org != (orgctx.Org{}) {
		t.Fatalf("handler ran despite resolver rejection: org=%+v", got.org)
	}
}

func TestTenantResolver_jwtClaim_used_whenNoSubdomain(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	setOrgIDClaim := func(c *gin.Context) {
		c.Set("org_id", acmeOrgID)
		c.Next()
	}

	rec := runResolver(t, lookup, cfg, got, req, setOrgIDClaim)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.org.ID != acmeOrgID {
		t.Fatalf("got org = %+v, want acme(%s)", got.org, acmeOrgID)
	}
}

func TestTenantResolver_jwtClaim_isDefaultUUID_fallsThrough(t *testing.T) {
	// Auth middleware sets org_id == defaultOrgID when JWT lacks the
	// claim. The resolver must skip step 2 and land on the default
	// fallback rather than performing a redundant lookup.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	setOrgIDClaim := func(c *gin.Context) {
		c.Set("org_id", defaultOrgID)
		c.Next()
	}

	rec := runResolver(t, lookup, cfg, got, req, setOrgIDClaim)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default(%s)", got.org, defaultOrgID)
	}
}

func TestTenantResolver_subdomain_overrides_jwt(t *testing.T) {
	// If both signals are present, subdomain wins.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "acme")

	setOrgIDClaim := func(c *gin.Context) {
		c.Set("org_id", bigcorpOrgID)
		c.Next()
	}

	rec := runResolver(t, lookup, cfg, got, req, setOrgIDClaim)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != acmeOrgID {
		t.Fatalf("got org = %+v, want acme (subdomain wins over JWT)", got.org)
	}
}

func TestTenantResolver_xOrgIDHeader_platformAdmin_used(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           defaultOrgID,
		PlatformAdminPredicate: func(*gin.Context) bool { return true },
	}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-ID", bigcorpOrgID)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.org.ID != bigcorpOrgID {
		t.Fatalf("got org = %+v, want bigcorp(%s)", got.org, bigcorpOrgID)
	}
	if !got.isPlatformAdmin {
		t.Fatal("platform-admin marker not attached to ctx")
	}
}

func TestTenantResolver_xOrgIDHeader_nonAdmin_ignored(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           defaultOrgID,
		PlatformAdminPredicate: func(*gin.Context) bool { return false },
	}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-ID", bigcorpOrgID)

	rec := runResolver(t, lookup, cfg, got, req)

	// Header ignored → falls through to default org.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default (non-admin X-Org-ID must be ignored)", got.org)
	}
	if got.isPlatformAdmin {
		t.Fatal("platform-admin marker attached for non-admin caller")
	}
}

func TestTenantResolver_xOrgIDHeader_noPredicate_ignored(t *testing.T) {
	// When PlatformAdminPredicate is nil the header is never honored.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{
		DefaultOrgFallback: true,
		DefaultOrgID:       defaultOrgID,
	}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-ID", bigcorpOrgID)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default (nil predicate => header ignored)", got.org)
	}
}

func TestTenantResolver_defaultFallback_off_rejectsUnresolved(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: false}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when fallback off and nothing resolves", rec.Code)
	}
	if got.org != (orgctx.Org{}) {
		t.Fatalf("handler ran despite resolver rejection: org=%+v", got.org)
	}
}

func TestTenantResolver_defaultFallback_on_resolvesDefault(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID || got.org.Slug != "default" {
		t.Fatalf("got org = %+v, want default", got.org)
	}
}

func TestTenantResolver_defaultFallback_on_butDefaultIDMissing_500(t *testing.T) {
	// Misconfiguration: fallback on but no DefaultOrgID. The resolver
	// must surface a 500, not silently no-op.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: ""}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestTenantResolver_lookupError_is500_notNotFound(t *testing.T) {
	lookup := newFakeLookup()
	lookup.fail = fmt.Errorf("connection lost")
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "acme")

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for generic lookup error", rec.Code)
	}
}

func TestTenantResolver_subdomainSlug_whitespace_trimmed(t *testing.T) {
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "  acme  ")

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != acmeOrgID {
		t.Fatalf("got org = %+v, want acme (X-Org-Slug should be trimmed)", got.org)
	}
}

func TestTenantResolver_emptyOrgSlugHeader_fallsThrough(t *testing.T) {
	// Empty header value should be ignored, not treated as "lookup
	// empty slug → not found".
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	req.Header.Set("X-Org-Slug", "")

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default (empty X-Org-Slug should fall through)", got.org)
	}
}

func TestTenantResolver_platformAdminMarker_attachedEvenWithDefaultOrg(t *testing.T) {
	// Platform admin reading the install with no explicit override
	// still gets the marker on the default org.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           defaultOrgID,
		PlatformAdminPredicate: func(*gin.Context) bool { return true },
	}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default", got.org)
	}
	if !got.isPlatformAdmin {
		t.Fatal("platform-admin marker missing from ctx")
	}
}

func TestErrOrgNotFound_isSentinel(t *testing.T) {
	wrapped := fmt.Errorf("wrapped: %w", ErrOrgNotFound)
	if !errors.Is(wrapped, ErrOrgNotFound) {
		t.Fatal("ErrOrgNotFound does not behave as a sentinel under errors.Is")
	}
}

func TestDefaultOrgID_matchesMigrationUUID(t *testing.T) {
	// v25 creates the default org row with this exact UUID; the v35
	// backfill and the Auth middleware both depend on it. If this
	// constant drifts from the migrations, single-tenant installs
	// break, so pin it.
	if DefaultOrgID != "00000000-0000-0000-0000-000000000010" {
		t.Fatalf("DefaultOrgID = %q, want the canonical v25 UUID", DefaultOrgID)
	}
}

func TestTenantResolver_infraPaths_skipResolution(t *testing.T) {
	// Health, readiness, and metrics endpoints must keep working when
	// the org lookup (i.e. the database) is down — Kubernetes probes
	// hit them to decide whether to restart the pod. The resolver
	// must pass these through without resolving an org.
	lookup := newFakeLookup()
	lookup.fail = errors.New("database is down")
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}

	for _, path := range []string{
		"/health",
		"/health/ready",
		"/health/live",
		"/metrics",
		"/ready",
		"/live",
	} {
		got := &capturedRequest{}
		req := httptest.NewRequest(http.MethodGet, path, nil)

		rec := runResolver(t, lookup, cfg, got, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (infra path must bypass resolver); body=%s",
				path, rec.Code, rec.Body.String())
		}
		if !errors.Is(got.orgErr, orgctx.ErrNoOrgContext) {
			t.Errorf("%s: orgctx err = %v, want ErrNoOrgContext (no org should be attached)",
				path, got.orgErr)
		}
	}
}

func TestTenantResolver_nonInfraPath_withInfraPrefixInName_isResolved(t *testing.T) {
	// "/healthcheck-export" is NOT an infra path: the skip must match
	// whole path segments, not raw string prefixes.
	lookup := newFakeLookup()
	cfg := TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: defaultOrgID}
	got := &capturedRequest{}
	req := httptest.NewRequest(http.MethodGet, "/healthcheck-export", nil)

	rec := runResolver(t, lookup, cfg, got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != defaultOrgID {
		t.Fatalf("got org = %+v, want default org resolved (path is not an infra path)", got.org)
	}
}

// TestTenantResolver_platformAdmin_crossOrg_firesAudit verifies that when a
// platform admin selects an org via X-Org-ID, the resolver resolves that org,
// sets the platform-admin marker, and invokes the mandatory OnPlatformCrossOrg
// audit hook with the target org.
func TestTenantResolver_platformAdmin_crossOrg_firesAudit(t *testing.T) {
	var hookCalls int
	var hookTarget orgctx.Org
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     false,
		DefaultOrgID:           defaultOrgID,
		PlatformAdminPredicate: func(*gin.Context) bool { return true },
		OnPlatformCrossOrg: func(_ *gin.Context, target orgctx.Org) {
			hookCalls++
			hookTarget = target
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
	req.Header.Set("X-Org-ID", acmeOrgID)

	var got capturedRequest
	rec := runResolver(t, newFakeLookup(), cfg, &got, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.org.ID != acmeOrgID {
		t.Fatalf("resolved org = %+v, want acme via X-Org-ID", got.org)
	}
	if !got.isPlatformAdmin {
		t.Fatal("expected platform-admin marker on context")
	}
	if hookCalls != 1 || hookTarget.ID != acmeOrgID {
		t.Fatalf("audit hook calls=%d target=%+v, want 1 call with acme", hookCalls, hookTarget)
	}
}

// TestTenantResolver_nonPlatformAdmin_ignoresXOrgID confirms a non-platform
// caller's X-Org-ID is ignored and the hook never fires (with fallback off the
// request is rejected because nothing else resolves).
func TestTenantResolver_nonPlatformAdmin_ignoresXOrgID(t *testing.T) {
	var hookCalls int
	cfg := TenantResolverConfig{
		DefaultOrgFallback:     false,
		PlatformAdminPredicate: func(*gin.Context) bool { return false },
		OnPlatformCrossOrg:     func(_ *gin.Context, _ orgctx.Org) { hookCalls++ },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
	req.Header.Set("X-Org-ID", acmeOrgID)

	var got capturedRequest
	rec := runResolver(t, newFakeLookup(), cfg, &got, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no org resolvable, fallback off)", rec.Code)
	}
	if hookCalls != 0 {
		t.Fatalf("audit hook fired %d times for non-platform-admin, want 0", hookCalls)
	}
}
