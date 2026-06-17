package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// runOrgSlug sends one request with the given Host through the
// middleware and returns the X-Org-Slug header as the terminal
// handler (standing in for the reverse proxy) would see it, plus a
// flag for whether the header was present at all.
func runOrgSlug(t *testing.T, baseDomain, host, spoofed string) (string, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(OrgSlugHeader(baseDomain))

	var got string
	var present bool
	r.GET("/", func(c *gin.Context) {
		got = c.Request.Header.Get("X-Org-Slug")
		_, present = c.Request.Header["X-Org-Slug"]
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	if spoofed != "" {
		req.Header.Set("X-Org-Slug", spoofed)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	return got, present
}

func TestOrgSlugHeader_subdomain_injected(t *testing.T) {
	slug, _ := runOrgSlug(t, "openidx.io", "acme.openidx.io", "")
	if slug != "acme" {
		t.Fatalf("X-Org-Slug = %q, want %q", slug, "acme")
	}
}

func TestOrgSlugHeader_clientSuppliedHeader_alwaysStripped(t *testing.T) {
	// A client must never pick its own tenant by sending the header
	// directly — the gateway is the only legitimate producer.
	slug, _ := runOrgSlug(t, "openidx.io", "acme.openidx.io", "victim-org")
	if slug != "acme" {
		t.Fatalf("X-Org-Slug = %q, want subdomain %q to override the spoofed value", slug, "acme")
	}
}

func TestOrgSlugHeader_unconfigured_stillStripsSpoofedHeader(t *testing.T) {
	// Even with no base domain configured, the spoofed header must
	// not pass through to backends.
	_, present := runOrgSlug(t, "", "anything.example.com", "victim-org")
	if present {
		t.Fatal("X-Org-Slug present, want stripped when no base domain is configured")
	}
}

func TestOrgSlugHeader_bareBaseDomain_noHeader(t *testing.T) {
	_, present := runOrgSlug(t, "openidx.io", "openidx.io", "")
	if present {
		t.Fatal("X-Org-Slug present, want none for the bare base domain")
	}
}

func TestOrgSlugHeader_multiLevelSubdomain_noHeader(t *testing.T) {
	// "a.b.openidx.io" is not a tenant subdomain — only a single
	// label directly under the base domain qualifies.
	_, present := runOrgSlug(t, "openidx.io", "a.b.openidx.io", "")
	if present {
		t.Fatal("X-Org-Slug present, want none for a multi-level subdomain")
	}
}

func TestOrgSlugHeader_unrelatedHost_noHeader(t *testing.T) {
	_, present := runOrgSlug(t, "openidx.io", "evil-openidx.io", "")
	if present {
		t.Fatal("X-Org-Slug present, want none for a host that merely ends in the base domain string")
	}
}

func TestOrgSlugHeader_hostPort_ignored(t *testing.T) {
	slug, _ := runOrgSlug(t, "openidx.io", "acme.openidx.io:8443", "")
	if slug != "acme" {
		t.Fatalf("X-Org-Slug = %q, want %q (port must be stripped)", slug, "acme")
	}
}

func TestOrgSlugHeader_hostCase_normalized(t *testing.T) {
	slug, _ := runOrgSlug(t, "OpenIDX.io", "ACME.openidx.IO", "")
	if slug != "acme" {
		t.Fatalf("X-Org-Slug = %q, want %q (hostnames are case-insensitive)", slug, "acme")
	}
}
