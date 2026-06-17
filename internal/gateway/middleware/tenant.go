// Package middleware — tenant header production for the gateway.
package middleware

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

// OrgSlugHeader is the producer half of tenant resolution (v2.0
// multi-tenancy design): backends resolve the org from the X-Org-Slug
// header as their highest-priority signal, and the gateway is the only
// legitimate place that header may come from.
//
// The middleware always strips a client-supplied X-Org-Slug — a
// caller must never pick its own tenant — and, when baseDomain is
// configured (TENANT_BASE_DOMAIN), re-injects the header from the
// request's Host: "acme.openidx.io" → "X-Org-Slug: acme". Only a
// single label directly under the base domain qualifies; the bare
// base domain, multi-level subdomains, and unrelated hosts forward
// with no header, which leaves backends on their default-org
// fallback. With baseDomain empty the middleware only strips.
func OrgSlugHeader(baseDomain string) gin.HandlerFunc {
	suffix := ""
	if baseDomain != "" {
		suffix = "." + strings.ToLower(baseDomain)
	}

	return func(c *gin.Context) {
		c.Request.Header.Del("X-Org-Slug")

		if suffix != "" {
			if slug := tenantLabel(c.Request.Host, suffix); slug != "" {
				c.Request.Header.Set("X-Org-Slug", slug)
			}
		}

		c.Next()
	}
}

// tenantLabel extracts the single hostname label directly under the
// base-domain suffix (".openidx.io"), or "" if the host doesn't match
// that shape. Hostnames are case-insensitive; an optional port is
// ignored.
func tenantLabel(host, suffix string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}
