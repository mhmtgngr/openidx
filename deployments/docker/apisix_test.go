package docker

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestAPISIXRoutesCarryConnectionCeilings pins the compose edge's slow-request
// floor (global-scale plan task 0.3). limit-req bounds the RATE of requests; a
// slow-body or long-poll flood spends OPEN connections instead, so every route
// that is rate-limited must also cap how many a single source may hold at
// once. The key must be remote_addr — which is the client only because the
// real-ip global rule (task 0.2) rewrites it — and the ISSUE upstream must not
// retry, because a retry under load multiplies the attack it is failing under.
func TestAPISIXRoutesCarryConnectionCeilings(t *testing.T) {
	raw, err := os.ReadFile("apisix/apisix.yaml")
	if err != nil {
		t.Fatalf("read apisix.yaml: %v", err)
	}
	var doc struct {
		Routes []struct {
			Name     string                 `yaml:"name"`
			Plugins  map[string]interface{} `yaml:"plugins"`
			Upstream struct {
				Retries *int           `yaml:"retries"`
				Timeout map[string]int `yaml:"timeout"`
			} `yaml:"upstream"`
		} `yaml:"routes"`
		GlobalRules []struct {
			Plugins map[string]interface{} `yaml:"plugins"`
		} `yaml:"global_rules"`
	}
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(string(raw), "#END", "")), &doc); err != nil {
		t.Fatalf("parse apisix.yaml: %v", err)
	}

	rateLimited, ceilinged := 0, 0
	for _, r := range doc.Routes {
		if _, ok := r.Plugins["limit-req"]; !ok {
			continue
		}
		rateLimited++
		lc, ok := r.Plugins["limit-conn"].(map[string]interface{})
		if !ok {
			t.Errorf("route %q is rate-limited but has no limit-conn ceiling", r.Name)
			continue
		}
		ceilinged++
		if lc["key"] != "remote_addr" {
			t.Errorf("route %q: limit-conn must key on remote_addr (the client after real-ip), got %v", r.Name, lc["key"])
		}
		if lc["rejected_code"] != 429 {
			t.Errorf("route %q: limit-conn must reject with 429 so clients back off, got %v", r.Name, lc["rejected_code"])
		}
		if r.Name == "oauth-service" {
			if r.Upstream.Retries == nil || *r.Upstream.Retries != 0 {
				t.Errorf("oauth-service upstream must set retries: 0")
			}
			if r.Upstream.Timeout["read"] == 0 || r.Upstream.Timeout["read"] > 10 {
				t.Errorf("oauth-service upstream read timeout must be short (<=10s), got %v", r.Upstream.Timeout["read"])
			}
		}
	}
	if rateLimited == 0 {
		t.Fatal("no rate-limited routes found; the file shape changed")
	}
	if ceilinged != rateLimited {
		t.Errorf("%d rate-limited routes but only %d carry limit-conn", rateLimited, ceilinged)
	}

	// The ceilings are only meaningful if remote_addr is the client.
	hasRealIP := false
	for _, g := range doc.GlobalRules {
		if _, ok := g.Plugins["real-ip"]; ok {
			hasRealIP = true
		}
	}
	if !hasRealIP {
		t.Error("global_rules must carry real-ip: without it every per-IP key is the TLS proxy's address")
	}
}

// TestAPISIXOperationalEndpointsAreClosed pins task 0.4 for the compose edge:
// /health, /health/*, /ready and /metrics answer 404 at APISIX with a priority
// above every other route, so neither a dependency-status feed nor the
// Prometheus surface is reachable from outside and a flood on them never
// reaches the data tier.
func TestAPISIXOperationalEndpointsAreClosed(t *testing.T) {
	raw, err := os.ReadFile("apisix/apisix.yaml")
	if err != nil {
		t.Fatalf("read apisix.yaml: %v", err)
	}
	var doc struct {
		Routes []struct {
			Name     string                 `yaml:"name"`
			URIs     []string               `yaml:"uris"`
			Priority int                    `yaml:"priority"`
			Plugins  map[string]interface{} `yaml:"plugins"`
		} `yaml:"routes"`
	}
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(string(raw), "#END", "")), &doc); err != nil {
		t.Fatalf("parse apisix.yaml: %v", err)
	}
	var deny *struct {
		Name     string                 `yaml:"name"`
		URIs     []string               `yaml:"uris"`
		Priority int                    `yaml:"priority"`
		Plugins  map[string]interface{} `yaml:"plugins"`
	}
	maxOther := 0
	for i := range doc.Routes {
		r := &doc.Routes[i]
		if r.Name == "deny-health-metrics" {
			deny = r
			continue
		}
		if r.Priority > maxOther {
			maxOther = r.Priority
		}
	}
	if deny == nil {
		t.Fatal("deny-health-metrics route missing")
	}
	if deny.Priority <= maxOther {
		t.Errorf("deny route priority %d must outrank every other route (max %d)", deny.Priority, maxOther)
	}
	fi, ok := deny.Plugins["fault-injection"].(map[string]interface{})
	if !ok {
		t.Fatal("deny route must answer at the edge via fault-injection")
	}
	abort, _ := fi["abort"].(map[string]interface{})
	if abort["http_status"] != 404 {
		t.Errorf("deny route must answer 404, got %v", abort["http_status"])
	}
	have := map[string]bool{}
	for _, u := range deny.URIs {
		have[u] = true
	}
	for _, want := range []string{"/health", "/health/*", "/ready", "/metrics"} {
		if !have[want] {
			t.Errorf("deny route must cover %s", want)
		}
	}
}

// TestAPISIXCORSIsOneTenantRulePlusProtocolWildcards pins task 0.6 for the
// compose edge: the tenant origin list lives in ONE place (the global rule),
// the catch-all preflight route is gone because the cors plugin answers
// OPTIONS itself, and only the OAuth/OIDC protocol routes (and the
// host-scoped guacamole/demo routes, which are not the tenant surface) carry a
// route-level override.
func TestAPISIXCORSIsOneTenantRulePlusProtocolWildcards(t *testing.T) {
	raw, err := os.ReadFile("apisix/apisix.yaml")
	if err != nil {
		t.Fatalf("read apisix.yaml: %v", err)
	}
	text := strings.ReplaceAll(string(raw), "#END", "")
	var doc struct {
		Routes []struct {
			Name    string                 `yaml:"name"`
			Plugins map[string]interface{} `yaml:"plugins"`
		} `yaml:"routes"`
		GlobalRules []struct {
			Plugins map[string]interface{} `yaml:"plugins"`
		} `yaml:"global_rules"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatalf("parse apisix.yaml: %v", err)
	}

	tenantList := ""
	for _, g := range doc.GlobalRules {
		if c, ok := g.Plugins["cors"].(map[string]interface{}); ok {
			tenantList, _ = c["allow_origins"].(string)
		}
	}
	if tenantList == "" {
		t.Fatal("global cors rule with the tenant origin list missing")
	}
	if n := strings.Count(text, tenantList); n != 1 {
		t.Errorf("tenant origin list must appear exactly once (the global rule), found %d copies", n)
	}

	wildcardOK := map[string]bool{"oauth-protocol": true, "oidc-discovery": true, "guacamole-gateway": true}
	for _, r := range doc.Routes {
		if r.Name == "cors-preflight" {
			t.Error("catch-all preflight route must be gone; the cors plugin answers OPTIONS")
		}
		c, ok := r.Plugins["cors"].(map[string]interface{})
		if !ok {
			continue
		}
		origins, _ := c["allow_origins"].(string)
		if origins == "*" && !wildcardOK[r.Name] {
			t.Errorf("route %q must not answer \"*\": only protocol endpoints are wildcard by design", r.Name)
		}
		if origins == tenantList {
			t.Errorf("route %q repeats the tenant origin list; the global rule owns it", r.Name)
		}
	}
	for _, must := range []string{"oauth-protocol", "oidc-discovery"} {
		found := false
		for _, r := range doc.Routes {
			if r.Name == must {
				found = true
				c, _ := r.Plugins["cors"].(map[string]interface{})
				if c["allow_origins"] != "*" {
					t.Errorf("protocol route %q must allow any relying-party origin", must)
				}
			}
		}
		if !found {
			t.Errorf("protocol route %q missing", must)
		}
	}
}
