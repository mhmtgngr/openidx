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
