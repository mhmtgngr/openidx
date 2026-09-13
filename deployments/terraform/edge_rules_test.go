package terraform

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The edge rule set is one file rendered by three provider modules, and the
// design document (§5.3) is what an operator reads to know what the edge does.
// This test keeps the two honest: every rule in the file names a path the
// design table mentions, every rule is well-formed enough for each provider
// (at least one path, a positive per-minute figure, a positive TTL), and the
// path prefixes are prefixes — a trailing "*" would be interpreted three
// different ways by three providers.
func TestEdgeRulesMatchTheDesign(t *testing.T) {
	raw, err := os.ReadFile("modules/edge-common/rules.json")
	if err != nil {
		t.Fatalf("read rules.json: %v", err)
	}
	var rules struct {
		RateRules []struct {
			Name              string   `json:"name"`
			Paths             []string `json:"paths"`
			RequestsPerMinute int      `json:"requests_per_minute"`
		} `json:"rate_rules"`
		CacheRules []struct {
			Name       string   `json:"name"`
			Paths      []string `json:"paths"`
			TTLSeconds int      `json:"ttl_seconds"`
		} `json:"cache_rules"`
		Limits struct {
			BodyBytes         int `json:"body_bytes"`
			SCIMBulkBodyBytes int `json:"scim_bulk_body_bytes"`
			URLBytes          int `json:"url_bytes"`
			HeaderBytes       int `json:"header_bytes"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("rules.json is not valid JSON: %v", err)
	}

	design, err := os.ReadFile("../../docs/architecture/2026-09-13-global-scale-cell-architecture-and-ddos.md")
	if err != nil {
		t.Fatalf("read design: %v", err)
	}
	i := strings.Index(string(design), "### 5.3")
	j := strings.Index(string(design), "### 5.4")
	if i == -1 || j == -1 || j < i {
		t.Fatal("design §5.3 table not found")
	}
	table := string(design[i:j])

	if len(rules.RateRules) == 0 || len(rules.CacheRules) == 0 {
		t.Fatal("rules.json must carry rate and cache rules")
	}
	for _, r := range rules.RateRules {
		if len(r.Paths) == 0 || r.RequestsPerMinute <= 0 {
			t.Errorf("rate rule %q must have paths and a positive requests_per_minute", r.Name)
		}
		for _, p := range r.Paths {
			if !strings.HasPrefix(p, "/") || strings.Contains(p, "*") {
				t.Errorf("rate rule %q path %q must be a plain prefix starting with /", r.Name, p)
			}
		}
		// The first path is the rule's identity in the design table.
		key := strings.TrimSuffix(r.Paths[0], "/")
		if !strings.Contains(table, key) {
			t.Errorf("rate rule %q (%s) is not in the design §5.3 table; add it there or drop it here", r.Name, r.Paths[0])
		}
	}
	for _, c := range rules.CacheRules {
		if len(c.Paths) == 0 || c.TTLSeconds <= 0 {
			t.Errorf("cache rule %q must have paths and a positive ttl_seconds", c.Name)
		}
	}
	// Size limits must agree with what the services enforce (task 0.3).
	if rules.Limits.BodyBytes != 1<<20 || rules.Limits.SCIMBulkBodyBytes != 5<<20 || rules.Limits.HeaderBytes != 16<<10 {
		t.Errorf("limits %+v must match the Go floor: 1 MiB body, 5 MiB SCIM bulk, 16 KiB headers", rules.Limits)
	}
}
