package access

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// BROWZER DOES NOT PASS ON WHO THE CALLER SAYS THEY ARE.
//
// The nginx configuration generated for BrowZer proxies a request to its
// application as the caller sent it, and nothing in front of it removes
// identity headers. An application that trusts X-Forwarded-User,
// X-Auth-Request-User or Remote-User because it sits behind OpenIDX believed
// whatever the caller wrote; the hop even set Remote-User from the caller's
// own header, and X-Forwarded-For carried the caller's chain.
//
// Routes are seeded as the route API stores them, over a migrated database,
// RegenerateConfigs writes the files the hop, the public vhosts and the router
// load, and every location in them that proxies is read back.
func TestTheBrowZerConfigurationPassesNoCallerIdentity(t *testing.T) {
	f := newAdminGateFixture(t)
	dir := t.TempDir()
	tm := NewBrowZerTargetManager(f.db, zap.NewNop(), "")
	tm.SetDomain("browzer-" + f.suffix + ".example.test")
	tm.SetHopConfigPath(filepath.Join(dir, "hop.conf"))
	tm.SetVHostConfigPath(filepath.Join(dir, "vhosts.conf"))
	tm.SetRouterConfigPath(filepath.Join(dir, "router.conf"))
	tm.SetOIDCCallbacks([]string{"signin-oidc"})

	seed := func(name, toURL, mode string) {
		t.Helper()
		if _, err := f.db.Pool.Exec(f.ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, enabled,
			                          ziti_enabled, browzer_enabled, ziti_service_name, hosting_mode)
			VALUES ($1::uuid, $2, $3, $4, true, true, true, true, $5, $6)`,
			f.orgA, name+"-"+f.suffix, "https://"+name+"-"+f.suffix+".example.test", toURL, name+"-"+f.suffix+"-zt", mode); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("payroll", "https://payroll-backend.example.test/app", "hop")
	seed("wiki", "http://10.0.0.7:8080", "hop")
	seed("docs", "http://10.0.0.8:8080", "direct")

	if err := tm.RegenerateConfigs(context.Background()); err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	proxying := 0
	for _, file := range []string{"hop.conf", "vhosts.conf", "router.conf"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		conf := string(raw)
		if file != "router.conf" && !strings.Contains(conf, "proxy_pass") {
			t.Fatalf("%s proxies nothing; the test would prove nothing:\n%s", file, conf)
		}
		// Nothing a caller chooses is written into a request header: the
		// only request variable left is the WebSocket upgrade.
		for _, v := range regexp.MustCompile(`\$(http_[a-z_]+|proxy_add_x_forwarded_for)`).FindAllString(conf, -1) {
			if v != "$http_upgrade" {
				t.Errorf("%s writes the caller's %s into the request it proxies", file, v)
			}
		}
		for _, loc := range proxyingLocations(conf) {
			proxying++
			for _, h := range append(namedIdentityHeaders(), "Remote-User") {
				if !strings.Contains(loc, "proxy_set_header "+h+` "";`) {
					t.Errorf("%s: a location passes the caller's %s on:\n%s", file, h, loc)
				}
			}
			if !strings.Contains(loc, "proxy_set_header X-Forwarded-For $remote_addr;") {
				t.Errorf("%s: a location does not set X-Forwarded-For to the peer:\n%s", file, loc)
			}
		}
	}
	// Two hop servers, and three vhosts, of which two hop routes carry the
	// OIDC callback location.
	if proxying != 7 {
		t.Errorf("%d proxying locations checked, want 7", proxying)
	}
}

// proxyingLocations returns the text of every location block in conf that
// proxies a request.
func proxyingLocations(conf string) []string {
	var out []string
	lines := strings.Split(conf, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, "location ") || !strings.HasSuffix(l, "{") {
			continue
		}
		depth, j := 0, i
		var block []string
		for ; j < len(lines); j++ {
			block = append(block, lines[j])
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			if depth == 0 {
				break
			}
		}
		i = j
		if b := strings.Join(block, "\n"); strings.Contains(b, "proxy_pass") {
			out = append(out, b)
		}
	}
	return out
}
