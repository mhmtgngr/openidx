package access

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// fnCheck adapts plain functions to the Check interface so each rule is a small literal.
type fnCheck struct {
	id, domain string
	detect     func(ctx context.Context) ([]Finding, error)
	fix        func(ctx context.Context, f Finding) error
}

func (c *fnCheck) ID() string     { return c.id }
func (c *fnCheck) Domain() string { return c.domain }
func (c *fnCheck) Detect(ctx context.Context) ([]Finding, error) {
	if c.detect == nil {
		return nil, nil
	}
	return c.detect(ctx)
}
func (c *fnCheck) Fix(ctx context.Context, f Finding) error {
	if c.fix == nil {
		return nil
	}
	return c.fix(ctx, f)
}

// dedupBrowzerConfigFinding is the pure decision for the ziti_browzer_config check.
func dedupBrowzerConfigFinding(rowCount int) Finding {
	f := Finding{CheckID: "browzer-config-dedup", Domain: "ziti", Subject: "ziti_browzer_config",
		Severity: "warn", Safe: true, Action: "dedup to newest enabled row"}
	if rowCount > 1 {
		f.Status = "drift"
		f.Detail = fmt.Sprintf("%d rows; expected 1", rowCount)
	} else {
		f.Status = "ok"
	}
	return f
}

// registerChecks builds the ordered check list. Later tasks (4,5) append more.
func registerChecks(s *Service) []Check {
	return []Check{
		&fnCheck{id: "browzer-config-dedup", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				var n int
				if err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM ziti_browzer_config`).Scan(&n); err != nil {
					return nil, err
				}
				return []Finding{dedupBrowzerConfigFinding(n)}, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				_, err := s.db.Pool.Exec(ctx, `
					DELETE FROM ziti_browzer_config WHERE id NOT IN (
						SELECT id FROM ziti_browzer_config ORDER BY enabled DESC, updated_at DESC NULLS LAST LIMIT 1)`)
				return err
			}},

		&fnCheck{id: "route-tile", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) { return s.detectRouteTileDrift(ctx) },
			fix:    func(ctx context.Context, f Finding) error { return s.healRouteTile(ctx, f.Subject) }},

		&fnCheck{id: "edge-config", domain: "access",
			detect: func(ctx context.Context) ([]Finding, error) { return s.detectEdgeConfigDrift(ctx) },
			fix: func(ctx context.Context, f Finding) error {
				if s.browzerTargetManager == nil {
					return nil
				}
				return s.browzerTargetManager.RegenerateConfigs(ctx)
			}},
	}
}

// apisixRouteNames returns the current APISIX route names, or nil when no APISIX
// client is wired (so dependent checks degrade gracefully rather than erroring).
func (s *Service) apisixRouteNames(ctx context.Context) ([]string, error) {
	if s.browzerTargetManager == nil {
		return nil, nil
	}
	rec := s.browzerTargetManager.apisixReconciler
	if rec == nil {
		return nil, nil
	}
	client := rec.Client()
	if client == nil {
		return nil, nil
	}
	return client.ListRouteNames(ctx)
}

// detectRouteTileDrift flags ziti/browzer routes whose launcher tile is missing
// (Subject = route id) and proxy-app tiles whose route is gone (Subject = client_id).
func (s *Service) detectRouteTileDrift(ctx context.Context) ([]Finding, error) {
	var out []Finding
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.name FROM proxy_routes r
		WHERE (r.ziti_enabled OR r.browzer_enabled)
		  AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.client_id = 'proxy-app-'||r.id::text)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Severity: "warn", Status: "drift",
				Safe: true, Subject: id, Detail: "route " + name + " has no launcher tile", Action: "create tile"})
		}
	}
	rows.Close()
	orphan, err := s.db.Pool.Query(ctx, `
		SELECT a.client_id FROM applications a
		WHERE a.client_id LIKE 'proxy-app-%'
		  AND NOT EXISTS (SELECT 1 FROM proxy_routes r WHERE 'proxy-app-'||r.id::text = a.client_id)`)
	if err != nil {
		return out, nil
	}
	for orphan.Next() {
		var cid string
		if orphan.Scan(&cid) == nil {
			out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Severity: "warn", Status: "orphan",
				Safe: true, Subject: cid, Detail: "tile " + cid + " has no route", Action: "delete tile"})
		}
	}
	orphan.Close()
	if len(out) == 0 {
		out = append(out, Finding{CheckID: "route-tile", Domain: "apps", Status: "ok"})
	}
	return out, nil
}

// healRouteTile repairs one route-tile finding: Subject is a route id (recreate
// the tile) or a "proxy-app-<id>" client id of an orphan tile (delete it).
func (s *Service) healRouteTile(ctx context.Context, subject string) error {
	if strings.HasPrefix(subject, "proxy-app-") {
		s.deleteAppTile(ctx, strings.TrimPrefix(subject, "proxy-app-"))
		return nil
	}
	var name, fromURL, org string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name, from_url, org_id::text FROM proxy_routes WHERE id=$1`, subject).Scan(&name, &fromURL, &org); err != nil {
		return err
	}
	s.upsertAppLauncherTile(ctx, org, subject, name, "", fromURL+"/")
	return nil
}

// detectEdgeConfigDrift flags browzer routes missing their APISIX edge route or
// whose host is absent from the browzer-client redirect_uris. One safe fix
// (RegenerateConfigs) reconverges all of it, so a single drift finding suffices.
func (s *Service) detectEdgeConfigDrift(ctx context.Context) ([]Finding, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT from_url FROM proxy_routes
		WHERE ziti_enabled AND browzer_enabled AND enabled AND ziti_service_name <> ''`)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			hosts = append(hosts, u)
		}
	}
	rows.Close()

	var drift []string
	if names, err := s.apisixRouteNames(ctx); err == nil && names != nil {
		have := map[string]bool{}
		for _, n := range names {
			have[n] = true
		}
		for _, u := range hosts {
			if h := hostOf(u); h != "" && !have["browzer-"+apisixSlug(h)] {
				drift = append(drift, "apisix:"+h)
			}
		}
	}
	var redirects []byte
	s.db.Pool.QueryRow(ctx, `SELECT redirect_uris FROM oauth_clients WHERE client_id='browzer-client'`).Scan(&redirects)
	for _, u := range hosts {
		if h := hostOf(u); h != "" && !bytesContainsHost(redirects, h) {
			drift = append(drift, "redirect:"+h)
		}
	}

	if len(drift) == 0 {
		return []Finding{{CheckID: "edge-config", Domain: "access", Status: "ok"}}, nil
	}
	return []Finding{{CheckID: "edge-config", Domain: "access", Severity: "warn", Status: "drift", Safe: true,
		Subject: "edge", Detail: fmt.Sprintf("edge drift: %v", drift), Action: "regenerate edge configs"}}, nil
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

func bytesContainsHost(jsonArr []byte, host string) bool {
	return strings.Contains(string(jsonArr), "//"+host)
}
