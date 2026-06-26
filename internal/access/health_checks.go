package access

import (
	"context"
	"encoding/json"
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

// presenceFinding flags an empty/unwired domain as report-only drift (info).
func presenceFinding(checkID, domain string, count int) Finding {
	f := Finding{CheckID: checkID, Domain: domain, Severity: "info", Subject: domain, Safe: false,
		Action: "wire up domain (manual)"}
	if count == 0 {
		f.Status = "drift"
		f.Detail = domain + " has no records (not wired up)"
	} else {
		f.Status = "ok"
	}
	return f
}

// orphanOpenidxServices returns controller service names that we own (openidx-*)
// but that no desired route claims. Non-openidx services are left alone.
func orphanOpenidxServices(controller []string, desired map[string]bool) []string {
	var out []string
	for _, n := range controller {
		if strings.HasPrefix(n, "openidx-") && !desired[n] {
			out = append(out, n)
		}
	}
	return out
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

		// route ↔ Ziti service (DB desired vs controller) — safe: reconcile converges.
		&fnCheck{id: "route-ziti", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx,
					`SELECT ziti_service_name FROM proxy_routes WHERE ziti_enabled AND enabled AND ziti_service_name <> ''`)
				if err != nil {
					return nil, err
				}
				var want []string
				for rows.Next() {
					var n string
					if rows.Scan(&n) == nil {
						want = append(want, n)
					}
				}
				rows.Close()
				zm := s.ziti()
				if zm == nil {
					return []Finding{{CheckID: "route-ziti", Domain: "ziti", Status: "ok"}}, nil
				}
				ents, err := zm.listEdgeEntities(ctx, "services")
				if err != nil {
					return nil, err
				}
				have := map[string]bool{}
				for _, e := range ents {
					have[e.Name] = true
				}
				var out []Finding
				for _, n := range want {
					if !have[n] {
						out = append(out, Finding{CheckID: "route-ziti", Domain: "ziti", Severity: "error",
							Status: "drift", Safe: true, Subject: n, Detail: "route service missing on controller", Action: "reconcile"})
					}
				}
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "route-ziti", Domain: "ziti", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error { s.enqueueReconcile(); return nil }},

		// orphan Ziti controller services (openidx-* with no route) — RISKY: teardown.
		&fnCheck{id: "ziti-orphan", domain: "ziti",
			detect: func(ctx context.Context) ([]Finding, error) {
				zm := s.ziti()
				if zm == nil {
					return []Finding{{CheckID: "ziti-orphan", Domain: "ziti", Status: "ok"}}, nil
				}
				rows, _ := s.db.Pool.Query(ctx,
					`SELECT ziti_service_name FROM proxy_routes WHERE ziti_enabled AND ziti_service_name <> ''`)
				desired := map[string]bool{}
				if rows != nil {
					for rows.Next() {
						var n string
						if rows.Scan(&n) == nil {
							desired[n] = true
						}
					}
					rows.Close()
				}
				ents, err := zm.listEdgeEntities(ctx, "services")
				if err != nil {
					return nil, err
				}
				var names []string
				for _, e := range ents {
					names = append(names, e.Name)
				}
				var out []Finding
				for _, n := range orphanOpenidxServices(names, desired) {
					out = append(out, Finding{CheckID: "ziti-orphan", Domain: "ziti", Severity: "warn",
						Status: "orphan", Safe: false, Subject: n, Detail: "controller service with no owning route", Action: "tear down service"})
				}
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "ziti-orphan", Domain: "ziti", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				zm := s.ziti()
				if zm == nil {
					return nil
				}
				return zm.TeardownZitiServiceByName(ctx, f.Subject)
			}},

		// per-host uniqueness: >1 proxy_route on one host — RISKY: consolidate (subject = host).
		&fnCheck{id: "host-unique", domain: "access",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT lower(split_part(split_part(from_url,'//',2),'/',1)) AS host, count(*)
					FROM proxy_routes WHERE ziti_enabled AND enabled
					GROUP BY 1 HAVING count(*) > 1`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var host string
					var n int
					if rows.Scan(&host, &n) == nil {
						out = append(out, Finding{CheckID: "host-unique", Domain: "access", Severity: "error",
							Status: "drift", Safe: false, Subject: host,
							Detail: fmt.Sprintf("%d routes share host %s", n, host), Action: "consolidate app"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "host-unique", Domain: "access", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				// Deterministic pick: if several published_apps somehow share the
				// host, consolidate the oldest (stable across re-runs) rather than
				// an arbitrary LIMIT 1. consolidateApp is idempotent, so a second
				// run on the same host is harmless if the choice ever differs.
				var appID, org string
				err := s.db.Pool.QueryRow(ctx, `
					SELECT id::text, org_id::text FROM published_apps
					WHERE public_host = $1 ORDER BY created_at, id LIMIT 1`, f.Subject).Scan(&appID, &org)
				if err != nil {
					return fmt.Errorf("no published_app for host %s: %w", f.Subject, err)
				}
				_, _, err = s.consolidateApp(ctx, org, appID, "")
				return err
			}},

		// INVARIANT: the report-only checks below (app-client, identity-ziti,
		// domain-presence) intentionally have NO fix func and emit Safe:false
		// findings — they surface a human-judgment situation, not auto-fixable
		// drift. Keep them Safe:false: a Safe:true finding with no fix would be
		// reported as "Healed" by ScanAndHeal while doing nothing.

		// app ↔ oauth_client: real OIDC app (non-proxy tile) without a client — report only.
		&fnCheck{id: "app-client", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT a.name, a.client_id FROM applications a
					WHERE a.client_id NOT LIKE 'proxy-app-%'
					  AND NOT EXISTS (SELECT 1 FROM oauth_clients oc WHERE oc.client_id=a.client_id)`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var name, cid string
					if rows.Scan(&name, &cid) == nil {
						out = append(out, Finding{CheckID: "app-client", Domain: "apps", Severity: "warn",
							Status: "orphan", Safe: false, Subject: cid, Detail: "application " + name + " has no oauth_client", Action: "review (manual)"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "app-client", Domain: "apps", Status: "ok"})
				}
				return out, nil
			}},

		// published_app status consistency — safe: mark published if it has a linked route.
		&fnCheck{id: "published-app", domain: "apps",
			detect: func(ctx context.Context) ([]Finding, error) {
				rows, err := s.db.Pool.Query(ctx, `
					SELECT pa.id::text, pa.name FROM published_apps pa
					WHERE pa.status <> 'published'
					  AND EXISTS (SELECT 1 FROM discovered_paths dp WHERE dp.app_id=pa.id AND dp.route_id IS NOT NULL)`)
				if err != nil {
					return nil, err
				}
				var out []Finding
				for rows.Next() {
					var id, name string
					if rows.Scan(&id, &name) == nil {
						out = append(out, Finding{CheckID: "published-app", Domain: "apps", Severity: "info",
							Status: "drift", Safe: true, Subject: id, Detail: name + " has routes but status<>published", Action: "set status=published"})
					}
				}
				rows.Close()
				if len(out) == 0 {
					out = append(out, Finding{CheckID: "published-app", Domain: "apps", Status: "ok"})
				}
				return out, nil
			},
			fix: func(ctx context.Context, f Finding) error {
				_, err := s.db.Pool.Exec(ctx, `UPDATE published_apps SET status='published', updated_at=NOW() WHERE id=$1`, f.Subject)
				return err
			}},

		// users ↔ ziti_identities — report only.
		&fnCheck{id: "identity-ziti", domain: "identity",
			detect: func(ctx context.Context) ([]Finding, error) {
				var unlinked int
				s.db.Pool.QueryRow(ctx,
					`SELECT count(*) FROM ziti_identities zi WHERE zi.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=zi.user_id)`).Scan(&unlinked)
				if unlinked > 0 {
					return []Finding{{CheckID: "identity-ziti", Domain: "identity", Severity: "warn", Status: "orphan",
						Safe: false, Subject: "ziti_identities", Detail: fmt.Sprintf("%d identities reference a missing user", unlinked), Action: "review (manual)"}}, nil
				}
				return []Finding{{CheckID: "identity-ziti", Domain: "identity", Status: "ok"}}, nil
			}},

		// governance + devices wired? — presence only.
		&fnCheck{id: "domain-presence", domain: "governance",
			detect: func(ctx context.Context) ([]Finding, error) {
				var policies, devices int
				s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM policies`).Scan(&policies)
				s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM known_devices`).Scan(&devices)
				return []Finding{presenceFinding("domain-presence", "governance", policies), presenceFinding("domain-presence", "devices", devices)}, nil
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

// bytesContainsHost reports whether any redirect URI in the oauth_clients
// redirect_uris JSON array has exactly the given host. It parses the array and
// compares hostnames (rather than a raw substring match, which could false-
// match a host that is a prefix/substring of another, e.g. app.tdv.org vs
// app.tdv.org.evil.com). Unparseable input → false.
func bytesContainsHost(jsonArr []byte, host string) bool {
	var uris []string
	if json.Unmarshal(jsonArr, &uris) != nil {
		return false
	}
	for _, u := range uris {
		if hostOf(u) == host {
			return true
		}
	}
	return false
}
