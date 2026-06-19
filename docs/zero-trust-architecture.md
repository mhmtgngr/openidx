# Zero Trust Access Architecture

This is the map of how OpenIDX enforces zero-trust access: where OpenZiti,
BrowZer, the HTTP proxy, posture, risk and device-trust each fit, and the order
in which a request is evaluated. The **Zero Trust Access** admin page
(`/zero-trust`) is the single pane over everything described here.

## The access spine: `proxy_routes`

Every protected resource is a row in `proxy_routes`. The row carries both **how
it is reached** (the access method) and **the controls guarding it** (the
zero-trust policy). The access service (`internal/access`) matches an inbound
request to a route by Host (`findRouteByHost`, `service.go:2044`), evaluates the
policy, then forwards over the chosen method.

## The five access paths

| # | Path | Enabled by | Where in code |
|---|------|-----------|---------------|
| 1 | **HTTP reverse proxy** (default) | always, for `route_type=http` | `handleProxy` (`service.go:1450`) |
| 2 | **OpenZiti overlay** | `ziti_enabled` + `ziti_service_name` | transport swap in `handleProxy` (~`service.go:1549`); `ziti.go` |
| 3 | **BrowZer** (clientless, browser→Ziti) | `browzer_enabled` (requires Ziti) | `ziti_browzer.go`, `ziti_browzer_handlers.go` |
| 4 | **Guacamole** (RDP/VNC/SSH gateway) | `guacamole_connection_id` / `route_type` | `feature_manager.go` (FeatureGuacamole) |
| 5 | **Forward-auth decision** (for external proxies like APISIX) | `POST /api/v1/access/auth/decide` | `context_evaluator.go` |

All five share the **same evaluation pipeline** below — the method only changes
how bytes are carried after a request is allowed. Methods 2–4 are toggled per
route via the Feature Manager (`EnableFeature`/`DisableFeature`,
`feature_manager.go:123`) and tracked in `service_features`.

## The evaluation pipeline (fail-closed)

`evaluateAccessContext` (`context_evaluator.go:105`) runs after
`buildAccessContext` (`context_evaluator.go:44`) gathers IP geo/threat, device
trust and posture. Order, each step short-circuits to DENY or adds risk:

1. **IP threat hard-block** — `ip_threat_list` active → DENY (risk 100).
2. **Geo-fence** — `allowed_countries` set and client country not in it → DENY.
3. **User-agent pinning** — major UA change → +risk.
4. **Device trust** — `require_device_trust` and session not trusted → DENY (step-up).
5. **Posture** — `posture_check_ids`; posture score below threshold → +risk / DENY.
6. **Risk cap** — accumulated `risk_score` > `max_risk_score` → DENY (step-up).
7. **Inline policy DSL** — `inline_policy` evaluated against the request context → DENY if false.

Continuous verification (`continuous_verify.go`) re-checks live sessions and can
flag step-up mid-session.

## Where each control lives

| Control | DB column (`proxy_routes`) | Evaluator step |
|--------|----------------------------|----------------|
| Require login | `require_auth` | session resolve (pre-pipeline) |
| Role/group gate | `allowed_roles`, `allowed_groups` | role check in `handleProxy` |
| Geo-fence | `allowed_countries` | step 2 |
| Device trust | `require_device_trust` | step 4 |
| Posture | `posture_check_ids` | step 5 |
| Risk cap | `max_risk_score` | step 6 |
| Custom logic | `inline_policy` | step 7 |
| Re-verify cadence | `reverify_interval` | continuous verify |

## Request path

```
Client ──HTTPS──> nginx / APISIX (TLS terminate, X-Forwarded-Proto, geo headers)
                      │
                      ▼
              access service · handleProxy (service.go:1450)
                      │  findRouteByHost (service.go:2044)
                      ▼
              session resolve (cookie / bearer)
                      │  none? → OAuth PKCE login at /access/.auth/login
                      ▼
              buildAccessContext (context_evaluator.go:44)
                 geo · IP-threat · device-trust · posture (via Ziti)
                      ▼
              evaluateAccessContext (context_evaluator.go:105)
                 IP → geo → UA → device → posture → risk-cap → inline-policy
                      │ allow
        ┌─────────────┼───────────────┬───────────────────┐
        ▼             ▼               ▼                   ▼
   route_type=http  ziti_enabled   browzer_enabled    guacamole_connection_id
   reverse proxy    Ziti transport  BrowZer bootstrap  Guacamole gateway
   → to_url         → overlay       → clientless       → RDP/VNC/SSH
```

## The unified view

`GET /api/v1/access/overview` (`overview_handler.go`) aggregates, per org, every
route with its derived access methods, the policy summary, live session count and
feature health, plus rollup counts and OpenZiti control-plane status. The
`/zero-trust` page renders this as three lenses:

- **Resources** — the spine: resource × methods × controls × sessions × health, with
  inline Ziti/BrowZer toggles (reusing `POST /services/:id/features/{ziti,browzer}/{enable,disable}`).
- **Live Access** — active sessions (`GET /sessions`) + recent allow/deny (`GET /audit/unified`).
- **Coverage Gaps** — resources missing auth / device-trust / posture / risk cap, to harden.

Deep edits stay on the dedicated pages (Proxy Routes, Ziti Network, App Publish,
Devices); the overview links out to them.
