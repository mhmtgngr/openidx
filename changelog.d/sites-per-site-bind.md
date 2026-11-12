### Added
- **Sites for split-site hosting.** A new `sites` table (seeded with a `default` site) and `site_routers` map Ziti edge routers to the place they run, and a network resource or proxied application can name its site (`site_id`; empty means the default site).
  Each edge router is tagged `site-<slug>` beside `ziti-routers`, and a router-hosted service in a non-default site is bound only to its own site's routers (`#site-<slug>`). If that site has no router, the service fails closed with the converge status "no router in site". Services in the default site are hosted exactly as before.

### Upgrade notes
- Migration 249 adds `sites`, `site_routers`, `network_targets.site_id` and `proxy_routes.site_id`. Existing rows stay in the default site, so nothing changes on upgrade.
