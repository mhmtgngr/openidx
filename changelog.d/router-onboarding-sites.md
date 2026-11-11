### Added
- **Router onboarding into a site.** Ziti Network > Overview has an **Add router** dialog: pick or create a site, give the router's advertised address, and copy a `docker run` command that enrolls and runs `openziti/ziti-router` in host mode. `POST /api/v1/access/ziti/fabric/routers/enroll-token` now takes `{name, site_slug, advertised_address, image_tag}`, tags the router `site-<slug>` and `ziti-routers`, and records it in `site_routers`.
- **Sites API.** `GET/POST /api/v1/access/sites` and `PATCH /api/v1/access/sites/:id` (writes are install-administrator only, with a fresh second factor). Network resources (including the CSV import's `site` column) and one-click app publishing take a site.
- New guide: *Split-site Azure Router* (`docs/docs/deployment/split-site-azure-router.md`).

### Configuration
- `ZITI_ROUTER_IMAGE_TAG` (default `1.6.12`) pins the router image the onboarding command uses. Keep it at the controller's version.

### Changed
- The onboarding command no longer uses `openziti/ziti-router:latest`, and the request needs `advertised_address`.
