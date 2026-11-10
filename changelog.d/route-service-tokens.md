### Added
- **Service tokens on proxied web applications.** A route can admit named
  service accounts (`POST /api/v1/access/routes/{id}/service-accounts`); an
  active API key of one of them (`Authorization: Bearer oidx_...`) then
  reaches the application through the built-in proxy and the APISIX
  forward-auth hook without a person. The application is told
  `service-account:<id>` with role `service_account` and never receives the
  key. Routes that need a person (assigned application, reason, trusted
  device, posture, policies, country fence, risk ceiling, roles or groups)
  never admit one. Every allow and refusal is audited. Migration 245.
