### Security
- **Adaptive MFA now sees login history (B7.4).** The risk `LoginContext`
  built at sign-in carries the failed-attempt count from before the
  successful login reset it, and the previous geolocated sign-in (IP, lat,
  lon, time). Impossible-travel, new-location and failed-attempt scoring in
  `AssessLoginRisk` could never fire before; they do now.
- **Per-account rate limit on credential endpoints (B7.5).** With
  `RATE_LIMIT_PER_USER=true`, `/oauth/login` and `/eam/*` are also counted
  against the submitted username (hashed) at the auth-tier limit, so rotating
  source IPs cannot spray one account. Recommended for internet-facing
  deployments.

### Changed
- **BrowZer user sync (B7.6).** The Ziti user-sync poller's batch and tick are
  configurable (`ZITI_USER_SYNC_BATCH`, default 100, was a fixed 10;
  `ZITI_USER_SYNC_INTERVAL`, default `30s`). A BrowZer sign-in queues an
  on-demand sync of that user in Redis, drained by the access service every
  few seconds.
- **DB pool budget (B7.7).** `DB_MAX_CONNS` and `DB_MIN_CONNS` are documented;
  identity, oauth and access should run with `DB_MAX_CONNS=25` before an
  internet-facing pilot, with Postgres `max_connections` raised to fit.
  `scripts/box-deploy.sh preflight` prints the pool budget and warns when it
  exceeds `max_connections`.
