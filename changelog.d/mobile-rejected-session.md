### Fixed
- **A phone whose session was revoked now asks you to sign in again.** When the
  server refused the stored refresh token (`invalid_grant`, e.g. after a sign-out
  or session revoke elsewhere), the mobile engine kept the dead session: every
  API call retried the refresh until `/oauth/token` rate-limited the phone, and
  the screens showed "ApiException(401): invalid token" with a Retry that could
  never work. The engine now clears a session whose refresh is rejected (a
  rate limit or outage still keeps it), and the app signs out locally when a
  request is still refused with the freshest token, so the sign-in screen
  appears.
