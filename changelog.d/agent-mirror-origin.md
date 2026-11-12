### Fixed
- **The box update mirror advertises the issuer origin.** PublicBaseURL
  defaults to http://localhost:3000 and outranked OAUTH_ISSUER, so the
  re-signed manifest sent agents to an MSI at localhost. Loopback origins are
  now skipped and the issuer comes first.
