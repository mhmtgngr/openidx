### Added
- **An identity provider's federation profile.** An upstream OpenID provider
  (Microsoft Entra ID, ADFS, Keycloak, a partner organization's issuer) can now
  be configured with its discovery location, PKCE, whether its own MFA claim is
  trusted for internal users, a claims mapping, a group mapping, a
  just-in-time provisioning policy (population, population rules by claim),
  the request parameters it forwards and which claim is the person's stable
  identifier (`oid` for Entra). Migration 246; every existing provider keeps
  today's behaviour.
- **A relying-party library that trusts only what the provider publishes.**
  `internal/federation/oidcrp` reads the provider's discovery document (the
  issuer must match), caches its keys per provider rather than through the
  install's own key cache, and checks every ID token's algorithm, signature,
  issuer, audience, lifetime and nonce.

### Security
- **Federated-sign-in discovery cannot be aimed inside the network.** The
  relying party fetches an issuer's discovery document, token endpoint and
  key set through the outbound guard (`OIDX_OUTBOUND_ALLOWLIST`): loopback,
  private, link-local and other internal addresses are refused at every
  connection, and redirects are followed only to https. Plain-http loopback
  issuers need `OIDCRP_ALLOW_LOOPBACK=true` (tests and development only).
