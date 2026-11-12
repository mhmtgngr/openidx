### Changed
- **The access proxy no longer talks to external identity providers itself
  (B1.5).** `/access/.auth/login?idp=<id>` and a route's `idp_id` now send
  the browser to OpenIDX's `/oauth/authorize?idp_hint=<id>`, so every
  federated sign-in goes through the OAuth service's verified callback
  (id_token signature, nonce, JIT provisioning, MFA). The proxy's own
  upstream code exchange and its unverified reading of the provider's token
  are removed. `proxy_sessions.idp_id` is now filled from the id_token's
  `idp` claim. An unknown or disabled `idp` is refused with `400`.

### Added
- **Partner onboarding in the console (B2.3).** The vendor organization form
  sets the onboarding mode, identity provider, sliding expiry and default
  groups (external-allowed groups only); a federated vendor cannot be saved
  without a default sponsor. A **Change default sponsor** action on each
  vendor. The external accounts list filters by source
  (`GET /external-users?source=federated`). The vendor API reads and writes
  the migration 247 fields. `FEDERATION-INBOUND.md` gains a "Paydaş
  kurumları" section.
