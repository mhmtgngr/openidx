### Added
- **OpenIDX as Microsoft Entra ID's second factor.** With `EAM_ENABLED=true`,
  OpenIDX serves an OpenID provider at `<OAUTH_ISSUER>/eam` that Entra can be
  registered against as an external authentication method: a discovery
  document, a key set with `x5c` certificates (`/eam/jwks`) and an
  authorization endpoint. Entra's request is checked (the configured
  `EAM_CLIENT_ID`, Entra's own reply address, a tenant on `EAM_TENANT_IDS`, and
  an `id_token_hint` that verifies against that tenant's published keys with
  the right audience). The person is found by the hint's `oid` (an Entra
  identity link, then a directory sync), then by a verified email; nobody is
  provisioned. They complete an OpenIDX second factor on the usual sign-in
  page (TOTP, passkey or push; `EAM_REQUIRE_STRONG_FACTORS=false` also allows
  SMS and email codes), and Entra receives a five-minute id_token with
  `acr=possessionorinherence` and `amr` `otp`, `fido` or `pop`. Audited as
  `eam.mfa_satisfied` with Entra's `client-request-id`.
- **EAM signing keys that rotate on Entra's schedule.** Migration 248 adds
  `eam_signing_keys` (install level, private key sealed with the install
  cipher). The first key is made on first use; `POST
  /api/v1/oauth/eam/keys/rotate` (platform administrators) publishes the next
  key two days before it signs, so Entra's cached key set has it first.
- **Entra External MFA card in the admin console.** Settings → Security shows
  platform administrators what to register in Entra (issuer, discovery, JWKS
  and authorization URLs, client ID), the allowed tenants, each signing key as
  signing, waiting or retired with a **Rotate key** button, and the last 24
  hours of satisfied and refused or failed verifications, read from the new
  `GET /api/v1/oauth/eam/status`. A runbook, `docs/guides/ENTRA-EAM.md`, covers
  the app registration, consent, a pilot-group external method, Conditional
  Access "Require MFA", rotation and tracing a sign-in by `client-request-id`.
