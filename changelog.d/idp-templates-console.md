### Added
- **Enterprise identity-provider templates and federation profile in the
  console.** Identity Providers adds quick-setup templates for Microsoft
  Entra ID (v2.0, `external_id_claim: oid`, standard claims mapping,
  `domain_hint` forwarded), AD FS (with its discovery URL), Keycloak and
  Generic OIDC, and the provider form now edits the whole federation profile:
  discovery URL, PKCE, external ID claim, forwarded parameters, trust of the
  provider's MFA, and the claims mapping, group mapping and JIT policy (JSON).
  English and Turkish.
- **Inbound federation guide** (`docs/FEDERATION-INBOUND.md`): Entra app
  registration (redirect `<issuer>/oauth/callback`, optional claims `email`,
  `groups`, `acct`), AD FS application group steps, the profile fields, the
  login page's SSO error codes, and the outbound SSRF guard
  (`OIDX_OUTBOUND_ALLOWLIST`, `OIDCRP_ALLOW_LOOPBACK` for tests only).
