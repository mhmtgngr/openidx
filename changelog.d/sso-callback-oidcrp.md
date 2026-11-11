### Changed
- **Enterprise SSO is a standards-conformant OpenID Connect relying party.**
  `/oauth/authorize?idp_hint=` and `/oauth/callback` now read the provider's
  authorization and token endpoints from its discovery document (honouring
  the IdP's `discovery_url`, for ADFS), send state, nonce and PKCE, forward
  only the request parameters the IdP profile allows (`pass_through_params`),
  verify the ID token fully (issuer, audience, signature, lifetime, nonce) and
  read the user through the IdP's claims mapping and `external_id_claim`
  (`oid` for Entra). An upstream `error=` returns to the login page with
  `sso_idp_error`.
- **OpenIDX ID tokens carry `idp`** for a session established by a federated
  sign-in, and discovery lists it in `claims_supported`. Such sessions record
  `amr` as `fed` (or `fed`,`mfa`).

### Security
- **No more substring email matching on SSO.** A federated sign-in is matched
  by the IdP link (`idp_id` + external id), then by exact email only when the
  provider says the email is verified or the IdP's `jit_policy.link_by_email`
  is set, and a new account is provisioned only when `jit_policy.provision`
  is on (internal population; external JIT is refused with
  `sso_partner_not_registered`). Otherwise the sign-in is refused with
  `sso_user_not_found`. A nonce mismatch is refused (`sso_nonce_mismatch`).
- **Upstream MFA is trusted only for internal users.** With
  `trust_upstream_mfa`, an upstream `amr` of mfa/otp/fido/hwk/swk/pop/sms/tel
  skips the OpenIDX second factor for an internal user; an external (vendor)
  user always gives an OpenIDX factor.
- **Group mapping touches only mapped groups**, and an external user joins
  only `external_allowed` groups. The country block now applies to SSO
  sign-ins.
