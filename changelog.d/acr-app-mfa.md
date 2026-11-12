### Added
- **Applications can ask for a stronger sign-in with `acr_values`.** `/oauth/authorize`
  accepts `urn:openidx:mfa` (a second factor in this session), `urn:openidx:mfa:fresh`
  (one within `STEPUP_MAX_AGE`) and `urn:openidx:phishing-resistant` (a passkey). A
  session that has not proved what was asked for is challenged for the factor before
  the code is issued, and the ID token's new `acr` claim says what the session proved.
  Discovery lists the classes in `acr_values_supported`.
- **Per-application access conditions can be edited.** `GET/PUT
  /api/v1/applications/{id}/conditions` and the console's **Access conditions** item on
  an application's menu set device trust, a risk ceiling, allowed countries and *Require
  a fresh second factor*. The last one now applies: every OIDC sign-in to the
  application asks for a fresh second factor, and the access proxy judges it against the
  login session and sends the browser through a fresh sign-in when it is missing.
- Guide: signing in to an ABP application with OpenIDX
  (`docs/docs/guides/ABP-INTEGRATION.md`).

### Changed
- **SAML sign-on to applications is narrowed.** SP-initiated SAML sign-on now answers
  `403 saml_sp_initiated_unsupported` after validating the request, and IdP-initiated
  sign-on is off unless `SAML_IDP_ENABLED=true`. Neither applied MFA policies,
  assignment or device trust. Connect applications with OpenID Connect.
- A passkey used as the second factor records `hwk` in the session's `amr`.
