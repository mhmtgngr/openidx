### Added
- **Enterprise SSO completes a pending third-party sign-in.** `/oauth/authorize`
  accepts `login_session` alongside `idp_hint`; the authorization request
  stored for that handle (client_id, redirect_uri, state, nonce, PKCE) is the
  one the SSO callback completes, and the handle is deleted on success. An
  unknown or expired handle returns to the login page with `sso_sign_in_failed`.
- **Home-realm discovery on the login page.** Leaving the email field asks
  `POST /api/v1/identity/federation/discover`; a rule with `auto_redirect`
  sends the browser to that IdP with `login_hint`, otherwise the IdP's button
  is highlighted. The login page explains `sso_nonce_mismatch`,
  `sso_idp_error`, `sso_user_not_found` and `sso_partner_not_registered`
  (English and Turkish).
