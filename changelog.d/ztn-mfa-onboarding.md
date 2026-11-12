### Documentation
- **Federated identity, OpenIDX MFA.** The inbound federation guide explains
  how a sign-in at Entra ID or AD FS still runs OpenIDX's own MFA evaluation,
  why `trust_upstream_mfa` starts false, how `sso_login`'s `upstream_amr`
  informs trusting it per provider, and the inline enrolment fallback.
- **MFA rollout runbook.** The MFA guide gains a concrete runbook: enrolling
  with Google/Microsoft Authenticator, a recommended first policy (internal
  users, TOTP + WebAuthn, 72h grace) via the console, and a deferred SMS
  activation runbook with every provider's credential variables.
