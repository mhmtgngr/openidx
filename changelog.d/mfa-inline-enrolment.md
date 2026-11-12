### Added
- **A missing second factor is added at sign-in instead of refusing it.** When an MFA
  policy refuses a sign-in because the person has none of the methods it requires
  (the grace period is over, or an external user has no authenticator app, passkey or
  push device), the login page now walks them through adding an authenticator app or
  a passkey, shows their backup codes, and finishes the sign-in. This works for
  password, social and enterprise SSO sign-ins, and an external account still waiting
  for its factor becomes active. Email and SMS codes are never offered here. Turn it
  off with `MFA_INLINE_ENROLLMENT=false` to keep the previous `mfa_enrollment_required`
  refusal. New endpoints: `POST /oauth/mfa/enroll/totp/begin|finish` and
  `POST /oauth/mfa/enroll/webauthn/begin|finish`.
