### Added
- **Reset a user's MFA from MFA Management.** The User MFA Status table has a
  Reset MFA action that, after a confirmation in the page, removes every second
  factor the user has (authenticator app, security keys, push devices, SMS,
  email codes, phone call and unused backup codes) in one step. The user signs
  in with their password and sets MFA up again under their MFA policy. Behind
  it is `POST /api/v1/identity/users/{id}/mfa/reset`, which takes an optional
  `factors` list, is limited to administrators and to users in their own
  organization, refuses the caller's own account (that goes through the
  profile), is gated by `STEPUP_GATE` like other admin writes, and is audited
  as `mfa.admin_reset`.
