# Identity Service API

Base URL: `http://localhost:8001`

The Identity Service manages users, groups, roles, permissions, sessions, identity providers, and MFA.

## Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/users` | List users (paginated) |
| POST | `/api/v1/identity/users` | Create user |
| GET | `/api/v1/identity/users/:id` | Get user by ID |
| PUT | `/api/v1/identity/users/:id` | Update user |
| DELETE | `/api/v1/identity/users/:id` | Delete user |
| GET | `/api/v1/identity/users/search` | Search users |
| POST | `/api/v1/identity/users/export` | Export users (CSV) |
| POST | `/api/v1/identity/users/import` | Import users (CSV) |

An external (vendor) user is a user with `userType` `external`. Such a user carries `accountStatus`, `vendorOrgId`, `sponsorUserId` and `accountExpiresAt`, which are read-only through these routes. An external user may hold only the `user` role and join only groups whose `attributes.externalAllowed` is `"true"`. Anything else is refused with `403` and a `code`: `external_role_cap`, `external_group_not_allowed` or `external_account_not_live`.

## Vendor organizations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/vendor-orgs` | List vendor organizations, with external-user counts by status |
| POST | `/api/v1/identity/vendor-orgs` | Create a vendor organization |
| GET | `/api/v1/identity/vendor-orgs/:id` | Get a vendor organization |
| PUT | `/api/v1/identity/vendor-orgs/:id` | Update one (status `active` or `suspended`) |
| POST | `/api/v1/identity/vendor-orgs/:id/close` | Close one, with a `reason`. Its external users are disabled. This cannot be undone |
| GET | `/api/v1/identity/vendor-orgs/:id/targets` | What is open to a vendor on a closed list: each target's type, id and name |
| POST | `/api/v1/identity/vendor-orgs/:id/targets` | Open a target: `target_type` (`pam_entry`, `application` or `network_service`) and `target_id`. A PAM entry, an application or a network service (one of the organization's Ziti services) must exist in the organization (`404`), and a second opening is a `409` |
| DELETE | `/api/v1/identity/vendor-orgs/:id/targets/:targetId` | Close a target again |

A vendor organization's `closed_list` (create and update; an update that leaves it out keeps it) puts its external users on the closed list: they ask for, and launch, only the PAM entries, applications and network services opened to the vendor. Anything else answers `403` with `external_target_not_open`, and the PAM entry lists show them only what is open. With `closed_list` off, the targets are kept and decide nothing. A closed vendor's targets cannot change (`vendor_org_closed`).

Suspending a vendor (`PUT` with `status` `suspended`) suspends each of its live accounts at once, with the same severing as an account's own suspension, and tells the SSF receivers `session-revoked`. While suspended, the vendor accepts no new invitations, extensions or reactivations, and the 7-day reactivation window of its accounts does not run. Setting it `active` again reactivates no account: it restarts each suspended account's 7-day window, in which a sponsor takes the account back with `reactivate`. Closing the vendor ends its accounts for good.

## External users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/external-users` | List external accounts, optionally by `vendor_org_id` and `status`, with vendor, sponsor, `expiring_soon` (active, ending within 14 days), `has_strong_factor` and, for a suspended one whose vendor is active, `reactivate_until` |
| POST | `/api/v1/identity/external-users/:id/suspend` | Suspend a live account. It can be reactivated within 7 days |
| POST | `/api/v1/identity/external-users/:id/disable` | Disable a live or suspended account. This is final; access needs a new invitation |
| POST | `/api/v1/identity/external-users/:id/extend` | Move the account's end, with `account_expires_at` or `extend_days`, within a year and the vendor's contract |
| POST | `/api/v1/identity/external-users/:id/reactivate` | Reactivate a suspended account with a new `sponsor_user_id`, within 7 days of its suspension and before its end |
| POST | `/api/v1/identity/external-users/:id/sponsor` | Hand a live account to another `sponsor_user_id` |

Each `POST` needs a `reason`, which is recorded in the audit trail with the change. An external user cannot call these routes (`external_not_permitted`). A move the account's state does not allow is `409` with `external_status_conflict`. Suspending and disabling end the account's sessions, tokens, API keys, vault checkouts and grants, and time-bound elevations at once. Extending does not lengthen grants already written: they still end on the old date unless they are granted again. Moving the end earlier cuts every grant past it to the new end.

The identity service also ends accounts on its own, every minute, and severs each one once:

| When | The account becomes |
|------|---------------------|
| It reaches `account_expires_at` | `expired` |
| Its vendor is closed | `disabled` |
| Its vendor is suspended | `suspended` |
| Its invitation lapses before a second factor is enrolled | `expired` |
| Its sponsor is disabled, or is no longer an active internal user | `suspended` |
| It stays suspended for 7 days, while its vendor is not suspended | `disabled` |

An external user's access request must name a duration, ending no later than the account; otherwise it is refused with `400` and `external_window_invalid`. A role, a PAM entry grant or a vault grant written for an external user directly is cut to end when the account does.

## Invitations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/invitations` | List invitations, with `user_type` and, for an external one, its vendor, sponsor and account expiry |
| POST | `/api/v1/identity/invitations` | Invite a user. An external invitation adds `user_type: "external"`, `vendor_org_id`, and optionally `sponsor_user_id` plus `expires_in_days` or `account_expires_at` |
| DELETE | `/api/v1/identity/invitations/:id` | Revoke an invitation |
| POST | `/api/v1/identity/invitations/:token/accept` | Accept an invitation (public; the token is the credential) |
| POST | `/api/v1/identity/invitations/:token/mfa` | Finish an external invitation: `{secret, code}` from the authenticator the acceptance returned (public) |

An external invitation is refused when the vendor is not active (`vendor_not_active`) or the address is outside its allowed domains (`external_email_domain`). It is also refused when the sponsor is not an enabled internal user (`external_sponsor_invalid`), the lifetime is not within a year and the contract (`external_expiry_invalid`), or it names a role other than `user` or a group not open to external users. Without a sponsor, the vendor's default sponsor is used, then the inviter. Without a lifetime, the vendor's default is used, cut back to the contract's end.

The acceptance creates an account in `pending_mfa` that cannot sign in. It answers with `mfa.secret` and `mfa.otpauth_url` for an authenticator app. The account becomes `active` only when `/mfa` receives a valid code. External users cannot enroll SMS, email or phone-call factors (`external_factor_not_allowed`).

## Roles & Permissions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/roles` | List roles |
| POST | `/api/v1/identity/roles` | Create role |
| GET | `/api/v1/identity/roles/:id` | Get role |
| PUT | `/api/v1/identity/roles/:id` | Update role |
| DELETE | `/api/v1/identity/roles/:id` | Delete role |
| POST | `/api/v1/identity/users/:id/roles` | Assign role to user |
| DELETE | `/api/v1/identity/users/:id/roles/:roleId` | Remove role from user |
| GET | `/api/v1/identity/permissions` | List permissions |

## Groups

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/groups` | List groups |
| POST | `/api/v1/identity/groups` | Create group |
| GET | `/api/v1/identity/groups/:id` | Get group |
| PUT | `/api/v1/identity/groups/:id` | Update group |
| DELETE | `/api/v1/identity/groups/:id` | Delete group |
| POST | `/api/v1/identity/groups/:id/members` | Add member |
| DELETE | `/api/v1/identity/groups/:id/members/:userId` | Remove member |

## Sessions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/users/:id/sessions` | List user sessions |
| DELETE | `/api/v1/identity/users/:id/sessions/:sessionId` | Revoke session |

## Password Management

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity/users/:id/change-password` | Change password |
| POST | `/api/v1/identity/forgot-password` | Request password reset |
| POST | `/api/v1/identity/reset-password` | Reset password with token |

## MFA — TOTP

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity/mfa/totp/setup` | Generate TOTP secret + QR |
| POST | `/api/v1/identity/mfa/totp/enroll` | Store the secret, confirmed by a code from it |
| DELETE | `/api/v1/identity/mfa/totp` | Disable TOTP |
| POST | `/api/v1/identity/mfa/totp/verify` | Verify TOTP code; a code is accepted once |
| POST | `/api/v1/identity/mfa/backup/generate` | Replace the unused backup codes with a new set |

## Changing your own second factors

A request that removes, replaces or adds to the caller's second factors must
carry proof that the account holder is making it, in its JSON body:

- `current_password`: the account's password. It is checked as at sign-in (the
  directory for an LDAP or Active Directory account), and a wrong one counts
  against the account's lockout.
- `totp_code`: a current code from the TOTP credential. It is accepted only
  where the change removes or replaces that credential, and once.

| Change | Routes | Proof |
|--------|--------|-------|
| Disable MFA, remove TOTP | `POST /users/me/mfa/disable`, `DELETE /mfa/totp` | password or TOTP code |
| Replace TOTP | `POST /users/me/mfa/enable`, `POST /mfa/totp/enroll` | password or a code from the current credential |
| Remove a factor | `DELETE /mfa/webauthn/credentials/:id`, `DELETE /mfa/push/devices/:id`, `DELETE /mfa/sms`, `DELETE /mfa/email`, `DELETE /mfa/phone` | password |
| Add a factor | `POST /mfa/webauthn/register/finish`, `POST /mfa/push/devices`, `POST /mfa/push/register`, `POST /mfa/push/enroll/start`, `POST /mfa/sms/verify`, `POST /mfa/email/enroll`, `POST /mfa/phone/verify`, `POST /mfa/totp/enroll` | password, when the account already has a second factor |
| Regenerate backup codes, remember a browser | `POST /mfa/backup/generate`, `POST /trusted-browsers` | password, when the account already has a second factor |
| Move a verified phone-call number | `POST /mfa/phone/enroll` | password |
| Link or unlink an external sign-in account | `POST /oauth/social/link/:provider_id/start` (oauth service), `DELETE /users/me/identity-links/:linkId` | password or TOTP code, when the account has a password or a second factor |
| Change the account's address | `PUT /users/me` with a new `email` | password |

Routes are under `/api/v1/identity`. The first factor of an account that has
none needs no proof. A request without the proof, or with a wrong one, gets
403 with `error` set to `reauthentication_required` or
`reauthentication_failed` and `accepts` naming the proofs this account can give;
`reauthentication_locked` means too many wrong attempts, and
`reauthentication_unavailable` means the change needs a password the account
does not have here (it signs in through an identity provider). An administrator
can then set a password (`POST /users/:id/set-password`) or issue an MFA bypass
code (`POST /mfa/bypass-codes`); both need the admin role. A new address is
unverified until the link sent to it is followed.

## MFA — SMS and email codes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity/mfa/sms/challenge` | Send a code by SMS |
| POST | `/api/v1/identity/mfa/email/challenge` | Send a code by email |
| POST | `/api/v1/identity/mfa/otp/verify` | Verify a code (`method` is `sms` or `email`) |

A challenge takes at most its `max_attempts` guesses (3 by default), however
they are sent: each guess is counted, and refused at the limit, before the code
is compared, and the right code verifies the challenge once. The sign-in's and
step-up's SMS and email steps use the same verifier.

## MFA — WebAuthn

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity/mfa/webauthn/register/begin` | Begin registration |
| POST | `/api/v1/identity/mfa/webauthn/register/finish` | Complete registration |
| POST | `/api/v1/identity/mfa/webauthn/authenticate/begin` | Begin authentication |
| POST | `/api/v1/identity/mfa/webauthn/authenticate/finish` | Complete authentication |

## Identity Providers

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/identity/identity-providers` | List configured IdPs |
| POST | `/api/v1/identity/identity-providers` | Add IdP (OIDC/SAML) |
| GET | `/api/v1/identity/identity-providers/:id` | Get IdP details |
| PUT | `/api/v1/identity/identity-providers/:id` | Update IdP |
| DELETE | `/api/v1/identity/identity-providers/:id` | Delete IdP |
