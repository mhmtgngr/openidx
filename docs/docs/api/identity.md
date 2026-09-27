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
