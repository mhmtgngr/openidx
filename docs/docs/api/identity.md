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
| POST | `/api/v1/identity/mfa/totp/enable` | Enable TOTP with verification code |
| POST | `/api/v1/identity/mfa/totp/disable` | Disable TOTP |
| POST | `/api/v1/identity/mfa/totp/verify` | Verify TOTP code |
| GET | `/api/v1/identity/mfa/totp/backup-codes` | Get backup codes |

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
