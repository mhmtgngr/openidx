# Admin API

Base URL: `http://localhost:8005`

The Admin API powers the Admin Console dashboard and system configuration.

## Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/dashboard` | Get dashboard statistics |

Returns: total users, active users, groups, applications, sessions, pending reviews, security alerts, recent activity, auth stats (logins by method/day), and security alert details.

## Settings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/settings` | Get system settings |
| PUT | `/api/v1/settings` | Update system settings |

### Settings Sections

- **General** — Organization name, support email, language, timezone
- **Security** — Password policy, session timeout, lockout policy, MFA requirement, IP allowlist
- **Authentication** — Registration, email verification, allowed domains, social providers
- **Branding** — Logo, favicon, colors, custom CSS, login page text

## Applications

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/applications` | List applications (paginated) |
| POST | `/api/v1/applications` | Create application |
| GET | `/api/v1/applications/:id` | Get application |
| PUT | `/api/v1/applications/:id` | Update application |
| DELETE | `/api/v1/applications/:id` | Delete application |

### Application Types

- `web` — Browser-based application
- `native` — Mobile or desktop application
- `service` — Backend service / API

### Protocols

- `oidc` — OpenID Connect
- `saml` — SAML 2.0

## SSO Settings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/applications/:id/sso-settings` | Get SSO config |
| PUT | `/api/v1/applications/:id/sso-settings` | Update SSO config |

Configures: access token lifetime, refresh token lifetime, consent requirements, refresh token usage.

## Directories

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/directories` | List directory integrations |
| POST | `/api/v1/directories` | Create directory integration |
| POST | `/api/v1/directories/:id/sync` | Trigger directory sync |

### Directory Types

- `ldap` — LDAP / Active Directory
- `azure_ad` — Microsoft Entra ID (Azure AD)
- `google` — Google Workspace

## MFA Configuration

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/mfa/methods` | List enabled MFA methods |
| PUT | `/api/v1/mfa/methods` | Update enabled methods |

Available methods: `totp`, `webauthn`, `sms`, `push`
