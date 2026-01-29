# OAuth/OIDC Service API

Base URL: `http://localhost:8006`

The OAuth Service implements OAuth 2.0 and OpenID Connect.

## OIDC Discovery

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/.well-known/openid-configuration` | OIDC discovery document | None |
| GET | `/.well-known/jwks.json` | JSON Web Key Set | None |

## Authorization

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/oauth/authorize` | Start authorization flow | None |
| POST | `/oauth/authorize` | Submit consent | None |
| POST | `/oauth/login` | Resource owner login | None |
| GET | `/oauth/callback` | OAuth callback handler | None |

### Authorization Code Flow with PKCE

```bash
# 1. Generate code verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=+/' )

# 2. Redirect user to authorize
GET /oauth/authorize?
  response_type=code&
  client_id=my-app&
  redirect_uri=http://localhost:3000/callback&
  scope=openid+profile+email&
  code_challenge=$CODE_CHALLENGE&
  code_challenge_method=S256&
  state=random-state

# 3. Exchange code for tokens
POST /oauth/token
  grant_type=authorization_code&
  code=AUTH_CODE&
  redirect_uri=http://localhost:3000/callback&
  client_id=my-app&
  code_verifier=$CODE_VERIFIER
```

## Token

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/oauth/token` | Exchange code / refresh token | None |
| POST | `/oauth/introspect` | Token introspection | Bearer |
| POST | `/oauth/revoke` | Token revocation | Bearer |

### Supported Grant Types

- `authorization_code` — with optional PKCE
- `refresh_token` — rotate refresh tokens
- `client_credentials` — service-to-service

## UserInfo

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/oauth/userinfo` | Get user claims | Bearer |
| POST | `/oauth/userinfo` | Get user claims | Bearer |

## Client Management

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/v1/oauth/clients` | List OAuth clients | Bearer |
| POST | `/api/v1/oauth/clients` | Create client | Bearer |
| GET | `/api/v1/oauth/clients/:id` | Get client | Bearer |
| PUT | `/api/v1/oauth/clients/:id` | Update client | Bearer |
| DELETE | `/api/v1/oauth/clients/:id` | Delete client | Bearer |
| POST | `/api/v1/oauth/clients/:id/regenerate-secret` | Regenerate secret | Bearer |
