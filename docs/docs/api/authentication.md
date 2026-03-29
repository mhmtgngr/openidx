# Authentication

OpenIDX provides multiple authentication mechanisms depending on your use case: OAuth 2.0/OIDC for applications, SAML 2.0 for enterprise SSO, and API keys for service-to-service communication.

## OAuth 2.0 / OpenID Connect

OpenIDX is a fully compliant OAuth 2.0 Authorization Server and OpenID Connect Provider.

### Authorization Code Flow with PKCE

The recommended flow for browser-based and mobile applications.

```mermaid
sequenceDiagram
    participant User
    participant App
    participant OAuth as OAuth Service
    participant Identity as Identity Service

    User->>App: Click "Login"
    App->>OAuth: GET /oauth/authorize?<br/>response_type=code&client_id=xxx&redirect_uri=yyy&code_challenge=zzz
    OAuth->>User: Return login page
    User->>OAuth: POST /oauth/login (username, password)
    OAuth->>Identity: Validate credentials
    Identity-->>OAuth: User valid
    OAuth->>OAuth: Verify MFA if enrolled
    OAuth->>OAuth: Generate auth code
    OAuth->>App: 302 Redirect to redirect_uri?code=ccc&state=sss
    App->>OAuth: POST /oauth/token<br/>grant_type=authorization_code&code=ccc&code_verifier=zzz
    OAuth->>App: {"access_token": "...", "id_token": "...", "refresh_token": "..."}
```

#### 1. Authorization Request

```http
GET /oauth/authorize?
    response_type=code
    &client_id=s6BhdRkqt3
    &redirect_uri=https://app.example.com/callback
    &scope=openid profile email
    &state=af0ifjsldkj
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

#### 2. User Authentication

The user is redirected to the login page. After entering credentials (and completing MFA if enrolled), they are redirected back with an authorization code.

```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=AUTH_CODE&state=af0ifjsldkj
```

#### 3. Token Exchange

```http
POST /oauth/token HTTP/1.1
Host: openidx.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://app.example.com/callback
&client_id=s6BhdRkqt3
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "JfRNHqeW5CHZd9xNfqYgmCj2Gp4zTGqxYuL0xH6qEaY",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

### Client Credentials Flow

For service-to-service authentication without user context.

```http
POST /oauth/token HTTP/1.1
Host: openidx.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=CLIENT_ID
&client_secret=CLIENT_SECRET
&scope=api.read
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api.read"
}
```

### Refresh Token Flow

Exchange a refresh token for a new access token.

```http
POST /oauth/token HTTP/1.1
Host: openidx.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=JfRNHqeW5CHZd9xNfqYgmCj2Gp4zTGqxYuL0xH6qEaY
&client_id=s6BhdRkqt3
```

### Token Introspection

Validate a token and retrieve its metadata.

```http
POST /oauth/introspect HTTP/1.1
Host: openidx.example.com
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "active": true,
  "client_id": "s6BhdRkqt3",
  "token_type": "Bearer",
  "exp": 1710807600,
  "iat": 1710804000,
  "sub": "user-123",
  "aud": ["api.example.com"],
  "iss": "https://openidx.example.com",
  "scope": "openid profile email"
}
```

## SAML 2.0

OpenIDX can act as both a SAML Service Provider (SP) and Identity Provider (IdP).

### Service Provider Mode

Use an external IdP (like Azure AD, Okta) to authenticate users.

```mermaid
sequenceDiagram
    participant User
    participant App
    participant OpenIDX as OpenIDX (SP)
    participant IdP

    User->>App: Click "Login with SAML"
    App->>OpenIDX: Initiate SAML request
    OpenIDX->>IdP: SAML AuthnRequest
    IdP->>User: Redirect to IdP login
    User->>IdP: Enter credentials
    IdP->>OpenIDX: SAML Response (assertion)
    OpenIDX->>App: Create local session + redirect
```

#### SAML Metadata

```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://openidx.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="https://openidx.example.com/saml/slo"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://openidx.example.com/saml/acs"
                              index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

### Identity Provider Mode

Allow other applications to use OpenIDX as their SAML IdP.

Configure via the Admin Console under **Applications > SAML Applications**.

## API Keys

For simple service authentication, you can use API keys instead of OAuth.

### Creating an API Key

```bash
curl -X POST http://localhost:8005/api/v1/apikeys \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monitoring Service",
    "scopes": ["audit.read", "audit.events"],
    "expires_at": "2025-12-31T23:59:59Z"
  }'
```

Response:

```json
{
  "id": "ak_1234567890",
  "key": "ak_live_abc123def456...",
  "name": "Monitoring Service",
  "scopes": ["audit.read", "audit.events"],
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Important**: Store the `key` value securely. It will not be shown again.

### Using an API Key

```bash
curl http://localhost:8004/api/v1/audit/events \
  -H "Authorization: Bearer ak_live_abc123def456..."
```

## Multi-Factor Authentication

OpenIDX supports multiple MFA methods that can be enforced per-user or per-policy.

### TOTP (Time-based One-Time Password)

Users can enroll in TOTP using any authenticator app (Google Authenticator, Authy, etc.).

```bash
# Generate TOTP secret for user
curl -X POST http://localhost:8001/api/v1/identity/users/{id}/mfa/totp \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Phone"}'

# Verify and enable TOTP
curl -X POST http://localhost:8001/api/v1/identity/users/{id}/mfa/totp/verify \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### WebAuthn / FIDO2

Passwordless authentication using security keys or biometrics.

```bash
# Begin WebAuthn registration
curl -X POST http://localhost:8001/api/v1/identity/users/{id}/mfa/webauthn/register/begin \
  -H "Authorization: Bearer TOKEN"

# Complete WebAuthn registration
curl -X POST http://localhost:8001/api/v1/identity/users/{id}/mfa/webauthn/register/finish \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credential": "..."}'
```

### Push MFA

Send push notifications to the user's mobile device for approval.

```bash
# Initiate push MFA challenge
curl -X POST http://localhost:8001/api/v1/identity/mfa/push \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-123", "transaction_id": "txn-456"}'
```

## JWT Token Structure

Access tokens and ID tokens are JWTs signed with RS256.

### ID Token Claims

```json
{
  "iss": "https://openidx.example.com",
  "sub": "user-123",
  "aud": "client-abc",
  "exp": 1710807600,
  "iat": 1710804000,
  "auth_time": 1710803900,
  "nonce": "n-0S6_WzA2Mj",
  "acr": "AAL2",
  "amr": ["pwd", "mfa"],
  "name": "Jane Doe",
  "email": "jane@example.com",
  "email_verified": true,
  "groups": ["developers", "admins"]
}
```

### Access Token Claims

```json
{
  "iss": "https://openidx.example.com",
  "sub": "user-123",
  "aud": ["api.example.com"],
  "exp": 1710807600,
  "iat": 1710804000,
  "jti": "at-abc123",
  "client_id": "client-abc",
  "scope": "openid profile email api.read",
  "roles": ["user"],
  "tenant_id": "tenant-456"
}
```

## JWKS Endpoint

Retrieve the public keys used to verify JWT signatures.

```bash
curl https://openidx.example.com/.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## OIDC Discovery

OpenID Connect Discovery endpoint.

```bash
curl https://openidx.example.com/.well-known/openid-configuration
```

Response:

```json
{
  "issuer": "https://openidx.example.com",
  "authorization_endpoint": "https://openidx.example.com/oauth/authorize",
  "token_endpoint": "https://openidx.example.com/oauth/token",
  "jwks_uri": "https://openidx.example.com/.well-known/jwks.json",
  "userinfo_endpoint": "https://openidx.example.com/oauth/userinfo",
  "introspection_endpoint": "https://openidx.example.com/oauth/introspect",
  "revocation_endpoint": "https://openidx.example.com/oauth/revoke",
  "response_types_supported": ["code", "id_token", "token id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "phone", "address"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```
