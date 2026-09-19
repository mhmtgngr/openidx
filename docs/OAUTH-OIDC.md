# OAuth 2.0 & OpenID Connect Provider - OpenIDX

## What is OAuth 2.0 and OpenID Connect?

**OAuth 2.0** is the industry-standard protocol for authorization, allowing applications to obtain limited access to user accounts.

**OpenID Connect (OIDC)** is an authentication layer built on top of OAuth 2.0, providing identity verification and user information.

### Key Benefits

✅ **Single Sign-On (SSO)** - Users log in once and access all connected applications
✅ **Secure Delegation** - Apps access resources without exposing passwords
✅ **Standard Protocol** - Works with any OAuth 2.0/OIDC compliant application
✅ **Identity Provider** - Become the central authentication authority
✅ **Cost Savings** - Replace Auth0, Okta, or Azure AD with OpenIDX

## Use Cases

### 1. Enterprise SSO
Enable employees to log into all company applications with a single set of credentials:
- Internal applications (CRM, HR systems, project management)
- Third-party SaaS applications
- Custom-built applications

### 2. Customer Identity (CIAM)
Provide secure authentication for your customers:
- Mobile apps
- Web applications
- API access

### 3. Partner/B2B Access
Allow partners and vendors to access your systems securely:
- Scoped permissions
- Temporary access tokens
- Audit trail

### 5. Single Sign-On with External Providers
Enable users to sign in with their existing accounts from other identity providers (IdPs).

**Use Case:**
- Allow users to "Login with Google"
- Federate with a corporate Okta or Azure AD
- Act as a service provider (SP) in a larger identity ecosystem

**Flow:**
1. User chooses to sign in with an external provider (e.g., Google).
2. OpenIDX redirects the user to the external IdP's login page.
3. User authenticates with the external IdP.
4. The IdP redirects the user back to OpenIDX with an authorization code.
5. OpenIDX exchanges the code for tokens, verifies the user's identity, and performs Just-In-Time (JIT) provisioning if the user is new.
6. OpenIDX issues its own session and access tokens to the client application.

## Architecture

```
┌─────────────────┐
│  User Browser   │
└────────┬────────┘
         │ 1. Authorize Request
         ▼
┌─────────────────────────┐
│   OpenIDX OAuth Service │
│   (Identity Provider)   │
└────────┬────────────────┘
         │ 2. Login + Consent
         │ 3. Authorization Code
         ▼
┌─────────────────┐
│  Client App     │──────┐
└─────────────────┘      │
         │               │ 4. Exchange Code for Token
         ▼               ▼
┌──────────────────────────┐
│   OpenIDX Token Endpoint │
└────────┬─────────────────┘
         │ 5. Access Token + ID Token
         ▼
┌─────────────────┐
│  Protected API  │
└─────────────────┘
```

## Supported OAuth 2.0 Flows

### 1. Authorization Code Flow (Recommended)
Most secure flow for web and mobile applications.

**Use Case:** Web applications, mobile apps

**Flow:**
1. Client redirects user to `/oauth/authorize`
2. User logs in and grants consent
3. OAuth service redirects back with authorization code
4. Client exchanges code for tokens at `/oauth/token`

### 2. Authorization Code Flow with PKCE
Enhanced security for public clients (mobile/SPA).

**Use Case:** Mobile apps, single-page applications

**Additional Security:** Code challenge/verifier prevents authorization code interception

### 3. Refresh Token Flow
Obtain new access tokens without re-authentication.

**Use Case:** Long-lived sessions

### 4. Client Credentials Flow
Machine-to-machine authentication.

**Use Case:** Backend services, API clients

## OpenID Connect Features

### ID Tokens
JWT tokens containing user identity claims:
- Subject (user ID)
- Email
- Name (given name, family name)
- Email verification status
- `sid`, `amr` and `auth_time` from the login session the code was bound to:
  the session id, the authentication methods it recorded (`pwd`, `mfa`, ...)
  and the moment it started. `auth_time` is the session's start, not the
  token's `iat`: with single sign-on a token minted from a two-hour-old
  session says so, and a client that requested `max_age` gets the number OIDC
  Core §3.1.2.1 obliges the ID token to carry. Without a session (client
  credentials, a code issued with no session bound) none of the three is
  emitted rather than guessed.

### UserInfo Endpoint
Retrieve detailed user information using access token.

### Discovery
Automatic service configuration via `.well-known/openid-configuration`

### Single Sign-On across applications
A login completion (password, MFA, passwordless, social, or after consent) sets
a browser cookie, `openidx_sso` (HttpOnly, SameSite=Lax, Secure, 24h). Secure
is unconditional: the cookie is a credential, and the issuer is served over
https wherever it is deployed (the compose stack terminates TLS at
`oauth.localtest.me:8446`); a plain-http developer instance gets no SSO. It holds a random token that the session Redis maps to the identity
session; it never carries a session or user id. `GET /oauth/authorize`, after
validating `client_id`, `redirect_uri`, `scope` and `response_type` against the
client exactly as before, reads that cookie:

- A token that resolves to a live, unrevoked, unexpired session of the request's
  tenant goes through the same assignment/ABAC and consent gates as the login
  flow and is redirected to the client with a code — no login page.
- Anything less — no cookie, a token Redis has forgotten, a session revoked,
  expired, deleted or belonging to another tenant, a session older than
  `max_age`, `prompt=login` — falls through to the login flow. A cookie that
  resolves to nothing is cleared.
- `prompt` (OIDC Core §3.1.2.1): `none` never shows UI and is answered at the
  `redirect_uri` with `login_required` (no usable session) or
  `consent_required` (consent outstanding); `login` forces re-authentication;
  `consent` and `select_account` need the login UI and take it. `none`
  combined with another value, or an unknown value, is `invalid_request`.
- `max_age` (seconds): a session authenticated longer ago than this
  re-authenticates. Malformed values are `invalid_request`.
- `/oauth/logout` ends the browser session as well: the cookie's session is
  revoked, the Redis mapping deleted and the cookie cleared, whether or not
  the caller supplied `id_token_hint` or a bearer token.
- `GET /oauth/authorize/v2` (the endpoint the mobile authenticator's
  browser-login fallback opens) reads the cookie the same way, with the same
  gates, `prompt` and `max_age` semantics and fallbacks. Its POST
  (`/oauth/authorize/v2` consent) accepts an optional `session_id` and binds
  it to the code only when it is a live session of the authenticated caller
  in this tenant; any other value is refused with `400 invalid_request`. The
  session row is where `sid`, `amr` and `auth_time` come from, so a caller
  must not be able to borrow another user's. No cookie is set on this path.

The cookie is set on the response to the login page's request to
`/oauth/login`, so it is stored only when the login UI and the issuer share an
origin — the production layout (nginx serves the console and the issuer from
one host). In the reference compose stack the console (`localhost:3000`) and
the issuer (`oauth.localtest.me:8446`) are different origins, that request is
cross-origin without credentials, and the cookie is never stored: there is no
SSO there, which is what it was before.

## Quick Start

### 1. Register an OAuth Client

```bash
curl -X POST http://localhost:8006/api/v1/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "description": "My awesome app",
    "type": "confidential",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "pkce_required": true,
    "allow_refresh_token": true,
    "access_token_lifetime": 3600,
    "refresh_token_lifetime": 86400
  }'
```

**Response:**
```json
{
  "id": "uuid",
  "client_id": "client_abc123...",
  "client_secret": "secret_xyz789...",
  "name": "My Application",
  ...
}
```

### 2. Authorization Code Flow

**Step 1: Redirect user to authorization endpoint**

```
GET /oauth/authorize?
  response_type=code&
  client_id=client_abc123&
  redirect_uri=https://myapp.com/callback&
  scope=openid%20profile%20email&
  state=random_state&
  nonce=random_nonce&
  code_challenge=base64url(sha256(verifier))&
  code_challenge_method=S256
```

**Step 2: User consents (handled by OpenIDX UI)**

**Step 3: OAuth service redirects back**

```
https://myapp.com/callback?
  code=auth_code_123&
  state=random_state
```

**Step 4: Exchange authorization code for tokens**

```bash
curl -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth_code_123" \
  -d "client_id=client_abc123" \
  -d "client_secret=secret_xyz789" \
  -d "redirect_uri=https://myapp.com/callback" \
  -d "code_verifier=original_verifier"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_123...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email offline_access"
}
```

### 3. Configure an External Identity Provider (for SSO)

```bash
curl -X POST http://localhost:8001/api/v1/identity/providers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Google",
    "provider_type": "oidc",
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-google-client-id.apps.googleusercontent.com",
    "client_secret": "your-google-client-secret",
    "scopes": ["openid", "profile", "email"],
    "enabled": true
  }'
```

### 4. Initiate SSO Flow

To start the SSO flow with an external provider, add the `idp_hint` parameter to the authorization request, using the ID of the identity provider you configured.

```
GET /oauth/authorize?
  response_type=code&
  client_id=client_abc123&
  redirect_uri=https://myapp.com/callback&
  scope=openid%20profile%20email&
  state=random_state&
  nonce=random_nonce&
  code_challenge=base64url(sha256(verifier))&
  code_challenge_method=S256&
  idp_hint=the-id-of-the-google-idp
```

### 5. Get User Info

```bash
curl http://localhost:8006/oauth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response:**
```json
{
  "sub": "user-id-123",
  "email": "john.doe@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "preferred_username": "john.doe@example.com"
}
```

### 4. Refresh Access Token

```bash
curl -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh_token_123..." \
  -d "client_id=client_abc123" \
  -d "client_secret=secret_xyz789"
```

## API Endpoints

### Discovery & Metadata

```bash
# OpenID Connect Discovery
GET /.well-known/openid-configuration

# JSON Web Key Set (public keys for token verification)
GET /.well-known/jwks.json
```

### OAuth 2.0 Endpoints

```bash
# Authorization endpoint
GET  /oauth/authorize
POST /oauth/authorize  # Consent submission

# Token endpoint
POST /oauth/token

# Token introspection
POST /oauth/introspect

# Token revocation
POST /oauth/revoke

# UserInfo endpoint
GET  /oauth/userinfo
POST /oauth/userinfo
```

### Client Management API

```bash
# List all OAuth clients
GET /api/v1/oauth/clients

# Create OAuth client
POST /api/v1/oauth/clients

# Get client details
GET /api/v1/oauth/clients/:id

# Update client
PUT /api/v1/oauth/clients/:id

# Delete client
DELETE /api/v1/oauth/clients/:id
```

## Token Types

### Access Token (JWT)
Signed JWT containing:
- `sub`: User ID
- `client_id`: OAuth client ID
- `scope`: Granted scopes
- `iss`: Issuer (OpenIDX URL)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

**Signature:** RS256 (RSA-SHA256)

### ID Token (JWT)
OpenID Connect identity token containing:
- `sub`: User ID
- `aud`: Client ID
- `iss`: Issuer
- `iat`, `exp`: Timestamps
- `email`, `name`, `given_name`, `family_name`: User claims
- `nonce`: Optional nonce for replay protection

### Refresh Token
Opaque token stored in database:
- Long-lived (default: 24 hours)
- Can be revoked
- Used to obtain new access tokens

## Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OpenID Connect, enables ID token |
| `profile` | Access to user profile (name, given_name, family_name) |
| `email` | Access to user email and email_verified |
| `offline_access` | Enables refresh token issuance |

## Security Features

### PKCE (Proof Key for Code Exchange)
- Protects against authorization code interception
- Recommended for all public clients
- Uses SHA-256 code challenge

### Token Signing
- RSA-2048 key pair generated on startup
- RS256 algorithm for JWT signatures
- Public keys available via JWKS endpoint

### Token Validation
- Signature verification
- Expiration validation
- Issuer validation
- Audience validation (for ID tokens)

### Single-Use Authorization Codes
- Codes deleted after first use
- 10-minute expiration
- Prevents replay attacks

## Integration Examples

### React Single-Page Application

```javascript
import { AuthProvider, useAuth } from '@openidx/react-auth'

function App() {
  return (
    <AuthProvider
      domain="https://openidx.example.com"
      clientId="client_abc123"
      redirectUri={window.location.origin + '/callback'}
      scope="openid profile email"
    >
      <MyApp />
    </AuthProvider>
  )
}

function MyComponent() {
  const { user, login, logout, isAuthenticated } = useAuth()

  if (!isAuthenticated) {
    return <button onClick={login}>Login</button>
  }

  return (
    <div>
      <h1>Welcome, {user.name}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  )
}
```

### Node.js Backend API

```javascript
const express = require('express')
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')

const client = jwksClient({
  jwksUri: 'https://openidx.example.com/.well-known/jwks.json'
})

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(null, key.publicKey || key.rsaPublicKey)
  })
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]

  jwt.verify(token, getKey, {
    issuer: 'https://openidx.example.com',
    algorithms: ['RS256']
  }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' })
    req.user = decoded
    next()
  })
}

app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: `Hello ${req.user.sub}` })
})
```

### Python Flask Application

```python
from flask import Flask, redirect, request, session
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'your-secret-key'

oauth = OAuth(app)
oauth.register(
    'openidx',
    client_id='client_abc123',
    client_secret='secret_xyz789',
    server_metadata_url='https://openidx.example.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oauth.openidx.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = oauth.openidx.authorize_access_token()
    user = oauth.openidx.parse_id_token(token)
    session['user'] = user
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')
```

## Client Credentials Flow (Machine-to-Machine)

```bash
curl -X POST http://localhost:8006/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=client_abc123" \
  -d "client_secret=secret_xyz789" \
  -d "scope=api:read api:write"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

## Configuring Third-Party Applications

### Configure Slack

1. Go to https://api.slack.com/apps
2. Create new app or select existing
3. OAuth & Permissions → Redirect URLs
   - Add: `https://openidx.example.com/oauth/callback`
4. In OpenIDX, register Slack as OAuth client
5. Update Slack app with OpenIDX client credentials

### Configure GitHub

1. GitHub Settings → Developer Settings → OAuth Apps
2. New OAuth App
   - Authorization callback URL: `https://openidx.example.com/oauth/callback`
3. Register in OpenIDX with GitHub client ID/secret

### Configure Custom Application

Any OAuth 2.0 compliant application can integrate:
1. Register client in OpenIDX
2. Configure application with:
   - Authorization URL: `https://openidx.example.com/oauth/authorize`
   - Token URL: `https://openidx.example.com/oauth/token`
   - Client ID and Client Secret
   - Redirect URI

## Monitoring & Analytics

### Key Metrics
- Total OAuth clients
- Active access tokens
- Token refresh rate
- Failed authentication attempts
- Most used scopes
- Client application usage

### Audit Logging
All OAuth events are logged:
- Client registration
- Authorization requests
- Token issuance
- Token revocation
- Failed authentication

## Best Practices

### Security
1. **Always use HTTPS** in production
2. **Enable PKCE** for all public clients
3. **Use short-lived access tokens** (1 hour recommended)
4. **Rotate refresh tokens** after each use
5. **Validate redirect URIs** strictly
6. **Store client secrets** securely (encrypted at rest)
7. **Implement rate limiting** on token endpoint

### Performance
1. **Cache JWKS** responses (public keys rarely change)
2. **Use Redis** for token storage and caching
3. **Set appropriate token lifetimes** to balance security and performance
4. **Monitor token generation rate**

### Integration
1. **Use standard libraries** (avoid custom OAuth implementations)
2. **Implement proper error handling**
3. **Log OAuth flows** for debugging
4. **Test with OAuth playground** tools
5. **Document scopes** clearly for developers

## Troubleshooting

### Common Issues

**Q: "invalid_client" error when exchanging code**
A: Verify client_id and client_secret match registered client

**Q: "invalid_grant" error with PKCE**
A: Ensure code_verifier matches the original used in code_challenge

**Q: Token signature verification fails**
A: Ensure you're using RS256 algorithm and fetching public key from JWKS endpoint

**Q: Refresh token not issued**
A: Check that `offline_access` scope was requested and client allows refresh tokens

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=debug
./oauth-service
```

## Comparing to Competitors

| Feature | OpenIDX | Auth0 | Okta | Azure AD |
|---------|---------|-------|------|----------|
| OAuth 2.0 | ✅ | ✅ | ✅ | ✅ |
| OpenID Connect | ✅ | ✅ | ✅ | ✅ |
| Self-Hosted | ✅ | ❌ | ❌ | ❌ |
| Open Source | ✅ | ❌ | ❌ | ❌ |
| Cost | Free | $$$$ | $$$$ | $$$ |
| PKCE Support | ✅ | ✅ | ✅ | ✅ |
| Custom Branding | ✅ | ✅ | ✅ | Limited |
| Unlimited Clients | ✅ | Limited | Limited | Limited |

## Standards Compliance

OpenIDX OAuth/OIDC implements:
- ✅ [RFC 6749](https://tools.ietf.org/html/rfc6749) - OAuth 2.0 Framework
- ✅ [RFC 7636](https://tools.ietf.org/html/rfc7636) - PKCE
- ✅ [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)
- ✅ [RFC 7517](https://tools.ietf.org/html/rfc7517) - JSON Web Key (JWK)
- ✅ [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- ✅ [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

---

**Ready to become an Identity Provider?** 🚀

Start issuing tokens and enabling SSO for all your applications today!
