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
- Email, when the `email` scope was granted (see below)
- Name (given name, family name), when `profile` was granted
- Email verification status, read from the user record rather than assumed
- `sid`, `amr` and `auth_time` from the login session the code was bound to:
  the session id, the authentication methods it recorded (`pwd`, `mfa`, ...)
  and the moment it started. `auth_time` is the session's start, not the
  token's `iat`: with single sign-on a token minted from a two-hour-old
  session says so, and a client that requested `max_age` gets the number OIDC
  Core §3.1.2.1 obliges the ID token to carry. Without a session (client
  credentials, a code issued with no session bound) none of the three is
  emitted rather than guessed.

### What a scope actually buys

The identity claims a token carries are decided by the scope the grant was
given, in the ID token, the access token and at the UserInfo endpoint alike
(OpenID Connect Core §5.4):

| Scope | Claims |
|---|---|
| `openid` alone | `sub` and the protocol claims. No name, no address. |
| `profile` | `name`, `given_name`, `family_name`, `preferred_username` |
| `email` | `email`, `email_verified` |

A claim whose scope was not granted is **absent**, not empty, so a relying
party cannot mistake "you did not ask" for "the user has no name". An empty
`scope` grants none of them: reading it as "everything" would leave a client
that omits the parameter better off than one that asks honestly.

Scopes are matched as **whole scopes**, never as substrings. A grant carrying
`openidx` does not carry `openid`, and one carrying `offline_access_reports`
does not carry `offline_access`; the first decides whether an ID token is
issued and the second whether a refresh token is. This applies to the
authorization-code grant, the refresh grant and the device-code flow alike.

`email_verified` carries three answers and only one of them is silent. Absent
means the `email` scope was not granted; `false` means it was and the address
is not verified; `true` means it was and the address is. Do not read an absent
value as `false`. The value is read from the user record rather than asserted,
because a relying party uses this claim to decide whether it may match the
identity onto an existing local account by address.

`roles`, `groups` and `permissions` are **not** gated on a scope. They are not
claims about the end user but the authorization facts the resource servers
behind this issuer read, and gating them on `profile` would silently turn
authorization off for a client that asked for `openid` alone.

### UserInfo Endpoint
Retrieve user information using an access token. The response carries exactly
the claims that token's own scope grants, per the table above; a token granted
only `openid` is answered with `sub` and nothing else.

### Introspection and revocation are scoped to the caller

`POST /oauth/introspect` and `POST /oauth/revoke` both require client
authentication, and both answer only for tokens issued to the client that
authenticated.

- A token that is not yours introspects as `active: false`, exactly as a token
  that does not exist does (RFC 7662 §2.2). The refusal carries no `sub`, no
  `client_id` and no `scope`.
- A token that is not yours is not revoked, and the endpoint still answers
  `200` (RFC 7009 §2.1 requires the ownership check; §2.2 already answers 200
  for an unrecognised token). Answering with an error instead would tell a
  registered client which of the tenant's tokens exist.

One asymmetry is deliberate: an access token that names no client at all is
refused by introspection but can still be revoked, because failing toward "the
credential still works" is the wrong direction for a kill switch.

This closes the resource-server pattern, where a separate service introspects
tokens issued to a front end. Re-opening it wants an explicit per-client
permission rather than letting any authenticated client introspect anything in
the tenant.

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
  `consent_required` (consent outstanding); `login` and `select_account`
  force the login form; `consent` re-shows the consent screen without
  re-authenticating (below). `none` combined with another value, or an
  unknown value, is `invalid_request`.
- A live session that still needs consent (or a `prompt=consent` request) is
  sent to the login UI with `resume=1` on the URL. The login page then posts
  the `login_session` to `POST /oauth/login/resume`, which resolves the
  cookie again and completes the request from that session — the consent
  challenge, then the code bound to the session — so the person approves the
  application without retyping a password. The endpoint refuses with
  `401 login_required` (and the page shows its form) when the request asked
  for the form itself (`prompt=login`, `select_account`), when the session is
  older than the request's `max_age`, or when there is no usable session.
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

### RP-initiated logout

`GET|POST /oauth/logout` is the `end_session_endpoint` in discovery and
implements OpenID Connect RP-Initiated Logout 1.0 §2.

- `id_token_hint` — an ID token previously issued to the relying party. Its
  signature is verified (an expired token is still accepted, as the spec
  requires); its `sub` names the user whose sessions end and its `aud` names
  the client.
- `client_id` — the relying party asking. It is how an RP that no longer
  holds the ID token still gets its registered landing page. When both it
  and `id_token_hint` are sent and they disagree, the request is refused with
  `400 invalid_request`: resolving it either way would let a caller aim one
  client's session at a page registered by another.
- `post_logout_redirect_uri` — followed only when it is registered for that
  client. A client with a `post_logout_redirect_uris` list is matched
  **exactly**, path and query included. A client with no list falls back to
  the older rule, which accepts any path on the same scheme+host as one of
  its `redirect_uris`; that fallback exists so an install that upgrades keeps
  working, it is logged with the client id, and registering a list replaces
  it. An unregistered or unverifiable target is refused with `400` — the
  logout itself has already happened either way.
- `state` — returned unchanged as the `state` query parameter on that
  redirect. It is appended to whatever the registered value already carries,
  and nothing is appended when no state is sent.

Register the list with `post_logout_redirect_uris` on
`POST /api/v1/oauth/clients` (and `PUT …/{id}`), at `POST /oauth/register`, or
from the admin console: Applications → the application's menu → Edit
application → **Post-logout redirect URIs**, one per line. The same field is on
the Register application dialog. The console sends it on every save, so an
empty box is an empty list and returns that client to the origin fallback;
saving any other field leaves the registration alone.

An application's detail and list responses report the list as an empty array
when the client has registered nothing and omit the key entirely when there is
no OAuth client behind the tile at all, which is how the console knows whether
to show the field.

### Back-channel logout
When a session stops being live — `/oauth/logout` (with the cookie, an
`id_token_hint` or a bearer), `/oauth/logout-all`, an SSF receiver acting on
an upstream signal, a concurrent-session eviction, a force-login termination,
or the inactivity and absolute-timeout sweeps — every relying party that
session reached is told, per OpenID Connect Back-Channel Logout 1.0. The
relying parties of a session are the client it was created for and every
client holding a refresh token bound to it (that is how a code issued from
the browser session shows up); only those whose registration carries a
`back_channel_logout_uri` in the session's tenant are told.

The logout token is a JWT signed with the ID-token key (`typ`
`logout+jwt`): `iss`, `sub` exactly as the relying party saw it in its ID
token (pairwise or public), `aud` (the client), `iat`, `exp` (two minutes),
`jti`, `events` naming `http://schemas.openid.net/event/backchannel-logout`,
and `sid` — the session id the relying party saw as its ID token's `sid`.
It never carries a `nonce`. It is POSTed as
`application/x-www-form-urlencoded` `logout_token=…`; `200` means the relying
party acted. Delivery is asynchronous and best-effort — one attempt, logged
and audited as `backchannel_logout` delivered/failed — and never delays or
fails the revocation itself: the tokens the session backed are cut by the
revocation marker whether or not the relying party heard.

Register the endpoint with `back_channel_logout_uri` on
`POST /api/v1/oauth/clients` (and `PUT …/{id}`), with
`backchannel_logout_uri` at `POST /oauth/register`, or in the console's
application editor (which writes it, with `pkce_required`, to the backing
OAuth client through `PUT /api/v1/applications/{id}`). It must be https
(http only on localhost).

A session ended by another binary is announced too. The identity service's
session pages, password change, offboarding, lifecycle actions and
deprovisioning, the admin console's revoke-session and revoke-all, the breach
responder, the DSAR delete and restrict, risk remediation, device revoke, the
kill switch and SCIM deprovisioning all end sessions with their own statement
and hold no signing key. Each of them first captures the session — tenant,
user, id and the clients it reached — into `backchannel_logout_pending`
(migration v198, `internal/common/sessionend`), on the handle it already
holds and before its own statement, because six of them delete the row.
oauth-service's drainer resolves the captured clients against the tenant's
registered URIs and delivers the same way. A guard in `sessionend` fails the
build's tests if a function revokes or deletes `sessions` rows without the
capture.

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

**Step 2: User authenticates and, if the application requires it, consents**

The login page completes authentication and follows the `redirect_url` the
server returns. When the application has **Require consent** enabled and the
user has not yet approved the requested scopes, the completion endpoint
(`/oauth/login`, `/oauth/mfa-verify`, passkey, push, QR, force-login) answers
`consent_required` with a `consent_session`, the client name and the scopes
instead of a `redirect_url`; the login page renders that as an approval
screen and posts the decision to `POST /oauth/consent`, whose `redirect_url`
carries the code on approval and `error=access_denied` back to the client on
denial. A recorded approval is not asked for again unless the requested
scopes widen.

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
- **Required of every public client**, on every authorization path, and of any
  confidential client whose registration sets `pkce_required`
- Uses SHA-256 code challenge; `plain` is refused outright in production and is
  not advertised in discovery, which lists `S256` only

One rule decides this (`internal/oauth/pkce_policy.go`) and every request path
that accepts a client-supplied `code_challenge` calls it: `/oauth/authorize`,
`/oauth/authorize/v2`, the `idp_hint` hop to an external IdP, the consent POST
and the native login-init endpoint. A request that must carry a challenge and
does not is refused at the authorization endpoint — reported to the client at
its registered `redirect_uri` per RFC 6749 §4.1.2.1, not rendered for a user
who cannot act on it — rather than being carried to a login page and failing
after credentials have been spent.

`pkce_required` is set by `POST /api/v1/oauth/clients` and `PUT …/{id}`, by
`POST /oauth/register` (which sets it for every public registration), or from
the console's application editor. Turning it on for a confidential client
requires that client to use PKCE from the next authorization request onward.

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
