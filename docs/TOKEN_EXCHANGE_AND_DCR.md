# Token Exchange (RFC 8693) & Dynamic Client Registration (RFC 7591/7592)

Together these are OpenIDX's **agent-identity substrate**: a service or
autonomous agent can register itself, obtain credentials, and trade tokens for
narrowed, delegated ones to call downstream APIs — without a human in the loop
and without holding a user's long-lived credentials.

## Token Exchange (RFC 8693)

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on the token
endpoint. A client trades a token it holds (the **subject token**) for a new
one, optionally recording the acting party (the **actor token**) for delegation.

### Request

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=https://api.example.com
&scope=read
&client_id=svc-a&client_secret=•••
&actor_token=<jwt>        # optional, for delegation
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Semantics

- **Subject validation** — the subject token must be a live, RS256 token
  OpenIDX issued (own `kid`). Cross-issuer federation is out of scope.
- **Scope narrowing** — the issued token's scope is the intersection of the
  requested scope with the subject's. Requesting a scope the subject lacks drops
  it; it never escalates. Empty request keeps the subject's scope.
- **Audience** — from `audience`/`resource`, else the requesting client.
- **Delegation** — when an `actor_token` is present, the issued token carries an
  `act` claim `{sub, client_id}` (RFC 8693 §4.1). A prior `act` on the subject
  token is nested for chained delegation.
- **Client authorization** — the requesting client must be registered with the
  `urn:ietf:params:oauth:grant-type:token-exchange` grant.

### Response (RFC 8693 §2.2.1)

```json
{
  "access_token": "<jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

## Dynamic Client Registration (RFC 7591)

`POST /oauth/register` — a client registers itself and receives credentials.

### Request

```json
POST /oauth/register
{
  "client_name": "My Agent",
  "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

- `redirect_uris` are required for `authorization_code`/`implicit`; not for
  machine grants (`client_credentials`/`token-exchange`). URIs must be `https`,
  loopback (`http://localhost`, `http://127.0.0.1`), or a native custom scheme.
- `token_endpoint_auth_method: none` yields a **public** client (no secret,
  PKCE required); otherwise **confidential** (secret minted).

### Response (RFC 7591 §3.2.1)

```json
{
  "client_id": "oidc_…",
  "client_secret": "…",
  "client_id_issued_at": 1730000000,
  "client_secret_expires_at": 0,
  "registration_access_token": "rat_…",
  "registration_client_uri": "https://…/oauth/register/oidc_…",
  "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

### Gating

Registration is **open by default** (dev/first-run). Set
`DCR_INITIAL_ACCESS_TOKEN` to require a bearer initial access token:

```
POST /oauth/register
Authorization: Bearer <initial-access-token>
```

## Client management (RFC 7592)

The `registration_access_token` authorizes managing the client:

- `GET /oauth/register/:client_id` — read metadata (secret never re-exposed)
- `PUT /oauth/register/:client_id` — update metadata (identity + secret
  preserved)
- `DELETE /oauth/register/:client_id` — delete the client + its registration
  token

All require `Authorization: Bearer <registration_access_token>`.

## Discovery

`/.well-known/openid-configuration` advertises:

- `registration_endpoint`
- `grant_types_supported` includes
  `urn:ietf:params:oauth:grant-type:token-exchange`

## Persistence

Migration **v97** adds `oauth_registration_tokens` (one hashed registration
access token per client). Token exchange is stateless — no schema.
