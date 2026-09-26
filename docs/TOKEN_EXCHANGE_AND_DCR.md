# Token Exchange (RFC 8693) & Dynamic Client Registration (RFC 7591/7592)

Together these are OpenIDX's **agent-identity substrate**: a service or
autonomous agent can register itself, obtain credentials, and trade tokens for
narrowed, delegated ones to call downstream APIs — without a human in the loop
and without holding a user's long-lived credentials.

## Token Exchange (RFC 8693)

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on the token
endpoint. A client trades a token it holds (the **subject token**) for a new
one, optionally recording the acting party (the **actor token**) for delegation.
The new token is the subject's: it carries the subject's user, roles and
groups, for the audience the exchange issues it for.

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

- **Client authentication** — the requesting client must be a confidential
  client and present its secret, in the form (`client_secret_post`) or as
  HTTP Basic (`client_secret_basic`), not both. A public client, a client
  without a secret, and a client the console registered as **Native/Mobile
  App** are refused with `401 invalid_client`, since the secret of an
  application installed on a device proves nothing about who is calling.
- **Client authorization** — the requesting client must be registered with the
  `urn:ietf:params:oauth:grant-type:token-exchange` grant; otherwise
  `400 unauthorized_client`.
- **Subject validation** — the subject token must be a live, RS256 access
  token OpenIDX issued (own `kid`), bound to the organization the request is
  for, and not revoked: not by `/oauth/revoke` or a sign-out, and not by the
  user's revocation cutoff (sign-out everywhere, the kill switch,
  deprovisioning). An ID token is refused, as subject or as actor, and so is a
  token of another organization. Cross-issuer federation is out of scope.
- **Audience** — `audience` or `resource`, else the requesting client. The
  audience must be the requesting client itself or one listed in its
  `token_exchange_audiences`, which an administrator sets through
  `POST`/`PUT /api/v1/oauth/clients`. Anything else, or two different targets
  in one request, is refused with `400 invalid_target`. A client lists no
  audience until an administrator gives it one; dynamic registration cannot.
- **Scope narrowing** — the issued token's scope is the intersection of the
  requested scope with the subject's. Requesting a scope the subject lacks drops
  it; it never escalates. Empty request keeps the subject's scope.
- **Roles and organization** — the issued token carries the subject token's
  roles, groups, email and name, and is bound to the same organization.
- **Lifetime** — the requesting client's access-token lifetime, but never
  past the subject token's own expiry. Exchanging an exchanged token does not
  extend it either.
- **Revocation** — the issued token dates from its subject token's grant
  (`granted_at_us`), so a revocation cutoff that revokes the subject token
  revokes it too. Revoking only the subject token with `/oauth/revoke`, after
  the exchange, does not revoke the issued token; it expires with the subject
  token at the latest.
- **Delegation** — when an `actor_token` is present, the issued token carries an
  `act` claim `{sub, client_id}` (RFC 8693 §4.1). The actor token is held to the
  subject token's rules. A prior `act` on the subject token is nested for
  chained delegation.
- **OpenIDX API access** — the issued token carries the `openidx_api` claim,
  which OpenIDX's own APIs require, only when the requesting client may call
  those APIs and the subject token carried the claim (see
  [OAUTH-OIDC.md](OAUTH-OIDC.md#which-applications-may-call-openidxs-apis)).

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
  PKCE required); otherwise **confidential** (secret minted). A public client
  cannot register for the `client_credentials` or token-exchange grant (`400
  invalid_client_metadata`): both need a client that authenticates.
- A registered client may not call OpenIDX's own APIs: its access tokens are
  refused by the admin, identity, governance and other OpenIDX APIs and the
  MCP gateway until the application's "May call the OpenIDX API" setting
  (`api_access`) is turned on through `/api/v1/oauth/clients` or the console.
  Registration and RFC 7592 updates cannot set it.

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
access token per client). Migration **v209** adds
`oauth_clients.token_exchange_audiences`, the audiences each client may obtain
through token exchange; it is empty for every client that existed before it.
Token exchange itself is stateless.
