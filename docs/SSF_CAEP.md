# SSF/CAEP — Shared Signals with Ziti-Honored Termination

OpenIDX is both an **SSF (Shared Signals Framework) transmitter and receiver**,
implementing CAEP (Continuous Access Evaluation Profile) events. The
differentiator: when OpenIDX *receives* a session-revoked signal, it doesn't
just clear a token — it revokes the subject's sessions, which the access-proxy
and continuous-verify enforce to **cut the user off the Ziti overlay**. First OSS
SSF/CAEP with native network termination.

## Two directions

```
 OpenIDX revokes a session ─► sign SET ─► push to subscribed receivers  (TRANSMITTER)
 (kill-switch / continuous-verify / SSF)

 upstream IdP session-revoked ─► POST /ssf/events ─► validate SET ─► revoke      (RECEIVER)
                                                     the subject's sessions
                                                     ⇒ access-proxy + continuous-verify
                                                       cut the user off the overlay
```

## Transmitter

When OpenIDX revokes all of a user's sessions (admin kill-switch, continuous
verification, or an inbound SSF signal), it emits a **CAEP session-revoked**
event: it builds and signs a SET (Security Event Token, RFC 8417) with its RS256
key and enqueues one per subscribed stream, which a push worker delivers as
`application/secevent+jwt` (RFC 8935) with retry/backoff + dead-lettering.

### Stream management

```
POST /ssf/streams
{
  "aud": "https://downstream-app.example.com",
  "delivery_endpoint": "https://downstream-app.example.com/ssf/events",
  "delivery_auth": "<optional bearer the receiver requires>",
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ]
}
```

- `GET/DELETE /ssf/streams[/:id]` — list / delete streams (delivery auth
  encrypted at rest, never returned).
- `POST /ssf/streams/:id/verify?state=...` — enqueue an SSF verification SET so a
  receiver can confirm end-to-end delivery.
- Empty `events_requested` means "all events".

### Emitted events

`session-revoked`, `credential-change`, `assurance-level-change`,
`token-claims-change`, `device-compliance-change`, `account-disabled`,
`account-purged`.

## Receiver

`POST /ssf/events` accepts a pushed SET. It:

1. Validates the signature — against OpenIDX's own keys for self-issued SETs, or
   a configured upstream's JWKS (`SSF_RECEIVER_ISSUER` + `SSF_RECEIVER_JWKS_URL`).
2. Dedups by `jti` (a re-delivered event is applied at most once).
3. Applies the CAEP event. **session-revoked / account-disabled / account-purged
   / credential-change** revoke *all* the subject's OpenIDX sessions (the Redis
   markers the access-proxy + continuous-verify honor to sever the user's Ziti
   overlay sessions) and refresh tokens; account-disabled/purged also disables
   the local account.

Returns `202 Accepted` (RFC 8935).

## Why this is the headline

Pure-IdP SSF receivers can only clear a token and hope every downstream app
re-checks. OpenIDX's receiver actuator reaches the **network**: because the same
identity drives both the IdP session and the Ziti overlay circuit, a
session-revoked signal terminates the user's *network* access, not just an
API token.

## Discovery

`GET /.well-known/ssf-configuration` advertises the spec version, JWKS URI,
stream configuration/status endpoints, supported delivery methods (push), and
supported event types.

## Persistence

Migration **v99**:
- `ssf_streams` — transmitter push streams (audience, endpoint, requested
  events, encrypted delivery auth, status).
- `ssf_stream_delivery` — the SET outbox (at-least-once, retry/backoff,
  dead-letter).
- `ssf_received_events` — inbound SET dedup/audit by jti.
