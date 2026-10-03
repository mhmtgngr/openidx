# SSF/CAEP — Shared Signals with Ziti-Honored Termination

OpenIDX is both an **SSF (Shared Signals Framework) transmitter and receiver**,
implementing CAEP (Continuous Access Evaluation Profile) events. The
differentiator: when OpenIDX *receives* a session-revoked signal, it doesn't
just clear a token — it revokes the subject's sessions, which the access-proxy
and continuous-verify enforce to **cut the user off the Ziti overlay**. First OSS
SSF/CAEP with native network termination.

!!! info "API-only today"

    Stream management ships as a **documented API**, not a console screen.
    The screen comes later, by a ratified decision
    ([ROADMAP.md](https://github.com/mhmtgngr/openidx/blob/main/ROADMAP.md#later-when-there-is-demand)),
    recorded so nobody goes hunting for a page that is not there. Everything
    below is served, routed and tested (including tenant isolation); the only
    missing piece is the admin UI. An administrator subscribes a receiver
    with a POST; `$TOKEN` is an access token holding the `admin` or
    `super_admin` role in the organization the stream is for, and any other
    caller, a receiver's own client-credentials token included, gets `403`:

    ```bash
    curl -X POST https://oauth.openidx.example.com/ssf/streams \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "description": "Downstream SaaS receiver",
        "aud": "https://saas.example.com",
        "delivery_endpoint": "https://saas.example.com/ssf/events",
        "delivery_auth": "Bearer <receiver-token>",
        "events_requested": [
          "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
        ],
        "status": "enabled"
      }'
    ```

    Then `GET /ssf/streams` to list, `DELETE /ssf/streams/{id}` to unsubscribe,
    and `POST /ssf/streams/{id}/verify` to send a verification event and prove
    the receiver is reachable before you rely on it. With `STEPUP_GATE` on, the
    writes also need a recently verified second factor, as admin-api's writes
    do (`403 step_up_required`).

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
Every push goes through the outbound guard (`internal/common/netutil/outbound.go`):
a delivery endpoint that names or resolves to an internal address is not
contacted, and the item fails and is retried like any failed push, unless the
host is in `OIDX_OUTBOUND_ALLOWLIST`. Redirects are not followed.

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

`/.well-known/ssf-configuration` advertises exactly the events that are sent
(`ssfEventsSupported`, which a census test holds to the code that emits them):

| Event | Sent when |
|---|---|
| `session-revoked` | All of a user's sessions are revoked here, or an external (vendor) account is suspended. A suspended account may come back (a new sponsor can reactivate it), so its sessions end and the account stays |
| `account-disabled` | A path that severs an account disables or deletes it: offboarding, deletion, an administrator's edit that disables it, a lifecycle policy, the kill switch, a directory deprovision, a SCIM delete or `active:false`, an anomaly lock, a quarantine. An edit or a SCIM push of an account already disabled sends nothing. An external account that expires or is disabled, its vendor closed included |
| `token-claims-change` | A user's roles or groups change, on any of the paths listed below. The event's `claims` carry the user's `roles`, `groups` and `permissions` as a token issued at that moment carries them |

`token-claims-change` is sent when:

- an access request that gives a role or a group is fulfilled, and when its window closes;
- an administrator grants, removes or deletes a role, or edits a user's role set;
- a member is added to or removed from a group, or a group is deleted;
- a lifecycle rule assigns or removes a role or a group;
- a time-bound role or group membership lapses (the identity expiry sweep).

A path that changes nothing sends nothing: a role the user already holds, a role set saved unchanged, a lifecycle removal of something the user does not hold. Each of these paths that takes a role or a group away also cuts the user's outstanding tokens (the revocation marker), because a token issued before still names it.

Not yet sent: the console's bulk operations, a certification's revocation, SCIM and directory group pushes, a self-service group join and a provisioning rule change roles or groups without this event. The ones that take access away cut the tokens as before.

A path outside oauth-service reaches the transmitter through
`internal/common/ssfsignal`: it writes a row to `ssf_pending_events`
(migration v196), and oauth-service's drainer signs it within about ten
seconds. For `token-claims-change` the drainer reads the claims itself, from the
rows a token is issued from, so the event cannot say something a token would
not.

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
