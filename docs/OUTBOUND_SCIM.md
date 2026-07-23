# Outbound SCIM Provisioning

OpenIDX can act as a **SCIM 2.0 client**, provisioning its users (and groups)
**out** to downstream SaaS applications (Okta, Microsoft Entra, Slack, GitHub,
Zoom, or any SCIM 2.0 service provider). This closes the single biggest
workforce-IAM functional gap versus Okta/Entra and unlocks automated
deprovisioning and IGA fulfillment.

OpenIDX already ships a SCIM 2.0 **server** (be provisioned *into*, in
`internal/provisioning`); this feature is the complementary **client** direction
(provision *out*).

## Architecture

```
 upstream IdP / HR          OpenIDX (this repo)                downstream SaaS
 (SCIM push / directory) ->  inbound SCIM write  ->  outbox  ->  SCIM client  -> Okta/Entra/Slack/...
                              (CreateSCIMUser,       (queue)     (worker)
                               UpdateSCIMUser,
                               DeleteSCIMUser)
```

Components:

- **`internal/scimclient`** — a persistence-agnostic SCIM 2.0 wire client
  (Users/Groups create/replace/patch/delete, `ServiceProviderConfig` probe,
  typed errors). Reusable and unit-tested against an in-memory mock SP.
- **`internal/provisioning/outbound_*.go`** — the target store, the fan-out
  enqueue helpers, the admin HTTP API, and the background worker.
- **Migration v95** — three org-scoped tables:
  - `scim_target_apps` — a configured downstream endpoint (base URL, auth,
    per-resource flags, deprovision policy). Secrets are encrypted at rest via
    `secretcrypt` (AES-256-GCM).
  - `scim_provisioning_records` — the local↔remote id mapping + sync status.
  - `scim_provisioning_queue` — the outbox, drained with at-least-once delivery,
    exponential backoff, and a dead-letter state.

## Delivery semantics

- **At-least-once.** Every inbound change fans out one outbox row per enabled
  target (single `INSERT..SELECT`, so it participates in the caller's tx). The
  worker claims items with `FOR UPDATE SKIP LOCKED`, so it is safe to run
  multiple replicas.
- **Idempotent.** Updates are skipped when the payload hash is unchanged; a
  remote `404` on update transparently recreates the resource; `DELETE` treats
  `404` as success.
- **Backoff + dead-letter.** Transient failures (`429`, `5xx`, network) retry
  with `2^attempts` seconds (capped at 1h) up to 8 attempts. Terminal client
  errors (`400/401/403/409/422`) dead-letter immediately.
- **Deprovision policy.** Per target: `deactivate` (PATCH `active=false`,
  reversible, default) or `delete` (DELETE, irreversible).

## Admin API

All under `/api/v1/provisioning/targets` (authenticated, org-scoped):

| Method | Path             | Purpose                                             |
|--------|------------------|-----------------------------------------------------|
| GET    | `/`              | List configured targets                             |
| POST   | `/`              | Create a target                                     |
| GET    | `/:id`           | Get a target (secrets never returned)               |
| PUT    | `/:id`           | Update (omit a secret field to preserve it)         |
| DELETE | `/:id`           | Delete a target (cascades records + queue)          |
| POST   | `/:id/test`      | Probe `ServiceProviderConfig`: reachability + auth  |
| POST   | `/:id/sync`      | Enqueue a full reconcile (one op per user/group)    |
| GET    | `/:id/status`    | Record counts by status + queue depth by state      |

### Create example

```json
POST /api/v1/provisioning/targets
{
  "name": "slack-prod",
  "base_url": "https://api.slack.com/scim/v2",
  "auth_type": "bearer",
  "bearer_token": "xoxb-...",
  "provision_users": true,
  "provision_groups": false,
  "deprovision_action": "deactivate",
  "enabled": true
}
```

## Configuration

- **`ENCRYPTION_KEY`** — used to encrypt target secrets (bearer / OAuth2 client
  secret) at rest. Without it, secrets fall back to plaintext (a startup warning
  is logged); set it in any real deployment.
- The worker runs inside `provisioning-service` automatically. It is idle
  (no-op) until a target is configured. Default poll interval 10s, batch 50.

## Operations

- **Backfill a new target:** after creating it, `POST /:id/sync` to reconcile
  the whole directory into it.
- **Inspect delivery:** `GET /:id/status`, or query `scim_provisioning_queue`
  (`state IN ('failed','dead')` for problems, `last_error` for the cause).
- **Retry dead-lettered items:** set them back to `pending` with a due
  `next_attempt_at` once the target-side issue is resolved:
  ```sql
  UPDATE scim_provisioning_queue
     SET state='pending', attempts=0, next_attempt_at=NOW()
   WHERE target_id = :id AND state='dead';
  ```
