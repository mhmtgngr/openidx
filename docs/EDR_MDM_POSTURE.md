# EDR/MDM Device Posture Ingestion

OpenIDX ingests device compliance from an external EDR/MDM (CrowdStrike Falcon,
Microsoft Intune, Jamf Pro) and feeds it into its **Ziti-bound posture
pipeline**. When the endpoint tool marks a device non-compliant or high-risk,
OpenIDX writes a failing posture result, and the existing enforcement revokes
the session and severs the overlay circuit — no new enforcement code.

## Why this is Ziti-native

OpenIDX already had a posture pipeline wired to the overlay:

```
agent posture report ─┐
                      ├─► device_posture_results ─► EvaluateIdentityPosture ─┐
EDR/MDM ingestion  ───┘   (keyed by ziti identity)                          │
                                                                            ▼
                                     proxy forward-auth / continuous-verify:
                                     posture fail ⇒ revoke session + sever Ziti circuit
```

The EDR ingestion is just a **new source** for the same `device_posture_results`
table. Enforcement (`context_evaluator`, `continuous_verify`) is unchanged: it
reads the latest posture result per Ziti identity, and a failing/expired result
cuts the device off the overlay. Posture results carry a TTL so a device that
stops reporting fails closed.

## Flow

1. An admin configures an EDR source (provider + credentials + which
   `posture_check` a non-compliant signal fails + how to match devices).
2. The ingestion worker polls the source on its interval.
3. For each device it resolves a local **Ziti identity** by serial / hostname /
   email, records a device mapping, and writes a posture result:
   **pass** when compliant AND not high/critical risk, **fail** otherwise.
4. The existing Ziti enforcement acts on the result on the next request /
   continuous-verify sweep.

## Supported providers

| Provider | Auth | Devices | Compliance signal |
|----------|------|---------|-------------------|
| **CrowdStrike Falcon** | OAuth2 client-credentials | `/devices/queries` + `/devices/entities` | host `status=normal` & no Reduced-Functionality-Mode |
| **Microsoft Intune** | Graph client-credentials | `deviceManagement/managedDevices` | `complianceState == compliant` |
| **Jamf Pro** | Basic → bearer | `computers-inventory` | managed (inventory presence) |

A device fails posture when the provider reports it non-compliant, or its
normalized risk is high/critical.

## Configuration

An EDR source is created under `/api/v1/access/ziti/posture/edr` (admin only):

```json
POST /api/v1/access/ziti/posture/edr
{
  "name": "corp-crowdstrike",
  "provider": "crowdstrike",
  "client_id": "•••",
  "client_secret": "•••",
  "posture_check_id": "<uuid of the posture_check this feeds>",
  "match_strategy": "serial",
  "result_ttl_minutes": 60,
  "poll_interval_minutes": 15,
  "enabled": true
}
```

- **provider** — `crowdstrike` | `intune` | `jamf`.
- **credentials** — CrowdStrike/Intune: `client_id`/`client_secret` (+ Intune
  `tenant_id`); Jamf: `api_user`/`api_token` + `base_url`. Secrets are encrypted
  at rest (secretcrypt) and never returned by the API.
- **posture_check_id** — the local `posture_checks.id` an ingested non-compliant
  signal fails. Attach this check to the routes/service policies you want gated.
- **match_strategy** — `serial` | `hostname` | `email`. Serial/hostname match a
  device's `enrolled_agents.metadata`; email matches `users.email`.
- **result_ttl_minutes** — posture results expire after this, so a device that
  stops reporting fails closed.
- **poll_interval_minutes** — how often the worker re-syncs the source.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/api/v1/access/ziti/posture/edr` | List sources |
| POST   | `/api/v1/access/ziti/posture/edr` | Create a source |
| GET    | `/api/v1/access/ziti/posture/edr/:id` | Get a source (secrets omitted) |
| DELETE | `/api/v1/access/ziti/posture/edr/:id` | Delete a source (+ mappings) |
| POST   | `/api/v1/access/ziti/posture/edr/:id/test` | Test connectivity + credentials |
| POST   | `/api/v1/access/ziti/posture/edr/:id/sync` | Run an ingestion pass now |

## Persistence

Migration **v98** adds `edr_posture_sources` (connection + encrypted creds +
poll/TTL config) and `edr_device_mappings` (external device id ↔ Ziti identity).
Posture results reuse the existing `device_posture_results`.
