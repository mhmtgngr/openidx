# Zero Trust Network (ZTNA)

OpenIDX's network plane makes internal services **dark**: they listen on no
public port anywhere. Reach happens over an [OpenZiti](https://openziti.io)
overlay, and only for identities the platform has synced there — so "on the
network" stops being a thing anyone is; you are only ever *on a service you
were granted*.

## The pieces

| Piece | What it is |
|---|---|
| **Ziti controller + router** | The overlay's brain and data plane, deployed with the stack |
| **Identity** | Every enabled OpenIDX user is mirrored to a Ziti identity by a 30-second sync; group memberships become identity attributes |
| **Service** | A dark endpoint (an internal web app, an SSH box, a database) registered on the overlay |
| **Dial policy** | Who may open circuits to which services — derived from OpenIDX state by a desired-state reconciler |
| **Endpoint agent** | Windows (signed) and Android clients that enroll a device, report **posture** (disk encryption, screen lock, EDR…), and tunnel |
| **BrowZer** | Clientless browser access for web apps — no agent install |

## How a user reaches something

1. They sign in and open **My Apps & Network** — one page showing their
   apps and what the network will actually let them reach (the listing is
   built from enforced state, not wishful catalogues).
2. Web apps open via BrowZer or the published route; native/TCP targets go
   through the enrolled agent.
3. The Ziti controller admits the circuit only if the identity's
   attributes satisfy the service's dial policy — including posture
   requirements like `#device-trusted`.
4. Disable the user (or fire the kill switch) and their edge and API
   sessions are deleted on the controller: live circuits die, not just
   future ones.

## Publishing a service (admin)

Console → **App Publish**: register the internal app, tick "expose over the
zero-trust network", and the reconciler provisions the Ziti service, bind
config, and dial policy. Manual **Add a resource** gives you explicit
`dial_roles` control. After the access-convergence rollout, an app-backed
service's dial policy is scoped to the users **assigned** the application —
assignment is the grant; the overlay enforces it.

Verification matters more than intention: the repo ships `tools/darkprobe`,
which proves a dark service is reachable by an authorized identity **and
not** by an unauthorized one — run it after publishing anything sensitive.

## Device posture checks

A posture check is one of two kinds, and the platform tells them apart by
its type:

- **Ziti posture checks** (`OS`, `Domain`, `MFA`, `Process`, `MAC`) are
  objects on the OpenZiti controller, which evaluates them when an identity
  dials a service. Console → **Ziti Network → Security → Posture Checks**.
- **Device agent checks** are run by the OpenIDX agents on the device. Their
  results set the device's compliance: a failing **critical** check makes it
  non-compliant, a failing **high** one starts its grace period, **medium**
  raises an alert and **low** only lowers the score. With
  `POSTURE_DEVICE_TRUST_GATE=enforce`, a compliant device earns the
  `device-trusted` overlay attribute. Console → **Agent Fleet → Device agent
  checks**.

An agent is sent only the agent checks, and only those scoped to its
platform (or to none). Nothing an agent runs is written to the controller.
When no agent check is configured, agents run three built-in defaults
(`os_version`, `disk_encryption`, `process_running`) that carry no severity,
so they can never start a grace period or make a device non-compliant.

| Check | Runs on | Params |
|---|---|---|
| `os_version` | windows, macos, linux, android | `min_version`: numbers and dots, such as `10.0.19045` |
| `agent_version` | windows, macos, linux, android, ios | `min_version`: numbers and dots |
| `patch_level` | windows, macos, linux, android | `max_days`: whole number, 1 to 3650 (agent default 30) |
| `process_running` | linux | `processes`: list of process names, 1 to 64, required |
| `disk_encryption` | windows, macos, linux, android | none |
| `screen_lock` | windows, macos, linux, android | none |
| `firewall` | windows, macos, linux | none |
| `antivirus` | windows, macos, linux | none |
| `domain_joined` | windows, macos, linux | none |
| `integrity` | linux | none |
| `play_integrity` | android | `require_meets_basic_integrity`, `require_meets_device_integrity`, `require_meets_strong_integrity`, `require_play_recognized`: true or false, judged by the server against Google's verdict |
| `enterprise_managed` | android | none |
| `developer_options` | android | none |
| `unknown_sources` | android | none |
| `accessibility_audit` | android | none |

The desktop agent reads the params. The Android agent runs `os_version`,
`patch_level` and the others with its own built-in thresholds.

The server refuses an agent check that does not fit this table, with a
`code` saying why: `unknown_check_type`, `invalid_name`, `invalid_severity`
(it must be `low`, `medium`, `high` or `critical`), `invalid_platform`,
`platform_not_supported` (a platform the check cannot run on, such as
`process_running` on windows), `unknown_param`, `missing_param` or
`invalid_param`. A check cannot change between the two kinds; delete it and
create the other. The table lives in
`internal/access/posturevocab/posturevocab.go`, and CI
(`tools/posturevocab`) fails when it stops matching what the agents
implement.

## Going fully dark

The platform can take its own API off the public internet: services bind
loopback-only and are reached over the overlay, with only the Tier-0
bootstrap surface (login/JWKS, enrollment) and the console public. A
`DARK_MODE_TIER*` flag plus a bind guard make it impossible for a "dark"
service to silently stay public.

## Going deeper

- [How network access works](https://github.com/mhmtgngr/openidx/blob/main/docs/how-network-access-works.md) — UI concepts mapped to Ziti objects, plus a diagnostic chain for "why can't I reach X"
- [Zero-trust architecture](https://github.com/mhmtgngr/openidx/blob/main/docs/zero-trust-architecture.md) — the five access paths and the fail-closed evaluation pipeline
- [Publishing a service](https://github.com/mhmtgngr/openidx/blob/main/docs/PUBLISHING_A_SERVICE.md) — the full admin walkthrough
- [Going dark runbook](https://github.com/mhmtgngr/openidx/blob/main/docs/GOING_DARK_RUNBOOK.md) — taking the API off the public internet
- [Easy Ziti deployment](https://github.com/mhmtgngr/openidx/blob/main/docs/ZITI_EASY_DEPLOYMENT.md) and [Ziti HA deployment](https://github.com/mhmtgngr/openidx/blob/main/docs/ZITI_HA_DEPLOYMENT.md)
