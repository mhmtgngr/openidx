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
