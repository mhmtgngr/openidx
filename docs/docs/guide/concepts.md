# Concepts: One Product, Four Pillars

OpenIDX bundles what the market sells as four products. This page is the
mental model that keeps them straight — read it once and the rest of the
documentation stops being confusing.

## Each pillar answers a different question about the same person

| Pillar | The question | What the person experiences |
|---|---|---|
| **IAM** (identity) | *Who are you, and is it really you?* | The login page, MFA prompts, passkeys, SSO into apps, "My Security", sessions |
| **IGA** (governance) | *Who approved that you have this, and for how long?* | Access requests, approvals, access reviews / certifications, SoD blocks, JIT expiry |
| **PAM** (privileged access) | *How do you borrow powerful credentials safely?* | Credential vault checkout, brokered SSH/RDP in the browser, recorded sessions |
| **ZTNA** (network, via OpenZiti) | *How do you reach things that have no public door?* | The endpoint agent / BrowZer, "My Apps & Network", dark services with no inbound port |

They are **one product** because of the spine they share:

```
one identity  →  one grant (application assignment)  →  one policy plane
       →  one audit trail (unified_audit_events)  →  one kill switch
```

A decision made anywhere propagates everywhere. Disable a user (API, SCIM,
directory sync, or the kill switch) and three enforcement layers sever their
IAM sessions, API keys, vault checkouts, live privileged sessions, and Ziti
network circuits — worst case within 30 seconds. The deep dive is
[IAM ⇄ PAM ⇄ Ziti — How the Three Pillars Interrelate](https://github.com/mhmtgngr/openidx/blob/main/docs/IAM_PAM_ZITI_INTERRELATION.md).

## The one grant: application assignment

Historically, four independent mechanisms decided what a user could reach
(application assignments, proxy route roles, Ziti dial policies, PAM entry
grants) — and they did not talk to each other. That is being converged:
**assigning an application is the single grant**, and the proxy, the
`/oauth/authorize` gate, and the Ziti dial policies are all derived from it
through one predicate (`internal/appaccess`).

The convergence ships behind one staged flag (`ACCESS_ASSIGNMENT_ENFORCE`)
with a **reachability report** an admin drives to clean before flipping
enforcement — nobody silently loses access. The login half is no longer a
flag: there is a single login UI, and `OAUTH_LOGIN_URL` says where it is. Until your
deployment flips the flags, treat route roles and dial policies as the
enforced truth and assignments as the catalogue. PAM entry grants stay their
own enforcement layer by design — privileged access is deliberately a
separate decision from ordinary reach.

## Glossary — use these words consistently

| Term | Means | Does **not** mean |
|---|---|---|
| **Application** | A thing users launch (an OIDC/SAML client and/or a published route) | A Ziti service (that's the transport underneath) |
| **Route** | The published web path to an application, optionally Ziti-overlaid | An access grant |
| **Service** (Ziti) | A dark network endpoint dialable over the overlay | Something end users see by name |
| **Assignment** | The admin act of granting an application to a user or group — *the* grant once convergence is enforced | A cosmetic catalogue entry (post-rollout) |
| **Entitlement / grant** | What governance reviews and certifies (assignments, roles, vault grants, JIT) | — |
| **Policy** | A rule evaluated at decision time (MFA policy, ABAC/OPA, dial policy, approval policy) | A grant |
| **Posture** | Device health facts an agent reports (disk encryption, screen lock, EDR…) that dial policies can require | Device *trust*, which is the IAM-side flag on a known device |
| **Kill switch** | One admin action severing a user's tokens, sessions, checkouts, privileged sessions, and circuits | Merely disabling the account |

## The two personas

Everything in the console is one of two views:

- **The admin operates the platform** — users, applications, policies,
  the Ziti network, PAM connections, audit. Start at
  [Quick Start](quickstart.md), then
  [Publishing a service](network-access.md) and
  [Privileged Access](privileged-access.md).
- **The end user serves themself** — signs in, enrolls MFA, opens
  **My Apps & Network** (their launcher and network view in one page),
  requests access, checks out privileged connections, and manages their
  devices and sessions. Their pages are role-gated inside the same console.

## Where the deep documents live

The repository carries in-depth design and operations documents beyond this
site — the ones most worth reading:

- [Zero-trust architecture](https://github.com/mhmtgngr/openidx/blob/main/docs/zero-trust-architecture.md) — the five access paths and the fail-closed evaluation pipeline
- [How network access works](https://github.com/mhmtgngr/openidx/blob/main/docs/how-network-access-works.md) — UI concepts mapped to Ziti objects, with a diagnostic chain
- [Security & tenancy trust boundary](https://github.com/mhmtgngr/openidx/blob/main/docs/SECURITY-TENANCY.md) — the FORCE row-level-security model
- [Production hardening checklist](https://github.com/mhmtgngr/openidx/blob/main/docs/SECURITY-HARDENING.md) — grounded in the startup validator
- [Project readiness guide](https://github.com/mhmtgngr/openidx/blob/main/docs/PROJECT-READINESS-GUIDE.md) — the honest state of the platform, next steps, and recurring controls
