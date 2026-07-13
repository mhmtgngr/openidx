# OpenIDX Remote Access — Lifecycle Scenarios, Roles & Interrelations

**Audience:** platform owners, security engineers, and operators designing how people (employees *and* external users) get, use, and lose privileged remote access on OpenIDX.

**What this answers:**
1. How the three pillars — **IAM**, **PAM**, and **ZTNA/OpenZiti** — relate, and where that coupling gets complicated.
2. Who does what (personas + RACI).
3. End-to-end scenarios, including **granting remote management to an external user from scratch**.
4. A recommended **mobile app + user-side Ziti** experience.
5. How **MFA integration** simplifies management and improves UX.

> Terminology note: "IAM" = identity, groups/roles, OIDC/SAML, MFA, lifecycle & governance. "PAM" = vault, credential rotation, brokered privileged sessions (Guacamole), JIT checkout, recording. "ZTNA/Ziti" = the OpenZiti overlay, edge routers, device trust, BrowZer clientless access, and the access proxy.

---

## 1. The three pillars and how they interrelate

```
                        ┌──────────────────────────────────────────┐
                        │                IDENTITY (IAM)             │
                        │  users · groups · roles · OIDC/SAML · MFA │
                        │  lifecycle (JML) · SCIM · governance/SoD  │
                        └───────────────┬──────────────┬───────────┘
                          identity is the │              │ authorizes
                          subject of ↓    │              │ every hop ↓
        ┌───────────────────────────────▼──┐        ┌────▼─────────────────────────┐
        │              PAM                  │        │           ZTNA / OpenZiti     │
        │ vault · rotation · JIT checkout   │        │ overlay · edge routers        │
        │ brokered sessions (Guacamole)     │◄──────►│ device trust · BrowZer         │
        │ recording · approval chains       │ reach  │ access proxy · published apps  │
        │ RDM connection manager (entries)  │ mode   │                                │
        └───────────────────┬───────────────┘        └───────────────┬───────────────┘
                            │                                        │
                            └──────────────┬─────────────────────────┘
                                           ▼
                         CROSS-PILLAR CORRELATION (per user)
             access map · kill switch · lifecycle propagation (one identity,
             one view across IAM entitlements, PAM checkouts, Ziti services)
```

**The one-line model:** *Identity says **who you are**. ZTNA/Ziti decides **whether your device may even reach** the target's network path. PAM decides **whether you may open a privileged session and with which (hidden) credential**, and records it.* A privileged remote session to a server typically crosses **all three** in a single click.

### The coupling that makes it complicated

| Coupling | What depends on what | Where it bites |
|---|---|---|
| Identity → everything | Every PAM grant and Ziti service authorization keys off a user/group/role in IAM. | Delete/disable a user in IAM and their PAM checkouts + Ziti access must die too (that's what **kill switch / lifecycle propagation** exists for). |
| PAM ↔ Ziti (`reach_mode`) | A PAM connection entry reaches its target either **direct** (broker dials the host) or over **Ziti** (broker → ziti-tunnel → overlay → target). | "direct" needs network line-of-sight from the broker; "ziti" needs a provisioned Ziti service + a running tunnel. Picking the wrong mode is the #1 "why won't it connect" cause. |
| MFA → session assurance | Step-up MFA can gate the *moment* a privileged session opens, not just login. | If MFA isn't wired into the PAM approval/launch path, a stolen web session can open privileged sessions. |
| Device trust → data plane | Ziti/BrowZer authorize the device; the access proxy enforces per-route policy. | **Known gap:** BrowZer clientless routes bypass the proxy's forward-auth, so `require_device_trust`/`allowed_roles` are *not* enforced on the data plane for those routes — device trust for clientless is gated at OIDC login instead. Design around this. |
| Governance → grants | Access reviews, SoD, and JIT expiry can *revoke* IAM entitlements. | A revoke must cascade to PAM (kill active leases) and Ziti (drop service policy). |

**Rule of thumb:** never grant PAM or Ziti access to a *person* directly. Grant to a **group/role** in IAM, attach PAM entitlements and Ziti service policies to that group, and let lifecycle events (disable, review-revoke, JIT-expiry) flow through one identity change.

---

## 2. Personas & RACI

### Role tiers (OpenIDX built-in hierarchy)

`super_admin (4) > admin (3) > operator (2) > auditor (1) > user (0)` — plus `compliance_reader` (read-only audit visibility). Console pages gate on a `minRole`.

| Persona | Role | Typical console surfaces |
|---|---|---|
| **Platform owner** | `super_admin` | Everything; org/tenant setup, branding, IdP/federation config, Ziti network, break-glass. |
| **IAM admin** | `admin` | Users, Groups, Roles, Directories, Identity Providers, SAML SPs, Lifecycle policies, Provisioning rules. |
| **PAM admin** | `admin` | Vault Secrets, Rotation Policies, PAM Connections, PAM Dashboard, Guacamole/Privileged Sessions. |
| **Access/network operator** | `operator` | PAM Connections (launch), Privileged Sessions (monitor/terminate), BrowZer management, Proxy routes, Device-trust approvals. |
| **Approver / manager** | `operator`+ | Access Requests (approve/deny), Access Reviews, Device-trust approvals. |
| **Auditor / compliance** | `auditor` / `compliance_reader` | Audit logs, Compliance dashboard/reports, Session recordings & transcripts, Attestation campaigns. |
| **End user (employee)** | `user` | My Access, My Devices, My Privileged Access, App Launcher, Notification/MFA settings. |
| **External user (contractor/vendor)** | `user` (scoped) | My Privileged Access (only their granted connections), My Devices. Nothing admin. |

### RACI for "grant an external user privileged remote access"

| Step | Platform owner | IAM admin | PAM admin | Approver/Mgr | Ziti operator | External user |
|---|---|---|---|---|---|---|
| Create external identity / invite | | **R/A** | | I | | C (accepts) |
| Enforce MFA enrollment | | **A** | | | | **R** (enrolls) |
| Put user in a scoped group | | **R/A** | | | | |
| Vault the target credential | | | **R/A** | | | |
| Build the PAM connection entry (+ `reach_mode`) | | | **R/A** | | C | |
| Provision the Ziti service (if `ziti`) | C | | C | | **R/A** | |
| Approve the access request | | | | **R/A** | | C (requests) |
| Launch & use the session | | | I | | | **R** |
| Monitor / record / terminate | | | **A** | | R | |
| Review & revoke / expire | | R | R | **A** | R | |

*(R = does the work, A = accountable/signs off, C = consulted, I = informed.)*

---

## 3. Core scenarios

### Scenario A — Give remote management to an **external user, from scratch** (the headline flow)

**Situation:** An external contractor must administer **one Linux server** over SSH for **two weeks**, with no VPN, no standing password, full recording, and automatic expiry.

**Phase 0 — foundations (one-time, platform owner):**
1. Create/confirm the **org/tenant** (multi-tenant RLS isolates this customer's data).
2. Configure an **Identity Provider** (or use the built-in one) and **enforce MFA** for the org.
3. Stand up the **OpenZiti overlay**: controller + at least one **edge router**; register the access service as a Ziti identity.
4. Stand up the **PAM session broker** (OpenIDX-owned Guacamole: `guacd` + web + its own DB) and point the access service at it (`GUACAMOLE_URL` for REST, `GUACAMOLE_PUBLIC_URL` for the browser-facing connect URL). For overlay reach, also run the **ziti-tunnel broker** and set `GUACAMOLE_ZITI_URL`.

**Phase 1 — identity (IAM admin):**
5. Create the external user (or invite them); mark them external/scoped to this org.
6. Require **MFA enrollment on first login** (TOTP, WebAuthn/passkey, or push).
7. Create a group like `contractor-acme-server1` and add the user. **Grant to the group, not the person.**

**Phase 2 — the target (PAM admin):**
8. **Vault** the server's admin/service credential (encrypted at rest). Optionally attach a **rotation policy** (e.g., rotate the SSH key on a schedule / after each checkout).
9. Create a **PAM connection entry** (`pam-connections`): protocol `ssh`, host/port, `record_session = true`, `require_approval = true`, `reach_mode = ziti` (so the broker reaches the server over the overlay — no inbound exposure of the server).
10. Grant the entry to the `contractor-acme-server1` group.

**Phase 3 — the path (Ziti operator, only for `reach_mode = ziti`):**
11. Provision the per-entry **Ziti service** and bind a **host.v1 terminator** on an edge router that can reach the server; the broker's ziti-tunnel binds a loopback port the entry dials.

**Phase 4 — the grant (time-boxed):**
12. The contractor signs in (MFA), opens **My Privileged Access**, and **requests** the connection for 2 weeks.
13. The **approver** approves (optionally with a second approver via an approval chain). The grant is **JIT** — it auto-expires.

**Phase 5 — use & control:**
14. Contractor clicks **Connect** → a brokered Guacamole SSH session opens in the browser at the public URL; the credential is injected server-side and **never shown**.
15. PAM **records** the session; an operator can **live-monitor**, **share**, or **force-terminate**.
16. At expiry (or on revoke), the JIT grant lapses → the contractor can no longer launch; rotation invalidates the credential; the Ziti service policy is dropped. **Nothing standing is left behind.**

> This single flow touches all three pillars: **IAM** (identity + MFA + group + approval), **PAM** (vault + entry + brokered/recorded session), **Ziti** (overlay path + device/edge). Remove any one and the scenario breaks — that's the "complication."

### Scenario B — Employee lifecycle (Joiner → Mover → Leaver)

- **Joiner:** SCIM/directory sync or manual create → group membership grants baseline app + (via group) any PAM/Ziti entitlements → MFA enrollment → App Launcher shows their apps.
- **Mover:** role change updates group membership → PAM entries and Ziti services follow the group automatically; an **access review** confirms the delta.
- **Leaver:** disable in IAM → **lifecycle propagation / kill switch** cascades: active PAM leases killed, credentials rotated, Ziti service policies revoked, OIDC/refresh tokens invalidated. One action, all pillars.

### Scenario C — Standing "break-glass" for emergencies

A tightly-scoped group with an entry that is `require_approval = true` + recorded + short JIT TTL; approval routed to on-call. Everything is audited; the credential is rotated immediately after the session returns.

### Scenario D — Vendor with many targets (RDM-style)

Use **PAM Connections** folders to organize many entries (RDP/SSH/VNC), import an existing connection inventory, grant folders to a vendor group, and let the vendor self-serve launches (each still approval/record-gated per entry). `reach_mode` is chosen per entry (direct for on-net, ziti for isolated targets).

---

## 4. "Where is it wired?" — quick map to the product

| Need | Surface / mechanism |
|---|---|
| Create/manage identities, groups, roles | Identity service · Users/Groups/Roles pages |
| Federate / SSO | Identity Providers, SAML Service Providers, Federation config |
| Enforce MFA / step-up | MFA management, Passwordless settings, Push devices |
| Joiner-mover-leaver automation | Lifecycle policies/workflows, Provisioning rules (SCIM) |
| Request/approve access | Access Requests, approval chains |
| Periodic recertification | Access Reviews, Attestation campaigns |
| Store/rotate secrets | Vault Secrets, Rotation Policies |
| Privileged connection catalog | **PAM Connections** (`pam-connections`) — folders, entries, grants, favorites |
| Open/monitor/record sessions | Privileged Sessions (`guacamole-sessions`), PAM Dashboard |
| Self-service (end user) | **My Privileged Access**, My Access, My Devices, App Launcher |
| Overlay networking | OpenZiti controller/edge routers, `reach_mode=ziti`, ziti-tunnel broker |
| Clientless browser access | BrowZer management |
| Device posture | Device-trust approvals, My Devices |
| See a user's whole footprint | **User Access 360** / cross-pillar correlation (access map + kill switch) |
| Prove compliance | Audit logs, Compliance dashboard/reports, session transcripts, legal hold |

---

## 5. Recommendation: a mobile app + user-side Ziti (strongly advised)

**Verdict: yes — a mobile app materially simplifies both *management* and *user experience*, and it fits OpenIDX's architecture cleanly.** Here's the shape.

### Why it helps
- **The user's device becomes the Ziti endpoint + the MFA authenticator in one.** OpenZiti has mobile SDKs (Ziti Mobile Edge / embedded SDK). If the OpenIDX app embeds the Ziti SDK, the phone can *be* a trusted Ziti identity — private access to internal targets with **no VPN**, and the same device is the MFA/passkey factor. One enrollment, two jobs.
- **Approvals become push, not email.** Approvers approve/deny access requests and PAM session requests from a push notification — cutting the slowest step in every scenario above from minutes to seconds.
- **Self-service on the go.** End users browse **My Privileged Access**, request a connection, and (for web-renderable protocols) launch the brokered session in an in-app webview pointed at the public Guacamole URL.
- **Device trust gets a real signal.** A managed app can attest device posture (OS version, screen-lock, jailbreak/root, biometric availability) feeding the device-trust decision — closing the gap where clientless routes can't enforce posture on the data plane.

### Suggested capability tiers (build incrementally)
1. **MVP — Authenticator + Approvals:** passkey/WebAuthn + push-based step-up MFA; approve/deny requests; view "My Access". No Ziti SDK yet. Highest value for least effort.
2. **Phase 2 — Self-service launch:** browse/request PAM connections; launch web-renderable sessions in-app; see status of JIT grants.
3. **Phase 3 — Embedded Ziti:** bundle the Ziti mobile SDK so the phone is a first-class overlay endpoint + posture source; native SSH/RDP viewers over the overlay.

### Design guardrails
- Keep the phone a **factor and a client**, not an admin console — management stays on the web console (role-gated).
- Bind the mobile identity to the **user + a specific device** (device-bound passkey); enrollment itself should be MFA-gated and, ideally, approver-confirmed for external users.
- Reuse the existing **OIDC/PKCE** flow the console uses; the app is just another OAuth client.

---

## 6. MFA integration advice (management + UX)

**MFA is the connective tissue that makes the whole model safe to simplify.** Recommendations:

1. **Passkeys / WebAuthn as the default factor.** Phishing-resistant, and on mobile it's just Face ID/fingerprint — the *easiest* factor is also the strongest. This is the single biggest UX+security win.
2. **Step-up MFA at the privileged moment, not just at login.** Require a fresh factor when a user **opens a privileged PAM session** or an approver **approves** one — bounded by session assurance, so a hijacked web session can't silently open a root shell. (OpenIDX already closed a step-up-bypass gap here; keep step-up wired into the PAM launch/approval path.)
3. **Push approvals with number-matching** for both login and access approvals — fast for users, resistant to MFA-fatigue attacks.
4. **Device-bound + posture-aware.** Tie the factor to a trusted device; feed the mobile app's posture into device trust so a healthy phone streamlines access and an unhealthy one triggers step-up or denial.
5. **External users: enrollment is the gate.** Force MFA enrollment on first login *before* any grant activates; consider approver-confirmed enrollment for contractors.
6. **Reduce friction with risk-based prompts.** Only step up when risk warrants (new device, new geo, sensitive target) so routine access stays one-tap — this is what makes "secure" feel "easy."

**Net effect:** MFA (especially passkey + push on the mobile app) lets you *shorten* every approval and login step while *raising* assurance — you simplify management (fewer help-desk resets, faster approvals) and improve UX (one-tap biometrics) at the same time.

---

## 7. Common failure points (checklist)

- **"Connect" returns 503 / broker unconfigured** → no `GUACAMOLE_URL` (direct) or `GUACAMOLE_ZITI_URL` (ziti) wired.
- **Session tab opens to an unreachable URL** → `GUACAMOLE_PUBLIC_URL` not set to a browser-reachable address behind the ingress.
- **`reach_mode=ziti` entry won't connect** → Ziti service/terminator not provisioned or the ziti-tunnel isn't running.
- **Access works but posture isn't enforced** → clientless BrowZer route bypasses proxy forward-auth; gate device trust at OIDC login instead.
- **User disabled but still has access** → confirm kill switch / lifecycle propagation reached PAM (leases) and Ziti (service policy), not just IAM.
- **401s everywhere in the console** → usually just an expired login session; re-authenticate.
```
