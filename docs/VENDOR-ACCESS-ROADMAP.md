# Third-party access: RDP, SSH and internal web, over ZTNA

> **The question.** External support staff — a hardware vendor, an ERP
> consultant, a contractor — occasionally need RDP or SSH to an internal host,
> or a browser on an internal web application. How does OpenIDX give them that
> without giving them the network?
>
> **Status.** This is a design and roadmap document, not a description of
> shipped behaviour. §2 is what exists today and is true now. §3 is a defect
> report and is also true now. §4 onward is the plan.

## 1. The short answer

Everything a safe answer needs already exists in the product **except the part
built for this exact question**, which bypasses all of it.

The pieces are: PAM entries per protocol with an ACL and expiry, session
recording, vault credential injection so the vendor never learns a password,
an approval gate, a fresh-MFA gate, and `PAM_REQUIRE_ZTNA` to force the
broker→target hop onto the OpenZiti overlay. For the vendor's own device —
which you do not control and cannot enrol — BrowZer makes a **browser** a
first-class overlay participant, so no client install is needed.

The feature literally named for this use case, **temporary access links**
(`internal/access/temp_access.go`), does none of it. It is a public,
unauthenticated URL that redirects to a Guacamole session with no recording, no
credential injection, no ZTNA check, and an MFA switch that is stored and never
read. That is the thing to fix first, and §3 is the evidence.

## 2. What the product already has

| Capability | Where | Notes |
|---|---|---|
| RDP / SSH / VNC / telnet sessions, brokered | `internal/access/pam_launch.go` | Guacamole; credentials injected from the vault |
| Clientless in-browser SSH | `pam_entries.go:286-294` (`wasm-ssh` renderer) | No Guacamole tab, no client |
| Internal web apps | proxy routes, Ziti services, `website` PAM entries | See §5 — the entry type is the wrong tool here |
| Per-entry ACL with expiry | `/pam/entries/:id/grants` (`expires_at`) | Time-bound grants exist today |
| Approval before launch | `require_approval` on the entry | |
| Session recording | `record_session` on the entry | |
| Fresh-MFA gate | `internal/access/stepup_gate.go`, wired at `service.go:733,735,742,760,764,765,803` | `STEPUP_GATE` + `STEPUP_MAX_AGE` |
| Target hop forced onto the overlay | `internal/access/pam_ztna.go`, called at `pam_launch.go:293` | `PAM_REQUIRE_ZTNA` (v1.34.0) |
| Risk / posture / ABAC gates | `PAM_SESSION_RISK_GATE`, `POSTURE_DEVICE_TRUST_GATE`, `ABAC_ENFORCE` | All tri-state |
| Time-bound elevation | `internal/jitgrant/`, expiry sweep in `internal/governance/jit_expiry.go` | |
| **Clientless overlay for an unmanaged device** | `internal/access/ziti_browzer.go:30` `BootstrapBrowZer` | External JWT signer trusting OpenIDX's own OIDC; `#browzer-users` dial `#browzer-enabled` services |

**BrowZer is the load-bearing piece for third parties** and deserves emphasis.
`PAM_REQUIRE_ZTNA=enforce` closes the broker→target hop in code, but the
user→broker hop is closed by the broker being published only at an overlay
address — which normally means the user runs the OpenIDX client. A vendor will
not install your client. BrowZer removes that requirement: the browser itself
authenticates to the Ziti controller with an OpenIDX-issued JWT and dials the
service. The vendor gets an overlay-only path with nothing to install.

## 3. The defect: the one feature built for this question

`temp_access.go` creates a link — protocol, target host and port, duration,
use cap, IP allowlist, "require MFA", "notify on use" — and hands out a URL.
Admins reach it from the console (`web/admin-console/src/pages/ziti-network.tsx:3701`,
`TempAccessLinksSection`). Redemption is `GET /temp-access/:token`
(`internal/access/service.go:1099`), deliberately anonymous — the repo's own
public-surface test lists it as serving anonymously
(`internal/access/public_surface_test.go:109`).

Being public is correct for a vendor link. Everything else is not:

| Control | PAM entry launch | Vendor temp link |
|---|---|---|
| Caller authenticated | required | **none, by design** |
| `require_mfa` | `requireFreshMFA` middleware | **stored at `:140`, scanned at `:363`, never read** |
| `PAM_REQUIRE_ZTNA` | `pam_launch.go:293` | **never consulted** |
| Broker selection | `brokerFor(reach_mode)` | **always `s.guacamoleClient`, the direct broker** (`:149`) |
| Session recording | `record_session` | **`CreateConnection(..., map[string]string{})`** — no parameters, so none (`:150-156`) |
| Credential injection | vault | **none** — the vendor must be told the password out of band |
| Approval gate | `require_approval` | none |
| Entry ACL | enforced | n/a |
| `notify_on_use` | — | **switch in the console form, no notification is ever sent** |
| IP allowlist | — | exact string equality (`:405`), so **no CIDR and no IPv6 normalisation** |
| Failure mode | refuse | **prints target host, port and username to the anonymous visitor** (`:460-467`) |

Three of these are this branch's recurring defect class — *a control that
displays without enforcing* — and they sit on the highest-risk surface in the
product: an unauthenticated URL granting an outsider RDP or SSH to an internal
host.

**And the register that exists to catch exactly this repeats the claim.**
`public_surface_test.go` is the guard that drives every access-service route
anonymously and requires each public one to carry a written justification. Its
entry for this route reads:

> `"GET /temp-access/:token"`: *"a vendor redeems a temporary access link whose
> path IS the secret; the handler checks expiry, revocation, use count, allowed
> IPs **and MFA** before granting anything"*

The handler checks the first four. It does not check MFA — `link.RequireMFA` is
scanned into the struct at `temp_access.go:363` and never compared to anything.
So the artefact a reviewer would consult to satisfy themselves that this
anonymous route is safe is the artefact telling them it is safe for a reason
that is not true. **Correct that sentence first** — before any code — because
until it is corrected it actively reassures the next person who looks.

Two more, smaller:

- If Guacamole is unreachable at creation time the link is still created
  (`:157-161` warns and continues) with an empty connection id, so redemption
  falls through to the host/port/username page above.
- `AccessProxyDomain` unset yields a link on **`browzer.localtest.me`**
  (`:165-168`) — a test domain in a vendor-facing URL.

**None of this is exploitable by a stranger without the token** — it is 32 bytes
from `crypto/rand`. The exposure is that a link, once issued or leaked, is a
standing, unattributable, unrecorded path to an internal host until it expires,
and the controls an operator believes are compensating for that are not running.

## 4. The roadmap

Three stages. **V0 is not optional and is not a feature** — it is making the
shipped surface tell the truth. V1 is the architecture worth having. V2 is
what turns it into a product other people can operate.

### V0 — Make the existing link honest (~3–4 days)

Order is by risk, and each item is independently shippable.

0. **Correct the public-surface register entry** (§3, last paragraph). One
   sentence, no code, and it stops the guard from vouching for a check that is
   not running. Do it in the same commit as item 2, so the register becomes true
   either by the code catching up or by the claim being withdrawn — never by
   being left as it is.
1. **Route redemption through the PAM launch core.** `handleUseTempAccess`
   should resolve the link to an entry-shaped launch and call the same code
   `handlePamConnect` calls, so it inherits `checkPamZTNA`, broker selection by
   reach mode, recording and credential injection instead of re-implementing a
   Guacamole redirect. This single change closes six rows of the table.
2. **Enforce `require_mfa` or delete it.** With no session there is no
   `mfa_verified_at` to read, so freshness in the PAM sense does not apply. The
   honest implementations are (a) require the vendor to complete an OTP to an
   email or phone recorded on the link before redemption, or (b) remove the
   field and say in the UI that these links are single-factor. Do not leave the
   field.
3. **Send the notification, or remove the switch.** `notify_on_use` and
   `notify_email` are in the console form; wire them to the notification service
   at redemption.
4. **CIDR and IPv6 in the allowlist**, with validation at creation so an
   operator who types `203.0.113.0/24` is told it is unsupported rather than
   silently locked out of their own link.
5. **Fail closed.** No Guacamole connection means no link — refuse at creation.
   Never render the target's host and port to an anonymous visitor.
6. **Refuse to start with the placeholder domain.** `browzer.localtest.me` in a
   production `access_url` is a `ValidateProduction` error, matching how
   `PAM_REQUIRE_ZTNA=enforce` already validates `GUACAMOLE_ZITI_PUBLIC_URL`.
7. **A guard, so this cannot recur.** The pattern here — a column written,
   selected and never compared — is mechanically detectable. Extend the existing
   unread-config census idea to struct fields on request objects: a field that
   is stored and read back but never appears in a conditional is a finding.

Each item needs a red proof, as everything else on this branch has.

### V1 — The vendor as a real, time-boxed identity (~2–3 weeks)

The link is a convenience. The durable answer is that the vendor is a **user**,
because every control in §2 keys off identity, and none of them can key off a
URL.

1. **A vendor identity type.** An external user with a mandatory sponsor, a
   mandatory expiry, and no default assignments. Lifecycle already exists
   (`internal/governance`, JIT expiry sweep); this is a constrained profile over
   it, not a new subsystem.
2. **BrowZer as the vendor's client.** `BootstrapBrowZer` already wires the
   external JWT signer and the `#browzer-users` → `#browzer-enabled` dial
   policy. What is missing is the operator path: a console flow that publishes a
   specific PAM target as a browzer-enabled service for a specific vendor for a
   specific window.
3. **Reuse the PAM entry, do not invent a vendor entry.** The vendor's target
   is an ordinary entry with `reach_mode=ziti`, `require_approval=true`,
   `record_session=true`, and a grant carrying `expires_at`. Nothing new to
   build; this is configuration the console should be able to produce in one
   step.
4. **Sponsor approval at launch, not just at grant.** The approval gate exists;
   the vendor case wants the sponsor notified and able to watch or terminate,
   which the Guacamole moderation and termination handlers already support.
5. **A closing report.** When the window ends: what was launched, when, from
   where, and the recording. The audit events exist; this is a query and a page.

### V2 — Operability (~1 week, after V1)

- A vendor register with active/expiring/expired, sponsor, and last use.
- Auto-revoke on sponsor departure — the leaver journey (J7) already sweeps
  elevations; vendors should ride the same sweep.
- Quarterly vendor access review, as an existing access-review campaign type.

## 5. Per protocol, concretely

**SSH.** Best case in the product. Use a PAM entry with the `wasm-ssh`
renderer: the terminal is in the vendor's browser, there is no Guacamole tab and
no client, and the session is brokered and recordable. With `reach_mode=ziti`
the target hop is on the overlay.

**RDP.** A PAM entry through Guacamole with `reach_mode=ziti` and
`record_session=true`. The vendor's browser reaches the broker; the broker
reaches the host over the overlay. Under `PAM_REQUIRE_ZTNA=enforce` the launch
is refused if the entry is still `direct` — which, since migration v82 made
`direct` the column default, is the case for any entry created without a
deliberate choice.

**Internal web.** Do **not** use a `website` PAM entry. Under
`PAM_REQUIRE_ZTNA=enforce` those are refused outright and the refusal says why:
a website entry returns a URL to the browser and brokers nothing, so no part of
it travels the overlay and there is no session to record. The right shapes are a
**proxy route** or publishing the site as a **Ziti service** the vendor reaches
through BrowZer. This is the one place where the honest answer is "the feature
you would reach for first is the wrong one".

## 6. What deployment must do, and code cannot

`docs/CLIENT-ACCESS-DESIGN.md` §4b states this for PAM generally and it applies
here unchanged: nothing in an HTTP request proves the caller arrived over the
overlay, and a header claiming it is set by whoever is calling. The user→broker
leg is closed by publishing the broker at an overlay address and nowhere else —
a property of the deployment. For vendors specifically that means BrowZer or an
issued client, and the operator check is the one already documented: from a host
with no client and no overlay membership, `curl` the broker's public URL and
require a connection failure.

## 7. Recommendation

Do **V0 item 1 first** — routing redemption through the PAM launch core — because
it converts six separate gaps into one change and makes every gate this branch
built apply to the vendor path for free. Then items 2 and 3, which are switches
that currently lie to the operator. Then decide V1 with the knowledge that the
link, once honest, may be sufficient for low-frequency vendor work and that V1
is what you need when third-party access becomes routine rather than occasional.
