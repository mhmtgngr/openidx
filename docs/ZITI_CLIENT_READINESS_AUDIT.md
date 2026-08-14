# OpenZiti Install-Readiness Audit — server, router, Windows client, Android client

**Dated:** 2026-08-14 · **Commit:** `b60b90d` · **Branch:** `claude/ziti-client-readiness-akzpro`

**Question asked:** does the "easy install" claim in `README.md` and
[`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) hold end-to-end for each of
the four things an operator actually installs — the **controller/server**, an
**edge router**, the **Windows client**, and the **Android client**?

**Short answer:** for one of the four, on a lab hostname. The dev
controller + router really is one command. Everything downstream of it —
every client, every non-compose router, both Kubernetes paths — is blocked,
undefined, or reachable only by reading source.

---

## 0. How to read this

**Method.** Static read of the repository at `b60b90d`. **No deployment was
performed**, no controller was contacted, and no client was installed. Every
claim below cites a file. Where a conclusion depends on runtime behavior that
cannot be settled from source, it is marked *plausible — verify live* and is not
counted as a finding.

**Severity ladder** (used throughout):

| | Meaning |
|---|---|
| **S1** | Blocks install — the documented path cannot complete on a clean machine. |
| **S2** | Completes but is non-functional — the install "succeeds", the thing doesn't work. |
| **S3** | Works in dev only — fails on a real hostname or off the compose network. |
| **S4** | Friction / doc drift — the operator gets there, by guessing or reading source. |

**Per-surface rubric.** Each of §2–§5 answers the same six questions: *claimed
install path · what exists · verified working · unverified · gaps · smallest fix.*

---

## 1. Verdict

| Surface | Verdict | S1 | S2 |
|---|---|---|---|
| **Server / controller** | 🟢 **One command — dev only.** Real, and the best surface in the repo. Kubernetes and Terraform paths are broken. | 1 | 3 |
| **Edge router** | 🟠 **One command in the dev compose; no product path anywhere else.** | 2 | 1 |
| **Windows client** | 🟠 **A real signed release exists and points at a data plane the client cannot resolve.** | 2 | 2 |
| **Android client** | 🔴 **No install path.** The APK the platform serves is not in the repo. | 2 | 1 |

Three findings matter more than the rest:

1. **The dev router advertises a Docker-internal hostname** (`ziti-router`), and
   the controller hands that string to every client verbatim. No client outside
   the compose network can reach the data plane, no matter how cleanly it
   installs. This is the single root cause behind the Windows and Android
   verdicts. → [G-R2](#g-r2)
2. **Clients are gated off by default and the readiness page cannot tell you.**
   `ZITI_AGENT_OVERLAY_ENABLED` defaults to false and appears in no checklist, no
   `.env.example`, and no deployment doc — so Network Setup can report all
   required steps complete on a deployment where not one device is on the
   overlay. → [G-X1](#g-x1)
3. **`deployments/android/` contains only `.gitkeep`.** The APK route, the
   checksum, and the Android Enterprise QR payload are all built around a file
   that does not exist in the repository and is never produced by CI. → [G-A1](#g-a1)

**On verification:** nothing in CI verifies that any of the four install paths
completes. `test-integration.sh` has zero Ziti references;
`internal/access/ziti_setup_test.go` unit-tests `buildSetupComponents` but never
asserts on the client/`tunneler` row; `web/admin-console/e2e/ziti-setup.spec.ts`
intercepts the endpoint with a hand-written literal and tests rendering. Every
"verified" claim in the Ziti docs traces to a human operating
`openidx.tdv.org`, not to a job that runs on merge.

---

## 2. Server / controller — 🟢 one command, dev only

**Claimed path.** `make ziti-quickstart` ([`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) §TL;DR).

**What exists.** `scripts/ziti-quickstart.sh` runs `docker compose up -d
ziti-controller ziti-router-init ziti-router` against
`deployments/docker/docker-compose.yml` (ziti block, lines 577–697), polls the
controller healthcheck, and prints the ZAC URL and credentials. `HA=1` adds a
second router via `docker-compose.ziti-ha.yml`. Exactly **one** mandatory
variable — `ZITI_PWD` (`${ZITI_PWD:?…}`) — and the script generates `.env` via
`scripts/generate-secrets.sh` if it is missing. `ZITI_VERSION` pins the image to
`1.6.12`.

**Verified working.** This part of the claim is true: the command is real, the
inputs are generated, and the wait-for-health loop is honest. The backend meets
it halfway — `ZitiManager.bootstrap()` (`internal/access/ziti.go`) creates the
edge-router policy, the service-edge-router policy, and enrolls OpenIDX's own
`access-proxy` identity with no operator step. Checklist steps 1–3 are real
probes (`CheckControllerHealth`; `os.Stat` on `ca.pem`), not config echoes.

**Unverified.** That the resulting fabric passes traffic — see §3.

### Gaps

**G-S1 (S3, M) — the advertised address is hardcoded and PKI-permanent.**
`docker-compose.yml:588` sets `ZITI_CTRL_ADVERTISED_ADDRESS=ziti-controller.localtest.me`
as a literal, not a variable. The controller's PKI embeds it permanently —
[`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) says so itself ("certificates
embed it; it cannot change later") — so there is no supported way to run the
quickstart on a real FQDN, and no guided step that warns you before the certs
are minted.

**G-S2 (S2, S) — the production compose contradicts itself.**
`docker-compose.prod.yml:431` points access-service at
`ZITI_CTRL_URL=https://ziti-controller.openidx.tdv.org:1280`, but its
`ziti-controller` override (lines 660–663) sets only `restart` and `profiles` —
it does **not** override the advertised address. Bringing up
`-f docker-compose.yml -f docker-compose.prod.yml --profile ziti` yields a
controller advertising `ziti-controller.localtest.me` that the app tries to reach
at `ziti-controller.openidx.tdv.org`. The file also hardcodes `tdv.org` in ~20
places: it is one deployment's config, not a product artifact.

<a id="g-s3"></a>
**G-S3 (S3, S) — `ZITI_CTRL_PUBLIC_ADDRESS` is implemented and invisible.** The
knob exists (`internal/common/config/config.go:243,253,950`) and is consumed by
`enrollmentJWTAddressStale` (`internal/access/enroll_handler.go:193-195`) to
re-issue JWTs that point at a controller address clients cannot reach — i.e. it
is the intended fix for the "a phone resolves `.localtest.me` to 127.0.0.1"
problem. It is set in **zero** compose files and named in **zero** docs. Note it
addresses only the *controller* address, not the router advertise
([G-R2](#g-r2)), which is the actual client-side blocker.

**G-S4 (S1, S) — the Terraform module deploys a second copy of the whole
product.** `deployments/terraform/modules/openziti/main.tf` creates
`helm_release "openidx-ziti-fabric"` of chart **`openidx`** (the full
application chart), setting only `zitiFabric.*`. Every application sub-chart
defaults to `enabled: true` (`values.yaml:64,92,120,148,188,216,244,272,…`), so
this release also stands up duplicate identity-service, oauth-service,
access-service, admin-api and gateway-service pods alongside the real release.
Called from `deployments/terraform/main.tf`.

**G-S5 (S2, M) — the Helm fabric renders but cannot be enrolled or
administered.** `templates/ziti-fabric.yaml` renders a controller StatefulSet, a
router Deployment, Services and PDBs behind `zitiFabric.enabled`
(`values.yaml:354`, default false). But the **router Deployment has no
enrollment path at all** — no `ZITI_ENROLL_TOKEN`, no
`ZITI_BOOTSTRAP_ENROLLMENT`, no init job, no JWT Secret; the only `ZITI_BOOTSTRAP*`
variables in the file (lines 69–75) are on the *controller*. And
`templates/secrets.yaml` carries no Ziti keys, so there is no `ZITI_PWD` for
anything to authenticate with afterwards.

**G-S6 (S2, M) — Helm "Raft HA" cannot form a quorum as written.**
`ziti-fabric.yaml:84` enables `ZITI_CTRL_RAFT_ENABLED` when replicas > 1 and the
comment above it claims each pod advertises its stable StatefulSet DNS name — but
`ZITI_CTRL_ADVERTISED_ADDRESS` is a single static value
(`.Values.zitiFabric.controller.advertisedAddress`, line 66) applied identically
to every replica, with no peer/bootstrap-members setting.
[`ZITI_HA_DEPLOYMENT.md`](./ZITI_HA_DEPLOYMENT.md) §"Cloud: Kubernetes / Helm"
sells this as working. *Plausible — verify live before acting.*

**G-S7 (S3, S) — Helm controller persistence is likely misdirected.** The
controller PVC mounts at `/persistent` with no `ZITI_HOME`, while the compose
controller persists to `/home/ziggy` + `/ziti-controller`. The bbolt DB and PKI
are probably not on the PVC. *Plausible — verify live.*

**G-S8 (S4, S) — Terraform floats to `:latest`.**
`modules/openziti/variables.tf` defaults `controller_image` / `router_image` to
`openziti/ziti-*:latest`, directly contradicting the never-float discipline
asserted in `values.yaml:357-360`, `docker-compose.yml:579-581` and
[`ZITI_HA_DEPLOYMENT.md`](./ZITI_HA_DEPLOYMENT.md).

**G-S9 (S4, S) — the quickstart's own "next step" does not exist.**
`scripts/ziti-quickstart.sh:94` prints *"Start OpenIDX (`make dev-docker`)"*.
There is no `dev-docker` target — `Makefile:225` defines `dev`, which is what
[`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) says. The one command the
successful path hands you next is wrong.

**G-S10 (S4, S) — no Ziti checks in the doctor.** `scripts/doctor.sh` and
`scripts/smoke-test.sh` contain zero Ziti references. `cmd/openidx doctor` checks
only that `ZITI_PWD` is present.

### Smallest fix

Parameterize `ZITI_CTRL_ADVERTISED_ADDRESS` (G-S1) and set/document
`ZITI_CTRL_PUBLIC_ADDRESS` beside it (G-S3); fix the banner (G-S9). For
Kubernetes, either wire router enrollment + a `ZITI_PWD` Secret into the chart,
or mark `zitiFabric` experimental until it is — and point the Terraform module at
a fabric-only chart rather than the full product (G-S4).

---

## 3. Edge router — 🟠 one command in the dev compose, no product path elsewhere

**Claimed path.** Bundled: none needed. Additional routers:
`ziti edge create edge-router … --jwt-output-file`, per the checklist's own
remediation string.

**What exists.** Within one Docker host this is clean. `ziti-router-init`
(compose 609–651) logs in, runs `ziti edge create edge-router openidx-router
--jwt-output-file`, and shares the JWT through the `ziti_router_shared` volume;
`deployments/docker/ziti-router/entrypoint.bash` copies the version-controlled
`config.yml` into the volume on first boot and calls the base image's `enroll()`.
`docker-compose.ziti-ha.yml` clones the pattern for router-2 with `config-2.yml`.
Idempotent and re-runnable.

### Gaps

<a id="g-r2"></a>
**G-R2 (S3, S) — the router advertises a name only Docker can resolve. This is
the audit's root cause.**

```
deployments/docker/ziti-router/config.yml:40   advertise: tls:ziti-router:3022
deployments/docker/ziti-router/config.yml:49   advertise: ziti-router:3022
deployments/docker/docker-compose.yml:662      ZITI_ROUTER_ADVERTISED_ADDRESS=ziti-router
```

The controller distributes that string to every SDK client verbatim. Nothing
outside the compose network resolves `ziti-router`. So **no off-host client can
reach the dev data plane** — the Windows agent, the Android agent, and the Expo
app all fail here regardless of how well they install. The verification command
is already written down in `docs/ziti-nat-firewall-requirements.md` §7
(`ziti edge list edge-routers -j`), just not connected to any install path.

`deployments/apisix-edge/ziti-router/config.reference.yml` is the only file in
the repo that solves this, and it is a hand-maintained snapshot of one production
host.

**G-R1 (S1, M) — no API to create an edge router or mint its JWT.**
`internal/access/service.go` exposes:

```
427: api.GET("/ziti/fabric/routers",     svc.handleListEdgeRouters)
428: api.GET("/ziti/fabric/routers/:id", svc.handleGetEdgeRouter)
441-444: /ziti/edge-router-policies  GET POST PUT DELETE   ← policies, not routers
```

`ZitiManager` matches — `ListEdgeRouters` / `GetEdgeRouter`
(`internal/access/ziti_fabric.go:84,131`) plus the `Ensure*Policy` helpers, and
**no `CreateEdgeRouter`**; no `POST` to `/edge/management/v1/edge-routers` exists
outside test fixtures. So the guided-setup page's answer to its own blocking step
is to go type a CLI command on the controller. For the bundled router that is
already done; for **any router an operator adds** — the entire point of adding
one being to put the data plane near an app the bundled router cannot reach —
the guided path stops.

**G-R5 (S1, L) — the production router is a hand-run recipe filed where nobody
will look.** `deployments/apisix-edge/ziti-router/README.md` +
`setup-router-wss.sh`: manual re-enroll, `podman cp` the JWT, `chmod 644`, a
hand-typed `podman run --network host`, and `openziti/ziti-router:latest`.
Nothing about it is driven from the product, and it lives under `apisix-edge/`.

**G-R3 (S2, M) — the shipped BrowZer WSS cert mechanism is the one the
operator README measured as broken.** `deployments/docker/ziti-router/config.yml`
presents the BrowZer cert via `identity.alt_server_certs` and a `transport.ws:`
block. `deployments/apisix-edge/ziti-router/README.md` states, from measurement
on **the same v1.6.12**, that the WSS listener does *not* honor
`alt_server_certs` (browser error `1016`), that the cert must come from
`transport.wss.identity`, and that `transport.ws` is rejected outright. The live
production file `config.reference.yml` uses `transport.wss.identity`. Meanwhile
`docker-compose.yml:699` comments that the WSS proxy was "removed —
router alt_server_certs handles TLS". Two in-repo sources, same version, opposite
conclusions.

**G-R4 (S4, S) — a code comment teaches a refuted model.** `config.yml` says WSS
hostnames "must be in the CSR SANs so the enrolled cert covers them"; the
operator README says flatly that `ziti router enroll` does **not** honor
`edge.csr.sans` (SANs derive from `ZITI_ROUTER_ADVERTISED_ADDRESS` plus
defaults).

**G-R6 (S4, S) — `--tunneler-enabled` is undetected.** The advisor warns that a
router without it cannot host direct/hop services, but nothing checks the flag on
an already-registered router; the operator finds out when a route fails to
converge.

### Smallest fix

Make the router advertise something resolvable off-host (G-R2) — a variable with
the compose default kept for pure-local use — then add
`POST /ziti/fabric/routers` wrapping the controller's
`POST /edge/management/v1/edge-routers` and returning the enrollment JWT, surfaced
as "Add a router" on the Ziti Network page (G-R1, G-R6). Reconcile the two WSS
configs and keep the measured one (G-R3, G-R4).

---

## 4. Windows client — 🟠 a real signed release, pointed at an unreachable data plane

**Claimed path.** `./install-openidx-agent.ps1` — "a bare invocation just works"
(`agent/scripts/install-openidx-agent.ps1` header).

**What exists — and this is genuine engineering.**
`.github/workflows/windows-client-build.yml` is a real release pipeline:
PR-time cross-compile check; tag-gated MSI build that **hard-fails** if the
libvpx/CGO screen-capture build falls back to pure Go (lines 166–172, "a
video-less agent must never be shipped"); capability verification of the built
binary; optional Authenticode signing; a `latest.json` update manifest;
placeholder stamping; release publish. `agent/packaging/wix/OpenIDX.wxs` and
winget manifests exist. The installer itself is well-built: elevation guard,
idempotent hosts handling, silent MSI, enroll, tray. Enrollment auto-enrolls a
Ziti identity (`agent/internal/enrollment/enroll.go`), keeping the JWT on disk
for manual retry and treating failure as non-fatal.

### Gaps

**G-W1 (S2, S) — the installer's hosts entries name a host the router never
advertises.** `install-openidx-agent.ps1:36` pins:

```powershell
[string[]]$ZitiNames = @("ziti-controller.localtest.me", "ziti-router.localtest.me")
```

The controller name matches. The **router name does not** — the router advertises
bare `ziti-router` ([G-R2](#g-r2)). So the install completes, enrollment
succeeds, and every dial then fails on DNS. This is the most concrete instance of
the root cause.

**G-W2 (S1, S) — the "one-liner" depends on unset, undocumented GitHub repo
variables.** `windows-client-build.yml:329-331` stamps from
`vars.AGENT_DEFAULT_SERVER_URL`, `vars.AGENT_DEFAULT_ENROLL_TOKEN`,
`vars.AGENT_DEFAULT_SERVER_IP`. Unset, they stamp as empty strings and the
script's own guards (`install-openidx-agent.ps1:53-54`) `throw "Server URL not
set"`. The promised bare invocation depends on repo configuration that is named
nowhere in the docs.

**G-W3 (S2 / security, S) — a reusable enrollment token is published as a
release asset.** `AGENT_DEFAULT_ENROLL_TOKEN` is a GitHub **variable**, not a
secret, and is stamped verbatim into an installer attached to a public release.

**G-W4 (S1, S) — the platform serves no MSI.** `internal/access/service.go:1013`
registers exactly one client-binary route, `/downloads/openidx-agent.apk`. There
is no `.msi` route anywhere in `internal/`, and no MSI link anywhere in
`web/admin-console/src/`. Windows users must be handed a GitHub URL out of band —
which is also why `install-openidx-agent.ps1:56,60` hardcodes
`github.com/mhmtgngr/openidx` as the fallback, leaving air-gapped and forked
installs with no path at all.

<a id="g-w5"></a>
**G-W5 (S4, S) — the agent is not a tunneler, but the product says it is.**
`agent/internal/ziti/dialer.go` is explicit in its own package comment:

> dial a named Ziti service in-process, and … bridge a service to a local
> `127.0.0.1` loopback port. **No TUN driver / no elevation** — matches the
> "embedded per-service dial" decision.

That is the right design for RDP/SSH/VNC brokering. But the install advisor
(`internal/access/ziti_setup_handlers.go`, `tunneler` component) tells the
operator *"The OpenIDX Agent **embeds a tunneler**"* and lists it interchangeably
with *"Windows/macOS: Ziti Desktop Edge"*. They are not interchangeable:
transparent interception of arbitrary traffic (an `intercept.v1` service a
third-party app should reach without knowing about Ziti) needs Ziti Desktop Edge.
An operator who installs the OpenIDX Agent expecting tunneler behavior gets
silent non-interception.

**G-W6 (S4, S) — "no elevation" is a component claim, not an install claim.**
The dialer needs no TUN and no elevation; the *installer* requires Administrator
(`install-openidx-agent.ps1:48`) to edit the hosts file and register the service.
Worth stating so the design note is not read as end-to-end.

**G-W7 (S4, S) — the release installer edits the hosts file by default.** A
signed, publicly released installer that rewrites
`%WINDIR%\System32\drivers\etc\hosts` for `*.localtest.me` names is a
production-hostile default and an antivirus-heuristic magnet — even though it is
guarded (skipped when `-ServerIP` is empty) and honestly documented.

### Smallest fix

Fix the advertised router name (G-R2) and the installer's `ZitiNames` with it
(G-W1); serve the MSI beside the APK with a `/downloads/agent-info` mirroring
`HandleAPKInfo` (G-W4); move the enroll token to a secret (G-W3); and split the
advisor's `tunneler` row into "OpenIDX Agent (per-service dial + loopback bridge)"
vs "Ziti Desktop Edge (full intercept)" so the choice is stated (G-W5).

---

## 5. Android client — 🔴 no install path

**Claimed path.** Android Enterprise QR from Agent Fleet, which downloads
`/downloads/openidx-agent.apk` and auto-enrolls.

**What exists.** The *mechanism* is well designed. `HandleGenerateQR`
(`internal/access/agent_api.go`) assembles a real `PROVISIONING_*` payload
carrying the APK's SHA-256, so a factory-reset scan installs and enrolls;
`HandleAPKInfo` / `HandleAPKDownload` serve and checksum it; Agent Fleet renders
the QR plus a checksummed download link (`agent-fleet.tsx:363-369`). And
`agent-android/` is a real client: `core/.../ZitiClient.kt` wraps the genuine
`org.openziti:ziti-android:0.30.0` SDK in seamless mode
(`core/build.gradle.kts:45`), with enrollment driven from
`OAuthEnrollmentFlow.kt` and `QrEnrollmentBootstrapper.kt`.

The mechanism has no artifact to operate on.

### Gaps

<a id="g-a1"></a>
**G-A1 (S1, S) — the APK the platform serves does not exist.**
`deployments/android/` contains **only `.gitkeep`**. That is the path
`internal/access/service.go:1013` serves and the path
`internal/access/agent_api.go:1816` hashes for the QR signature checksum. On a
fresh install the download 404s and the provisioning payload cannot be built. The
checksummed link in Agent Fleet renders with an empty checksum.

**G-A2 (S1, M) — no signed release APK is ever produced.**
`agent-android/app/build.gradle.kts` contains **no `signingConfig` block at all**.
`.github/workflows/ci-android.yml:84` runs only `gradle :app:assembleDebug` and
uploads the debug APK as a workflow artifact — no release job, no tag trigger, no
upload. So G-A1 has no automated remedy: the only way to populate
`deployments/android/` is a human building an APK and copying it onto the server,
an unsigned-provenance step in the middle of an otherwise checksum-verified
Android Enterprise flow.

**G-A3 (S4, S) — there are three Android narratives and no authoritative one.**

| | `agent-android/` | `mobile/` | `docs/mobile-openziti-integration-guide.md` |
|---|---|---|---|
| identity | `com.openidx.agent` | `org.tdv.openidx` (`mobile/app.json`) | — |
| stack | Kotlin / Gradle | Expo / React Native | "native Android (Kotlin / Jetpack Compose)" |
| Ziti | real SDK, seamless mode | 73-line stub (below) | tells the reader to copy `agent-android`'s `ZitiClient.kt` |
| role | managed device: kiosk, device admin, posture, remote support | end-user self-service / authenticator | a third app that does not exist |

Nothing states which one an end user installs. `mobile/README.md` is the
untouched `create-expo-app` boilerplate ("Welcome to your Expo app 👋 … run `npm
run reset-project`").

**G-A4 (S2, M) — `mobile/`'s Ziti module is a scaffold, not a client.**
`mobile/modules/ziti/android/…/OidxZitiModule.kt` is **73 lines** and its `dial()`
rejects with the message *"bridge ctx.dial(name) to a 127.0.0.1 loopback socket
and return host:port"*; the Swift side (103 lines) is the same. Its own README
confirms the module has never been compiled into an EAS build, so
`requireOptionalNativeModule('OidxZiti')` returns `null` and overlay features
silently disable while enrollment and posture keep working over plain HTTP — the
app looks healthy and cannot dial. `mobile/app.json:74` also ships
`eas.projectId: "00000000-0000-0000-0000-000000000000"`, so an EAS build cannot
run as committed. The Android SDK floats (`0.30.+`) where the native agent pins
(`0.30.0`).

**G-A5 (S3, M) — the only known-working topology is prose, not config.**
`docs/mobile-openziti-integration-guide.md:8-15` documents a *verified* production
setup — controller advertising `ctrl.tdv.org`, BrowZer on `browzer.tdv.org:3022/3023`,
fresh-JWT minting confirmed — that exists nowhere in committed config, which
still ships `localtest.me` plus bare `ziti-router`. The working Ziti client
deployment is not reproducible from this repository.

**G-A6 (S4, S) — the Gradle wrapper jar is not checked in.**
`agent-android/README.md` requires `gradle wrapper --gradle-version 8.7` first;
CI sidesteps it with a pinned distribution. No human first-build is one command.

### Smallest fix

Add `assembleRelease` + a signing config + a release job that publishes the APK
and drops it at `deployments/android/openidx-agent.apk` (G-A1, G-A2) — this is
the highest-value single change in the audit, because it converts a well-designed
provisioning flow from non-functional to working. Then write down the
agent-vs-mobile division and either finish or delete the Expo module (G-A3, G-A4).

---

## 6. Cross-cutting

<a id="g-x1"></a>
### G-X1 (S2, S/M) — clients are gated off by default, invisibly

`ZITI_AGENT_OVERLAY_ENABLED` defaults to **false**
(`internal/access/agent_api.go`, `agentZitiOverlayEnabled()`), so enrolled agents
receive no Ziti identity and fall back to HTTPS. The default is well defended in
its comment — a `*.localtest.me` controller cannot complete a remote OTT
enrollment, and handing agents an unusable JWT surfaces a confusing
`crypto/rsa: verification error`. Given [G-R2](#g-r2), that caution is correct.

The problem is discoverability:

| Where an operator would look | Mentions the flag? |
|---|---|
| `.env.example` | ❌ (only `ZITI_PWD`, `ZITI_CONSOLE_URL`) |
| [`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) | ❌ |
| [`OPENIDX_ZITI_ARCHITECTURE.md`](./OPENIDX_ZITI_ARCHITECTURE.md) | ❌ |
| Network Setup checklist (`ziti_setup_handlers.go`) | ❌ |
| `docs/remote-support-runbook.md:157` | ✅ — the only mention |

Combined with G-X2, the result is that Network Setup can report **all required
steps complete** on a deployment where no client is on the overlay — and the
agent's `ResilientTransport` HTTPS fallback means nothing visibly breaks.

<a id="g-x2"></a>
### G-X2 (S4, S) — client readiness is structurally unmeasurable

In `buildSetupComponents` (`internal/access/ziti_setup_handlers.go`), the
`tunneler` component's `Required` field *is* dynamic —
`requiredIf(identityRoutes > 0 && browzerRoutes == 0)` — and `Detail`
interpolates the identity-route count. Only `Status` is the literal
`setupOptional`, where every sibling component calls `statusOf(...)`. So the
component already knows when a client is required; it simply cannot say
`action_needed`. Step 7 `client_access` is likewise `setupOptional` on every
non-BrowZer path, and the summary loop excludes optional steps from both the
counter and `Ready`:

```go
case setupOptional:
    // not counted
```

Nothing in the payload consults `enrolled_agents` or counts `Device`-type Ziti
identities, both already in the database. `TestBuildSetupComponents`
(`internal/access/ziti_setup_test.go`) asserts on controller / edge-router /
browzer / hop and never touches `tunneler`, so the gap is neither caught nor
protected — which also means the one-line `statusOf(...)` fix breaks nothing.

### G-X3 (S4, S) — SDK skew across the estate

| Component | SDK | channel |
|---|---|---|
| Backend (`go.mod:30,182`) | `sdk-golang v1.9.0` | `channel/v5 v5.0.10` |
| Windows agent (`agent/go.mod:10,82`) | `sdk-golang v1.7.0` | `channel/v4 v4.3.9` |
| Controller (compose / Helm) | pinned `1.6.12` | — |
| Android agent / Expo module | `ziti-android:0.30.0` / `0.30.+` | — |

[`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) itself warns that
"SDK↔controller skew has caused silent dial failures before — bump the tag and
the SDK together". The agent is two minor versions and a channel major behind
the backend.

### G-X4 (S4, S) — a widely-cited design spec is not in the repo

`docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md` is
referenced from `internal/common/config/config.go`,
`internal/access/enroll_handler.go`, `scripts/dark-mode.sh`,
`scripts/register-console-dark-app.sh` and the `Makefile`. The whole
`docs/superpowers/` tree is absent.

### G-X5 (S4, S) — the best Ziti document is unreachable from any install path

`docs/ziti-nat-firewall-requirements.md` is the strongest artifact in this area:
measured, honest about its own corrections, and it produces a concrete
NAT/firewall port list plus the exact command to check what a router advertises.
It is **Turkish-only** and is linked from none of the install docs.

### G-X6 (S4, S) — `install.cmd` at the repo root is not an OpenIDX installer

It is an unrelated Claude Code bootstrap script (it downloads from a
`claude-code-dist-*` GCS bucket). It sits at the root of a repository whose
install story is under audit, named exactly what someone looking for an installer
would try first.

---

## 7. Doc contradiction register

| Claim A | Claim B | Which is true |
|---|---|---|
| [`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md) §5: "The OpenIDX chart **deliberately does not** deploy the fabric; use upstream's charts next to it" | [`ZITI_HA_DEPLOYMENT.md`](./ZITI_HA_DEPLOYMENT.md): set `zitiFabric.enabled: true`, "what the chart does automatically…" — and `templates/ziti-fabric.yaml` exists | **B** describes what exists; A is stale. But B oversells it — see G-S5/G-S6 |
| `deployments/docker/ziti-router/config.yml`: `alt_server_certs` + `transport.ws` | `deployments/apisix-edge/ziti-router/README.md`: `alt_server_certs` ignored by WSS on v1.6.12; `transport.ws` rejected | **B** — measured on the pinned version |
| `config.yml`: "WSS hostnames must be in the CSR SANs" | apisix README: "`ziti router enroll` does **not** honor `edge.csr.sans`" | **B** |
| `scripts/ziti-quickstart.sh:94`: `make dev-docker` | `Makefile:225`: `dev` | **Makefile** |
| Pin-never-`:latest` in `values.yaml`, `docker-compose.yml`, `ZITI_HA_DEPLOYMENT.md` | `terraform/modules/openziti/variables.tf` + apisix README run command, both `:latest` | **pinning** |
| Advisor: "The OpenIDX Agent embeds a tunneler" | `agent/internal/ziti/dialer.go`: "No TUN driver / no elevation" | **dialer.go** |

---

## 8. Prioritized gap list

| # | ID | Surface | Gap | Sev | Effort |
|---|---|---|---|---|---|
| 1 | [G-A1](#g-a1) | Android | `deployments/android/` holds only `.gitkeep`; the served APK 404s and the QR checksum is unbuildable | S1 | S |
| 2 | G-A2 | Android | No signed release APK; no `signingConfig`; CI is debug-artifact-only | S1 | M |
| 3 | [G-R2](#g-r2) | Router | Router advertises `ziti-router` → **no off-host client can reach the data plane** | S3¹ | S |
| 4 | G-R1 | Router | No API to create an edge router / mint its JWT | S1 | M |
| 5 | G-S4 | Server | Terraform module installs a 2nd full `openidx` chart release | S1 | S |
| 6 | G-W2 | Windows | Stamped one-liner depends on unset, undocumented GitHub repo vars | S1 | S |
| 7 | G-R5 | Router | Remote/prod router is a hand-typed podman recipe under `apisix-edge/` | S1 | L |
| 8 | G-W4 | Windows | No MSI download endpoint; PS1 hardcodes a GitHub URL → air-gapped installs blocked | S1 | S |
| 9 | [G-X1](#g-x1) | Cross | Agents get no overlay identity by default; flag invisible to docs, env, checklist | S2 | S–M |
| 10 | G-W1 | Windows | Installer pins `ziti-router.localtest.me`; the router advertises `ziti-router` | S2 | S |
| 11 | G-S5 | Server | Helm router Deployment has no enrollment path; no `ZITI_PWD` Secret | S2 | M |
| 12 | G-S6 | Server | Helm Raft: one static advertised address across all replicas | S2 | M |
| 13 | G-R3 | Router | Dev BrowZer WSS uses the cert mechanism the operator README measured as broken | S2 | M |
| 14 | G-A4 | Android | Expo Ziti module is a 73-line stub; `dial()` throws; placeholder EAS projectId | S2 | M |
| 15 | G-W3 | Windows | Reusable enroll token stamped from a repo *variable* into a public release asset | S2 | S |
| 16 | G-S2 | Server | Prod compose: app points at `*.tdv.org`, controller still advertises `localtest.me` | S2 | S |
| 17 | G-S1 | Server | Controller advertised address hardcoded and PKI-permanent | S3 | M |
| 18 | G-A5 | Android | The only working topology is prose in a doc, not committed config | S3 | M |
| 19 | [G-S3](#g-s3) | Server | `ZITI_CTRL_PUBLIC_ADDRESS` implemented but set and documented nowhere | S3 | S |
| 20 | G-S7 | Server | Helm controller PVC at `/persistent` with no `ZITI_HOME` *(verify live)* | S3 | S |
| 21 | [G-X2](#g-x2) | Cross | `tunneler` `Status` pinned optional; optional steps excluded from `Ready` | S4 | S |
| 22 | [G-W5](#g-w5) | Windows | Agent is a per-service dialer, advertised as a tunneler | S4 | S |
| 23 | — | Windows | "Get the client" (`my-devices.tsx:291`) opens `openziti.io/downloads`; not OS-aware, no MSI/APK link | S4 | S |
| 24 | G-A3 | Android | Three Android narratives, no authoritative one; `mobile/README.md` is Expo boilerplate | S4 | S |
| 25 | G-A6 | Android | Gradle wrapper jar not checked in | S4 | S |
| 26 | G-W6/W7 | Windows | Installer requires admin and edits the hosts file by default | S4 | S |
| 27 | G-R4 | Router | `edge.csr.sans` comment teaches a model the operator README refutes | S4 | S |
| 28 | G-R6 | Router | `--tunneler-enabled` missing on a registered router is never detected | S4 | S |
| 29 | G-S8 | Server | Terraform image defaults `:latest` vs the repo-wide pinning rule | S4 | S |
| 30 | G-S9 | Server | Quickstart banner points at a nonexistent `make dev-docker` | S4 | S |
| 31 | G-S10 | Server | `scripts/doctor.sh` has no Ziti checks | S4 | S |
| 32 | G-X3 | Cross | SDK skew: backend v1.9.0/channel v5 vs agent v1.7.0/channel v4 | S4 | M |
| 33 | G-X4 | Cross | ~12 files cite a spec absent from the repo | S4 | S |
| 34 | G-X5 | Cross | The best Ziti doc is Turkish-only and unlinked from any install path | S4 | S |
| 35 | G-X6 | Cross | Root `install.cmd` is an unrelated Claude Code bootstrap script | S4 | S |

¹ Rated S3 by the ladder (works in dev, fails off-network) but it is the
**highest-leverage** item here: it is the shared cause of #10, most of §4, and
the reason #9's cautious default is correct.

### Suggested order

1. **G-R2** — make the router advertise a resolvable name. Nothing client-side
   can be validated until a client can reach the data plane; this unblocks #10
   and makes #9's default safe to flip.
2. **G-A1 + G-A2** — ship a signed release APK and publish it. Converts a
   well-designed provisioning flow from non-functional to working.
3. **G-X1 + G-X2** — surface `ZITI_AGENT_OVERLAY_ENABLED` and let the checklist
   fail on clients. Together these are the difference between a page that
   describes the fabric and one that describes the deployment.
4. **G-W4 + G-W2 + the "Get the client" link** — make "which client, from where"
   answerable inside the product.
5. **G-R1** — the router-create API, which unblocks multi-site deployments.
6. **G-S4, G-S5** — stop the Terraform module duplicating the product; either
   finish the Helm fabric or mark it experimental.

---

## 9. What "a well-defined one-command install" would require

Acceptance criteria, per surface — not a plan.

- **Server.** `make ziti-quickstart FQDN=ziti.example.com` produces a controller
  whose PKI, advertised address and `ZITI_CTRL_PUBLIC_ADDRESS` all agree, and
  `cmd/openidx doctor` reports the fabric reachable.
- **Router.** An operator adds a router from the console: the UI mints the JWT,
  shows one copy-pasteable `docker run`, and the new router appears online and
  correctly tagged without anyone touching the controller CLI.
- **Windows.** One signed installer, fetched from the OpenIDX deployment itself,
  that enrolls and then successfully dials a service — with the console stating
  plainly whether the user needs the OpenIDX Agent or Ziti Desktop Edge.
- **Android.** One documented app, built and signed by CI, published to
  `/downloads/openidx-agent.apk`, installable by scanning the Agent Fleet QR on a
  factory-reset device, ending in a device that dials over the overlay.
- **All four.** A CI job that performs one of these installs end-to-end and fails
  the build when it stops working. None exists today.

---

## Appendix A — What this audit did not cover

A live deployment; BrowZer end-to-end; the PAM broker tunneler
(`deployments/docker/pam-ziti-tunnel-entrypoint.sh`); iOS, macOS and Linux
clients; and the CI-over-overlay path
(`deployments/ci/azure-pipelines-ziti.yml`).

## Appendix B — Ziti file map

So the next pass need not re-derive it. ~409 files mention ziti.

**Backend core** (`internal/access/`, 46 dedicated `ziti_*` files): `ziti.go`
(~2.8k lines — the `ZitiManager`: mgmt-API client, bootstrap, PKI, identity and
service CRUD, policies, terminators, sessions, health), `ziti_reconciler.go`
(desired-state DB→controller loop; hosting modes `identity`/`direct`/`hop`),
`ziti_setup_handlers.go` (the readiness payload audited here),
`ziti_fabric{,_handlers}.go`, `ziti_handlers.go`, `ziti_user_sync.go`,
`ziti_sync_handlers.go`, `ziti_browzer{,_handlers}.go`, `ziti_hardening.go`
(circuit breakers, cert renewal), `ziti_settings{,_handlers}.go` (encrypted,
DB-persisted connection settings), `ziti_ai{,_handlers}.go`, `ziti_discovery.go`,
`ziti_explain.go`, `ziti_auth_handlers.go`, `pam_ziti.go`. Consumers:
`service.go` (route table), `agent_api.go`, `enroll_handler.go`, `posture.go`,
`kill_switch.go`, `feature_manager.go`, `health_checks.go`.

**Enrollment JWT flows** — three kinds: router JWT (compose init container /
`setup-router-wss.sh --enroll`); service-identity JWT
(`ensureAccessProxyIdentity` → `enrollIdentity`; PAM broker via
`pam-ziti-tunnel-entrypoint.sh`); end-user/device JWT (`CreateIdentity` →
`ziti_identities.enrollment_jwt`, distributed by `POST /api/v1/access/enroll` —
the one route that stays public when the platform goes dark —
`POST /agent/enroll{,/oauth}`, and `GET /ziti/identities/:id/enrollment-jwt`).
Freshness guards in `enroll_handler.go`: `enrollmentJWTExpired` and
`enrollmentJWTAddressStale`.

**Deployment** — `deployments/docker/docker-compose{,.prod,.ziti-ha,.pam-broker}.yml`,
`deployments/docker/ziti-router/`, `deployments/apisix-edge/ziti-router/`,
`deployments/kubernetes/helm/openidx/templates/ziti-fabric.yaml`,
`deployments/terraform/modules/openziti/`,
`deployments/ci/azure-pipelines-ziti.yml`,
`deployments/ci/setup-ci-overlay-access.sh`.

**Scripts** — `scripts/ziti-quickstart.sh`, `dark-mode.sh`, `dark-drill-live.sh`,
`service-dark-bind.sh`, `deploy-box.sh`, `mynetwork-score.sh`, `ci-overlay-score.sh`.

**Clients** — `agent/` (Go/Windows: `internal/ziti/dialer.go`,
`internal/transport/{ziti,resilient,factory}.go`, `internal/enrollment/enroll.go`,
`packaging/{wix,winget}`, `scripts/install-openidx-agent.ps1`);
`agent-android/` (Kotlin: `core/.../ZitiClient.kt`,
`app/.../enrollment/{OAuthEnrollmentFlow,QrEnrollmentBootstrapper}.kt`);
`mobile/modules/ziti/` (Expo module, iOS Swift + Android Kotlin — stub).

**Console** — `ziti-network.tsx` (~4.1k lines), `ziti-setup.tsx`,
`ziti-discovery.tsx`, `ziti-ai-insights.tsx`, `zero-trust.tsx`, `my-network.tsx`,
`my-devices.tsx`, `agent-fleet.tsx`, `browzer-management.tsx`, `proxy-routes.tsx`;
e2e under `web/admin-console/e2e/ziti-*.spec.ts`.

**Migrations** — `017_openziti.{up,down}.sql`, `029_ziti_enhanced.{up,down}.sql`,
`202503290001_enrolled_agents.up.sql`.

**Related docs** — [`OPENIDX_ZITI_ARCHITECTURE.md`](./OPENIDX_ZITI_ARCHITECTURE.md),
[`ZITI_EASY_DEPLOYMENT.md`](./ZITI_EASY_DEPLOYMENT.md),
[`ZITI_HA_DEPLOYMENT.md`](./ZITI_HA_DEPLOYMENT.md),
[`ziti-nat-firewall-requirements.md`](./ziti-nat-firewall-requirements.md),
[`mobile-openziti-integration-guide.md`](./mobile-openziti-integration-guide.md),
[`mobile-mfa-and-ziti-posture-access.md`](./mobile-mfa-and-ziti-posture-access.md),
[`ci-over-ziti-overlay.md`](./ci-over-ziti-overlay.md),
[`GOING_DARK_RUNBOOK.md`](./GOING_DARK_RUNBOOK.md),
[`remote-support-runbook.md`](./remote-support-runbook.md),
[`IAM_PAM_ZITI_INTERRELATION.md`](./IAM_PAM_ZITI_INTERRELATION.md).
