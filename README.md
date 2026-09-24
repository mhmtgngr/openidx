# OpenIDX - Open Source Zero Trust Access Platform

<p align="center">
  <strong>Identity, governance, privileged access and zero-trust network access in one self-hosted control plane</strong>
</p>

<p align="center">
  <a href="#feature-maturity">Feature maturity</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

OpenIDX is an open-source Zero Trust Access Platform (ZTAP) that unifies four
capabilities that are usually four separate products — **identity (IAM),
governance (IGA), privileged access (PAM), and a zero-trust network plane
(ZTNA)** — in one self-hostable platform over one PostgreSQL database. It is
built to replace a stack of Microsoft Entra ID, Okta, SailPoint, CyberArk, and
Zscaler/NetFoundry. It is self-hosted and Apache-2.0, so what it costs is your
infrastructure and your operators rather than a per-user licence — what that
works out to against your current stack depends on your seat counts and
contracts, and nobody here has measured yours.

Because the IdP, the policy engine, the PAM broker, and the OpenZiti network
overlay share one control plane, a single decision propagates end-to-end: an
access-review revoke or an admin kill-switch severs the user's tokens, sessions,
vault checkouts, live privileged sessions, **and** network circuits in seconds —
not as a multi-connector integration project.

> **Multi-tenant, enforced at the database.** OpenIDX is tenant-scoped: every
> tenant-owned table carries an `org_id` and is protected by PostgreSQL **FORCE
> row-level security**, with the tenant stamped onto each pooled connection at
> checkout (`internal/common/database/rls.go`) and resolved per request from the
> subdomain, JWT, or `X-Org-ID` header. Access is **fail-closed** — no tenant
> context yields zero rows — and a merge-blocking CI linter (`tools/orgscope`)
> fails the build on any tenant-table query missing an `org_id` predicate. See
> [docs/SECURITY-TENANCY.md](./docs/SECURITY-TENANCY.md) for the trust boundary.
> One gap is open: the application's own database role can switch the
> row-level-security bypass on, so one SQL injection could lift the boundary
> ([#964](https://github.com/mhmtgngr/openidx/issues/964)).

### Why OpenIDX?

- 🧩 **Unified** - IAM + IGA + PAM + ZTNA in one platform, not four SKUs
- 🔐 **Zero Trust Native** - identity-driven dark services over OpenZiti; never trust, always verify
- 🏢 **Multi-Tenant** - FORCE row-level security with a CI-enforced tenant boundary
- 💰 **Cost Effective** - flat infrastructure cost vs per-user/per-identity pricing
- 🏛️ **Data Sovereignty** - fully self-hostable; your data, your infrastructure, your region
- 🔓 **No Vendor Lock-in** - open standards, Apache-2.0 core
- 🚀 **Modern Architecture** - Go services, React console, Kubernetes-ready

## Feature maturity

Each feature below has a maturity level, the reason for it, and the evidence.
[docs/MATURITY.md](docs/MATURITY.md) defines the levels and the rules for
changing one:

- **GA**: enforced, tested both ways, documented, used in production, and
  covered by the M1 verification.
- **Beta**: works and is tested, but is off by default or not externally
  verified.
- **Experimental**: partial, or has no runtime.

**No feature is GA yet.** GA needs the M1 verification: an OpenID Connect
conformance run ([#958]), SAML interop and SCIM compliance tests ([#955]), and
an independent penetration test ([#959]). None of these has run. "GA
candidate" marks a Beta feature that M1 is meant to verify. Each level was
checked against the code, the tests and the docs on `main` on 2026-09-24.

### Identity

| Feature | Level | Why | Evidence |
|---|---|---|---|
| OAuth 2.0 and OpenID Connect provider: authorization code with PKCE, refresh rotation, client credentials, token exchange, device flow, dynamic registration, per-application consent | Beta (GA candidate) | Works and is tested, also against the running services. No conformance run yet. | [OAUTH-OIDC.md](docs/OAUTH-OIDC.md), [`oauth_flow_test.go`](test/integration/oauth_flow_test.go), [#958] |
| SAML 2.0 identity provider | Beta (GA candidate) | Signs assertions with XML-DSig and serves metadata and single logout. Unit-tested; not yet tested against another SP. | [`saml_test.go`](internal/oauth/saml_test.go), [#955] |
| MFA: TOTP, WebAuthn and passkeys, push, SMS and email codes | Beta (GA candidate) | Each factor is tested. SMS, email and push need a provider you configure, and no delivery has been recorded on a live install. | [MFA guide](docs/MFA_IMPLEMENTATION_GUIDE.md), [operational controls][ops] |
| MFA policies | Beta | Required methods and a per-user grace period are enforced at password sign-in, tested both ways. Conditions are refused. | [display = enforcement][dee] |
| OATH hardware tokens | Experimental | Tokens can be registered and verified through the identity API, but sign-in does not accept them. FIDO2 security keys work, through WebAuthn. | [`hardware_token.go`](internal/identity/hardware_token.go) |
| Passwordless: magic link and QR sign-in | Beta | The organization and user settings are enforced; tested against the running services. | [`passwordless_test.go`](test/integration/passwordless_test.go) |
| Risk-based MFA and step-up | Beta | Risk-scored MFA at sign-in is on by default. The step-up gate for privileged actions (`STEPUP_GATE`) is off by default. | [configuration][cfg-gates], [`stepup_test.go`](test/integration/stepup_test.go) |
| Social sign-in and external identity providers | Experimental | The sign-in round trip has no test. A generic OIDC provider is called at Keycloak's endpoint paths, not through discovery, and a SAML provider can be configured but nothing signs a user in through it. | [`social_login.go`](internal/oauth/social_login.go) |
| Directory sync: LDAP and Active Directory | Beta | Scheduled user and group sync; referrals are followed, and a lost group loses its access. Tested against a fake directory. | [`ldap_referral_test.go`](internal/directory/ldap_referral_test.go) |
| Directory sync: Azure AD (Entra ID) | Experimental | The Microsoft Graph calls have no test; only the configuration and the routing are tested. | [`azure_ad.go`](internal/directory/azure_ad.go) |
| SCIM 2.0 server | Beta | Users and groups, with filters and PATCH; tested. No SCIM compliance run yet. | [SCIM.md](docs/SCIM.md), [#955] |
| Outbound SCIM | Beta | API only, with no console screen; tested. | [OUTBOUND_SCIM.md](docs/OUTBOUND_SCIM.md) |
| HR-driven joiner/mover/leaver | Beta | BambooHR only, and API only. Tested against a fake BambooHR. | [HR_DRIVEN_JML.md](docs/HR_DRIVEN_JML.md) |
| SSF/CAEP transmitter and receiver | Beta | API only. Tested, including delivery to receivers and tenant isolation. | [SSF_CAEP.md](docs/SSF_CAEP.md) |

### Governance and authorization

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Access requests, approvals, access reviews and certification campaigns | Beta | A review's revoke removes the role and ends the user's live token; this runs against the services in CI. | [`governance_loop_test.go`](test/integration/governance_loop_test.go) |
| Segregation of duties | Beta | Checked before a role is granted, and a sweep records the conflicts that already exist; tested. | [`sod_sweep_test.go`](internal/governance/sod_sweep_test.go) |
| Just-in-time elevation | Beta | A time-boxed role ends at its expiry and at the kill switch, tested both ways. | [display = enforcement][dee] |
| Roles (RBAC) and delegation to the whole organization | Beta | A role opens an admin route to a member and to no one else, tested both ways. A delegation grants its permissions across its own organization only; tested. | [display = enforcement][dee], [`delegation_tenant_isolation_test.go`](internal/common/middleware/delegation_tenant_isolation_test.go) |
| Application assignment as a grant | Beta | Enforced at `/oauth/authorize`, the access proxy and the Ziti dial on a fresh install, tested both ways. An existing install keeps its setting until the operator changes it. | [display = enforcement][dee], [configuration][cfg-gates] |
| ABAC | Beta | Tested in all three modes. A fresh install runs it in `observe`, and the operator turns on `enforce` ([#956]). | [display = enforcement][dee], [configuration][cfg-gates] |
| OPA authorization | Experimental | Off by default. The policy parses and its tests pass, but it has no rules yet for the end-user request pages, API keys, internal service calls or delegated permissions, and no observe mode. | [#980] |
| Delegation scopes narrower than the organization | Experimental | Not enforced, so the API refuses new ones. A delegation made before [#956] with such a scope still applies to the whole organization. | [`delegation_scope_test.go`](internal/admin/delegation_scope_test.go) |
| Lifecycle policies and workflows | Experimental | Each runs only when an administrator starts it. The schedule and the scheduled and webhook triggers that the console offers are stored, and nothing acts on them. | [`deprovisioning.go`](internal/admin/deprovisioning.go) |

### Privileged access (PAM)

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Credential vault | Beta (GA candidate) | Envelope encryption under a rotatable KEK. A reveal follows the grant and is audited, tested both ways. | [display = enforcement][dee], [OPENBAO_KEK.md](docs/OPENBAO_KEK.md) |
| Brokered SSH, RDP and VNC sessions through Guacamole | Beta (GA candidate) | Connect follows the grant, tested both ways, and the credential is injected on the server. A full session through guacd to a target has not been run in CI or recorded. | [privileged access guide][pam], [display = enforcement][dee] |
| Session recording | Beta | Encrypted at rest, sealed once, with retention and legal holds; tested. | [privileged access guide][pam] |
| Credential rotation | Beta | Eight connectors: SSH, SSH key, PostgreSQL, MySQL, AWS IAM, GCP service account, LDAP/AD and generate-only. The AWS and GCP tests run against fakes, not a real account. | [`shipped_types.go`](internal/credentials/shipped_types.go) |
| Privileged sessions only over the overlay | Beta | Off by default (`PAM_REQUIRE_ZTNA`); `observe` and `enforce` are tested. | [configuration][cfg-gates] |

### Zero-trust network (ZTNA)

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Dark services over OpenZiti | Beta (GA candidate) | The Dial policy the reconciler writes follows assignment, tested both ways against a fake controller. The overlay is optional in an install. | [display = enforcement][dee], [PUBLISHING_A_SERVICE.md](docs/PUBLISHING_A_SERVICE.md) |
| BrowZer clientless access | Beta (GA candidate) | The targets, routes and virtual hosts it needs are generated and tested. BrowZer itself is OpenZiti's component and is not tested here. | [network access guide](docs/docs/guide/network-access.md), [`browzer_targets_test.go`](internal/access/browzer_targets_test.go) |
| Device posture and device trust | Beta | Only a device's own credential may report its posture; tested. The gate that lets posture decide access (`POSTURE_DEVICE_TRUST_GATE`) is off by default. | [display = enforcement][dee], [`network_access_test.go`](test/integration/network_access_test.go) |
| Cross-pillar kill switch | Beta | Cuts tokens, sessions, vault checkouts, privileged sessions and overlay access; tested, and the leaver journey runs against the services in CI. No drill on a live install has been recorded. | [`kill_switch_test.go`](internal/access/kill_switch_test.go), [`leaver_test.go`](test/integration/leaver_test.go), [operational controls][ops] |

### Clients

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Windows endpoint agent | Beta | Its tests run in CI, also on a Windows runner. It is signed with the project's self-signed certificate, which Windows trusts only where you distribute it. | [agent/packaging/wix/README.md](agent/packaging/wix/README.md) |
| Mobile app (Flutter, Android and iOS) | Beta | Its tests run in CI. It cannot be published yet: the app ID is a placeholder, the released APK is debug-signed and the iOS build is unsigned. | [#966] |
| Desktop app (Flutter shell) | Experimental | The step that bundles the agent into it is not done. | [#966] |
| Android device-owner agent (Kotlin): enrollment, kiosk, remote support | Experimental | It has no tests and duplicates the Flutter app. On hold. | [ROADMAP.md](ROADMAP.md#on-hold), [#966] |

### Platform

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Multi-tenancy | Beta (GA candidate) | FORCE row-level security on every tenant table, tested in CI with a role that cannot bypass it. The bypass is a setting the application's role can change ([#964]). | [SECURITY-TENANCY.md](docs/SECURITY-TENANCY.md), [#964] |
| Audit trail and SIEM forwarding | Beta | Each tenant's events are HMAC-chained, and an edited or deleted row breaks the chain; tested. Elasticsearch search is optional. | [`audit_chain_test.go`](test/integration/audit_chain_test.go) |
| Compliance reports: SOC 2, ISO 27001, GDPR | Beta | Computed from the product's own data, tested against the migrated schema. They are evidence for an audit, not a certification. | [COMPLIANCE-CONTROL-MAPPING.md](docs/COMPLIANCE-CONTROL-MAPPING.md) |
| API keys and service accounts | Beta | Keys are stored as hashes, expire and can be revoked; tested. With OPA authorization on, a key is refused ([#980]). | [`apikeys_test.go`](internal/apikeys/apikeys_test.go) |
| Rate limiting and the API gateway | Beta | Per-route limits in the services and at the APISIX edge; tested. | [configuration][cfg-rate] |
| Service TLS and mTLS | Beta | A service asks for client certificates once it is given a CA; tested. Inter-service TLS is off in the Helm chart by default (`serviceTLS.enabled`). | [`tlsutil_test.go`](internal/common/tlsutil/tlsutil_test.go) |
| Admin console and end-user portal | Beta | English and Turkish. Unit tests run in CI, and 12 of the 50 browser specs run against a live stack. The refresh token is kept in `localStorage`, and there is no CSP yet ([#965]). | [`e2e/suite.txt`](web/admin-console/e2e/suite.txt), [#965] |
| AI-agent registry | Experimental | Agents and their credentials are stored, and nothing verifies the credentials, so no agent can act through it. | [`tablewriters/known.go`](tools/tablewriters/known.go) |
| Outbox and event relay | Experimental | The relay drains a table that nothing writes to. | [`outbox_has_producer_test.go`](internal/common/events/outbox_has_producer_test.go) |

### Install and operations

| Feature | Level | Why | Evidence |
|---|---|---|---|
| Docker Compose | Experimental | CI checks only that the quick start writes its secrets and that the compose file resolves; nothing starts the stack. The console is built from its development stage, and an outsider cannot reach a login ([#961]). | [`check-first-run.test.sh`](scripts/check-first-run.test.sh), [#961] |
| Helm chart | Beta | CI installs it on kind on every chart change. Image tags default to `latest`, and `values-prod.yaml` pins `v0.1.0`, a version no release has had ([#960]). | [Helm workflow](.github/workflows/helm.yml), [#960] |
| Terraform: AWS and Azure | Experimental | CI runs `fmt` and `validate`; neither root has been applied from this repository. | [operator guide §13][opguide-13] |
| Backup and restore | Experimental | `cmd/backup` wraps `pg_dump` and `pg_restore`, and only its encryption is tested. No restore has run in CI or been recorded on a live install ([#962]). | [disaster-recovery.md](docs/disaster-recovery.md), [#962] |
| Metrics, tracing and alerts | Beta | Every service exports metrics, and CI checks the chart's alert rules with `promtool`. No SLOs are defined ([#962]). | [operator guide §10][opguide-10] |
| Cells (multi-region) | Experimental | The functional half runs on kind in CI; no cell has carried traffic. On hold by [ADR 0001](docs/adr/0001-product-focus-and-trusted-core.md). | [operator guide §13][opguide-13] |

[dee]: docs/evidence/display-equals-enforcement.md
[ops]: docs/evidence/operational.md
[cfg-gates]: docs/docs/deployment/configuration.md#enforcement-gates
[cfg-rate]: docs/docs/deployment/configuration.md#rate-limiting
[pam]: docs/docs/guide/privileged-access.md
[opguide-10]: docs/docs/deployment/operator-guide.md#10-observability-and-the-alerts-that-matter
[opguide-13]: docs/docs/deployment/operator-guide.md#13-what-is-not-done-and-not-claimed
[#955]: https://github.com/mhmtgngr/openidx/issues/955
[#956]: https://github.com/mhmtgngr/openidx/issues/956
[#958]: https://github.com/mhmtgngr/openidx/issues/958
[#959]: https://github.com/mhmtgngr/openidx/issues/959
[#960]: https://github.com/mhmtgngr/openidx/issues/960
[#961]: https://github.com/mhmtgngr/openidx/issues/961
[#962]: https://github.com/mhmtgngr/openidx/issues/962
[#964]: https://github.com/mhmtgngr/openidx/issues/964
[#965]: https://github.com/mhmtgngr/openidx/issues/965
[#966]: https://github.com/mhmtgngr/openidx/issues/966
[#980]: https://github.com/mhmtgngr/openidx/issues/980

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.26+ and Node.js 20+ (only for building from source)
- kubectl + Helm (for Kubernetes deployment)
- **Hardware floor**: the full stack is ~39 containers (Postgres,
  Elasticsearch, OpenZiti, Guacamole, observability, 8 Go services…) —
  plan on **≥ 8–10 GB RAM** and 4+ cores for a complete single-box install.

### Docker Compose

This path is Experimental today (see
[Install and operations](#install-and-operations)): no CI job starts the
stack, and the compose file builds the console from its development stage.
[#961](https://github.com/mhmtgngr/openidx/issues/961) adds a lite install
that CI starts, and points this quick start at it.

```bash
# Clone the repository
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Generate a .env with random secrets (compose refuses to start without them)
./scripts/generate-secrets.sh

# Start everything (compose files live under deployments/docker/)
docker compose -f deployments/docker/docker-compose.yml up -d

# Watch it come up
docker compose -f deployments/docker/docker-compose.yml logs -f
```

Then open http://localhost:3000 and sign in with the seeded admin —
**`admin` / `Admin@123` — and rotate that password immediately** (see
[First Login](docs/GETTING-STARTED.md#1-first-login)). In production the
identity and oauth services refuse to start while the default still works.

For a production single-VM install, layer the hardened overlay:
`-f deployments/docker/docker-compose.yml -f deployments/docker/docker-compose.prod.yml`
(see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

### Local development (services on the host)

```bash
make dev-infra   # infrastructure only (Postgres, Redis, Elasticsearch…)
make dev         # or: full stack via the base compose file
```

### Kubernetes

Each tagged release publishes the Helm chart to GHCR as a cosign-signed
OCI artifact (chart version = release version; see the
[releases page](https://github.com/mhmtgngr/openidx/releases) for
available versions and [docs/RELEASING.md](docs/RELEASING.md) for
signature verification):

```bash
helm install openidx oci://ghcr.io/mhmtgngr/openidx/charts/openidx \
  --version <X.Y.Z> --namespace openidx --create-namespace
```

The chart runs database migrations itself (a post-install/pre-upgrade
hook Job) and deploys OPA with the policy it ships. The services consult
OPA only when OPA authorization is turned on, which is off by default
([#980](https://github.com/mhmtgngr/openidx/issues/980)). Read
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before using it. To install
from source instead, run `helm dependency update` first for the bundled
PostgreSQL/Redis/Elasticsearch:

```bash
helm install openidx ./deployments/kubernetes/helm/openidx \
  --namespace openidx --create-namespace \
  -f deployments/kubernetes/helm/openidx/values-prod.yaml
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway (APISIX)                        │
│              TLS • Rate Limiting • Routing • Auth               │
└─────────────────────────────────────────────────────────────────┘
                                │
   ┌───────────┬───────────┬────┴──────┬───────────┬───────────┐
   │           │           │           │           │           │
┌──▼───┐  ┌────▼────┐  ┌───▼────┐  ┌───▼───┐  ┌────▼────┐  ┌───▼────┐
│OAuth/│  │Identity │  │Governance│ │Provis.│  │  Audit  │  │ Access │
│ OIDC │  │ Service │  │ Service │  │(SCIM) │  │ Service │  │Service │
│(IdP) │  │ (MFA)   │  │(IGA·PAM)│  │       │  │         │  │(ZTNA)  │
└──┬───┘  └────┬────┘  └────┬────┘  └───┬───┘  └────┬────┘  └───┬────┘
   │           │            │           │           │          │
   └───────────┴────────────┼───────────┴───────────┘          │
                            │                                   │
              ┌─────────────▼─────────────┐        ┌────────────▼───────────┐
              │     Policy: RBAC • ABAC   │        │   OpenZiti overlay     │
              │    OPA: off by default    │        │  controller + router   │
              └─────────────┬─────────────┘        │  BrowZer · dark services│
                            │                       └────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│         Data Layer — one store, FORCE row-level security        │
│         PostgreSQL • Redis • Elasticsearch                      │
└─────────────────────────────────────────────────────────────────┘

Admin console + end-user portal: React (web/admin-console).
Native services in Go; no Keycloak — the IdP is OpenIDX's own OAuth/OIDC service.
```

## Project Structure

```
openidx/
├── cmd/                    # Application entrypoints
├── internal/               # Private application code
├── pkg/                    # Public libraries
├── api/                    # API definitions (OpenAPI, protobuf)
├── web/                    # Frontend applications
├── deployments/            # Deployment configurations
│   ├── docker/
│   ├── kubernetes/
│   └── terraform/
├── scripts/                # Build and utility scripts
├── docs/                   # Documentation
└── test/                   # Integration tests
```

## Documentation

- [Getting Started Guide](docs/GETTING-STARTED.md) — quick start and **first login**
- [Feature maturity levels](docs/MATURITY.md) — what GA, Beta and Experimental mean; the matrix itself is [above](#feature-maturity)
- [Roadmap](ROADMAP.md) — priorities, milestones, and what is on hold
- [Deployment Guide](docs/DEPLOYMENT.md) and the condensed [Operator Guide](docs/docs/deployment/operator-guide.md) — what to run, supply, verify, upgrade and watch, and what is not done
- [Zero Trust Architecture](docs/zero-trust-architecture.md) and [How Network Access Works](docs/how-network-access-works.md)
- [How IAM ⇄ PAM ⇄ Ziti Interrelate](docs/IAM_PAM_ZITI_INTERRELATION.md)
- [Zero Trust Network: Easy Ziti Deployment](docs/ZITI_EASY_DEPLOYMENT.md)
- [Security Hardening Checklist](docs/SECURITY-HARDENING.md) and [Tenancy Trust Boundary](docs/SECURITY-TENANCY.md)
- [API Reference](docs/api/README.md)

## Roadmap

**Current focus: milestone M1, "Trusted Core" (v2.0 LTS).** M1 adds no new
features. It covers secure defaults, conformance and interop testing in CI, an
independent penetration test, a lite install that runs in 15 minutes on 4 GB
of RAM, and releases that pin what actually runs. That verification is what
can move a feature in the [maturity matrix](#feature-maturity) to GA.
[ROADMAP.md](ROADMAP.md) has the product definition, the milestones and what
is deliberately on hold.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install dependencies
make deps

# Run tests
make test

# Run linters
make lint

# Build all services
make build
```

## License

OpenIDX is licensed under the [Apache 2.0 License](LICENSE). The entire platform
in this repository is Apache-2.0 today. A future commercial/open-core boundary
(for MSP orchestration, compliance packs, and enterprise support) may apply to
new buyer-tier features; the Apache-2.0 core is committed to staying Apache-2.0.

## Support

- 📖 [Documentation site](https://mhmtgngr.github.io/openidx); the sources are in [docs/](docs/README.md)
- 💬 [GitHub Discussions](https://github.com/mhmtgngr/openidx/discussions) for questions and ideas
- 🐛 [Issue Tracker](https://github.com/mhmtgngr/openidx/issues) for bugs and feature requests
- 🔒 Security vulnerabilities: report them privately, as described in [SECURITY.md](SECURITY.md). Never use a public issue
- 🤝 [Support policy](SUPPORT.md): where to ask, what to expect, and what is not on offer

---

<p align="center">
  Built with ❤️ by the OpenIDX Community
</p>
