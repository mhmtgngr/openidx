# OpenIDX - Open Source Zero Trust Access Platform

<p align="center">
  <strong>Enterprise-grade Identity & Access Management for the Modern Era</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
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
Zscaler/NetFoundry at a fraction of the cost — a **70–80% saving** against the
stacked per-user pricing of those tools.

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

### Why OpenIDX?

- 🧩 **Unified** - IAM + IGA + PAM + ZTNA in one platform, not four SKUs
- 🔐 **Zero Trust Native** - identity-driven dark services over OpenZiti; never trust, always verify
- 🏢 **Multi-Tenant** - FORCE row-level security with a CI-enforced tenant boundary
- 💰 **Cost Effective** - flat infrastructure cost vs per-user/per-identity pricing
- 🏛️ **Data Sovereignty** - fully self-hostable; your data, your infrastructure, your region
- 🔓 **No Vendor Lock-in** - open standards, Apache-2.0 core
- 🚀 **Modern Architecture** - Go services, React console, Kubernetes-ready

## Features

### Identity & Access Management (IAM)
- ✅ Native OAuth 2.0 / OIDC provider (authorization code + PKCE, refresh rotation, client credentials, token exchange, JWKS with key rotation)
- ✅ SAML 2.0 Identity Provider (standards-compliant XML-DSig signing, SP metadata, SLO)
- ✅ Single Sign-On (SSO) with per-application consent
- ✅ Multi-Factor Authentication — TOTP, WebAuthn/passkeys, push, hardware tokens, email/SMS OTP
- ✅ Passwordless & magic-link authentication
- ✅ Adaptive / risk-based authentication with step-up
- ✅ Directory integration & sync (LDAP, Active Directory, Azure AD)
- ✅ SCIM 2.0 provisioning (users & groups, filtering, PATCH)
- ✅ Social / external IdP federation

### Identity Governance (IGA)
- ✅ Access reviews & certification campaigns
- ✅ Access-request & multi-step approval workflows
- ✅ Segregation-of-Duties (SoD) — preventive, enforced fail-closed
- ✅ Just-in-Time (JIT) elevation with automatic expiry
- ✅ Entitlement catalog, delegations, and lifecycle policies
- ✅ RBAC, ABAC, and OPA policy-based access control

### Privileged Access Management (PAM)
- ✅ Envelope-encrypted credential vault with KEK rotation
- ✅ Automated credential rotation (SSH, AWS IAM, GCP SA, Postgres, MySQL, LDAP)
- ✅ Brokered SSH/RDP/VNC sessions via Guacamole with server-side credential injection
- ✅ Session recording (encrypted at rest), transcripts, legal holds, retention
- ✅ Per-user broker identities and RDM-parity connection manager
- ✅ Privileged sessions over the OpenZiti overlay — targets have no inbound port

### Zero Trust Network (ZTNA over OpenZiti)
- ✅ Identity-driven "dark" services (no exposed inbound ports)
- ✅ BrowZer clientless browser access (no agent install)
- ✅ Desktop (Windows, signed) and mobile / Android endpoint agents with posture checks
- ✅ Desired-state reconciler syncing OpenIDX policy to the Ziti controller
- ✅ Cross-pillar kill switch: revoke tokens, sessions, vault checkouts, and network circuits in one action

### API Security & Platform
- ✅ APISIX API gateway with rate limiting
- ✅ JWT validation & OAuth 2.0 Token Exchange (RFC 8693)
- ✅ mTLS & certificate management
- ✅ Multi-tenancy with FORCE row-level security (CI-enforced)
- ✅ API keys & service-account authentication

### Governance & Compliance
- ✅ Tamper-evident audit log (HMAC hash-chain) with Elasticsearch search
- ✅ Audit logging & SIEM integration
- ✅ Compliance reports (SOC 2, ISO 27001, GDPR)
- ✅ Observability: Prometheus metrics, OpenTelemetry tracing, SLOs
- ✅ Automated backups with tested restore

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.25+ and Node.js 20+ (only for building from source)
- kubectl + Helm (for Kubernetes deployment)
- **Hardware floor**: the full stack is ~39 containers (Postgres,
  Elasticsearch, OpenZiti, Guacamole, observability, 8 Go services…) —
  plan on **≥ 8–10 GB RAM** and 4+ cores for a complete single-box install.

### Docker Compose (the supported quick start)

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

The Helm chart lives in-repo at `deployments/kubernetes/helm/openidx`
(no hosted chart repository yet) and currently expects you to run
migrations and provide OPA yourself — read
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before using it:

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
              │    Policy Engine (OPA)     │        │   OpenZiti overlay     │
              │   RBAC • ABAC • fail-closed │        │  controller + router   │
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
├── configs/                # Configuration files
├── scripts/                # Build and utility scripts
├── docs/                   # Documentation
└── test/                   # Integration tests
```

## Documentation

- [Getting Started Guide](docs/GETTING-STARTED.md) — quick start and **first login**
- [Project Readiness Guide](docs/PROJECT-READINESS-GUIDE.md) — the user-perspective state of the platform, next steps, and controls
- [Production Readiness](docs/PRODUCTION-READINESS.md) — can I deploy this, and how
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Zero Trust Architecture](docs/zero-trust-architecture.md) and [How Network Access Works](docs/how-network-access-works.md)
- [How IAM ⇄ PAM ⇄ Ziti Interrelate](docs/IAM_PAM_ZITI_INTERRELATION.md)
- [Zero Trust Network: Easy Ziti Deployment](docs/ZITI_EASY_DEPLOYMENT.md)
- [Security Hardening Checklist](docs/SECURITY-HARDENING.md) and [Tenancy Trust Boundary](docs/SECURITY-TENANCY.md)
- [API Reference](docs/api/README.md)

## Status & Roadmap

The core platform is built and self-hostable today. Shipped and working:

- [x] OAuth 2.0 / OIDC provider (PKCE, refresh rotation, token exchange, JWKS rotation)
- [x] SAML 2.0 IdP with standards-compliant XML-DSig signing
- [x] MFA — TOTP, WebAuthn/passkeys, push, hardware tokens; passwordless & magic-link
- [x] Adaptive / risk-based authentication with step-up
- [x] Per-application OAuth consent
- [x] Directory sync (LDAP / AD / Azure AD) and SCIM 2.0 provisioning
- [x] Access reviews, certification campaigns, approval workflows, enforced SoD
- [x] JIT elevation, credential vault with rotation, brokered & recorded PAM sessions
- [x] OpenZiti ZTNA plane — dark services, BrowZer clientless access, endpoint agents
- [x] Multi-tenancy (FORCE RLS), tamper-evident audit, backups, observability

Near-term focus areas: outbound SCIM provisioning to SaaS apps, HR-driven
joiner/mover/leaver, Ziti fabric-event ingestion into the audit pipeline,
per-org overlay scoping for MSP/multi-tenant deployments, and the agent-identity
substrate (dynamic client registration, MCP gateway).

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

- 📖 [Documentation](https://docs.openidx.io)
- 💬 [Discord Community](https://discord.gg/openidx)
- 🐛 [Issue Tracker](https://github.com/mhmtgngr/openidx/issues)
- 📧 [Email Support](mailto:support@openidx.io)

---

<p align="center">
  Built with ❤️ by the OpenIDX Community
</p>
