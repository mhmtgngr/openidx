# OpenIDX

**Open Source Zero Trust Access Platform**

OpenIDX is an enterprise-grade Identity and Access Management (IAM) platform that provides OAuth 2.0, OpenID Connect, SAML 2.0, SCIM 2.0, Multi-Factor Authentication, and Identity Governance — all as open source software.

## Features

- **OAuth 2.0 / OpenID Connect** — Authorization code flow with PKCE, client credentials, refresh tokens
- **SAML 2.0** — Service Provider and Identity Provider support
- **SCIM 2.0** — Automated user and group provisioning
- **Multi-Factor Authentication** — TOTP, WebAuthn/FIDO2, Push notifications
- **Identity Governance** — Access reviews, certification campaigns, policy engine
- **Audit & Compliance** — SOC2, ISO 27001, GDPR, HIPAA, PCI-DSS reporting
- **Admin Console** — React-based management dashboard
- **API Gateway** — Centralized routing with Apache APISIX
- **Policy Engine** — Open Policy Agent (OPA) integration

## Architecture

OpenIDX follows a microservices architecture with 7 backend services:

| Service | Port | Description |
|---------|------|-------------|
| Identity Service | 8001 | User management, authentication, sessions, MFA |
| Governance Service | 8002 | Access reviews, policies, certifications |
| Provisioning Service | 8003 | SCIM 2.0, user lifecycle, directory sync |
| Audit Service | 8004 | Event logging, compliance reports, export |
| Admin API | 8005 | Dashboard, settings, application management |
| OAuth Service | 8006 | OAuth/OIDC authorization server |
| Gateway Service | 8080 | API routing, rate limiting |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/openidx/openidx.git
cd openidx

# Generate secrets
./scripts/generate-secrets.sh

# Start infrastructure
make dev-infra

# Start all services
make dev
```

Then open the Admin Console at [http://localhost:3000](http://localhost:3000).

## License

OpenIDX is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
