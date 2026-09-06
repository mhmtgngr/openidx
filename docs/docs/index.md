# OpenIDX

**Open Source Zero Trust Access Platform**

OpenIDX unifies four capabilities that are usually four separate products —
**identity (IAM), governance (IGA), privileged access (PAM), and a zero-trust
network plane (ZTNA)** — in one self-hostable platform over one PostgreSQL
database. The IdP, the policy engine, the PAM broker, and the OpenZiti network
overlay share one control plane, so a single decision propagates end to end:
an access-review revoke or an admin kill switch severs the user's tokens,
sessions, vault checkouts, live privileged sessions, **and** network circuits.

New here? Start with **[Concepts](guide/concepts.md)** — one page that
explains how the four pillars fit together, and the glossary that keeps
them straight.

## The four pillars

| Pillar | The question it answers | What people experience |
|---|---|---|
| **IAM** | Who are you, and is it really you? | Login, MFA/passkeys, SSO into apps, sessions |
| **IGA** | Who approved that you have this, and for how long? | Access requests, approvals, reviews, SoD, JIT expiry |
| **PAM** | How do you borrow powerful credentials safely? | Vault checkout, brokered SSH/RDP in the browser, recorded sessions |
| **ZTNA** | How do you reach things with no public door? | Endpoint agent / BrowZer, dark services over OpenZiti |

## Feature highlights

- **OAuth 2.0 / OpenID Connect provider** — authorization code + PKCE, client credentials, refresh rotation, token exchange, JWKS rotation
- **SAML 2.0 IdP** — XML-DSig signing, SP metadata, Single Logout
- **MFA** — TOTP, WebAuthn/passkeys, push, hardware tokens; passwordless & magic-link
- **Adaptive authentication** — risk-scored logins (device, location, IP threat list) with step-up MFA
- **Directory sync & SCIM 2.0** — LDAP / Active Directory / Azure AD, users and groups
- **Governance** — access reviews, certification campaigns, approval workflows, fail-closed SoD, JIT elevation
- **Privileged access** — envelope-encrypted vault with rotation, brokered & recorded SSH/RDP/VNC, in-browser SSH, legal holds
- **Zero-trust network** — identity-driven dark services over OpenZiti, BrowZer clientless access, posture checks, cross-pillar kill switch
- **Multi-tenancy** — enforced at the database with PostgreSQL FORCE row-level security and a CI-enforced tenant linter
- **Audit & compliance** — tamper-evident HMAC hash-chain log, SIEM forwarding, SOC 2 / ISO 27001 / GDPR reporting

## Architecture at a glance

Eight Go services behind an APISIX gateway, one PostgreSQL (with FORCE RLS),
Redis, optional Elasticsearch, and an OpenZiti controller + router for the
network plane:

| Service | Port | Responsibility |
|---------|------|----------------|
| Identity Service | 8001 | Users, groups, sessions, MFA, federation, passwordless |
| Governance Service | 8002 | Access reviews, ABAC/OPA policies, certifications |
| Provisioning Service | 8003 | SCIM 2.0, provisioning rules |
| Audit Service | 8004 | Unified audit events, streaming, compliance reports |
| Admin API | 8005 | Aggregated admin surface behind the console |
| OAuth Service | 8006 | OAuth 2.0 / OIDC authorization server, SAML IdP |
| Gateway Service | 8088 | APISIX integration, proxy routes, app publishing |
| Access Service | — | Zero-trust access, OpenZiti, posture, PAM broker, agents |

See [Architecture](guide/architecture.md) for the full picture.

## Quick start

```bash
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Generate a .env with random secrets (compose refuses to start without them)
./scripts/generate-secrets.sh

# Start everything (compose files live under deployments/docker/)
docker compose -f deployments/docker/docker-compose.yml up -d
```

Then open `http://localhost:3000` and sign in with the seeded admin —
**`admin` / `Admin@123` — and rotate that password immediately**. In
production the identity and oauth services refuse to start while the
default still works.

The full stack is ~39 containers (Postgres, Elasticsearch, OpenZiti,
Guacamole, observability, 8 services…): plan on **≥ 8–10 GB RAM**.

Continue with the [Quick Start guide](guide/quickstart.md).

## Where to go next

- [Concepts — one product, four pillars](guide/concepts.md)
- [Privileged Access (PAM)](guide/privileged-access.md)
- [Zero Trust Network (ZTNA)](guide/network-access.md)
- [Deployment](deployment/docker.md)
- [API Reference](api/overview.md)
