# OpenIDX - Open Source Zero Trust Access Platform

<p align="center">
  <img src="docs/images/openidx-logo.svg" alt="OpenIDX Logo" width="200"/>
</p>

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

OpenIDX is an open-source Zero Trust Access Platform (ZTAP) that unifies API gateway capabilities, AAA controls, identity management, and Zero Trust architecture. Built to compete with commercial solutions like Microsoft Entra ID, Okta, and Duo while offering **70-80% cost savings**.

### Why OpenIDX?

- 🔐 **Zero Trust Native** - Never trust, always verify
- 💰 **Cost Effective** - Fraction of commercial solution costs
- 🏛️ **Data Sovereignty** - Your data, your control
- 🔓 **No Vendor Lock-in** - Open standards, open source
- 🚀 **Modern Architecture** - Cloud-native, Kubernetes-ready

## Features

### Identity Management
- ✅ Single Sign-On (SSO) with OIDC/SAML/OAuth 2.0
- ✅ Multi-Factor Authentication (MFA)
- ✅ Directory Integration (LDAP, Active Directory)
- ✅ Social Login Providers
- ✅ Passwordless Authentication (WebAuthn/FIDO2)

### Access Control
- ✅ Role-Based Access Control (RBAC)
- ✅ Attribute-Based Access Control (ABAC)
- ✅ Policy-Based Access Control (PBAC)
- ✅ Just-in-Time (JIT) Access Provisioning
- ✅ Privileged Access Management (PAM)

### API Security
- ✅ API Gateway with Rate Limiting
- ✅ Request/Response Transformation
- ✅ JWT Validation & Token Exchange
- ✅ mTLS & Certificate Management

### Governance & Compliance
- ✅ Access Reviews & Certifications
- ✅ Audit Logging & SIEM Integration
- ✅ Compliance Reports (SOC2, ISO27001, GDPR)
- ✅ Risk-Based Authentication

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.22+
- Node.js 20+
- kubectl (for Kubernetes deployment)

### Local Development

```bash
# Clone the repository
git clone https://github.com/openidx/openidx.git
cd openidx

# Start infrastructure services
make dev-infra

# Start all services
make dev

# Access the admin console
open http://localhost:3000
```

### Docker Compose

```bash
# Start everything
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Kubernetes

```bash
# Add Helm repository
helm repo add openidx https://charts.openidx.io

# Install OpenIDX
helm install openidx openidx/openidx \
  --namespace openidx \
  --create-namespace \
  --values values.yaml
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Load Balancer                            │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway (APISIX)                        │
│              Rate Limiting • Auth • Routing                     │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────▼───────┐     ┌─────────▼─────────┐    ┌───────▼───────┐
│   Identity    │     │    Governance     │    │     Admin     │
│   Service     │     │     Service       │    │   Console     │
│  (Keycloak)   │     │      (Go)         │    │   (React)     │
└───────────────┘     └───────────────────┘    └───────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                   Policy Engine (OPA)                           │
│              RBAC • ABAC • Custom Policies                      │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      Data Layer                                 │
│         PostgreSQL • Redis • Elasticsearch                      │
└─────────────────────────────────────────────────────────────────┘
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

- [Getting Started Guide](docs/getting-started.md)
- [Architecture Overview](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Configuration Guide](docs/configuration.md)
- [Deployment Guide](docs/deployment.md)
- [Security Best Practices](docs/security.md)

## Roadmap

### Phase 1: Foundation (Months 1-3)
- [x] Core SSO functionality
- [x] Basic MFA support
- [x] Admin console MVP
- [ ] SCIM 2.0 provisioning

### Phase 2: Enterprise (Months 4-6)
- [ ] Advanced MFA (FIDO2, push)
- [ ] Directory sync
- [ ] Access reviews
- [ ] Risk-based authentication

### Phase 3: Governance (Months 7-9)
- [ ] Identity lifecycle management
- [ ] Automated provisioning
- [ ] Compliance reporting
- [ ] SIEM integration

### Phase 4: Intelligence (Months 10-12)
- [ ] AI-driven anomaly detection
- [ ] Predictive access analytics
- [ ] Automated policy recommendations
- [ ] Self-service portal

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

OpenIDX is licensed under the [Apache 2.0 License](LICENSE) for the core platform.

Enterprise features are available under the [Business Source License](LICENSE-BSL.md).

## Support

- 📖 [Documentation](https://docs.openidx.io)
- 💬 [Discord Community](https://discord.gg/openidx)
- 🐛 [Issue Tracker](https://github.com/openidx/openidx/issues)
- 📧 [Email Support](mailto:support@openidx.io)

---

<p align="center">
  Built with ❤️ by the OpenIDX Community
</p>
