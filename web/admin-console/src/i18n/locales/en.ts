// English catalog — the source of truth for translation keys. Other locales
// are typed against this object, so a missing or extra key fails type-check.
const en = {
  switcher: {
    label: 'Language',
  },
  landing: {
    nav: {
      features: 'Features',
      integrations: 'Integrations',
      documentation: 'Documentation',
      signIn: 'Sign In',
      getStarted: 'Get Started',
    },
    hero: {
      badge: 'Open source · Self-hosted · Apache-2.0',
      titleLead: 'Zero Trust Access Platform for',
      titleHighlight: 'Modern Enterprises',
      subtitle:
        'OpenIDX provides complete Identity and Access Management with SSO, MFA, access governance, privileged access, and Zero Trust networking — plus the audit and compliance reporting to prove it. Open source, self-hosted, enterprise-ready.',
      viewDocs: 'View Documentation',
      point1: '100% open source (Apache-2.0)',
      point2: 'Self-hosted — your data stays on your infrastructure',
      point3: 'Docker Compose quick start',
    },
    stats: {
      pillars: 'Pillars: IAM · IGA · PAM · ZTNA',
      services: 'Go Services',
      openSource: 'Open Source',
      darkPorts: 'Inbound Ports for Dark Services',
    },
    features: {
      title: 'Complete Security Platform',
      subtitle:
        'Everything you need to secure access to your applications, data, and infrastructure',
      zeroTrust: {
        title: 'Zero Trust Architecture',
        description:
          'Never trust, always verify. Every access request is fully authenticated, authorized, and encrypted before granting access.',
      },
      iam: {
        title: 'Identity & Access Management',
        description:
          'Centralized user provisioning, role-based access control, and lifecycle management for all your applications.',
      },
      mfa: {
        title: 'Multi-Factor Authentication',
        description:
          'TOTP, WebAuthn (passkeys and security keys), push approvals, and SMS or email one-time codes.',
      },
      sso: {
        title: 'Single Sign-On (SSO)',
        description:
          'One login to access all your applications with support for SAML, OIDC, and social identity providers.',
      },
      monitoring: {
        title: 'Real-time Monitoring',
        description:
          'Comprehensive audit logging, session monitoring, and security analytics with instant alerts.',
      },
      governance: {
        title: 'Compliance & Governance',
        description:
          'Automated access reviews, certification campaigns, and compliance reporting for SOC 2 and ISO 27001.',
      },
      gateway: {
        title: 'API Gateway & Security',
        description:
          'Powerful API gateway with rate limiting, IP allowlists, and OAuth 2.0 token validation.',
      },
      performance: {
        title: 'High Performance',
        description:
          'Stateless Go services built to scale horizontally, with health probes, graceful drains, and HA-ready deployment profiles.',
      },
    },
    integrations: {
      title: 'Integrates with Your Stack',
      subtitle:
        'Federate and provision over open standards — SAML 2.0, OIDC, SCIM 2.0, and LDAP',
    },
    cta: {
      title: 'Ready to Secure Your Access?',
      subtitle:
        'Run the complete IAM · IGA · PAM · ZTNA stack on your own infrastructure — one identity, one policy plane, one audit trail.',
      viewOnGitHub: 'View on GitHub',
    },
    footer: {
      tagline: 'Open source Zero Trust Access Platform for modern enterprises.',
      product: 'Product',
      project: 'Project',
      securityLegal: 'Security & License',
      apiReference: 'API Reference',
      issues: 'Issue Tracker',
      contributing: 'Contributing',
      changelog: 'Changelog',
      license: 'License (Apache-2.0)',
      securityPolicy: 'Security Policy',
      threatModel: 'Threat Model',
      complianceMapping: 'Compliance Mapping',
      copyright: '© {{year}} OpenIDX contributors. Apache-2.0 licensed.',
      sourceOnGitHub: 'Source on GitHub',
    },
  },
}

export default en
