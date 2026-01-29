# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in OpenIDX, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email **security@openidx.io** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Disclosure Policy

- We will work with you to understand and validate the issue
- We will prepare a fix and coordinate disclosure timing
- We will credit reporters in the release notes (unless anonymity is requested)

## Security Best Practices for Deployment

- Change all default passwords and secrets before deploying to production
- Use TLS for all external-facing endpoints
- Enable MFA for all administrator accounts
- Review OPA policies and adjust to your organization's requirements
- Regularly rotate JWT signing keys and database credentials
- Enable audit logging and monitor for suspicious activity
- Keep all dependencies up to date
