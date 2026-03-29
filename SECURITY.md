# Security Policy

## Supported Versions

OpenIDX follows semantic versioning. Security updates are provided for the following versions:

| Version | Supported          |
|---------|--------------------|
| 1.x.x   | :white_check_mark: |
| 0.x.x   | :x:                |

Security patches are released for the current major version (1.x). Previous major versions (0.x) are no longer supported.

## Reporting a Vulnerability

The OpenIDX team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Do NOT** open a public GitHub issue for security vulnerabilities.

Instead, please send an email to:

- **Email**: `security@openidx.io`
- **PGP Key**: Available at `https://openidx.io/security/pgp-key.txt`

### What to Include

To help us respond effectively, please include:

1. **Description**: A clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact**: The potential impact of the vulnerability
4. **Proof of Concept**: A working exploit or demonstration (if safe to share)
5. **Affected Versions**: Which versions are affected (if known)

### Response Timeline

Our team commits to the following response times:

| Severity Level | Initial Response | Resolution Target |
|----------------|------------------|-------------------|
| Critical       | 24 hours         | 48 hours          |
| High           | 48 hours         | 1 week            |
| Medium         | 72 hours         | 2 weeks           |
| Low            | 1 week           | Next release      |

### Disclosure Process

1. **Receipt**: We will acknowledge receipt of your report within the timelines above
2. **Validation**: Our security team will validate and investigate the vulnerability
3. **Resolution**: We will develop a fix and coordinate a release date with you
4. **Disclosure**: We will publicly disclose the vulnerability after a fix is released

We aim to coordinate public disclosure within 90 days of the initial report, or sooner if a fix is ready.

### Safe Harbor

OpenIDX pledges not to pursue legal action against security researchers who:

- Follow our responsible disclosure process
- Limit testing to their own accounts or accounts with explicit permission
- Do not access, modify, or delete data that is not their own
- Do not degrade system performance or availability
- Share details of the vulnerability only with our team

We will not pursue legal action if you act in good faith and comply with these guidelines.

### Bounty Program

OpenIDX offers a bounty program for qualifying vulnerability reports:

| Severity | Bounty Range |
|----------|--------------|
| Critical | $500 - $1,000 |
| High     | $200 - $500   |
| Medium   | $50 - $200    |
| Low      | $25 - $50     |

**Bounty Eligibility**:
- First report of a vulnerability
- Vulnerability must be reproducible
- Report must follow the disclosure process
- Vulnerability must not have been previously reported

Bounties are paid at our discretion and are subject to change without notice.

### Security Best Practices for Testing

When investigating potential vulnerabilities:

1. **Never** test on production systems without explicit permission
2. **Never** access another user's account or data
3. **Never** attempt to degrade system performance
4. **Always** use test environments when possible
5. **Document** your findings thoroughly

### Severity Classification

We use the CVSS v3.1 scoring system for classification:

| Score | Severity | Description |
|-------|----------|-------------|
| 9.0-10.0 | Critical | Remote code execution, full system compromise |
| 7.0-8.9 | High | Privilege escalation, data breach |
| 4.0-6.9 | Medium | Limited impact, requires user interaction |
| 0.1-3.9 | Low | Minimal impact, difficult to exploit |

### Security Features

OpenIDX includes the following security features:

- **Zero Trust Architecture**: All access requests are verified
- **Multi-Factor Authentication**: Support for TOTP, WebAuthn, and more
- **Role-Based Access Control**: Granular permissions management
- **Audit Logging**: Comprehensive logging of all security events
- **Encryption**: Data at rest and in transit encryption
- **Security Headers**: CSP, HSTS, and other security headers
- **Regular Updates**: Automated dependency updates and security patches

### Receiving Security Updates

To receive security notifications:

1. **Watch the Repository**: Enable "Custom" -> "Include security alerts"
2. **Subscribe to Announcements**: Join `security-announce@openidx.io`
3. **Follow on Social Media**: `@openidx_project` on Twitter

### Security Team

The OpenIDX security team can be reached at:

- **General Security**: `security@openidx.io`
- **PGP Key**: `https://openidx.io/security/pgp-key.txt`

For general inquiries, please contact `hello@openidx.io`.

### Related Resources

- [Security Advisories](https://github.com/openidx/openidx/security/advisories)
- [Security Policy](https://github.com/openidx/openidx/blob/main/SECURITY.md)
- [Contributing Guidelines](https://github.com/openidx/openidx/blob/main/CONTRIBUTING.md)
- [Code of Conduct](https://github.com/openidx/openidx/blob/main/CODE_OF_CONDUCT.md)

### Third-Party Disclosures

If you discover a vulnerability in a third-party dependency used by OpenIDX:

1. Report directly to the project maintainer following their security policy
2. CC `security@openidx.io` so we can track the issue
3. We will work with the upstream project to ensure a timely resolution

### License

By submitting a vulnerability report, you agree that your disclosure may be used by OpenIDX for security purposes, subject to our privacy policy and any applicable agreements.

---

## Security Best Practices for Deployment

### Pre-Deployment Checklist

- Change all default passwords and secrets before deploying to production
- Use TLS for all external-facing endpoints
- Enable MFA for all administrator accounts
- Review OPA policies and adjust to your organization's requirements
- Regularly rotate JWT signing keys and database credentials
- Enable audit logging and monitor for suspicious activity
- Keep all dependencies up to date

### Runtime Security

- Run services as non-root users
- Use read-only file systems where possible
- Implement resource limits (CPU, memory)
- Enable security scanning for Docker images
- Regular vulnerability scanning with Dependabot/Trivy

### Network Security

- Use API Gateway (APISIX) for all external traffic
- Implement network policies in Kubernetes
- Use TLS mutual authentication for service-to-service communication
- Configure firewall rules to limit inbound/outbound traffic

### Data Security

- Enable PostgreSQL transparent data encryption (TDE)
- Use Redis AUTH with strong passwords
- Encrypt sensitive configuration values
- Regular database backups with encryption

### Monitoring

- Enable audit logging for all security events
- Set up alerts for suspicious activity
- Regular security reviews of access logs
- Monitor for unusual login patterns or failed authentication attempts

---

Thank you for helping keep OpenIDX secure!
