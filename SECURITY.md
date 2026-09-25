# Security Policy

OpenIDX is maintained by a very small team (see [SUPPORT.md](SUPPORT.md)).
This page says how to report a vulnerability, what happens next, and what is
not on offer, so that nobody sends a report to a channel that does not exist.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest 1.x release | :white_check_mark: |
| Older 1.x releases | :x: upgrade to the latest release |
| 0.x | :x: |

Security fixes ship in the next release of the current line. They are not
backported to earlier 1.x releases. A long-term-support line is planned; see
[ROADMAP.md](ROADMAP.md).

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security
vulnerability.**

Report it privately through GitHub:

**[Report a vulnerability](https://github.com/mhmtgngr/openidx/security/advisories/new)**
(the "Report a vulnerability" button on the repository's **Security** tab).

This creates a private advisory that only you and the maintainers can see. We
use it to discuss the report, work on the fix, request a CVE and publish the
advisory. If the link does not work for you, open a public issue titled
"Security contact request". Put no details in it, and a maintainer will reach
out privately.

There is no security email address and no PGP key. Earlier versions of this
file listed addresses at `openidx.io`. That domain is not ours, and nothing
sent there reaches us.

### What to include

1. A description of the vulnerability and its impact.
2. Steps to reproduce, and a proof of concept if it is safe to share.
3. The affected version (`VERSION`, or the image tag) and deployment path
   (Docker Compose or the Helm chart).
4. Whether you have shared it with anyone else.

## What happens next

Handling is best effort. There is no service-level agreement.

- **Acknowledgement:** we aim to acknowledge a report within 7 days.
- **Assessment:** we confirm the issue, rate it with CVSS v3.1, and tell you
  what we plan to do.
- **Fix and release:** the fix ships in a release. The advisory, and a CVE
  where one applies, is published when that release is available.
- **Disclosure:** coordinated. We ask for up to 90 days from the report to a
  public disclosure, or less if a fix is released sooner. If we cannot meet
  that, we will say so in the advisory thread.
- **Credit:** reporters are credited in the advisory and the release notes,
  unless they prefer not to be.

There is **no bug bounty** and no paid reward for reports.

### Safe harbor

We will not pursue legal action against security research carried out in
good faith that:

- follows this reporting process,
- tests only against your own installation, or accounts you have explicit
  permission to use,
- does not access, modify or delete data that is not your own,
- does not degrade the performance or availability of anyone's service, and
- keeps the details private until the advisory is published.

### Severity

We use CVSS v3.1:

| Score | Severity | Typical example |
|-------|----------|-----------------|
| 9.0–10.0 | Critical | Remote code execution; a bypass of authentication or of the tenant boundary |
| 7.0–8.9 | High | Privilege escalation; access to another user's data |
| 4.0–6.9 | Medium | Limited impact, or requires user interaction |
| 0.1–3.9 | Low | Minimal impact, or hard to exploit |

### Vulnerabilities in dependencies

Report a vulnerability in a third-party dependency to that project, following
its own policy. If OpenIDX is affected, please also tell us through the private
report above so that we can track it.

## Advisories

The text of each advisory lives in
[docs/security/advisories/](docs/security/advisories/), one file per advisory,
named by a local ID such as `OPENIDX-2026-001`. The file gives the severity
with its CVSS v3.1 vector, the affected and patched versions, workarounds, and
how to check the fix.

Each one is published as a GitHub security advisory when the release that
carries its fix is available, as described under
[What happens next](#what-happens-next). The file then records the GHSA ID,
and the CVE where one applies.

## Receiving security updates

- **Watch** the repository with **Custom → Security alerts** selected.
- Published advisories are listed at
  [github.com/mhmtgngr/openidx/security/advisories](https://github.com/mhmtgngr/openidx/security/advisories).
- Every release lists its fixes in [CHANGELOG.md](CHANGELOG.md).

There is no security mailing list and no social-media channel.

## Trust model (multi-tenant, enforced at the database)

> Earlier revisions of this section said OpenIDX was single-tenant and that
> multi-tenant isolation was not implemented. **That is no longer true**.
> The tenant boundary landed in v1.6–v1.8. This section previously
> contradicted [docs/SECURITY-TENANCY.md](./docs/SECURITY-TENANCY.md), which
> is the authoritative trust-boundary document.

OpenIDX is **multi-tenant**: one deployment can serve many organizations,
and the isolation boundary is enforced in PostgreSQL, not in application
code alone.

- Every tenant-owned table carries an `org_id` and is protected by
  **FORCE row-level security**. The tenant is stamped onto each pooled
  connection at checkout (`internal/common/database/rls.go`). It is resolved
  per request from the subdomain, the JWT, or the `X-Org-ID` header. Access is
  **fail-closed**: no tenant context yields zero rows.
- A merge-blocking CI linter (`tools/orgscope`) fails the build on any
  tenant-table query missing an `org_id` predicate. Legitimate install-wide
  paths carry an audited `//orgscope:ignore` annotation.
- Within an organization, users holding an **`admin`** role can read and
  manage that organization's users, roles, groups, and configuration. RLS
  confines them to their own org. `super_admin` is platform-scoped. Treat
  both as fully privileged within their scope and grant them sparingly.
- The administrative API requires an admin role. This covers everything
  under `/api/v1/identity` except the caller's own `/users/me/*` and MFA
  self-service paths. Ordinary authenticated users can only manage their own
  account.
- Single-org deployments remain fully supported. They are simply a
  one-tenant instance of the same model.

See [docs/SECURITY-TENANCY.md](./docs/SECURITY-TENANCY.md) for the policy
SQL shape, known limitations (a small set of documented non-org-scoped
tables), and deployment topologies.

## Security best practices for deployment

The production hardening checklist lives in
**[docs/SECURITY-HARDENING.md](./docs/SECURITY-HARDENING.md)**. That file is
grounded in the code: every required item maps to a check in
`Config.ValidateProduction()`, which the service runs as a blocking startup
gate. Keeping the checklist and the validator in sync is part of the PR
checklist for any new gate.

The trust boundary is documented in
**[docs/SECURITY-TENANCY.md](./docs/SECURITY-TENANCY.md)**. Read it before
deploying OpenIDX in a setting where two unrelated organizations share one
installation.

For security reviewers and auditors:

- **[docs/THREAT-MODEL.md](./docs/THREAT-MODEL.md)** is the full platform
  threat model: trust boundaries, per-component STRIDE analysis (overlay,
  PAM broker, recordings, credential vault, audit chain), and the honest
  residual-risk and operator-obligation list.
- **[docs/COMPLIANCE-CONTROL-MAPPING.md](./docs/COMPLIANCE-CONTROL-MAPPING.md)**
  maps SOC 2 and ISO/IEC 27001:2022 criteria to OpenIDX capabilities, with
  evidence pointers. It also covers the project's own SDLC controls for
  vendor-risk reviews.
- OpenIDX has **not** yet had an independent penetration test or a
  third-party audit, and it has not run the OpenID Foundation conformance
  suite. These are planned; see [ROADMAP.md](ROADMAP.md). The scope for the
  penetration test is
  [docs/security/pentest-scope.md](./docs/security/pentest-scope.md).
- The [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/mhmtgngr/openidx)
  checks the repository's supply-chain practices every week
  (`.github/workflows/scorecard.yml`).

Thank you for helping keep OpenIDX secure.
