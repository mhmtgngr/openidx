# Compliance Control Mapping — SOC 2 & ISO/IEC 27001:2022

> **What this is:** a mapping from common audit criteria to the OpenIDX
> capability that satisfies them and the **evidence** an auditor can be
> shown. It exists so a customer running OpenIDX can answer "how does this
> platform support control X?" without reverse-engineering the code.
>
> **What this is not:** a certification. OpenIDX is self-hosted software —
> the *customer's* deployment gets audited, not this repository. Rows marked
> **Operator** are the customer's responsibility entirely; **Configurable**
> means the capability ships but must be enabled/configured; **Shared**
> means the platform provides the mechanism and the operator provides the
> process; **Provided** means the platform enforces it by default.
>
> Companions: [THREAT-MODEL.md](./THREAT-MODEL.md) (why these mechanisms
> exist), [SECURITY-HARDENING.md](./SECURITY-HARDENING.md) (the enforced
> production gates), [PROJECT-READINESS-GUIDE.md §5](./PROJECT-READINESS-GUIDE.md)
> (the recurring control checklists that *generate* much of the evidence
> below).

## Two lenses

1. **Product as control** (§1, §2): OpenIDX *is* the access-control,
   privileged-access, and logging control for the customer's environment.
   Most rows are this lens.
2. **Project SDLC** (§3): the controls this repository applies to its own
   development — what a customer's vendor-risk review of OpenIDX itself
   would ask about.

Evidence pointer conventions: `code:` a path in this repo; `ops:` a
recurring checklist item in the readiness guide §5 (run it, keep the
output — that output is the audit evidence); `doc:` a document; `ci:` a
workflow under `.github/workflows/`.

---

## 1. SOC 2 Trust Services Criteria

### Logical and physical access (CC6)

| Criterion | Requirement (abridged) | OpenIDX capability | Status | Evidence |
|---|---|---|---|---|
| **CC6.1** | Restrict logical access to authorized users; authenticate before granting access | OAuth2/OIDC provider (RS256, PKCE), MFA (TOTP, WebAuthn/FIDO2, push, SMS/email OTP), risk-based step-up (threat-list IPs force MFA), dark ZTNA services reachable only via authorized mTLS dials | Provided | code: `internal/oauth`, `internal/identity`, `internal/risk`; ops: §5.2 "MFA factors offered are deliverable"; doc: THREAT-MODEL.md §4.1, §4.4 |
| **CC6.1** (tenancy) | Segregate data of different entities | FORCE row-level security per `org_id`, fail-closed; merge-blocking `tools/orgscope` linter | Provided | code: `internal/common/database/rls.go`; ci: orgscope in Required Checks; doc: SECURITY-TENANCY.md |
| **CC6.2** | Register, authorize, and de-register users | Admin user lifecycle, SCIM 2.0 inbound provisioning, AD/LDAP directory sync, JIT provisioning; deactivation severs sessions | Provided | code: `internal/provisioning`, `internal/directory`; ops: §5.2 revocation drill |
| **CC6.3** | Modify/remove access based on roles; least privilege; segregation of duties | RBAC, group- and role-based app assignment (single predicate `internal/appaccess`), governance policies incl. **SoD** and time-bound access, access reviews with revoke propagation | Configurable (assignments must be curated; enforcement flag must be on — see convergence rollout) | code: `internal/appaccess`, `internal/governance`; ops: §5.2 four-surfaces agreement check; doc: `docs/plans/2026-08-30-access-and-login-convergence.md` |
| **CC6.4** | Physical access | Not in platform scope | Operator | — |
| **CC6.5** | Disposal of data/assets | Recording retention + legal hold; vault secret versioning; checkout expiry sweeper | Shared (DB/backup disposal is operator's) | code: `internal/access` recording retention, `internal/vault/sweeper.go` |
| **CC6.6** | Protect against threats from outside boundaries | APISIX edge, TLS, CSRF/CORS/security-header production gates, rate limiting; ZTNA removes public listeners entirely | Provided | code: `Config.ValidateProduction()`; doc: SECURITY-HARDENING.md; ops: §5.1 darkprobe |
| **CC6.7** | Restrict movement of information; protect during transmission | TLS at the edge and to the DB (gated), mTLS inside the Ziti overlay, short-lived access tokens, broker-side credential injection (secrets never transit to the end user) | Provided | doc: THREAT-MODEL.md §4.5, §5 assumptions |
| **CC6.8** | Prevent/detect unauthorized or malicious software | Device posture checks, Android Play Integrity verification, kiosk lockdown | Configurable | code: `internal/access/play_integrity.go`, posture APIs |

### System operations (CC7)

| Criterion | Requirement | OpenIDX capability | Status | Evidence |
|---|---|---|---|---|
| **CC7.1** | Detect configuration changes and vulnerabilities | `ValidateProduction()` blocks insecure boot configs; login-anomaly detection; (platform vulns: §3) | Provided | code: config gates; doc: SECURITY-HARDENING.md |
| **CC7.2** | Monitor for anomalies | Risk scoring on every login (IP threat list, geo, device, behavior), risk dashboard, login anomalies page, Prometheus metrics + health endpoints | Provided | code: `internal/risk`; ops: §5.2 platform checks |
| **CC7.3** | Evaluate security events | Unified, **HMAC-SHA256 chain-linked** audit events; streaming; compliance reports; Elasticsearch search | Provided | code: `internal/audit/logger.go` (`VerifyChain`); ops: §5.2 audit pipeline check |
| **CC7.4** | Respond to incidents | Per-user kill switch (IAM + PAM + Ziti severed together), session revocation with Redis markers, break-glass with mandatory reason, SIEM export via audit streaming | Shared (playbooks are operator's) | code: `internal/admin/sessions.go`, `internal/access/pam_checkout_control.go`; ops: §5.2 kill-switch drill |

### Change management (CC8), Availability (A1), Confidentiality (C1)

| Criterion | Requirement | OpenIDX capability | Status | Evidence |
|---|---|---|---|---|
| **CC8.1** | Authorize, test, approve changes | For the customer: config changes are admin actions in the audit chain. For the project: §3 | Shared | §3 below |
| **A1.2 / A1.3** | Backup, recovery, DR testing | `cmd/backup` CLI (backup/restore), `make dr-game-day` restore-verify drill; leader-gated background jobs tolerate multi-replica | Shared (schedules and offsite storage are operator's) | code: `cmd/backup`; ops: §5.1 DR drill |
| **C1.1 / C1.2** | Identify and protect confidential info; dispose per commitments | Vault envelope encryption (AES-256-GCM, HKDF per version, KEK rotation, optional OpenBao source), recording encryption at rest, retention + legal hold, step-up-gated reveals with recorded reasons | Provided | code: `internal/vault/crypto.go`, `internal/access/recording_crypto.go`; doc: THREAT-MODEL.md §4.6–4.7 |

---

## 2. ISO/IEC 27001:2022 Annex A

| Control | Title | OpenIDX capability | Status | Evidence |
|---|---|---|---|---|
| **5.15** | Access control | Policy-driven RBAC + app assignment; one predicate feeds portal display, proxy routes, and Ziti dial policies ("display == enforcement") | Configurable | code: `internal/appaccess`; ops: §5.3 invariant check |
| **5.16** | Identity management | Full lifecycle (create/disable/deprovision), SCIM, directory sync, JML via provisioning rules | Provided | code: `internal/provisioning`, `internal/directory` |
| **5.17** | Authentication information | Argon2id hashing (legacy bcrypt verified), password policy, seeded-credential **startup gate** in production, self-service reset with verified factors | Provided | code: `internal/common/pwhash`, `internal/identity/default_admin_gate.go` |
| **5.18** | Access rights | Assignment workflows, access requests + approvals, periodic **access reviews** with enforced revocation, time-bound grants | Configurable | code: `internal/governance`; ops: §5.2 review-revoke propagation |
| **5.28** | Collection of evidence | Tamper-evident audit chain + PAM session recordings with legal hold | Provided | code: `internal/audit`, recording legal hold |
| **5.33** | Protection of records | HMAC chain (integrity), Elasticsearch retention, recording encryption + retention | Shared | THREAT-MODEL.md §4.7–4.8 |
| **8.2** | Privileged access rights | PAM: vault checkout with reason + expiry + sweeper, JIT elevation via governance workflow, per-secret step-up MFA, SSH short-lived certificates (CA key vault-held), break-glass as distinct audited path, full session recording | Provided | code: `internal/vault`, `internal/access/ssh_ca.go`, `pam_*` |
| **8.3** | Information access restriction | FORCE RLS tenant wall; role-gated admin API; dark services | Provided | doc: SECURITY-TENANCY.md |
| **8.5** | Secure authentication | MFA incl. phishing-resistant WebAuthn; adaptive step-up; login feedback that doesn't leak account existence | Provided | code: `internal/identity`, `internal/oauth/mfa_policy.go` |
| **8.8** | Technical vulnerability management | (platform's own: §3); for target systems, posture checks inform access decisions | Shared | §3; posture APIs |
| **8.9** | Configuration management | `ValidateProduction()` refuses insecure production configs (secrets, CORS, CSRF, DB TLS); compose/env templates fail on unset secrets (`:?`) | Provided | code: config validation; doc: SECURITY-HARDENING.md |
| **8.10** | Information deletion | Recording retention windows; vault version disposal; checkout expiry | Shared | code: retention paths |
| **8.13** | Information backup | `cmd/backup` + restore-verify drill target | Shared | ops: §5.1 |
| **8.15** | Logging | Structured logs with CRLF scrubbing on attacker-influenced fields; unified audit events for security-relevant actions | Provided | code: `scrubLogValue` pattern; ci: CodeQL log-injection query |
| **8.16** | Monitoring activities | Prometheus metrics, health/readiness endpoints on all services, risk dashboards, audit streaming to SIEM | Configurable (operator must scrape + alert) | ops: §5.2 |
| **8.17** | Clock synchronization | Assumed from infrastructure (TOTP and token expiry depend on it) | Operator | THREAT-MODEL.md §5 assumptions |
| **8.24** | Use of cryptography | RS256 JWTs w/ JWKS, AES-256-GCM envelope encryption (vault + recordings) with HKDF-SHA256 derivation and rotating keyrings, TLS enforced to DB in prod, verified-TLS-only OpenBao fetch | Provided | code: `internal/vault/crypto.go`, `internal/access/recording_crypto.go`, `internal/vault/openbao.go` |
| **8.28** | Secure coding | §3 | Provided (project) | §3 |
| **8.32** | Change management | §3; customer-side config changes audited | Shared | §3 |

---

## 3. Project SDLC controls (vendor-risk lens)

What this repository enforces on itself — the answers to a customer's
vendor questionnaire about OpenIDX as a supplier:

| Control | Mechanism | Blocking? | Evidence |
|---|---|---|---|
| Static analysis | CodeQL (incl. log-injection, injection queries); Semgrep | CodeQL blocking | ci: `codeql.yml`, `security-scan.yml` |
| Dependency vulnerabilities | `govulncheck` at **symbol level**; Trivy scans; Dependabot/Renovate updates | govulncheck blocking (no `continue-on-error`) | ci: `security-scan.yml` |
| Secret leakage | Gitleaks in CI | Advisory (license-gated; documented in the workflow) | ci: `security-scan.yml` |
| Tenant boundary regression | `tools/orgscope` linter — any tenant-table query without an org predicate fails the build | Blocking | ci: Required Checks |
| Tests | Unit + integration (`test-integration`) + race detector across ~130 test files, testcontainers for real Postgres | Blocking | ci: `ci.yml` |
| Reviewability | All changes via PR against Required Checks; audit-relevant fixes land with tests that pin the behavior (e.g. revocation markers, step-up window, default-admin gate) | Blocking | repo history |
| Build provenance | Images built in CI with provenance + SBOM attestation; **binary signing is roadmap** (readiness guide P3) | Partial | ci: `docker.yml`, `release.yml` |
| Vulnerability disclosure | Security policy with response SLAs, safe harbor, bounty | — | doc: `SECURITY.md` |

---

## 4. Producing evidence for an audit

The readiness guide §5 checklists are designed to *be* the evidence
generator. For an audit period:

1. Run §5.1 (release gates) per release and archive the CI run links.
2. Run §5.2 (operational controls) monthly; keep the filled checklist —
   the revocation drill, kill-switch drill, four-surfaces agreement check,
   and audit-pipeline check map directly to CC6.2/CC7.4/CC6.3/CC7.3 above.
3. Export access-review outcomes from governance (5.18 / CC6.3).
4. Run the audit chain verification and archive the result (5.28 / CC7.3).
5. Keep the assignment report from before each enforcement change (5.15).

## 5. Keeping this mapping true

Re-verify a row whenever the capability behind it changes; the
[THREAT-MODEL.md](./THREAT-MODEL.md) change-triggers (§6) apply here too.
A row whose evidence pointer dangles is a defect — same contract as the
readiness guide §7. When OpenIDX gains a capability that upgrades a
**Shared**/**Configurable** row to **Provided** (e.g. signed binaries), flip
the row in the same PR.
