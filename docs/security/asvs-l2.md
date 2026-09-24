# OWASP ASVS 4.0.3 Level 2 self-assessment

This is OpenIDX's own assessment of the platform against every Level 2
requirement of the [OWASP Application Security Verification Standard
4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3_release): 259
requirements in chapters V1 to V14. It is not an independent review. The
independent penetration test is scoped in [pentest-scope.md](pentest-scope.md).

- **Assessed:** 2026-09-24, on `main` at commit `586db11f`.
- **Scope:** the Go services, the admin console, the endpoint agent's update
  path, and the deployment defaults under `deployments/`. The Flutter client
  and the Android agent were looked at only where a requirement names them.
- **Method:** reading the code, configuration and CI workflows. Nothing was
  tested against a running deployment, and no scanner was run for this
  document.

## How to read the statuses

| Status | Meaning |
|---|---|
| Pass | The evidence named in the row was read in the code or configuration and meets the requirement. |
| Fail | The requirement is not met. The row says why. |
| Fail — reported privately | The gap is a vulnerability. Its details are in a private report under [SECURITY.md](https://github.com/mhmtgngr/openidx/blob/main/SECURITY.md) and will be published in an advisory once it is fixed. |
| N/A | The requirement does not apply, for the reason given. |
| Not assessed | Nobody has verified it yet. This is not a Pass. |

A Pass covers what its row names and nothing more. Where a row says
"not reviewed", the requirement is open.

## Summary

| Chapter | L2 requirements | Pass | Fail | of which reported privately | N/A | Not assessed |
|---|---:|---:|---:|---:|---:|---:|
| V1 Architecture, Design and Threat Modeling | 38 | 19 | 12 | 4 | 0 | 7 |
| V2 Authentication | 53 | 29 | 16 | 3 | 1 | 7 |
| V3 Session Management | 18 | 9 | 9 | 4 | 0 | 0 |
| V4 Access Control | 9 | 4 | 5 | 4 | 0 | 0 |
| V5 Validation, Sanitization and Encoding | 30 | 14 | 5 | 5 | 0 | 11 |
| V6 Stored Cryptography | 13 | 8 | 3 | 0 | 2 | 0 |
| V7 Error Handling and Logging | 12 | 6 | 3 | 1 | 0 | 3 |
| V8 Data Protection | 15 | 4 | 6 | 0 | 0 | 5 |
| V9 Communication | 7 | 2 | 1 | 0 | 0 | 4 |
| V10 Malicious Code | 5 | 2 | 1 | 1 | 0 | 2 |
| V11 Business Logic | 8 | 4 | 2 | 2 | 0 | 2 |
| V12 Files and Resources | 15 | 2 | 2 | 1 | 0 | 11 |
| V13 API and Web Service | 13 | 2 | 6 | 2 | 4 | 1 |
| V14 Configuration | 23 | 13 | 5 | 1 | 2 | 3 |
| **Total** | **259** | **118** | **76** | **28** | **9** | **56** |

### Failures

Reported privately, with no details here:

V1.2.2, V1.2.4, V1.4.1, V1.5.4, V2.2.2, V2.8.4, V2.8.5, V3.3.3, V3.4.5, V3.5.3, V3.7.1, V4.1.1, V4.1.2, V4.1.3, V4.2.1, V5.1.5, V5.2.1, V5.2.6, V5.3.1, V5.3.3, V7.3.3, V10.3.3, V11.1.4, V11.1.6, V12.6.1, V13.1.4, V13.2.1, V14.5.4.

Public failures:

- **V1.1.2** Threat modelling for every design change or sprint: no threat-modelling step per change.
- **V1.1.6** Security controls are centralised and reused, not duplicated: role gates, JWT validation and CORS are each implemented more than once.
- **V1.4.4** One well-vetted access control mechanism for all requests: authorization is split across several mechanisms.
- **V1.4.5** Feature or attribute checks, not only role names: most administrative routes check only a role name.
- **V1.6.2** Key material is protected with a key vault or API: keys come from environment variables unless OpenBao is configured.
- **V1.8.1** Sensitive data is identified and classified into protection levels: no data classification scheme.
- **V1.8.2** Each protection level has protection requirements: no protection levels, so no per-level requirements.
- **V1.9.2** Components verify the other side of each link: PostgreSQL `sslmode=require` passes the production gate without certificate verification.
- **V2.1.1** User passwords are at least 12 characters: minimum length is 8; the console's password policy setting is not enforced.
- **V2.1.2** Passwords of 64 characters are allowed and over 128 are refused: no maximum length.
- **V2.1.7** Passwords are checked against breached-password lists: the breached-password check is never called.
- **V2.1.8** A password strength meter is provided: no strength meter.
- **V2.1.9** No password composition rules: four character classes are required.
- **V2.1.12** The user can reveal the masked password: no control to reveal a masked password.
- **V2.2.3** Users are notified after changes to authentication details: no notification after credential or factor changes.
- **V2.4.5** An extra KDF iteration with a secret salt stored apart from the hashes: no secret salt (pepper).
- **V2.5.4** No shared or default accounts: the seeded `admin` account remains (its default password is refused in production).
- **V2.5.5** Users are notified when an authentication factor changes: no notification when a factor changes.
- **V2.5.6** Recovery uses a secure mechanism such as TOTP, push or an offline method: recovery is by emailed link only.
- **V2.8.2** OTP verification keys are highly protected (HSM or OS key store): TOTP secrets have no application-layer encryption.
- **V2.10.1** Service-to-service secrets are not static passwords or API keys: services use static passwords and keys.
- **V3.2.3** Browser tokens are stored only in secure cookies or sessionStorage: the console keeps tokens in localStorage.
- **V3.3.1** Logout and expiry invalidate the session, including for relying parties: access tokens stay valid for up to an hour after logout.
- **V3.3.2** Sessions require re-authentication periodically, when active and when idle: an actively used browser session never has to re-authenticate.
- **V3.3.4** Users can view and log out any or all of their sessions: no way to end a single session; no re-authentication.
- **V3.4.4** Session cookies use the __Host- prefix: cookies do not use the `__Host-` prefix.
- **V4.3.1** Administrative interfaces require MFA: administrators are not required to use MFA by default.
- **V6.1.1** Regulated private data (PII) is encrypted at rest: PII has no application-layer encryption.
- **V6.4.1** A secrets management solution creates, stores and destroys secrets: no secrets manager by default.
- **V6.4.2** Key material is used inside an isolated security module: keys are used in process memory.
- **V7.2.2** Access control decisions can be logged; failures are logged: 403s from the API role gates are not audited.
- **V7.4.1** Unexpected errors show a generic message: many handlers return internal error text.
- **V8.1.1** Sensitive data is not cached by load balancers or caches: no `Cache-Control: no-store`, including on token responses.
- **V8.2.1** Anti-caching headers keep sensitive data out of browser caches: no anti-caching headers.
- **V8.2.2** Browser storage holds no sensitive data: tokens in localStorage.
- **V8.3.1** Sensitive data travels in the body or headers, not the query string: the QR-login poll carries its token in the query string.
- **V8.3.4** Sensitive data is identified, with a policy for handling it: no data classification policy.
- **V8.3.6** Sensitive data in memory is overwritten when no longer needed: secrets are not zeroed after use.
- **V9.2.1** Server connections use trusted certificates; internal CAs are pinned: see V1.9.2.
- **V12.1.1** Large files that could exhaust storage are refused: the access service caps no request body.
- **V13.1.3** API URLs expose no keys or session tokens: see V8.3.1.
- **V13.1.5** Unexpected or missing content types are rejected (406, 415): content types are not checked.
- **V13.2.2** JSON schema validation before input is accepted: no JSON Schema validation.
- **V13.2.5** REST services check the incoming Content-Type: content types are not checked.
- **V14.3.3** Responses do not expose detailed version information: APISIX's default `Server` header shows its version.
- **V14.4.2** API responses carry Content-Disposition: attachment: no Content-Disposition on API responses.
- **V14.4.3** A Content-Security-Policy is in place: the console is served without a CSP.
- **V14.5.1** Only used HTTP methods are accepted; invalid ones are logged or alerted: invalid methods are not logged or alerted on.

### Important items not assessed

- **V7.1.1**: whether any path writes credentials or session tokens to logs.
- **V9.1.2**: no TLS scanner has been run against a deployment.
- **V14.4.5**: HSTS depends on the edge in front of the services.
- **V2.7.3**: whether a one-time code is bound to the sign-in that requested it.
- **V5.1.3**: input validation coverage across handlers.
- **V1.12.2, V12.1.2 to V12.5.2**: upload and download handling was not reviewed.
- **V8.3.2**: whether data-subject requests lead to export and erasure.
- **V10.2.1**: phone-home behaviour of third-party libraries.
- **V10.2.2**: whether the Android agent needs each permission it requests.
- **V1.6.1**: no key-management policy was checked against NIST SP 800-57.

## V1 Architecture, Design and Threat Modeling

### V1.1 Secure Software Development Lifecycle

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.1.1 | A secure development lifecycle covers every stage | Pass | `docs/AI-WORKING-AGREEMENT.md` (security-critical paths need maintainer approval; two-sided tests; definition of done), `CONTRIBUTING.md` (DCO, `make guards`), CI gates in `.github/workflows/ci.yml`, `.github/workflows/codeql.yml` and `.github/workflows/security-scan.yml`. Changes are reviewed by one maintainer. |
| V1.1.2 | Threat modelling for every design change or sprint | Fail | A platform threat model exists (`docs/THREAT-MODEL.md`, with re-check triggers in §6), but no per-change threat-modelling step is required: `.github/pull_request_template.md` has no such item. |
| V1.1.3 | User stories carry functional security constraints | Not assessed | The definition of done asks for a negative test for every control (`docs/AI-WORKING-AGREEMENT.md` §3). Issues and stories were not sampled. |
| V1.1.4 | Trust boundaries, components and data flows are documented | Pass | `docs/THREAT-MODEL.md` §1 (diagram and trust-boundary table TB1 to TB6), `docs/SECURITY-TENANCY.md`. |
| V1.1.5 | High-level architecture and connected services are analysed | Pass | `docs/THREAT-MODEL.md` §4 (STRIDE per component) and §5 (residual risks). |
| V1.1.6 | Security controls are centralised and reused, not duplicated | Fail | Several controls exist more than once: role gates per service (`internal/admin/handler.go`, `internal/identity/service.go`, `internal/access/ziti_settings_handlers.go`), two JWT validators (`internal/common/middleware/middleware.go` and the identity service's own), two CORS middlewares (`internal/common/middleware/middleware.go`, `internal/middleware/cors.go`). |
| V1.1.7 | A secure coding checklist or guideline is available | Pass | `docs/AI-WORKING-AGREEMENT.md`, `CONTRIBUTING.md`, `docs/SECURITY-HARDENING.md`. |

### V1.2 Authentication Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.2.1 | Components run as unique low-privilege OS accounts | Pass | Service images switch to a non-root user (`USER openidx` in `deployments/docker/Dockerfile.identity-service` and the other service Dockerfiles). The database runtime role `openidx_app` does not own the tables (`docs/SECURITY-TENANCY.md` §2). |
| V1.2.2 | Communication between components is authenticated, least privilege | Fail — reported privately | Details reported privately under SECURITY.md. |
| V1.2.3 | One vetted authentication mechanism, extensible to strong auth, logged | Pass | The OAuth 2.0/OIDC service (`internal/oauth`) issues RS256 tokens that the other services verify against its JWKS (`internal/common/middleware/middleware.go`). MFA is available. Sign-in outcomes are audited (`internal/identity/service.go`, `user.login_succeeded` and `user.login_failed`). |
| V1.2.4 | All authentication paths have consistent strength | Fail — reported privately | Details reported privately under SECURITY.md. |

### V1.4 Access Control Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.4.1 | Access control is enforced at trusted server-side points | Fail — reported privately | Details reported privately under SECURITY.md. |
| V1.4.4 | One well-vetted access control mechanism for all requests | Fail | Authorization is split across role gates written per service (see V1.1.6), an optional OPA layer (`ENABLE_OPA_AUTHZ`, off by default), the assignment predicate in `internal/appaccess` and row-level security. RLS is the one layer every tenant query passes through. |
| V1.4.5 | Feature or attribute checks, not only role names | Fail | A permission model exists (`middleware.PermissionResolver`, `RequirePermission`), and ABAC runs in observe mode by default, but most administrative routes check only the role name `admin` or `super_admin`. |

### V1.5 Input and Output Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.5.1 | Input and output handling requirements are defined per data type | Not assessed | No such specification was found; not searched exhaustively. |
| V1.5.2 | No serialization with untrusted clients, or it is integrity-protected | Pass | Clients exchange JSON (and SAML XML) decoded into typed structs. No native object serialization was found on the network path. |
| V1.5.3 | Input validation runs on a trusted service layer | Pass | Validation happens in the Go handlers (request binding, `internal/common/validation`), not only in the console. |
| V1.5.4 | Output encoding happens close to the interpreter | Fail — reported privately | Details reported privately under SECURITY.md. |

### V1.6 Cryptographic Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.6.1 | Key management policy follows a standard such as NIST SP 800-57 | Not assessed | Key rotation is described in `docs/OPENBAO_KEK.md` and the readiness guide; no single key-management policy was checked against SP 800-57. |
| V1.6.2 | Key material is protected with a key vault or API | Fail | OpenBao can supply the vault KEK (`internal/vault/openbao.go`), but it is optional; by default keys and secrets come from environment variables (`docs/THREAT-MODEL.md` residual risk R1). |
| V1.6.3 | Keys and passwords are replaceable, with a re-encryption process | Pass | Keyrings with key ids for the vault and recordings (`internal/vault/crypto.go`, `internal/access/recording_crypto.go`), re-encryption tool `cmd/rekey`, signing-key rotation in `internal/signingkeys`. |
| V1.6.4 | Client-side secrets are treated as insecure | Not assessed | The console is a public PKCE client with no secret. The mobile and desktop clients were not reviewed. |

### V1.7 Errors, Logging and Auditing Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.7.1 | A common logging format is used across the system | Pass | Structured zap logging through `internal/common/logger` in every service; unified audit events in `internal/audit`. |
| V1.7.2 | Logs are sent securely to a remote system | Not assessed | A SIEM forwarder exists (`AUDIT_SIEM_ENABLED`, off by default). Its transport security was not checked. |

### V1.8 Data Protection and Privacy Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.8.1 | Sensitive data is identified and classified into protection levels | Fail | `docs/THREAT-MODEL.md` §2 lists assets, but there is no classification scheme with protection levels. |
| V1.8.2 | Each protection level has protection requirements | Fail | Follows from V1.8.1: no protection levels are defined. |

### V1.9 Communications Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.9.1 | Communication between components is encrypted | Pass | In production `Config.ValidateProduction()` (`internal/common/config/config.go`) refuses to start without TLS for inter-service HTTP, PostgreSQL and Redis. |
| V1.9.2 | Components verify the other side of each link | Fail | Redis and the Ziti controller must verify certificates in production, but PostgreSQL passes the production gate with `sslmode=require`, which encrypts without verifying the server certificate (`internal/common/config/config.go`). |

### V1.10 Malicious Software Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.10.1 | Source control with traceable, access-controlled changes | Pass | GitHub pull requests, a DCO sign-off on every commit (`scripts/check-dco.sh`), `.github/CODEOWNERS`. |

### V1.11 Business Logic Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.11.1 | All components are documented with their business or security function | Pass | `docs/THREAT-MODEL.md` §1 and §4, `docs/architecture`. |
| V1.11.2 | High-value flows do not share unsynchronized state | Not assessed | Several single-use credentials are claimed atomically (see V11.1.6); the flows were not reviewed as a whole. |

### V1.12 Secure File Upload Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.12.2 | User-uploaded files are served as downloads or from another domain, with CSP | Not assessed | Upload and download paths were not reviewed. |

### V1.14 Configuration Architecture

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V1.14.1 | Components of different trust levels are segregated | Pass | APISIX edge, Kubernetes NetworkPolicies (`deployments/kubernetes/helm/openidx/templates/networkpolicy.yaml`), dark services on the OpenZiti overlay. |
| V1.14.2 | Binaries deployed to remote devices are signed and verified | Pass | The endpoint agent installs an update only after checking the manifest signature against a pinned publisher and the artifact's SHA-256 (`agent/internal/updater/trust.go`, `agent/internal/updater/updater.go`). |
| V1.14.3 | The build pipeline warns of outdated or insecure components | Pass | govulncheck (blocking) in `.github/workflows/ci.yml`; Trivy in `.github/workflows/security-scan.yml`; Renovate (`renovate.json`). |
| V1.14.4 | The pipeline builds and verifies the secure deployment automatically | Pass | CI renders and tests the Helm chart (`.github/workflows/helm.yml`); services refuse insecure production configuration at startup (`internal/common/config/config.go`). |
| V1.14.5 | Deployments sandbox, containerize or isolate components | Pass | Non-root containers, NetworkPolicies, and an isolated PAM broker segment (`docs/THREAT-MODEL.md` §4.5, operator obligation R3). |
| V1.14.6 | No unsupported client-side technologies (Flash, ActiveX, applets) | Pass | The console is a React single-page application (`web/admin-console`). |

## V2 Authentication

### V2.1 Password Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.1.1 | User passwords are at least 12 characters | Fail | The minimum is 8 (`internal/identity/passwords.go`, `ValidatePasswordPolicyChecks`). The password policy in the console settings (seeded with `min_length` 12) is not read by this check, and invitation acceptance hashes the chosen password without running it (`internal/identity/service.go`, `handleAcceptInvitation`). |
| V2.1.2 | Passwords of 64 characters are allowed and over 128 are refused | Fail | Long passwords are accepted, but no maximum is enforced. |
| V2.1.3 | Passwords are not truncated | Pass | New hashes are Argon2id, which has no length limit (`internal/common/pwhash/pwhash.go`). Legacy bcrypt hashes (72-byte limit) are replaced at the next sign-in. |
| V2.1.4 | Any printable Unicode character is allowed in passwords | Pass | The policy check classifies characters but rejects none (`internal/identity/passwords.go`). |
| V2.1.5 | Users can change their password | Pass | `POST /api/v1/identity/users/me/change-password` (`internal/identity/service.go`, `handleChangePassword`). |
| V2.1.6 | Password change requires the current and the new password | Pass | `handleChangePassword` verifies the current password before setting the new one. |
| V2.1.7 | Passwords are checked against breached-password lists | Fail | `CheckCompromisedPassword` (HIBP k-anonymity) exists in `internal/identity/passwords.go`, but nothing calls it at registration, sign-in or password change. |
| V2.1.8 | A password strength meter is provided | Fail | None in the console's password forms (`web/admin-console/src/pages/reset-password.tsx`, `web/admin-console/src/pages/user-profile.tsx`). |
| V2.1.9 | No password composition rules | Fail | Upper case, lower case, a digit and a special character are required (`internal/identity/passwords.go`). |
| V2.1.10 | No periodic rotation or password-history requirements | Pass | `CheckPasswordExpiry`, `CheckPasswordExpiration` and `CheckPasswordHistory` exist but nothing calls them, so no rotation is enforced by default. The console settings still show a 90-day maximum age and a history of 5, which are not enforced. An administrator can create a `password_expiry_enforcement` lifecycle policy that disables or deletes accounts with old passwords (`internal/admin/deprovisioning.go`); none exists by default. |
| V2.1.11 | Paste, browser password helpers and password managers are allowed | Pass | The console's sign-in form uses `autocomplete="current-password"` and blocks no paste (`web/admin-console/src/pages/login.tsx`). |
| V2.1.12 | The user can reveal the masked password | Fail | No reveal control in `web/admin-console/src/pages/login.tsx` or the password-change forms. |

### V2.2 General Authenticator Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.2.1 | Anti-automation limits credential testing to 100 failures an hour per account | Pass | Five failures lock the account for 15 minutes by default, counted atomically in the database (`internal/identity/service.go`, `lockoutPolicy` and `recordFailedLogin`); rate limits at the edge and in `internal/common/middleware/ratelimit.go`. |
| V2.2.2 | Weak authenticators (SMS, email) are secondary only | Fail — reported privately | Details reported privately under SECURITY.md. |
| V2.2.3 | Users are notified after changes to authentication details | Fail | No notification is sent for a password change or reset, a factor change, or a risky sign-in. `internal/notifications/catalogue.go` lists what is sent, and none of these is on it. |

### V2.3 Authenticator Lifecycle

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.3.1 | Initial passwords and activation codes are random, short-lived, not long-term | Pass | Invitation tokens are random UUIDv4 values that expire in 7 days and are claimed once; reset tokens are 32 random bytes that expire in 1 hour (`internal/identity/service.go`). The user chooses the password. |
| V2.3.2 | User-provided authenticators such as FIDO tokens are supported | Pass | WebAuthn and passkeys through go-webauthn (`internal/identity/webauthn.go`). |
| V2.3.3 | Renewal instructions are sent for time-bound authenticators | Not assessed | Not reviewed. |

### V2.4 Credential Storage

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.4.1 | Passwords are stored with an approved salted KDF | Pass | Argon2id, m=19 MiB, t=2, p=1 (`internal/common/pwhash/pwhash.go`). |
| V2.4.2 | Salts are at least 32 bits, random, unique per credential | Pass | 16 random bytes per hash from `crypto/rand` (`internal/common/pwhash/pwhash.go`). |
| V2.4.3 | PBKDF2 uses at least 100,000 iterations | N/A | PBKDF2 is not used for stored passwords. It appears only in the SCRAM client that authenticates to upstream databases (`internal/access/dbproxy/scram.go`). |
| V2.4.4 | bcrypt uses a work factor of at least 10 | Pass | bcrypt is verified only for legacy password hashes, which are rehashed with Argon2id at sign-in. One-time codes use cost 12 (`internal/identity/passwords.go`, `bcryptCost`). |
| V2.4.5 | An extra KDF iteration with a secret salt stored apart from the hashes | Fail | No pepper or secret salt is used (`internal/common/pwhash/pwhash.go`). |

### V2.5 Credential Recovery

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.5.1 | Recovery secrets are not sent in clear text | Pass | Recovery sends a single-use reset link, not a password (`internal/identity/service.go`, `handleForgotPassword`). |
| V2.5.2 | No password hints or secret questions | Pass | None found in `internal/identity` or the console. |
| V2.5.3 | Recovery does not reveal the current password | Pass | Recovery only sets a new password. |
| V2.5.4 | No shared or default accounts | Fail | Migration v10 seeds `admin` with a published password. In production the identity and OAuth services refuse to start while it still authenticates with that password (`internal/identity/default_admin_gate.go`), but the account itself remains. |
| V2.5.5 | Users are notified when an authentication factor changes | Fail | Factor changes are audited (for example `mfa.totp_enrolled`) but the user is not notified. See V2.2.3. |
| V2.5.6 | Recovery uses a secure mechanism such as TOTP, push or an offline method | Fail | The only self-service recovery path is an emailed link. |
| V2.5.7 | Lost MFA factors need identity proofing at enrolment level | Not assessed | Administrators can issue bypass codes (`internal/identity/mfa_bypass.go`); the proofing procedure is an operator matter and was not reviewed. |

### V2.6 Look-up Secret Verifier

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.6.1 | Lookup secrets are single-use | Pass | Backup codes are consumed with one conditional UPDATE (`internal/identity/service.go`, `ValidateBackupCode`). |
| V2.6.2 | Lookup secrets have 112 bits of entropy, or are salted and hashed | Pass | Codes are 8 base32 characters (40 bits) stored as salted bcrypt hashes. Rows written before the move to bcrypt hold unsalted SHA-256 until they are used. |
| V2.6.3 | Lookup secrets resist offline attacks and are not predictable | Pass | Generated from `crypto/rand` and stored as bcrypt hashes. |

### V2.7 Out of Band Verifier

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.7.1 | Clear-text out-of-band authenticators are not the default; push is offered first | Not assessed | SMS is disabled by default (`internal/sms/config_bridge.go`); the order in which the sign-in page offers factors was not checked. |
| V2.7.2 | Out-of-band codes expire after 10 minutes | Pass | SMS and email codes default to 5 minutes and are clamped to 60 to 600 seconds (`internal/sms/config_bridge.go`, `ValidateOTPSettings`). |
| V2.7.3 | Out-of-band codes are single-use and bound to the original request | Not assessed | A verified challenge is marked verified; binding to the original sign-in transaction was not verified. |
| V2.7.4 | The out-of-band channel is secure and independent | Not assessed | Not reviewed. |
| V2.7.5 | Only a hash of the out-of-band code is kept | Pass | SHA-256 of the code is stored (`internal/identity/otp.go`, `hashOTPCode`). |
| V2.7.6 | Out-of-band codes have at least 20 bits from a CSPRNG | Pass | Six digits from `crypto/rand` by default (`internal/identity/otp.go`, `generateOTPCode`). |

### V2.8 One Time Verifier

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.8.1 | Time-based OTPs have a defined lifetime | Pass | 30-second period with one step of clock skew (`internal/identity/service.go`, `validateTOTPWithSkew`). |
| V2.8.2 | OTP verification keys are highly protected (HSM or OS key store) | Fail | TOTP shared secrets are stored in the database without application-layer encryption; they rely on database access control and RLS. Hardware-token secrets are encrypted (`internal/identity/hardware_token.go`). |
| V2.8.3 | OTPs are generated and verified with approved algorithms | Pass | HMAC-SHA1 TOTP per RFC 6238 with 32-byte secrets from `crypto/rand` (pquerna/otp). |
| V2.8.4 | A TOTP code is usable only once in its validity period | Fail — reported privately | Details reported privately under SECURITY.md. |
| V2.8.5 | A reused TOTP is logged, rejected and the holder is notified | Fail — reported privately | Details reported privately under SECURITY.md. |
| V2.8.6 | A lost single-factor OTP device can be revoked at once | Pass | `RevokeHardwareToken` and `ReportTokenLost` (`internal/identity/hardware_token.go`). |
| V2.8.7 | Biometrics are used only as a secondary factor | Not assessed | Biometric settings in the mobile clients were not reviewed. |

### V2.9 Cryptographic Verifier

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.9.1 | Verifier keys are stored securely | Pass | For WebAuthn the server stores only public keys (go-webauthn). Push-MFA device keys were not reviewed. |
| V2.9.2 | The challenge nonce is at least 64 bits and unique | Pass | go-webauthn v0.17.4 issues 32-byte challenges (`DefaultChallengeLength`); challenges live in Redis for 5 minutes (`internal/identity/webauthn.go`). |
| V2.9.3 | Cryptographic verifiers use approved algorithms | Pass | WebAuthn signature verification by go-webauthn (COSE ES256, RS256 and others). |

### V2.10 Service Authentication

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V2.10.1 | Service-to-service secrets are not static passwords or API keys | Fail | Services authenticate to PostgreSQL, Redis, the APISIX admin API and the Ziti controller with static passwords or keys. |
| V2.10.2 | Service accounts do not use default credentials | Pass | In production the services refuse the built-in Ziti and Guacamole admin passwords and placeholder secrets (`internal/common/config/config.go`, `ValidateProduction`). |
| V2.10.3 | Service passwords are protected against offline recovery | Not assessed | They come from the environment or Kubernetes secrets; the Ziti admin password saved from the console is encrypted (`internal/access/secret_cipher.go`). Not reviewed further. |
| V2.10.4 | Secrets are not in source code and are managed securely | Pass | Only development defaults are in the source, and production refuses them (see V2.10.2 and V2.5.4). Compose templates require secrets with `:?`. Gitleaks runs in CI but does not block. |

## V3 Session Management

### V3.1 Fundamental Session Management Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.1.1 | Session tokens never appear in URL parameters | Pass | Sessions use HttpOnly cookies or bearer headers. Pre-session handles (login session, magic-link token, QR-login token) do travel in URLs; log redaction covers parameters named like tokens (`internal/common/logsafe/redact.go`). |

### V3.2 Session Binding

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.2.1 | A new session token is issued at authentication | Pass | The SSO cookie token is minted at each code issuance (`internal/oauth/browser_session.go`, `setBrowserSessionCookie`); the proxy session is created at its callback. |
| V3.2.2 | Session tokens have at least 64 bits of entropy | Pass | 32 random bytes (`internal/oauth/service.go`, `GenerateRandomToken`; `internal/access/service.go`, `generateSessionToken`). |
| V3.2.3 | Browser tokens are stored only in secure cookies or sessionStorage | Fail | The console keeps its access and refresh tokens in localStorage (`web/admin-console/src/lib/auth.tsx`). Tracked in [#965](https://github.com/mhmtgngr/openidx/issues/965). |
| V3.2.4 | Session tokens come from approved cryptographic algorithms | Pass | `crypto/rand` (see V6.3.1). |

### V3.3 Session Termination

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.3.1 | Logout and expiry invalidate the session, including for relying parties | Fail | Logout revokes the browser session and refresh tokens and sends back-channel logout (`internal/oauth/backchannel_logout.go`), but access tokens stay valid until they expire, up to one hour (`docs/THREAT-MODEL.md` residual risk R2). |
| V3.3.2 | Sessions require re-authentication periodically, when active and when idle | Fail | Idle sessions are revoked after 30 minutes by default (`internal/oauth/session_worker.go`, `internal/oauth/session_policy.go`). An active browser session has no end: each activity update slides its expiry forward (`internal/identity/session_repository.go`), and browser clients have no refresh-family cap by decision (migration v187, `internal/migrations/sql_v187.go`). `reauth_interval` defaults to 0. |
| V3.3.3 | Other sessions can be ended after a password change | Fail — reported privately | Details reported privately under SECURITY.md. |
| V3.3.4 | Users can view and log out any or all of their sessions | Fail | Users can list their sessions (`GET /api/v1/identity/users/me/sessions`) and sign out everywhere (`POST /oauth/logout-all`), but cannot end one session, and neither action asks for credentials again. |

### V3.4 Cookie-based Session Management

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.4.1 | Session cookies set Secure | Pass | `openidx_sso` always (`internal/oauth/browser_session.go`); the proxy cookie whenever the request arrived over TLS or the install is production (`internal/access/session_cookie.go`). |
| V3.4.2 | Session cookies set HttpOnly | Pass | Both session cookies set HttpOnly. |
| V3.4.3 | Session cookies set SameSite | Pass | Both session cookies set SameSite=Lax. |
| V3.4.4 | Session cookies use the __Host- prefix | Fail | The cookies are named `openidx_sso` and `_openidx_proxy_session`, without the prefix. |
| V3.4.5 | Cookie scope keeps session cookies from other applications on the domain | Fail — reported privately | Details reported privately under SECURITY.md. |

### V3.5 Token-based Session Management

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.5.1 | Users can revoke OAuth tokens issued to linked applications | Pass | `DELETE /api/v1/identity/users/me/consents/:client_id` deletes the application's refresh and access token rows (`internal/identity/handlers_selfservice.go`). |
| V3.5.2 | Session tokens are used rather than static API secrets | Pass | Interactive use runs on OAuth tokens. API keys and personal access tokens exist for automation, with scopes and revocation. |
| V3.5.3 | Stateless tokens resist tampering, substitution and replay | Fail — reported privately | Details reported privately under SECURITY.md. |

### V3.7 Defenses Against Session Management Exploits

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V3.7.1 | Sensitive changes need a valid session or re-authentication | Fail — reported privately | Details reported privately under SECURITY.md. |

## V4 Access Control

### V4.1 General Access Control Design

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V4.1.1 | Access control is enforced on a trusted service layer | Fail — reported privately | Details reported privately under SECURITY.md. |
| V4.1.2 | Users cannot manipulate the attributes used for access control | Fail — reported privately | Details reported privately under SECURITY.md. |
| V4.1.3 | Least privilege for functions, data and resources | Fail — reported privately | Details reported privately under SECURITY.md. |
| V4.1.5 | Access control fails securely, including on exceptions | Pass | No tenant context yields zero rows under FORCE RLS (`internal/common/database/rls.go`); OPA and rate-limit failures deny (`internal/common/middleware/opa_failclosed_test.go`, `internal/common/middleware/ratelimit_failclosed_test.go`). |

### V4.2 Operation Level Access Control

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V4.2.1 | Sensitive data and APIs resist IDOR | Fail — reported privately | Details reported privately under SECURITY.md. |
| V4.2.2 | Strong anti-CSRF for authenticated functions | Pass | APIs take bearer tokens, not cookies. Cookie paths use SameSite=Lax, and the proxy checks Origin and Referer on state-changing requests (`internal/common/middleware/csrf.go`); production refuses `CSRF_ENABLED=false`. |

### V4.3 Other Access Control Considerations

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V4.3.1 | Administrative interfaces require MFA | Fail | Administrators are not required to use MFA by default: MFA policies are optional and the admin step-up gate (`STEPUP_GATE`) defaults to off (`internal/common/config/config.go`). |
| V4.3.2 | No directory browsing or metadata files exposed | Pass | The console image serves only the build output through nginx without autoindex (`deployments/docker/Dockerfile.admin-console`, `deployments/docker/nginx/admin-console.conf`); the Go services serve no directories. |
| V4.3.3 | Step-up or adaptive authentication, or segregation of duties | Pass | Risk-based MFA (`internal/oauth/mfa_policy.go`), per-secret step-up at vault reveal (`internal/vault`), separation-of-duties policies in governance (`internal/governance`). |

## V5 Validation, Sanitization and Encoding

### V5.1 Input Validation

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V5.1.1 | Defences against HTTP parameter pollution | Not assessed | Not reviewed. |
| V5.1.2 | Protection against mass assignment | Pass | Handlers bind into explicit request structs, and partial updates build SET clauses from fixed column lists (for example `internal/admin/service.go`). |
| V5.1.3 | All input is validated with allow lists | Not assessed | Validation exists on many structs (binding tags, `internal/common/validation`); coverage of all input was not checked. |
| V5.1.4 | Structured data is typed and validated against a schema | Not assessed | JSON is decoded into typed structs; field-level rules were not checked across handlers. |
| V5.1.5 | Redirects go only to allow-listed destinations | Fail — reported privately | Details reported privately under SECURITY.md. |

### V5.2 Sanitization and Sandboxing

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V5.2.1 | Untrusted HTML from editors is sanitized | Fail — reported privately | Details reported privately under SECURITY.md. |
| V5.2.2 | Unstructured data is sanitized for characters and length | Not assessed | Not reviewed. |
| V5.2.3 | Input is sanitized before it reaches mail systems | Not assessed | Not reviewed. |
| V5.2.4 | No eval() or dynamic code execution | Pass | Go has no eval; the console has no `eval` or `new Function` in `web/admin-console/src`. |
| V5.2.5 | Template injection is prevented | Pass | Administrator-authored email templates are parsed with Go `html/template` and executed with a fixed map of string values (`internal/admin/email_templates.go`); the built-in templates are embedded files (`internal/email/service.go`). |
| V5.2.6 | SSRF is prevented with allow lists of protocols, hosts and ports | Fail — reported privately | Details reported privately under SECURITY.md. |
| V5.2.7 | User-supplied SVG is sanitized or sandboxed | Not assessed | Not reviewed. |
| V5.2.8 | User-supplied Markdown, CSS or XSL is sanitized | Not assessed | Not reviewed. |

### V5.3 Output Encoding and Injection Prevention

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V5.3.1 | Output encoding fits the interpreter and context | Fail — reported privately | Details reported privately under SECURITY.md. |
| V5.3.2 | Output encoding preserves the user's character set | Not assessed | Not reviewed. |
| V5.3.3 | Context-aware escaping prevents reflected, stored and DOM XSS | Fail — reported privately | Details reported privately under SECURITY.md. |
| V5.3.4 | Queries are parameterized | Pass | pgx queries with placeholders throughout; dynamic UPDATE builders join fixed column names with placeholders. CodeQL runs its SQL-injection query in CI (`.github/workflows/codeql.yml`). |
| V5.3.5 | Context-specific escaping where parameters are not possible | Pass | Identifiers placed into SQL text come from code, not from requests (for example `cmd/rekey`). |
| V5.3.6 | Protection against JSON injection and JSON eval | Pass | `encoding/json` on the server and `JSON.parse` in the console. |
| V5.3.7 | Protection against LDAP injection | Pass | User input in LDAP filters goes through `ldap.EscapeFilter` (`internal/directory/ldap.go`). |
| V5.3.8 | Protection against OS command injection | Pass | Commands run fixed programs with argument lists, without a shell built from input (`internal/backup/backup.go`, `internal/admin/handlers/selfheal.go`, `internal/access/remote_support_retention.go`). |
| V5.3.9 | Protection against local and remote file inclusion | Not assessed | Not reviewed. |
| V5.3.10 | Protection against XPath and XML injection | Not assessed | SAML documents are built with etree (`internal/oauth/saml_signing.go`); not reviewed further. |

### V5.4 Memory, String, and Unmanaged Code

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V5.4.1 | Memory-safe strings and copies prevent overflows | Pass | Go is memory-safe. `unsafe` appears only in three Windows system-call files of the agent (`agent/internal/remotesupport/input_windows.go`, `agent/internal/plugin/trust_windows.go`, `agent/internal/secretfile/secretfile_windows.go`). |
| V5.4.2 | Format strings are constant | Pass | The govet linter, whose printf analyzer flags non-constant format strings, runs in CI through golangci-lint (`.golangci.yml`). |
| V5.4.3 | Integer overflows are prevented | Not assessed | CodeQL reports integer-conversion findings (`docs/evidence/codeql-triage.md`); not reviewed further. |

### V5.5 Deserialization Prevention

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V5.5.1 | Serialized objects are integrity-protected or encrypted | Pass | Tokens are signed JWTs and SAML messages are signed; other client data is JSON bound to typed structs. |
| V5.5.2 | XML parsers are restricted; external entities disabled (XXE) | Pass | Go's `encoding/xml`, which etree also uses, does not resolve external entities or DTDs. |
| V5.5.3 | Deserialization of untrusted data is avoided or protected | Pass | Only typed JSON, XML and YAML decoding; no gob or native object formats on untrusted input. |
| V5.5.4 | JSON is parsed with JSON.parse, never eval | Pass | The console uses `JSON.parse` and fetch's `json()`. |

## V6 Stored Cryptography

### V6.1 Data Classification

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V6.1.1 | Regulated private data (PII) is encrypted at rest | Fail | User PII (names, email addresses, phone numbers) has no application-layer encryption; it relies on database and disk encryption, which is the operator's (`docs/THREAT-MODEL.md` residual risks R6 and R7). |
| V6.1.2 | Regulated health data is encrypted at rest | N/A | OpenIDX does not process health data. |
| V6.1.3 | Regulated financial data is encrypted at rest | N/A | OpenIDX does not process financial data. |

### V6.2 Algorithms

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V6.2.1 | Cryptographic modules fail securely; no padding oracles | Pass | AES-256-GCM (authenticated) everywhere data is encrypted (`internal/common/secretcrypt/secretcrypt.go`, `internal/vault/crypto.go`, `internal/access/recording_crypto.go`). |
| V6.2.2 | Proven algorithms and libraries, no custom cryptography | Pass | Go standard library and `golang.org/x/crypto`. |
| V6.2.3 | IVs, cipher configuration and modes follow current advice | Pass | GCM with a fresh random 12-byte nonce per encryption; per-secret keys derived with HKDF-SHA256 in the vault and recordings. |
| V6.2.4 | Algorithms and key lengths can be changed | Pass | Keyrings with key ids; Argon2id parameters stored in each hash; signing-key rotation (`internal/signingkeys`). |
| V6.2.5 | No weak modes, padding, ciphers or hashes except for compatibility | Pass | SHA-1 appears only where a protocol requires it (HOTP/TOTP, TURN credentials, the HIBP range API) and MD5 only in PostgreSQL MD5 authentication to upstream databases (`internal/access/dbproxy/upstream.go`). |
| V6.2.6 | Nonces and IVs are never reused with the same key | Pass | Random 96-bit GCM nonces, and per-version derived keys in the vault. |

### V6.3 Random Values

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V6.3.1 | Random values meant to be unguessable come from a CSPRNG | Pass | `crypto/rand`; no `math/rand` in non-test Go under `internal`, `cmd`, `pkg`, `agent` or `tools`. |
| V6.3.2 | Random GUIDs are v4 from a CSPRNG | Pass | `github.com/google/uuid` `uuid.New()`, which reads `crypto/rand`. |

### V6.4 Secret Management

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V6.4.1 | A secrets management solution creates, stores and destroys secrets | Fail | Platform secrets come from environment variables unless OpenBao is configured for the vault KEK (see V1.6.2). |
| V6.4.2 | Key material is used inside an isolated security module | Fail | Keys are loaded into service memory; OpenBao is used as a key source, not for cryptographic operations. |

## V7 Error Handling and Logging

### V7.1 Log Content

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V7.1.1 | Credentials and payment data are not logged; session tokens only hashed | Not assessed | Log-injection guards exist (`internal/common/logsafe`), and query parameters named like tokens are redacted; logs were not reviewed for secrets as a whole. |
| V7.1.2 | Other sensitive data is not logged | Not assessed | Not reviewed. |
| V7.1.3 | Security events are logged (authentication, access control, validation) | Pass | Sign-in successes and failures, lockouts and proxy denials are audited (`internal/identity/service.go`, `internal/access/service.go`). |
| V7.1.4 | Log events carry what an investigation needs | Pass | Audit events record time, actor, IP address, action, outcome, target and request id (`internal/audit`). |

### V7.2 Log Processing

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V7.2.1 | All authentication decisions are logged, without secrets | Pass | Password, magic-link and passkey sign-ins are audited; codes and secrets are not written to the audit trail. |
| V7.2.2 | Access control decisions can be logged; failures are logged | Fail | Proxy denials are audited, but the API role gates answer 403 without an audit event (for example `internal/admin/handler.go`, `RequireRole`). |

### V7.3 Log Protection

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V7.3.1 | Logging components encode data to prevent log injection | Pass | `internal/common/logsafe` with census tests (`internal/common/logsafe/no_tainted_field_test.go`); CodeQL's log-injection query in CI. |
| V7.3.3 | Security logs are protected from unauthorized access and change | Fail — reported privately | Details reported privately under SECURITY.md. |
| V7.3.4 | Time sources are synchronized; UTC is preferred | Not assessed | Time synchronization is left to the operator (`docs/THREAT-MODEL.md` §5, assumptions). |

### V7.4 Error Handling

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V7.4.1 | Unexpected errors show a generic message | Fail | Many handlers return the internal error text to the client (`c.JSON(..., gin.H{"error": err.Error()})` appears in about 300 places under `internal`). |
| V7.4.2 | Exception handling covers expected and unexpected errors | Pass | Go error returns; a CI guard checks that database query errors are handled (`scripts/check-query-error-coverage.sh`). |
| V7.4.3 | A last-resort handler catches unhandled exceptions | Pass | The eight gin services mount `gin.Recovery()` (for example `cmd/identity-service/main.go`); `cmd/verify-service` and `cmd/event-relay` use `net/http`, which recovers a handler panic itself. |

## V8 Data Protection

### V8.1 General Data Protection

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V8.1.1 | Sensitive data is not cached by load balancers or caches | Fail | API responses, including the token endpoint, carry no `Cache-Control: no-store` (RFC 6749 §5.1 requires it for token responses; `internal/oauth/service.go`, `handleToken`). |
| V8.1.2 | Server-side cached copies are protected or purged | Not assessed | Not reviewed. |
| V8.1.3 | Requests carry a minimum of parameters | Not assessed | Not reviewed. |
| V8.1.4 | Abnormal request volumes are detected and alerted on | Pass | Rate-limit metrics and Prometheus alerts such as `HighAuthFailureRate` and `HighClientErrorRate` (`deployments/kubernetes/helm/openidx/templates/prometheus-rules.yaml`). |

### V8.2 Client-side Data Protection

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V8.2.1 | Anti-caching headers keep sensitive data out of browser caches | Fail | See V8.1.1. |
| V8.2.2 | Browser storage holds no sensitive data | Fail | Access and refresh tokens are kept in localStorage (`web/admin-console/src/lib/auth.tsx`). Tracked in [#965](https://github.com/mhmtgngr/openidx/issues/965). |
| V8.2.3 | Authenticated data is cleared from the client at session end | Pass | Sign-out removes the tokens from localStorage (`web/admin-console/src/lib/auth.tsx`). |

### V8.3 Sensitive Private Data

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V8.3.1 | Sensitive data travels in the body or headers, not the query string | Fail | Most APIs comply, but the QR-login poll takes its session token in the query string (`GET /oauth/qr-login/poll`, `internal/oauth/handlers_passwordless.go`). |
| V8.3.2 | Users can remove or export their data on demand | Not assessed | Users can file a data-subject request (`POST /api/v1/identity/users/me/privacy/dsar`); whether export and erasure are carried out was not verified. |
| V8.3.3 | Clear notice and opt-in consent before personal data is used | Not assessed | Privacy-consent endpoints exist; not reviewed. |
| V8.3.4 | Sensitive data is identified, with a policy for handling it | Fail | See V1.8.1. |
| V8.3.5 | Access to sensitive data is audited without logging the data | Pass | Vault reveals and recording downloads are audited with actor and reason (`docs/THREAT-MODEL.md` §4.6). |
| V8.3.6 | Sensitive data in memory is overwritten when no longer needed | Fail | Secrets are not zeroed after use; Go strings are immutable and garbage-collected. |
| V8.3.7 | Encryption provides confidentiality and integrity with approved algorithms | Pass | AES-256-GCM (see V6.2.1). |
| V8.3.8 | Sensitive personal data follows a retention schedule | Not assessed | Recording and audit retention exist; privacy retention policies exist in `internal/admin/privacy.go`; automatic deletion was not verified. |

## V9 Communication

### V9.1 Client Communication Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V9.1.1 | TLS for all client connections, with no fallback | Pass | Production requires TLS (`internal/common/config/config.go`); when TLS is enabled a service listens only for TLS (`internal/common/tlsutil/tlsutil.go`). |
| V9.1.2 | Only strong cipher suites, checked with current tools | Not assessed | Go's default suites are used; no TLS scanner has been run against a deployment. |
| V9.1.3 | Only TLS 1.2 and 1.3 | Pass | `MinVersion: tls.VersionTLS12` (`internal/common/tlsutil/tlsutil.go`). Edge TLS settings are deployment configuration. |

### V9.2 Server Communication Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V9.2.1 | Server connections use trusted certificates; internal CAs are pinned | Fail | See V1.9.2: `sslmode=require` passes the production gate. |
| V9.2.2 | TLS for all inbound and outbound connections, no fallback | Not assessed | The production gate covers PostgreSQL, Redis and inter-service HTTP; the scheme of every internal service URL was not checked. |
| V9.2.3 | Encrypted connections to external systems are authenticated | Not assessed | Not reviewed. |
| V9.2.4 | Certificate revocation (such as OCSP stapling) is configured | Not assessed | Deployment configuration; not reviewed. |

## V10 Malicious Code

### V10.2 Malicious Code Search

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V10.2.1 | No unauthorized phone-home or data collection | Not assessed | First-party Go code calls external services only for integrations an operator configures (social sign-in, FCM, Play Integrity, SMS providers). Third-party libraries were not reviewed. |
| V10.2.2 | No unnecessary permissions to privacy-related sensors | Not assessed | The Android agent requests camera, accessibility, device-admin and screen-capture permissions (`agent-android/app/src/main/AndroidManifest.xml`); whether each is necessary was not reviewed. |

### V10.3 Application Integrity

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V10.3.1 | Auto-updates come over secure channels and are signature-checked | Pass | See V1.14.2: HTTPS-only URLs, manifest signature against a pinned publisher, then SHA-256 of the artifact (`agent/internal/updater/updater.go`). |
| V10.3.2 | Integrity protection such as code signing or SRI; no untrusted code | Pass | Release artifacts and images are signed with cosign (`.github/workflows/release.yml`); the console loads no externally hosted scripts (`web/admin-console/index.html`). |
| V10.3.3 | Protection from subdomain and domain takeover | Fail — reported privately | Details reported privately under SECURITY.md. |

## V11 Business Logic

### V11.1 Business Logic Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V11.1.1 | Business flows run in order without skipped steps | Not assessed | Not reviewed as a whole. |
| V11.1.2 | Business flows run at realistic human speed | Not assessed | Not reviewed. |
| V11.1.3 | Per-user limits on business actions are enforced | Pass | For example 100 device-enrolment tokens an hour per tenant (`internal/access/enrollment_quota.go`), and hourly caps on magic links and one-time codes (`internal/identity/passwordless.go`, `internal/identity/otp.go`). |
| V11.1.4 | Anti-automation against excessive calls and denial of service | Fail — reported privately | Details reported privately under SECURITY.md. |
| V11.1.5 | Business logic limits address threats from threat modelling | Pass | Quotas and gates tied to `docs/THREAT-MODEL.md` (lockout, enrolment quota, checkout expiry). |
| V11.1.6 | No TOCTOU or race conditions in sensitive operations | Fail — reported privately | Details reported privately under SECURITY.md. |
| V11.1.7 | Unusual business-logic activity is monitored | Pass | Risk scoring and login-anomaly detection (`internal/risk`). |
| V11.1.8 | Alerting on automated attacks or unusual activity is configurable | Pass | Prometheus rules in the Helm chart (see V8.1.4). |

## V12 Files and Resources

### V12.1 File Upload

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.1.1 | Large files that could exhaust storage are refused | Fail | Six services cap request bodies with `middleware.MaxBodySize` at 1 to 10 MB (for example `cmd/identity-service/main.go`). The access service sets no cap, and its certificate upload handlers read the whole upload into memory at the size the request declares (`internal/access/platform_certs.go`). Only administrators can reach them. |
| V12.1.2 | Compressed files are checked for size and file count before extraction | Not assessed | Not reviewed. |
| V12.1.3 | Per-user file size and count quotas | Not assessed | Not reviewed. |

### V12.2 File Integrity

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.2.1 | Files from untrusted sources are checked by content type | Not assessed | Not reviewed. |

### V12.3 File Execution

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.3.1 | User-supplied file names are not used directly by filesystems | Not assessed | Not reviewed. |
| V12.3.2 | User-supplied file names are validated or ignored (LFI) | Not assessed | Not reviewed. |
| V12.3.3 | User-supplied file names cannot trigger RFI or SSRF | Not assessed | Not reviewed. |
| V12.3.4 | Protection against reflective file download | Not assessed | Not reviewed. |
| V12.3.5 | Untrusted file metadata is not passed to system APIs | Not assessed | Not reviewed. |
| V12.3.6 | No code from untrusted sources (CDNs, packages, DLLs) | Pass | The console is served from its own build; Go modules are checked against `go.sum`, npm packages against `web/admin-console/package-lock.json`. |

### V12.4 File Storage

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.4.1 | Untrusted files are stored outside the web root, with limited permissions | Not assessed | Recordings go to a filesystem or S3 store outside any web root (`docs/THREAT-MODEL.md` §4.7); other uploads were not reviewed. |
| V12.4.2 | Untrusted files are scanned by antivirus | Not assessed | Not reviewed. |

### V12.5 File Download

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.5.1 | The web tier serves only allowed file types | Pass | The console image contains only the build output (`deployments/docker/Dockerfile.admin-console`). |
| V12.5.2 | Uploaded files are never executed as HTML or JavaScript | Not assessed | Not reviewed. |

### V12.6 SSRF Protection

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V12.6.1 | The server may send requests only to an allow list of destinations | Fail — reported privately | Details reported privately under SECURITY.md. |

## V13 API and Web Service

### V13.1 Generic Web Service Security

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V13.1.1 | All components use the same encodings and parsers | Not assessed | Not reviewed. |
| V13.1.3 | API URLs expose no keys or session tokens | Fail | See V8.3.1. |
| V13.1.4 | Authorization is checked at the route and at the resource | Fail — reported privately | Details reported privately under SECURITY.md. |
| V13.1.5 | Unexpected or missing content types are rejected (406, 415) | Fail | `middleware.ValidateContentType` exists but no service mounts it (`internal/common/middleware/validation.go`). |

### V13.2 RESTful Web Service

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V13.2.1 | Enabled HTTP methods match what each user may do | Fail — reported privately | Details reported privately under SECURITY.md. |
| V13.2.2 | JSON schema validation before input is accepted | Fail | Input is decoded into typed structs; no JSON Schema validation is used. |
| V13.2.3 | Cookie-authenticated REST services are protected from CSRF | Pass | See V4.2.2. |
| V13.2.5 | REST services check the incoming Content-Type | Fail | See V13.1.5. |
| V13.2.6 | Headers and payload are protected in transit | Pass | TLS is required in production (see V9.1.1). |

### V13.3 SOAP Web Service

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V13.3.1 | SOAP: XSD schema validation before processing | N/A | No SOAP services. The SAML SOAP binding is declared but not used (`internal/oauth/saml.go`). |
| V13.3.2 | SOAP: payloads signed with WS-Security | N/A | No SOAP services. |

### V13.4 GraphQL

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V13.4.1 | GraphQL: query allow list or depth and amount limits | N/A | No GraphQL. |
| V13.4.2 | GraphQL: authorization in the business layer | N/A | No GraphQL. |

## V14 Configuration

### V14.1 Build and Deploy

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V14.1.1 | Build and deployment are automated and repeatable | Pass | CI workflows under `.github/workflows`, Dockerfiles under `deployments/docker`, the Helm chart under `deployments/kubernetes/helm/openidx`. |
| V14.1.2 | Compiler flags enable overflow protections and fail on unsafe operations | N/A | Go is memory-safe; the requirement targets unmanaged languages. See V5.4.1. |
| V14.1.3 | Server configuration is hardened | Pass | `docs/SECURITY-HARDENING.md`, enforced by `Config.ValidateProduction()`. |
| V14.1.4 | Redeploy from automation or restore from backup in reasonable time | Pass | Helm and Compose, `cmd/backup`, `docs/disaster-recovery.md`, the `make dr-game-day` self-test. |

### V14.2 Dependency

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V14.2.1 | Components are up to date, with a dependency checker | Pass | See V1.14.3. |
| V14.2.2 | Unneeded features, samples and configurations are removed | Not assessed | The repository ships demo applications and development-only switches; production refuses some of them (`internal/common/config/config.go`). What a production install deploys was not reviewed. |
| V14.2.3 | Externally hosted assets use Subresource Integrity | N/A | The console loads no externally hosted assets (`web/admin-console/index.html`). |
| V14.2.4 | Third-party components come from trusted, maintained repositories | Pass | Go module proxy with `go.sum`; the npm registry with `web/admin-console/package-lock.json`. |
| V14.2.5 | An SBOM of third-party libraries is maintained | Pass | Image builds attach SBOM and provenance attestations (`.github/workflows/docker.yml`). |
| V14.2.6 | Third-party libraries are sandboxed or encapsulated | Not assessed | Not reviewed. |

### V14.3 Unintended Security Disclosure

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V14.3.2 | Debug modes are off in production | Pass | gin release mode in production, pprof only in development (`internal/profiling/middleware.go`), and `DEBUG_OTP_IN_RESPONSE` and `DEV_ADMIN_BYPASS` are refused in production (`internal/common/config/config.go`). |
| V14.3.3 | Responses do not expose detailed version information | Fail | nginx sets `server_tokens off`, but the APISIX configurations leave APISIX's default `Server` header, which carries its version (`deployments/docker/apisix/config.yaml`). |

### V14.4 HTTP Security Headers

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V14.4.1 | Every response has a Content-Type with a safe charset | Pass | gin's JSON and string writers set it; the HTML pages set `text/html; charset=utf-8`. |
| V14.4.2 | API responses carry Content-Disposition: attachment | Fail | JSON responses carry no Content-Disposition header. |
| V14.4.3 | A Content-Security-Policy is in place | Fail | The Go services send a CSP (`internal/common/middleware/security.go`), but the console is served without one (`deployments/docker/nginx/admin-console.conf`, `web/admin-console/nginx.conf`). Tracked in [#965](https://github.com/mhmtgngr/openidx/issues/965). |
| V14.4.4 | Every response has X-Content-Type-Options: nosniff | Pass | `internal/common/middleware/security.go` and the console's nginx configuration. |
| V14.4.5 | Strict-Transport-Security on all responses, including subdomains | Not assessed | The services add HSTS only when TLS terminates in the service; the reference nginx front end adds it (`deployments/docker/nginx/nginx.conf`). Other edges were not checked. |
| V14.4.6 | A suitable Referrer-Policy is set | Pass | `strict-origin-when-cross-origin` (`internal/common/middleware/security.go`, `deployments/docker/nginx/admin-console.conf`). |
| V14.4.7 | Content cannot be framed by third parties | Pass | `X-Frame-Options: DENY` and `frame-ancestors 'self'` on the services; `SAMEORIGIN` on the console. |

### V14.5 HTTP Request Header Validation

| ID | Requirement | Status | Evidence or reason |
|---|---|---|---|
| V14.5.1 | Only used HTTP methods are accepted; invalid ones are logged or alerted | Fail | Unregistered methods get 404 from gin, but such requests are neither logged as invalid nor alerted on. |
| V14.5.2 | The Origin header is not used for authentication or authorization | Pass | Origin is used only for CSRF and WebSocket origin checks, alongside token verification. |
| V14.5.3 | CORS uses a strict allow list and rejects the null origin | Pass | Exact-match origin list, and production refuses `*` (`internal/common/middleware/middleware.go`, `CORS`). The OAuth protocol endpoints answer `*` without credentials by design (`internal/common/middleware/oauth_cors.go`). |
| V14.5.4 | Headers added by a trusted proxy are authenticated | Fail — reported privately | Details reported privately under SECURITY.md. |

## Keeping this current

- Update a row in the pull request that changes what it describes, and
  change its status only with evidence.
- When a privately reported gap is fixed and its advisory is published,
  replace the row's status with the result and link the advisory.
- Re-assess the Not-assessed rows before the penetration test starts, so
  the testers get the current list.
- The next full pass is due when OWASP ASVS 5.0 is adopted, or at the next
  major release, whichever comes first.
