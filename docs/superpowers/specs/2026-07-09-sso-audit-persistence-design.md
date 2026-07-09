# SSO/OAuth Audit Persistence + Lifecycle Instrumentation — Design

**Date:** 2026-07-09
**Status:** approved (autonomous work block)
**Author:** Claude (autonomous)

## Problem

The oauth service's `logAuditEvent` (`internal/oauth/saml.go:1098`) writes only to the
zap application log — it does **not** persist to the `audit_events` table. Every other
service (identity `internal/identity/service.go`, admin, the tenant cross-org auditor)
persists audit rows. As a result, **all SSO/OAuth/SAML audit activity — user logins,
logout / single-logout, and JIT provisioning — is missing from the `audit_events` table**,
and therefore from:

- the audit query API (`GET /api/v1/audit/events`), and
- compliance reports (SOC2/ISO/GDPR generators read `audit_events`).

For an IAM platform this is a real compliance gap: "who logged in via SSO, and how were
their accounts provisioned/linked" is exactly what an auditor expects in the trail.

Additionally, the SSO JIT provisioning flow (shipped in v1.24.4–v1.24.6) makes several
security-relevant decisions — provision a new user, link a federated identity, match a
returning user by IdP subject, backfill a link — that emit **no** audit signal at all.

## Goals

1. Make the oauth service's `logAuditEvent` **persist** to `audit_events` (in addition to
   the existing zap log), matching the proven identity-service pattern (async,
   org-scoped, best-effort — never blocks or fails the request).
2. Instrument the SSO JIT lifecycle in `handleCallback` with audit events:
   - `sso.user.provisioned` — a new user was JIT-created from an SSO login
   - `sso.identity.linked` — federated identity (`idp_id`+`sub`) bound on create
   - `sso.identity.matched` — a returning user matched by `(idp_id, sub)`
   - `sso.identity.backfilled` — federated link backfilled for an email-matched user
   - `sso.login` — an existing user completed SSO login
3. Not change any request outcome (audit is fire-and-forget) or add dependencies.

## Non-goals

- No admin-console UI (out of scope; backend/API only).
- No schema change — `audit_events` already has the needed columns (v68).
- No change to the zap logging (kept for operational visibility).

## Design

### 1. Persist in `logAuditEvent`

Mirror `internal/identity/service.go`'s `logAuditEvent`: read the org synchronously from
the request context (fall back to the default org UUID), then in a detached goroutine with
a 5s timeout INSERT into `audit_events`. Keep the existing zap log line. The oauth
signature carries more fields than identity's (`ipAddress`, `resourceID`, `resourceType`),
which map cleanly:

```
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
                          actor_id, actor_type, actor_ip, target_id, target_type,
                          resource_id, details, org_id)
VALUES (gen_random_uuid(), NOW(), $1,$2,$3,$4, $5,'user',$6, $7,$8,$7, $9,$10)
-- eventType, category, action, status(outcome), userID(actor_id), ipAddress(actor_ip),
-- resourceID(target_id/resource_id), resourceType(target_type), metadata(details), orgID
```

Best-effort: on error, `logger.Warn` (never surfaced to the caller). RLS is applied by the
pool acquire hook from the request context's org; the explicit `org_id` column matches.

### 2. Lifecycle events in `handleCallback`

Add `s.logAuditEvent(...)` calls at the three match/create branches (and the login), using
`category="authentication"`, `resourceType="user"`, `actor_ip=c.ClientIP()`, and metadata
carrying `idp_id` + a boolean/step marker (never the raw `sub` value verbatim beyond what's
already stored — include it as an opaque `external_user_id` field for traceability, which is
already persisted on the user row).

### 3. Testability

`logAuditEvent`'s DB write is async + DB-bound (integration territory). To get unit
coverage without a DB, extract the pure argument→SQL-args mapping into a small helper
`buildAuditInsertArgs(...)` (returns the positional args + resolved org) that
`logAuditEvent` uses; unit-test the org-resolution fallback and field mapping. The INSERT
itself is a near-verbatim copy of the proven identity path (low risk) and is exercised live
on deploy.

## Verification

- `go build/vet/gofmt/golangci-lint/orgscope/test` green.
- Unit test for `buildAuditInsertArgs` (org fallback + field mapping).
- Deploy oauth-service; verify 8×health + that the service boots clean (no audit errors in
  logs). The persistence path reuses the identity pattern + the same pool/role that already
  writes `audit_events`, so RLS/permissions are known-good.

## Rollout

Single cohesive PR (persistence + lifecycle events + test) → release (oauth binary changes)
→ box deploy → verify. Backend-only, no migration (v68).
