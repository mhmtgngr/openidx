package migrations

// Migration v201 -- the index the per-tenant enrolment quota counts on.
//
// AGENT_ENROLLMENT_QUOTA_PER_HOUR (decided 2026-09-20, default 100) is
// enforced by counting a tenant's agent_enrollment_tokens rows created in the
// last hour, on every mint. v197 gave the table org_id and an index on it
// alone; the quota's predicate is (org_id, created_at > now - 1h), which that
// index answers by scanning every token the tenant has ever minted. This one
// answers it by range. No data changes, nothing to back fill, Down drops it.
var enrollmentQuotaIndexUp = `-- Migration 201: the enrolment quota's index.

CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tokens_org_created
    ON agent_enrollment_tokens (org_id, created_at);
`

var enrollmentQuotaIndexDown = `-- Rollback 201.

DROP INDEX IF EXISTS idx_agent_enrollment_tokens_org_created;
`
