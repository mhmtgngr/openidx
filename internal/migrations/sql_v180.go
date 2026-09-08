package migrations

// v180 — the index the audit filter has always needed, and the one that makes
// its own list of choices answerable.
//
// audit_events carries an index on event_type alone and one on org_id only
// through the RLS policy's predicate. Every read of this table is tenant-scoped
// first, so `WHERE org_id = $1 AND event_type = $2` -- the console's own filter
// query -- had to fetch every row of that event type across the install and
// discard the ones belonging to other tenants.
//
// It is also what lets the product answer "which event types does this tenant
// actually have", cheaply, instead of offering a hard-coded list. That list had
// drifted badly: the console offered eight names taken from the EventType
// constants in internal/audit/service.go, and only two of them -- authentication
// and authorization -- are ever written. The other six return an empty result,
// and an empty audit list reads as "nothing happened", which on this surface is
// the worst available wrong answer. Meanwhile the ten values the product does
// write (identity, provisioning, oauth, access, security, and five specific
// pam./certificate./session. events) could not be filtered for at all.
//
// A composite index on (org_id, event_type) serves both: the filtered read, and
// the grouped scan behind GET /api/v1/audit/event-types.
const auditEventTypeIndexUp = `-- Migration 180: tenant-scoped audit event-type index.

CREATE INDEX IF NOT EXISTS idx_audit_events_org_type ON audit_events(org_id, event_type);
`

// Down drops it. The single-column idx_audit_events_type stays, so the filter
// keeps working -- slowly, the way it did before.
const auditEventTypeIndexDown = `
DROP INDEX IF EXISTS idx_audit_events_org_type;
`
