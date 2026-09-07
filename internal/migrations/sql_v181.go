package migrations

// v181 — somewhere to put the audit hash chain.
//
// docs/docs/index.md, docs/docs/guide/architecture.md,
// docs/docs/reference/audit.md and README.md's readiness checklist all state
// that OpenIDX keeps a tamper-evident audit log with an HMAC hash chain.
// internal/audit/logger.go implements one -- ComputeHash over canonical bytes,
// PrepareForStorage to link each event to its predecessor, verifyEventChain to
// walk a run and name the first break. Until this migration there was nowhere
// to store any of it: audit_events had no hash column, no previous-hash column
// and no chain position, so nothing could have been chained even if something
// had tried. Found by tools/deadservice: no binary reaches audit.Logger or
// audit.AuditEvent, and the tests that cover them define their own
// ComputeHashForChain to make the chain assertions work at all.
//
// THE CHAIN IS PER ORG. audit_events is under FORCE row-level security and
// every read of it is tenant-scoped, so one install-wide chain would be
// unverifiable by the tenant it belongs to: they cannot see the rows in
// between. chain_seq is therefore dense within an org, and the unique index is
// on (org_id, chain_seq) -- which is also what makes a deleted sealed row
// visible, because the gap it leaves cannot be closed without rewriting every
// later row's hash.
//
// SEALED, NOT SEALED-ON-WRITE. The columns are nullable and filled by a
// background sealer (internal/audit/chain.go), for the same reason v88's
// indexed_at is: sixteen different statements across this tree INSERT into
// audit_events, several of them inside request transactions, and a chain has to
// be built in one serialized order. Making every one of those call sites take a
// per-org lock would put a serialization point in the middle of login. So rows
// land unsealed and a sweep chains them in (timestamp, id) order under an
// advisory lock, exactly as the Elasticsearch reconciler backfills indexed_at.
// The consequence is stated rather than hidden: an event is tamper-evident once
// sealed, and the sealer's lag is the window in which a row could be altered
// without leaving a trace. Verification reports the unsealed count so that
// window is visible rather than assumed.
//
// Additive and idempotent; the partial indexes keep both the sweep and the
// tail lookup cheap. Down drops all three columns, which discards the chain --
// re-running the sealer after a rollback rebuilds it from the rows themselves.
var auditChainUp = `-- Migration 181: audit hash chain storage.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS chain_seq BIGINT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_chain
    ON audit_events (org_id, chain_seq) WHERE chain_seq IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_events_unsealed
    ON audit_events (org_id, timestamp, id) WHERE event_hash IS NULL;`

var auditChainDown = `-- Rollback 181.
DROP INDEX IF EXISTS idx_audit_events_unsealed;
DROP INDEX IF EXISTS idx_audit_events_chain;
ALTER TABLE audit_events DROP COLUMN IF EXISTS event_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS prev_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS chain_seq;`
