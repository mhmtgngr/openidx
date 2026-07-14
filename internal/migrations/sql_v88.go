package migrations

// Migration v88 — audit → Elasticsearch reconcile watermark.
//
// audit_events is written to Postgres (authoritative) and then indexed to
// Elasticsearch by a fire-and-forget goroutine. If that goroutine fails or the
// process dies, the ES copy is silently lost and audit SEARCH misses the event
// (the data is safe in Postgres). This adds an `indexed_at` watermark set when
// the ES write succeeds; a background reconciler backfills any row still NULL,
// guaranteeing ES search completeness. The partial index keeps the reconcile
// scan cheap. Additive/idempotent.
var auditIndexedAtUp = `-- Migration 088: audit → ES reconcile watermark.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS indexed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_audit_events_unindexed
    ON audit_events (timestamp) WHERE indexed_at IS NULL;`

var auditIndexedAtDown = `-- Rollback 088.
DROP INDEX IF EXISTS idx_audit_events_unindexed;
ALTER TABLE audit_events DROP COLUMN IF EXISTS indexed_at;`
