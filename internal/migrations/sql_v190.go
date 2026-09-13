package migrations

// Migration v190 — the index keyset paging of the audit log needs to be fast.
//
// Task 2.5 changes the audit event list from
//
//	ORDER BY timestamp DESC OFFSET $n LIMIT $m
//
// to a cursor:
//
//	WHERE org_id = $1 AND (timestamp, id) < ($ts, $id)
//	ORDER BY timestamp DESC, id DESC LIMIT $m
//
// That rewrite is only worth having if an index can answer it by seeking
// straight to the cursor. The table's existing indexes cannot:
//
//   - idx_audit_events_timestamp is (timestamp) alone, install-wide. Every read
//     of this table is tenant-scoped first, so a scan of it walks every
//     tenant's events in that time range and discards the ones that are not
//     yours -- the same defect v176 fixed for (org_id, event_type).
//   - the (org_id, event_type) index leads with the wrong second column for an
//     ordering query.
//
// (org_id, timestamp DESC, id DESC) matches the WHERE and the ORDER BY in one
// object, so the row-comparison seeks and LIMIT stops. The DESC in the index
// is not cosmetic: a forward index can be read backwards, but a composite read
// backwards must reverse EVERY column, and this ordering is descending on both
// -- declaring it that way is what keeps the scan a plain forward one.
//
// id is in the index because it is in the ordering, and it is in the ordering
// because timestamp alone is not a total order: the column defaults to NOW()
// and a burst writes several rows in the same microsecond. Postgres may return
// tied rows in any order and need not repeat it, so OFFSET paging could show a
// row on two consecutive pages or on neither. On an audit log that is the worst
// available wrong answer, and it was true of this query before task 2.5 --
// the tie-break is a correctness fix that the cursor happens to need anyway.
//
// CONCURRENTLY is deliberately NOT used: it cannot run inside a transaction
// block, and Migrator.applyMigration wraps every migration in one (that is what
// carries the bypass_rls GUC the seeds need). On a large existing table this
// index build therefore takes a write lock for its duration -- stated here
// rather than discovered, because the alternative is a migration framework
// change, which is not this task.
var auditKeysetIndexUp = `-- Migration 190: index the audit log for keyset paging.
CREATE INDEX IF NOT EXISTS idx_audit_events_org_ts_id
  ON audit_events (org_id, timestamp DESC, id DESC);
`

// Down drops it. The queries keep working without it, the way they did before:
// correctly, and slowly.
var auditKeysetIndexDown = `-- Migration 190 down: drop the keyset index.
DROP INDEX IF EXISTS idx_audit_events_org_ts_id;
`
