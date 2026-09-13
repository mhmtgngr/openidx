package migrations

// Migration v191 — index the SCIM list endpoints for the order they page by.
//
// Task 2.5's remaining half. SCIM cannot become a cursor: RFC 7644 §3.4.2.4
// pages a ListResponse by `startIndex` and requires `totalResults`, so the
// client picks the offset and the count has to be computed. What CAN be fixed
// is the ordering, and it needed fixing for correctness before it needed an
// index.
//
// `ORDER BY created_at` alone is not a total order, and in this schema the ties
// are guaranteed rather than unlucky: created_at defaults to NOW(), which in
// Postgres is the TRANSACTION timestamp, so every row a single transaction
// writes carries the identical value. One SCIM bulk create, one directory sync,
// one CSV import -- each lands a block of rows that tie exactly. Measured: two
// hundred rows inserted in one transaction, ONE distinct created_at.
//
// Tied rows with no second key may come back in any order, and Postgres is not
// required to repeat it between executions. Under OFFSET paging that shows a
// user on two pages or on neither -- on a provisioning API, an account that
// never reaches a downstream application, or one provisioned twice, with
// nothing logged because every page was a valid answer.
//
// So the list orders by (created_at, id), and this is the index that answers it
// without a sort. It leads with org_id because every SCIM read is tenant-scoped
// first; a (created_at) index would be install-wide and would walk every
// tenant's rows to find yours -- the defect v176 fixed for audit_events and
// v190 avoided.
//
// ASC, not DESC: the SCIM lists page forward from the oldest row, which is the
// order the API has always presented.
//
// CONCURRENTLY is deliberately NOT used, for the same reason as v190:
// applyMigration wraps every migration in a transaction (that is what carries
// the bypass_rls GUC the seeds need) and CREATE INDEX CONCURRENTLY cannot run
// inside one. On a large existing table this takes a write lock for the build.
var scimListIndexUp = `-- Migration 191: index the SCIM list ordering.
CREATE INDEX IF NOT EXISTS idx_users_org_created_id
  ON users (org_id, created_at, id);

CREATE INDEX IF NOT EXISTS idx_groups_org_created_id
  ON groups (org_id, created_at, id);
`

// Down drops both. The lists keep working without them, the way they did
// before: correctly -- the tie-break is in the query, not in the index -- and
// with a sort.
var scimListIndexDown = `-- Migration 191 down: drop the SCIM list indexes.
DROP INDEX IF EXISTS idx_users_org_created_id;
DROP INDEX IF EXISTS idx_groups_org_created_id;
`
