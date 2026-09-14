package migrations

// Migration v192 -- the platform outbox (global-scale plan task 3.1, ADR-6).
//
// WHY A TABLE AND NOT A QUEUE CLIENT. An event that describes a state change
// has to be atomic with it. Write the row and then publish, and a crash between
// the two loses the event with nothing to replay it from; publish and then
// write, and the platform has announced something that did not happen. Neither
// window can be closed by retrying, because the failure is that nobody knows
// which side of it the process died on. Writing the event INTO the same
// transaction removes the window entirely: one commit, or neither.
//
// WHY id IS bigserial AND WHY THE RELAY MUST NOT PAGE BY IT. A sequence hands
// out numbers at INSERT time and transactions commit in whatever order they
// finish, so a later id can become visible BEFORE an earlier one: tx A takes
// 5 and is slow, tx B takes 6 and commits first. A relay that remembers "I have
// published up to 6" then never sees 5 -- and 5 is not late, it is lost, with
// nothing in the table to say so. That is why the index below is on the
// UNPUBLISHED rows rather than on the id: the relay claims by state
// (published_at IS NULL ... FOR UPDATE SKIP LOCKED), never by cursor, which is
// the same shape the SCIM provisioning queue already uses. The id is for
// ordering within a claimed batch and for naming a row in a log line.
//
// THE PARTIAL INDEX IS THE POINT. An outbox is append-mostly and read-once: the
// published rows are the overwhelming majority within a day, and the relay only
// ever wants the ones that are not. A plain index on (published_at) would grow
// with the whole table and the relay's query would still have to walk it.
// WHERE published_at IS NULL keeps the index the size of the BACKLOG, so the
// hot query costs the same on a table of ten thousand rows and one of ten
// million.
//
// TENANCY. org_id is NOT NULL with a real foreign key from the start, because
// the register's recurring finding is a nullable tenant column on a belted
// table: under FORCE RLS a NULL-org row does not leak, it DISAPPEARS -- here
// that would be an event no tenant-scoped reader can see and no operator can
// explain. The belt is applied at creation for the same reason: a table that
// gets its policy in a later migration spends the interval unbelted, and every
// row written in that interval has to be trusted rather than checked.
//
// THE RELAY IS CROSS-TENANT BY DESIGN and reaches these rows under
// orgctx.WithBypassRLS, the same way the SCIM outbound worker and the SSF
// transmitter do: one relay serves every tenant, claims by state alone, and the
// tenant travels on each claimed row into the subject it publishes to.
var outboxUp = `-- Migration 192: the platform outbox.
CREATE TABLE IF NOT EXISTS outbox (
    id            BIGSERIAL PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_id      UUID NOT NULL,
    event_type    TEXT NOT NULL,
    source        TEXT NOT NULL,
    payload       JSONB NOT NULL,
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at  TIMESTAMPTZ,
    attempts      INT NOT NULL DEFAULT 0,
    last_error    TEXT
);

-- The relay's only query: the backlog, oldest first. Partial, so it stays the
-- size of the backlog rather than of the table.
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished
    ON outbox (id)
    WHERE published_at IS NULL;

-- A consumer that sees an event twice must be able to recognise it. event_id is
-- unique per tenant rather than globally: it is generated per event, and a
-- collision across tenants is not a duplicate delivery, it is a coincidence
-- that should not make one tenant's write fail on another's.
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_org_event_id
    ON outbox (org_id, event_id);

-- Retention is the relay's job, not this migration's, but the sweep it will run
-- needs to find published rows by age without scanning the backlog index.
CREATE INDEX IF NOT EXISTS idx_outbox_published_at
    ON outbox (published_at)
    WHERE published_at IS NOT NULL;

DROP POLICY IF EXISTS pol_outbox_org_scope ON outbox;
CREATE POLICY pol_outbox_org_scope ON outbox
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE  ROW LEVEL SECURITY;
`

// Down drops the table. There is no data to preserve that anything else can
// read: an outbox row is a message in flight, and a rollback that kept them
// would keep them unreachable.
var outboxDown = `-- Migration 192 down: drop the platform outbox.
DROP TABLE IF EXISTS outbox;
`
