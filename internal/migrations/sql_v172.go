package migrations

// Migration v172 — the inbound SSF replay-dedup ledger gets the tenant it was
// already acting on.
//
// ssf_received_events (v99) records every inbound Security Event Token the
// receiver applies, keyed on the SET's jti so a re-delivery is applied once. It
// was created with an org_id column and nothing has ever written it, so every
// row on every install carries a NULL tenant — a ledger of applied security
// events that cannot say which organization each was applied to.
//
// The orgscope register recorded the table as belt-exempt because "the public
// receiver endpoint carries no tenant context". That is not true of the code:
// /ssf/events is not on tenantSkipPaths, so TenantResolver runs on it, and
// resolveUserBySubject two functions below the writer reads orgctx.From and
// refuses to resolve a subject without one — every user lookup it makes carries
// AND org_id = $2, and applyCAEPEvent's account-disable does too. The effect of
// an inbound event has always been scoped to one organization. Only the record
// of it was not.
//
// The dedup key changes with it. jti was the table's PRIMARY KEY, so the ledger
// was install-wide: a per-tenant dedup read against a global key would apply an
// event correctly for a second tenant and then silently fail to record it
// (ON CONFLICT (jti) DO NOTHING), losing replay protection for that tenant from
// then on. (org_id, jti) makes the read and the key agree.
//
// Not belted. The receiver is a public endpoint reached by an external
// transmitter, and RLS here would be a second control on a path whose tenant
// resolution is the thing worth getting right first; the register's exemption
// stays, with its reason corrected to the true one.
//
// Backfill: existing rows carry no attribution and none can be recovered — the
// writer never recorded it — so they go to the oldest organization, which is
// the organization a single-tenant install applied them under. On a
// multi-tenant install this means a SET already applied for another tenant can
// be delivered once more and applied again; applyCAEPEvent's actions (revoke
// sessions, disable an account) are idempotent, so the cost is a repeat, not a
// wrong outcome.
const ssfReceivedTenantUp = `
ALTER TABLE ssf_received_events
    ADD COLUMN IF NOT EXISTS org_id UUID;

UPDATE ssf_received_events
   SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
 WHERE org_id IS NULL;

DELETE FROM ssf_received_events WHERE org_id IS NULL;

ALTER TABLE ssf_received_events ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE ssf_received_events
    DROP CONSTRAINT IF EXISTS ssf_received_events_org_fk;

ALTER TABLE ssf_received_events
    ADD CONSTRAINT ssf_received_events_org_fk
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE ssf_received_events DROP CONSTRAINT IF EXISTS ssf_received_events_pkey;

ALTER TABLE ssf_received_events ADD PRIMARY KEY (org_id, jti);

CREATE INDEX IF NOT EXISTS idx_ssf_received_events_org_received
    ON ssf_received_events (org_id, received_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ssf_received_events TO openidx_app;
`

// Down returns the install-wide key. A duplicate jti across organizations would
// block it, so the newer of each duplicated pair is dropped first — the same
// rows the up migration made addressable per tenant.
const ssfReceivedTenantDown = `
DELETE FROM ssf_received_events a
 USING ssf_received_events b
 WHERE a.jti = b.jti AND a.received_at > b.received_at;

ALTER TABLE ssf_received_events DROP CONSTRAINT IF EXISTS ssf_received_events_pkey;

ALTER TABLE ssf_received_events ADD PRIMARY KEY (jti);

DROP INDEX IF EXISTS idx_ssf_received_events_org_received;

ALTER TABLE ssf_received_events DROP CONSTRAINT IF EXISTS ssf_received_events_org_fk;

ALTER TABLE ssf_received_events ALTER COLUMN org_id DROP NOT NULL;
`
