package migrations

// v175 — the SIEM forwarder's cursor, created by a migration instead of by the
// forwarder itself.
//
// internal/audit/siem_forwarder.go opened with
//
//	CREATE TABLE IF NOT EXISTS siem_forward_cursor (...)
//
// executed through the service's own pool at startup. That pool connects as
// openidx_app, and v53 created that role without DDL rights on the schema.
// Measured against a database with the full migration chain applied:
//
//	SELECT has_schema_privilege('openidx_app','public','CREATE')  ->  f
//
// So ensureCursorTable has always returned "permission denied for schema
// public", the table has never existed, and every forwardBatch after it failed
// on "read cursor: relation siem_forward_cursor does not exist". Audit events
// have never been forwarded to a SIEM on any install that used the pool role --
// which is every deployment this repo ships, since docker-compose and the Helm
// chart both give the services the app role by design.
//
// The least-privilege work and this table were each correct on their own and
// were never read together: one removed DDL from the runtime role, the other
// assumed it. Schema belongs in the migration chain, where the owner role runs
// it, where orgscope can see it, and where a restore recreates it.
//
// Install-wide by construction: a single row (id = 1) holding one watermark
// over audit_events for one outbound SIEM connection, which is an install-level
// integration and not a tenant's. Declared as such in tools/orgscope so it
// cannot be mistaken for a table that forgot its org_id.
const siemForwardCursorUp = `
CREATE TABLE IF NOT EXISTS siem_forward_cursor (
    id            INT PRIMARY KEY DEFAULT 1,
    last_ts       TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    last_id       UUID,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT siem_forward_cursor_singleton CHECK (id = 1)
);

INSERT INTO siem_forward_cursor (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON siem_forward_cursor TO openidx_app;
`

// Down drops the cursor. The watermark is not data anybody loses sleep over --
// a fresh cursor re-forwards from the beginning, and SIEMs dedupe on event id,
// which is the same at-least-once property forwardBatch already relies on when
// delivery succeeds and the cursor update does not.
const siemForwardCursorDown = `
DROP TABLE IF EXISTS siem_forward_cursor;
`
