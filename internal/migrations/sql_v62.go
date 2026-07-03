package migrations

// Migration v62 — reconcile referenced-but-uncreated tables (readiness W2.8).
//
// Four tables are referenced by Go code but created by neither a migration nor
// init-db.sql — the same latent-500 drift class the v58 (M2a) jit_grants fix closed:
//
//   - admin_console_settings: internal/admin/handlers/settings.go SELECT/UPSERTs it
//     (ON CONFLICT (key)) for console setting categories.
//   - auth_contexts: internal/admin/continuous_auth.go SELECT/UPDATEs it by session_id
//     for continuous-auth risk context.
//   - breach_incidents / breach_alerts: internal/admin/ibdr.go INSERT/SELECT/UPDATEs them
//     across the identity-breach detection & response flow.
//
// Columns match the code's exact SQL usage and the Go struct field types (arrays -> TEXT[],
// float64 -> DOUBLE PRECISION, json.RawMessage -> JSONB). Not under the v37 FORCE-RLS belt:
// the code does not org-scope these (no org_id in any query) — matching the v58 reconcile
// precedent; org_id/RLS is a separate hardening follow-up. Idempotent (IF NOT EXISTS).
// (access_stats, also flagged by the survey, is a CTE — not a table — so nothing to create.)
// Mirrored into init-db.sql so TestInitDBParity stays green.
var reconcileMissingTablesUp = `-- Migration 062: reconcile referenced-but-uncreated tables.
CREATE TABLE IF NOT EXISTS admin_console_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS auth_contexts (
    session_id         UUID PRIMARY KEY,
    user_id            UUID,
    auth_time          TIMESTAMPTZ,
    auth_method        TEXT,
    auth_strength      TEXT,
    current_risk_score DOUBLE PRECISION,
    device_fingerprint TEXT,
    ip_address         TEXT,
    location           TEXT,
    user_agent         TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS breach_incidents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type              TEXT,
    severity          TEXT,
    status            TEXT,
    title             TEXT,
    description       TEXT,
    affected_user_ids TEXT[],
    affected_sessions TEXT[],
    detection_method  TEXT,
    first_detected_at TIMESTAMPTZ,
    last_activity_at  TIMESTAMPTZ,
    confidence        DOUBLE PRECISION,
    indicators        JSONB,
    quarantine_action TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_status ON breach_incidents(status, created_at DESC);

CREATE TABLE IF NOT EXISTS breach_alerts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  UUID REFERENCES breach_incidents(id) ON DELETE CASCADE,
    type         TEXT,
    severity     TEXT,
    message      TEXT,
    user_id      UUID,
    session_id   TEXT,
    ip_address   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    acked_at     TIMESTAMPTZ,
    acked_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_breach_alerts_incident ON breach_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_breach_alerts_ack      ON breach_alerts(acknowledged, created_at DESC);

-- Grant DML to the runtime app role (belt-and-suspenders; v53's ALTER DEFAULT PRIVILEGES
-- already covers new tables). Plain GRANT (no DO/$$ block) per the splitSQL constraint.
GRANT SELECT, INSERT, UPDATE, DELETE ON
  admin_console_settings, auth_contexts, breach_incidents, breach_alerts
  TO openidx_app;
`

var reconcileMissingTablesDown = `-- Migration 062 down.
DROP TABLE IF EXISTS breach_alerts CASCADE;
DROP TABLE IF EXISTS breach_incidents CASCADE;
DROP TABLE IF EXISTS auth_contexts CASCADE;
DROP TABLE IF EXISTS admin_console_settings CASCADE;
`
