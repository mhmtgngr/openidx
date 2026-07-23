package migrations

// Migration v102 — usage metering (Wave A4).
//
// The MSP billing substrate + NetFoundry-parity feature. The Ziti fabric event
// stream is already ingested into unified_audit_events (source='ziti': overlay
// logins ziti.api_session.created, service dials ziti.service.dialed). This adds
// a daily rollup so operators can bill/report usage per org / service / identity
// without scanning the raw event table.
//
// A metering aggregator worker consumes unified_audit_events past a cursor and
// upserts per-(org, user, service, metric, day) counters. The counters are
// additive and idempotent under re-processing of the same window (the cursor is
// advanced only after a batch commits, and the upsert is keyed).
//
// Additive + idempotent.
var usageMeteringUp = `-- Migration 102: usage metering rollup + cursor.
CREATE TABLE IF NOT EXISTS usage_metering_daily (
    id          BIGSERIAL PRIMARY KEY,
    org_id      UUID,
    -- The metered principal (nullable for org-level totals).
    user_id     UUID,
    -- The Ziti service dialed (empty for login/auth metrics).
    service     VARCHAR(255) NOT NULL DEFAULT '',
    -- What is counted: 'overlay_login' | 'service_dial'.
    metric      VARCHAR(64) NOT NULL,
    day         DATE NOT NULL,
    count       BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    -- One counter row per (org, user, service, metric, day). NULL org/user are
    -- normalized to the zero-uuid in the worker so the unique key is total.
    UNIQUE (org_id, user_id, service, metric, day)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_org_day ON usage_metering_daily(org_id, day DESC);
CREATE INDEX IF NOT EXISTS idx_usage_metering_service ON usage_metering_daily(service, day DESC);

CREATE TABLE IF NOT EXISTS usage_metering_cursor (
    id          INT PRIMARY KEY DEFAULT 1,
    last_ts     TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    last_id     UUID,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT usage_metering_cursor_singleton CHECK (id = 1)
);
INSERT INTO usage_metering_cursor (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
`

var usageMeteringDown = `-- Rollback 102.
DROP TABLE IF EXISTS usage_metering_cursor;
DROP TABLE IF EXISTS usage_metering_daily;
`
