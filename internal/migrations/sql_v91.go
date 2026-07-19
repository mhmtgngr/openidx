package migrations

// Migration v91 — remote-support device consent (attended support).
//
// Adds an explicit consent gate to a remote-support session so a support
// session can require the person at the device to click Allow before the admin
// can view/control. Fields:
//   - consent_required: when true, the session stays consent-blocked until the
//     device accepts (attended support of a user's own machine). Servers /
//     unattended targets leave this false and behave exactly as today.
//   - consent_status: 'pending' | 'granted' | 'denied' (only meaningful when
//     consent_required). Set by the device via the accept/decline endpoint.
//   - consent_decided_at: when the device decided (for deny-on-timeout + audit).
//
// It ALSO backfills two columns the session-start code (HandleStartSession) has
// long referenced but no migration ever created — org_id and
// recording_retention_days — so remote-support session start stops failing with
// "column does not exist" (SQLSTATE 42703). Pre-existing schema/code drift;
// fixed here since this migration already touches the table.
//
// Additive + idempotent; existing sessions get consent_required=false, so there
// is NO behavior change for the current (unattended) flow. The DO block keeps
// `$$` on its own line for the migration runner's splitter.
var remoteSupportConsentUp = `-- Migration 091: remote-support device consent (+ backfill drifted columns).
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_retention_days INTEGER;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS consent_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS consent_status VARCHAR(16) NOT NULL DEFAULT 'granted';
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS consent_decided_at TIMESTAMPTZ;
DO
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'remote_support_consent_status_check') THEN
        ALTER TABLE remote_support_sessions
            ADD CONSTRAINT remote_support_consent_status_check
            CHECK (consent_status IN ('pending', 'granted', 'denied'));
    END IF;
END
$$;`

var remoteSupportConsentDown = `-- Rollback 091.
ALTER TABLE remote_support_sessions DROP CONSTRAINT IF EXISTS remote_support_consent_status_check;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS consent_decided_at;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS consent_status;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS consent_required;`
