package migrations

// Migration 235: a vendor's remote support on an engagement's device.
//
// A vendor's technician may now help on an enrolled device from their own
// browser, with nothing installed, when a running engagement covers the
// device (internal/access/remote_support_external.go). Such a session is
// different from a staff one in three ways the row has to carry:
//
//   - engagement_id: the engagement that allows it. The access service's
//     janitor ends the session when the engagement ends, is closed, or stops
//     covering the device or the technician, and evicts both peers.
//   - expires_at: the latest the session may run, the engagement's end or
//     the external session ceiling, whichever is first.
//   - server_recording / recording_format: the session is recorded by the
//     broker, not by the viewer's browser (a vendor's own browser is not a
//     place to keep the evidence of what the vendor did). The relay transport
//     carries the device's VP8 frames through the broker, which writes them
//     to the session's recording as IVF; recording_format tells the download
//     which container it holds ('webm' for a browser recording, 'ivf' for the
//     broker's).
//
// No new table: the columns are under remote_support_sessions' existing org
// policy. Down drops them.
var remoteSupportExternalUp = `-- Migration 235: vendor remote support.
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS engagement_id UUID REFERENCES vendor_engagements(id) ON DELETE SET NULL;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS server_recording BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_format VARCHAR(8) NOT NULL DEFAULT 'webm';
CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_engagement
    ON remote_support_sessions (engagement_id) WHERE engagement_id IS NOT NULL AND status IN ('pending', 'active');
`

var remoteSupportExternalDown = `-- Rollback migration 235.
DROP INDEX IF EXISTS idx_remote_support_sessions_engagement;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS recording_format;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS server_recording;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS expires_at;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS engagement_id;
`
