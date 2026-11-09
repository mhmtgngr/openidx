package migrations

// Migration 242: a watermark over privileged sessions.
//
// org_pam_policy gains watermark_internal: when true, an internal user's
// brokered session window is overlaid with their identity, the session id and
// the time. An external user's session is always watermarked, whatever this
// says. The watermark is drawn by the OpenIDX session window over the broker's
// frame, so it deters a screenshot or a photo of the screen from leaving
// without a name on it; it is not enforcement, and the console says so.
//
// Default false, so no organization's sessions change on upgrade.

var pamWatermarkUp = `-- Migration 242: org_pam_policy.watermark_internal.
ALTER TABLE org_pam_policy ADD COLUMN IF NOT EXISTS watermark_internal BOOLEAN NOT NULL DEFAULT false;
`

var pamWatermarkDown = `-- Rollback migration 242.
ALTER TABLE org_pam_policy DROP COLUMN IF EXISTS watermark_internal;
`
