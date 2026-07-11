package migrations

// Migration v78 — recording_retention_policies for the remote-support
// recording retention subsystem.
//
// The per-org retention surface (internal/access/remote_support_retention.go)
// is fully live: RegisterRetentionAdminRoutes mounts GET/PUT
// /recording-retention-policy, and the background retention enforcer resolves
// each session's effective retention through this table on every sweep. But
// no runner migration ever created it: GET and PUT both 500'd ("relation does
// not exist" is not ErrNoRows, so even the documented default fallback never
// triggered on GET), and resolveEffectiveRetention silently swallowed the
// error, so every org was forced onto the global default — per-org retention
// was configurable in name only.
//
// org_id is the primary key (one policy row per org; the handlers upsert with
// ON CONFLICT (org_id)). retention_days = 0 means "infinite retention" per
// the handler contract; negatives are rejected by both the handler and the
// CHECK belt. updated_by is provenance metadata with no FK so policy history
// survives admin-account deletion. Plain statements only — the runner's
// splitSQL cannot handle DO $$ blocks.
var recordingRetentionPoliciesUp = `-- Migration 078: recording_retention_policies (per-org retention was configurable in name only).
CREATE TABLE IF NOT EXISTS recording_retention_policies (
    org_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    retention_days INTEGER NOT NULL CHECK (retention_days >= 0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_by UUID
);`

var recordingRetentionPoliciesDown = `-- Rollback 078
DROP TABLE IF EXISTS recording_retention_policies;`
