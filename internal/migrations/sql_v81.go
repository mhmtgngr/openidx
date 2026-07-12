package migrations

// Migration v81 — PAM connection manager (Devolutions RDM parity).
//
// Adds the entry-tree layer the PAM milestones (M1–M5) left out: a Remote
// Desktop Manager-style catalog of vaults/folders and typed entries (RDP/SSH/
// VNC/Telnet/website sessions, credentials, SSH keys, API keys, and secure
// information records), each optionally backed by an envelope-encrypted
// vault_secrets row. Sessions launch through the existing Guacamole broker
// with the credential injected server-side, so a user can open a remote
// session without ever seeing the password.
//
//   - pam_folders               hierarchical folder tree (RDM "groups")
//   - pam_entries               typed entries; secret payloads live in vault_secrets
//   - pam_entry_grants          per-entry ACL (view/connect/edit/reveal)
//   - pam_entry_favorites       per-user favorites
//   - pam_entry_access_requests pre-connect approval lifecycle (RDM "checkout")
//   - pam_entry_sessions        launch ledger (who connected where, when)
//
// All six tables are org-scoped under the v37 FORCE-RLS belt. Idempotent.
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks
// (v56/v57 lesson).
var pamEntriesUp = `-- Migration 081: PAM connection manager (RDM parity) — folders, entries, grants, favorites, approvals, session ledger.

CREATE TABLE IF NOT EXISTS pam_folders (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    parent_id   UUID REFERENCES pam_folders(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    icon        VARCHAR(64),
    description TEXT,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pam_folders_org    ON pam_folders(org_id);
CREATE INDEX IF NOT EXISTS idx_pam_folders_parent ON pam_folders(parent_id);

CREATE TABLE IF NOT EXISTS pam_entries (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID NOT NULL,
    folder_id                UUID REFERENCES pam_folders(id) ON DELETE SET NULL,
    name                     VARCHAR(255) NOT NULL,
    entry_type               VARCHAR(32) NOT NULL,
    description              TEXT,
    tags                     TEXT[] NOT NULL DEFAULT '{}',
    hostname                 VARCHAR(512),
    port                     INTEGER,
    username                 VARCHAR(255),
    domain                   VARCHAR(255),
    url                      TEXT,
    settings                 JSONB NOT NULL DEFAULT '{}',
    vault_secret_id          UUID REFERENCES vault_secrets(id) ON DELETE SET NULL,
    credential_entry_id      UUID REFERENCES pam_entries(id) ON DELETE SET NULL,
    guacamole_connection_id  VARCHAR(255),
    allow_reveal             BOOLEAN NOT NULL DEFAULT false,
    require_approval         BOOLEAN NOT NULL DEFAULT false,
    record_session           BOOLEAN NOT NULL DEFAULT false,
    created_by               UUID,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_connected_at        TIMESTAMPTZ,
    connect_count            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pam_entries_org    ON pam_entries(org_id);
CREATE INDEX IF NOT EXISTS idx_pam_entries_folder ON pam_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_pam_entries_type   ON pam_entries(org_id, entry_type);

CREATE TABLE IF NOT EXISTS pam_entry_grants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    entry_id       UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    principal_type VARCHAR(32) NOT NULL,
    principal_id   VARCHAR(255) NOT NULL,
    actions        TEXT[] NOT NULL,
    granted_by     UUID,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (entry_id, principal_type, principal_id)
);
CREATE INDEX IF NOT EXISTS idx_pam_entry_grants_entry ON pam_entry_grants(entry_id);

CREATE TABLE IF NOT EXISTS pam_entry_favorites (
    org_id     UUID NOT NULL,
    entry_id   UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entry_id, user_id)
);

CREATE TABLE IF NOT EXISTS pam_entry_access_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    entry_id     UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL,
    reason       TEXT,
    status       VARCHAR(16) NOT NULL DEFAULT 'pending',
    approver_id  UUID,
    decided_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pam_entry_access_requests_lookup
    ON pam_entry_access_requests(entry_id, requester_id, status);

CREATE TABLE IF NOT EXISTS pam_entry_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL,
    entry_id            UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    user_id             UUID,
    protocol            VARCHAR(32),
    guac_connection_id  VARCHAR(255),
    credential_injected BOOLEAN NOT NULL DEFAULT false,
    recording_path      TEXT,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMPTZ,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_entry
    ON pam_entry_sessions(entry_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_pam_entry_sessions_status
    ON pam_entry_sessions(status);

-- v37-style RLS belts.
DROP POLICY IF EXISTS pol_pam_folders_org_scope ON pam_folders;
CREATE POLICY pol_pam_folders_org_scope ON pam_folders
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_folders FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_entries_org_scope ON pam_entries;
CREATE POLICY pol_pam_entries_org_scope ON pam_entries
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_entries FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_entry_grants_org_scope ON pam_entry_grants;
CREATE POLICY pol_pam_entry_grants_org_scope ON pam_entry_grants
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_entry_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_entry_grants FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_entry_favorites_org_scope ON pam_entry_favorites;
CREATE POLICY pol_pam_entry_favorites_org_scope ON pam_entry_favorites
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_entry_favorites ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_entry_favorites FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_entry_access_requests_org_scope ON pam_entry_access_requests;
CREATE POLICY pol_pam_entry_access_requests_org_scope ON pam_entry_access_requests
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_entry_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_entry_access_requests FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_entry_sessions_org_scope ON pam_entry_sessions;
CREATE POLICY pol_pam_entry_sessions_org_scope ON pam_entry_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_entry_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_entry_sessions FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role. Plain GRANT (no DO $$ block) — the
-- migration runner's splitSQL only recognises $$ at the start of a line
-- (same lesson as v56/v57/v59).
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_folders, pam_entries, pam_entry_grants, pam_entry_favorites, pam_entry_access_requests, pam_entry_sessions TO openidx_app;
`

var pamEntriesDown = `-- Rollback 081.
DROP TABLE IF EXISTS pam_entry_sessions CASCADE;
DROP TABLE IF EXISTS pam_entry_access_requests CASCADE;
DROP TABLE IF EXISTS pam_entry_favorites CASCADE;
DROP TABLE IF EXISTS pam_entry_grants CASCADE;
DROP TABLE IF EXISTS pam_entries CASCADE;
DROP TABLE IF EXISTS pam_folders CASCADE;
`
