-- Migration 018: Directory Sync State and Logs

-- Add directory sync columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);

CREATE INDEX IF NOT EXISTS idx_users_directory_id ON users(directory_id);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);

-- Add directory sync columns to groups
ALTER TABLE groups ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_groups_directory_id ON groups(directory_id);

-- Sync state per directory
CREATE TABLE IF NOT EXISTS directory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_usn_changed BIGINT,
    last_modify_timestamp VARCHAR(255),
    users_synced INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    sync_duration_ms INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(directory_id)
);

-- Sync log history
CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    users_added INTEGER DEFAULT 0,
    users_updated INTEGER DEFAULT 0,
    users_disabled INTEGER DEFAULT 0,
    groups_added INTEGER DEFAULT 0,
    groups_updated INTEGER DEFAULT 0,
    groups_deleted INTEGER DEFAULT 0,
    error_message TEXT,
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_sync_logs_directory ON directory_sync_logs(directory_id);
CREATE INDEX IF NOT EXISTS idx_sync_logs_started ON directory_sync_logs(started_at DESC);
