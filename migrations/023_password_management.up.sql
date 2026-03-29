-- Migration 023: Password History and Credential Rotation

CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credential_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL,
    old_key_id UUID,
    new_key_id UUID,
    rotation_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'completed',
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_by UUID
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_rotations_sa ON credential_rotations(service_account_id);
