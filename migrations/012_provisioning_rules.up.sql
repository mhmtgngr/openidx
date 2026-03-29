-- Migration 012: Provisioning Rules and Password Reset Tokens

CREATE TABLE IF NOT EXISTS provisioning_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger VARCHAR(50) NOT NULL,
    conditions JSONB DEFAULT '[]',
    actions JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provisioning_rules_trigger ON provisioning_rules(trigger);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_enabled ON provisioning_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_priority ON provisioning_rules(priority);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- Add foreign key for password_reset_tokens after users table exists
-- Note: This uses REFERENCES users(id) but we can't add FK in IF NOT EXISTS
-- The FK is implicitly handled at application level
