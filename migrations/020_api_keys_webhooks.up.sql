-- Migration 020: API Keys, Webhooks, Email Verification, Invitations

-- Service accounts
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    owner_id UUID,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID,
    service_account_id UUID,
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CHECK (user_id IS NOT NULL OR service_account_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_sa ON api_keys(service_account_id);

-- Webhook subscriptions
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Webhook delivery log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempt INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'pending',
    next_retry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub ON webhook_deliveries(subscription_id);

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User invitations
CREATE TABLE IF NOT EXISTS user_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL,
    roles TEXT[],
    groups TEXT[],
    token VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON user_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON user_invitations(email);

-- Add lifecycle columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false;
