-- Migration: Add missing columns for production deployment
-- Fixes database schema mismatches between init-db.sql and existing databases

-- =====================================================
-- 1. Add device_trusted to proxy_sessions if missing
-- =====================================================
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;

-- =====================================================
-- 2. Add labels to ziti_metrics if missing
-- =====================================================
ALTER TABLE ziti_metrics ADD COLUMN IF NOT EXISTS labels JSONB DEFAULT '{}';

-- =====================================================
-- 3. Add device_trusted to user_sessions for session management UI
-- =====================================================
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);

-- =====================================================
-- 4. Add indexes for performance
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_device_trusted ON proxy_sessions(device_trusted);
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
CREATE INDEX IF NOT EXISTS idx_user_sessions_risk_score ON user_sessions(risk_score);

-- =====================================================
-- 5. Create trusted_browsers table if not exists
-- =====================================================
CREATE TABLE IF NOT EXISTS trusted_browsers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    browser_hash VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    trusted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    UNIQUE(user_id, browser_hash)
);

CREATE INDEX IF NOT EXISTS idx_trusted_browsers_user ON trusted_browsers(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_hash ON trusted_browsers(browser_hash);

-- =====================================================
-- 6. Create risk_policies table if not exists
-- =====================================================
CREATE TABLE IF NOT EXISTS risk_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_policies_enabled ON risk_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_risk_policies_priority ON risk_policies(priority);
