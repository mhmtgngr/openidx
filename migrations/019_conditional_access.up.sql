-- Migration 019: Conditional Access and Risk Engine

-- Known/trusted devices per user
CREATE TABLE IF NOT EXISTS known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    trusted BOOLEAN DEFAULT false,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_known_devices_user ON known_devices(user_id);

-- Login history for risk analysis
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    location VARCHAR(255),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    device_fingerprint VARCHAR(128),
    risk_score INTEGER DEFAULT 0,
    success BOOLEAN NOT NULL,
    auth_methods TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, created_at DESC);

-- Step-up MFA challenges
CREATE TABLE IF NOT EXISTS stepup_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stepup_user ON stepup_challenges(user_id, status);

-- Enhance proxy_sessions with risk context
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(128);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);
