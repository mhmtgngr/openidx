-- Migration: Risk Events Table for Real-time Risk-Based Authentication
-- Description: Creates table for tracking risk events (FR-M009)
--              Supports real-time risk-based authentication decisions

CREATE TABLE IF NOT EXISTS risk_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id TEXT,
    event_type VARCHAR(50) NOT NULL, -- impossible_travel, new_device, blocked_ip, brute_force, anomaly
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    action_taken VARCHAR(50), -- allow, mfa_required, blocked, password_reset
    ip_address VARCHAR(45),
    user_agent TEXT,
    location_country VARCHAR(2),
    location_city VARCHAR(100),
    details JSONB DEFAULT '{}'::jsonb,
    resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_events_user_id ON risk_events(user_id);
CREATE INDEX IF NOT EXISTS idx_risk_events_event_type ON risk_events(event_type);
CREATE INDEX IF NOT EXISTS idx_risk_events_created_at ON risk_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_unresolved ON risk_events(resolved) WHERE resolved = false;
CREATE INDEX IF NOT EXISTS idx_risk_events_risk_score ON risk_events(risk_score DESC);

COMMENT ON TABLE risk_events IS 'Risk events for real-time risk-based authentication (FR-M009)';
