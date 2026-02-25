-- Migration: Add GenAI Attack Detection, Passwordless Auth, Continuous Auth, and IBDR tables
-- Version: 017
-- Created: 2025-02-25

-- ====================================================================
-- GenAI Attack Detection Tables
-- ====================================================================

-- GenAI audit logs for tracking AI/LLM requests
CREATE TABLE IF NOT EXISTS genai_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    agent_id VARCHAR(255),
    prompt TEXT NOT NULL,
    response TEXT,
    attack_detected BOOLEAN DEFAULT FALSE,
    attack_types JSONB,
    severity VARCHAR(50),
    risk_score FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    session_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_genai_audit_user ON genai_audit_logs(user_id);
CREATE INDEX idx_genai_audit_agent ON genai_audit_logs(agent_id);
CREATE INDEX idx_genai_audit_attack ON genai_audit_logs(attack_detected);
CREATE INDEX idx_genai_audit_created ON genai_audit_logs(created_at);

-- GenAI attack incidents
CREATE TABLE IF NOT EXISTS genai_attack_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    agent_id VARCHAR(255),
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    reasons JSONB,
    matched_patterns JSONB,
    suggested_actions JSONB,
    risk_score FLOAT,
    ip_address VARCHAR(45),
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_genai_incident_user ON genai_attack_incidents(user_id);
CREATE INDEX idx_genai_incident_type ON genai_attack_incidents(attack_type);
CREATE INDEX idx_genai_incident_severity ON genai_attack_incidents(severity);
CREATE INDEX idx_genai_incident_created ON genai_attack_incidents(created_at);

-- GenAI security rules
CREATE TABLE IF NOT EXISTS genai_security_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    attack_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    patterns JSONB,
    keywords JSONB,
    action VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================================================
-- AI Policy Recommendations Tables
-- ====================================================================

-- Access pattern analysis results
CREATE TABLE IF NOT EXISTS access_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    role_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    last_accessed TIMESTAMP WITH TIME ZONE,
    access_count BIGINT DEFAULT 0,
    access_frequency FLOAT DEFAULT 0,
    average_session FLOAT DEFAULT 0,
    is_unused BOOLEAN DEFAULT FALSE,
    is_rarely_used BOOLEAN DEFAULT FALSE,
    is_heavily_used BOOLEAN DEFAULT FALSE,
    peak_usage_hours INT[],
    anomaly_score FLOAT DEFAULT 0,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_access_pattern_unique ON access_patterns(user_id, role_id, resource_type);
CREATE INDEX idx_access_pattern_user ON access_patterns(user_id);
CREATE INDEX idx_access_pattern_unused ON access_patterns(is_unused) WHERE is_unused = TRUE;

-- Policy recommendations
CREATE TABLE IF NOT EXISTS policy_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(100) NOT NULL,
    priority VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    estimated_effort VARCHAR(50),
    confidence FLOAT NOT NULL,
    reasoning JSONB,
    affected_users INT DEFAULT 0,
    affected_roles INT DEFAULT 0,
    affected_resources JSONB,
    metadata JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    implemented_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_policy_recommendation_status ON policy_recommendations(status);
CREATE INDEX idx_policy_recommendation_priority ON policy_recommendations(priority);
CREATE INDEX idx_policy_recommendation_type ON policy_recommendations(type);

-- Compliance gaps
CREATE TABLE IF NOT EXISTS compliance_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    standard VARCHAR(100) NOT NULL,
    control_id VARCHAR(255) NOT NULL,
    control_name TEXT NOT NULL,
    current_state TEXT,
    desired_state TEXT,
    gap_description TEXT,
    remediation_plan TEXT,
    priority VARCHAR(50) NOT NULL,
    estimated_effort INT DEFAULT 0,
    due_date DATE,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_compliance_gap_standard ON compliance_gaps(standard);
CREATE INDEX idx_compliance_gap_status ON compliance_gaps(status);
CREATE INDEX idx_compliance_gap_priority ON compliance_gaps(priority);

-- ====================================================================
-- Passwordless Authentication Tables
-- ====================================================================

-- Passwordless challenges
CREATE TABLE IF NOT EXISTS passwordless_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    method VARCHAR(50) NOT NULL,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    metadata JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_passwordless_challenge_user ON passwordless_challenges(user_id);
CREATE INDEX idx_passwordless_challenge_expires ON passwordless_challenges(expires_at);
CREATE INDEX idx_passwordless_challenge_status ON passwordless_challenges(status);

-- Passkey (WebAuthn) credentials
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key JSONB NOT NULL,
    attestation_type VARCHAR(100),
    aaguid VARCHAR(255),
    sign_count BIGINT DEFAULT 0,
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE,
    name VARCHAR(255),
    device_type VARCHAR(50) DEFAULT 'single_device',
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_passkey_user ON passkey_credentials(user_id);

-- Magic links for passwordless auth
CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    redirect_url TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_magic_link_user ON magic_links(user_id);
CREATE INDEX idx_magic_link_token ON magic_links(token);
CREATE INDEX idx_magic_link_expires ON magic_links(expires_at);

-- SMS OTP for passwordless auth
CREATE TABLE IF NOT EXISTS sms_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50) NOT NULL,
    code VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sms_otp_user ON sms_otps(user_id);
CREATE INDEX idx_sms_otp_expires ON sms_otps(expires_at);

-- Push notifications for passwordless auth
CREATE TABLE IF NOT EXISTS push_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    challenge_id UUID REFERENCES passwordless_challenges(id),
    status VARCHAR(50) DEFAULT 'pending',
    approved BOOLEAN,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_push_notification_user ON push_notifications(user_id);
CREATE INDEX idx_push_notification_challenge ON push_notifications(challenge_id);

-- Passwordless sessions
CREATE TABLE IF NOT EXISTS passwordless_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    challenge_id UUID REFERENCES passwordless_challenges(id),
    method VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'initiated',
    verified_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    device_trust VARCHAR(50) DEFAULT 'unknown',
    remember_device BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_passwordless_session_user ON passwordless_sessions(user_id);
CREATE INDEX idx_passwordless_session_expires ON passwordless_sessions(expires_at);

-- ====================================================================
-- Continuous Authentication Tables
-- ====================================================================

-- Authentication contexts for continuous auth
CREATE TABLE IF NOT EXISTS auth_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(255) NOT NULL,
    auth_time TIMESTAMP WITH TIME ZONE NOT NULL,
    auth_method VARCHAR(100) NOT NULL,
    auth_strength VARCHAR(50) DEFAULT 'medium',
    current_risk_score FLOAT DEFAULT 0,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    location JSONB,
    user_agent TEXT,
    metadata JSONB,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_auth_context_session ON auth_contexts(session_id);
CREATE INDEX idx_auth_context_user ON auth_contexts(user_id);

-- Session risk calculations
CREATE TABLE IF NOT EXISTS session_risks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) NOT NULL,
    overall_risk FLOAT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    action_required VARCHAR(50) NOT NULL,
    risk_factors JSONB,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    previous_risk FLOAT DEFAULT 0,
    risk_delta FLOAT DEFAULT 0
);

CREATE INDEX idx_session_risk_session ON session_risks(session_id);
CREATE INDEX idx_session_risk_level ON session_risks(risk_level);
CREATE INDEX idx_session_risk_calculated ON session_risks(calculated_at);

-- Risk factors tracking
CREATE TABLE IF NOT EXISTS risk_factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255),
    type VARCHAR(100) NOT NULL,
    severity FLOAT NOT NULL,
    description TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_risk_factor_session ON risk_factors(session_id);
CREATE INDEX idx_risk_factor_resolved ON risk_factors(resolved);

-- User devices for continuous auth
CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(100),
    trusted BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_user_device_fingerprint ON user_devices(user_id, device_fingerprint);

-- ====================================================================
-- Identity Breach Detection & Response Tables
-- ====================================================================

-- Breach incidents
CREATE TABLE IF NOT EXISTS breach_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'detected',
    title TEXT NOT NULL,
    description TEXT,
    affected_user_ids JSONB,
    affected_sessions JSONB,
    affected_resources JSONB,
    detection_method VARCHAR(100),
    first_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    confidence FLOAT NOT NULL,
    indicators JSONB,
    metadata JSONB,
    assigned_to VARCHAR(255),
    quarantine_action VARCHAR(50) DEFAULT 'none',
    containment_steps JSONB,
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_breach_incident_status ON breach_incidents(status);
CREATE INDEX idx_breach_incident_severity ON breach_incidents(severity);
CREATE INDEX idx_breach_incident_type ON breach_incidents(type);
CREATE INDEX idx_breach_incident_created ON breach_incidents(created_at);

-- Breach alerts
CREATE TABLE IF NOT EXISTS breach_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES breach_incidents(id),
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(255),
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    acked_at TIMESTAMP WITH TIME ZONE,
    acked_by VARCHAR(255)
);

CREATE INDEX idx_breach_alert_incident ON breach_alerts(incident_id);
CREATE INDEX idx_breach_alert_acknowledged ON breach_alerts(acknowledged);

-- Blocked IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT,
    blocked_by VARCHAR(255),
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    permanent BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_blocked_ip_expires ON blocked_ips(expires_at);

-- User monitoring for enhanced tracking
CREATE TABLE IF NOT EXISTS user_monitoring (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    level VARCHAR(50) NOT NULL,
    reason VARCHAR(255),
    incident_id UUID,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_user_monitoring_user ON user_monitoring(user_id);
CREATE INDEX idx_user_monitoring_enabled ON user_monitoring(enabled);

-- Quarantine actions audit
CREATE TABLE IF NOT EXISTS quarantine_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES breach_incidents(id),
    user_id VARCHAR(255),
    action_type VARCHAR(100) NOT NULL,
    description TEXT,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    executed_by VARCHAR(255),
    reversible BOOLEAN DEFAULT FALSE,
    reversed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_quarantine_action_incident ON quarantine_actions(incident_id);
