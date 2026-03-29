-- Migration 022: Security Alerts and Anomaly Detection

CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB,
    source_ip VARCHAR(45),
    remediation_actions JSONB DEFAULT '[]',
    resolved_by UUID,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_threat_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    threat_type VARCHAR(50) NOT NULL,
    reason TEXT,
    blocked_until TIMESTAMP WITH TIME ZONE,
    permanent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_threat_list_ip ON ip_threat_list(ip_address);

-- Seed audit events for demo/testing
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, resource_id, details)
VALUES
  (gen_random_uuid(), NOW() - INTERVAL '6 days 14 hours', 'system', 'operational', 'system_startup', 'success',
   'system', 'system', '127.0.0.1', '', 'system', '', '{"message": "OpenIDX platform initialized"}'),
  (gen_random_uuid(), NOW() - INTERVAL '5 days 10 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '3 days 12 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '1 day 15 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '6 hours', 'authentication', 'security', 'login', 'success',
   '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.20', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}');
