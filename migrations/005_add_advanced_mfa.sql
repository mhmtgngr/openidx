-- Migration: Advanced MFA Features
-- Hardware Tokens, Biometrics, Phone Call, Device Trust Approval, Bypass Codes, Passwordless

-- =====================================================
-- 1. Hardware Token (YubiKey OATH-HOTP) Support
-- =====================================================

CREATE TABLE IF NOT EXISTS hardware_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255),
    token_type VARCHAR(50) NOT NULL DEFAULT 'yubikey', -- yubikey, oath-hotp, oath-totp
    secret_key VARCHAR(255) NOT NULL, -- Encrypted HOTP secret
    counter BIGINT DEFAULT 0, -- HOTP counter
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'available', -- available, assigned, revoked, lost
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMP WITH TIME ZONE,
    assigned_by UUID REFERENCES users(id),
    last_used_at TIMESTAMP WITH TIME ZONE,
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT
);

CREATE INDEX idx_hardware_tokens_serial ON hardware_tokens(serial_number);
CREATE INDEX idx_hardware_tokens_assigned ON hardware_tokens(assigned_to);
CREATE INDEX idx_hardware_tokens_status ON hardware_tokens(status);

-- Token usage audit log
CREATE TABLE IF NOT EXISTS hardware_token_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES hardware_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- assigned, unassigned, used, failed, revoked, lost_reported
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_token_events_token ON hardware_token_events(token_id);
CREATE INDEX idx_token_events_user ON hardware_token_events(user_id);

-- =====================================================
-- 2. Biometric Authentication Preferences
-- =====================================================

CREATE TABLE IF NOT EXISTS biometric_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    platform_authenticator_preferred BOOLEAN DEFAULT true,
    allow_cross_platform BOOLEAN DEFAULT true,
    require_user_verification BOOLEAN DEFAULT true,
    biometric_only_enabled BOOLEAN DEFAULT false, -- Can login with biometric only
    resident_key_required BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Biometric-only login policies
CREATE TABLE IF NOT EXISTS biometric_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    applies_to_groups UUID[], -- NULL means all users
    applies_to_roles VARCHAR(100)[],
    require_platform_authenticator BOOLEAN DEFAULT false,
    allowed_authenticator_types VARCHAR(50)[] DEFAULT ARRAY['platform', 'cross-platform'],
    min_authenticator_level VARCHAR(50) DEFAULT 'any', -- any, single, multi
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- 3. Phone Call Verification
-- =====================================================

CREATE TABLE IF NOT EXISTS mfa_phone_call (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL,
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    voice_language VARCHAR(10) DEFAULT 'en-US',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS phone_call_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(25) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    call_type VARCHAR(20) DEFAULT 'outbound', -- outbound, callback
    call_sid VARCHAR(100), -- Twilio call SID
    status VARCHAR(20) DEFAULT 'pending', -- pending, calling, answered, completed, failed
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_phone_challenges_user ON phone_call_challenges(user_id);
CREATE INDEX idx_phone_challenges_status ON phone_call_challenges(status);

-- =====================================================
-- 4. Admin Device Trust Approval
-- =====================================================

CREATE TABLE IF NOT EXISTS device_trust_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL, -- References known_devices
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    justification TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected, expired
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,
    auto_expire_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_trust_requests_user ON device_trust_requests(user_id);
CREATE INDEX idx_trust_requests_status ON device_trust_requests(status);
CREATE INDEX idx_trust_requests_pending ON device_trust_requests(status) WHERE status = 'pending';

-- Device trust approval settings
CREATE TABLE IF NOT EXISTS device_trust_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    require_approval BOOLEAN DEFAULT false, -- If true, all trust requests need admin approval
    auto_approve_known_ips BOOLEAN DEFAULT false,
    auto_approve_corporate_devices BOOLEAN DEFAULT false,
    request_expiry_hours INTEGER DEFAULT 72,
    notify_admins BOOLEAN DEFAULT true,
    notify_user_on_decision BOOLEAN DEFAULT true,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default settings
INSERT INTO device_trust_settings (id, require_approval, auto_approve_known_ips, request_expiry_hours)
VALUES (gen_random_uuid(), false, false, 72)
ON CONFLICT DO NOTHING;

-- =====================================================
-- 5. MFA Bypass Codes (Admin-generated)
-- =====================================================

CREATE TABLE IF NOT EXISTS mfa_bypass_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    generated_by UUID REFERENCES users(id) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 1,
    use_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active', -- active, used, expired, revoked
    used_at TIMESTAMP WITH TIME ZONE,
    used_from_ip VARCHAR(45),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_bypass_codes_user ON mfa_bypass_codes(user_id);
CREATE INDEX idx_bypass_codes_status ON mfa_bypass_codes(status);

-- Bypass code audit log
CREATE TABLE IF NOT EXISTS mfa_bypass_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bypass_code_id UUID REFERENCES mfa_bypass_codes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- generated, used, revoked, expired
    performed_by UUID REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_bypass_audit_user ON mfa_bypass_audit(user_id);

-- =====================================================
-- 6. Passwordless Authentication
-- =====================================================

-- Magic link tokens
CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) DEFAULT 'login', -- login, verify_email, link_device
    redirect_url TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- pending, used, expired
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_magic_links_token ON magic_links(token_hash);
CREATE INDEX idx_magic_links_user ON magic_links(user_id);
CREATE INDEX idx_magic_links_email ON magic_links(email);

-- QR code login sessions
CREATE TABLE IF NOT EXISTS qr_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) NOT NULL UNIQUE,
    qr_code_data TEXT NOT NULL, -- Encrypted payload
    status VARCHAR(20) DEFAULT 'pending', -- pending, scanned, approved, rejected, expired
    user_id UUID REFERENCES users(id), -- Set when user scans and approves
    browser_info JSONB, -- Info about the browser requesting login
    mobile_info JSONB, -- Info about the mobile device that scanned
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_qr_sessions_token ON qr_login_sessions(session_token);
CREATE INDEX idx_qr_sessions_status ON qr_login_sessions(status);

-- Passwordless user preferences
CREATE TABLE IF NOT EXISTS passwordless_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webauthn_only BOOLEAN DEFAULT false, -- Can login with WebAuthn without password
    magic_link_enabled BOOLEAN DEFAULT true,
    qr_login_enabled BOOLEAN DEFAULT true,
    preferred_method VARCHAR(50) DEFAULT 'webauthn', -- webauthn, magic_link, qr_code
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- Views and Indexes
-- =====================================================

-- View for available hardware tokens
CREATE OR REPLACE VIEW available_hardware_tokens AS
SELECT
    id, serial_number, name, token_type, manufacturer, model,
    firmware_version, created_at
FROM hardware_tokens
WHERE status = 'available';

-- View for pending device trust requests
CREATE OR REPLACE VIEW pending_device_trust_requests AS
SELECT
    dtr.*,
    u.email as user_email,
    u.first_name || ' ' || u.last_name as user_name
FROM device_trust_requests dtr
JOIN users u ON dtr.user_id = u.id
WHERE dtr.status = 'pending'
ORDER BY dtr.created_at ASC;

-- View for active bypass codes
CREATE OR REPLACE VIEW active_bypass_codes AS
SELECT
    bc.*,
    u.email as user_email,
    g.email as generated_by_email
FROM mfa_bypass_codes bc
JOIN users u ON bc.user_id = u.id
JOIN users g ON bc.generated_by = g.id
WHERE bc.status = 'active'
  AND bc.valid_until > NOW()
  AND (bc.max_uses IS NULL OR bc.use_count < bc.max_uses);
