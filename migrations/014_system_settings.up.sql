-- Migration 014: System Settings

CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID
);

-- Seed default system settings
INSERT INTO system_settings (key, value) VALUES
('system', '{
    "general": {
        "organization_name": "OpenIDX",
        "support_email": "support@openidx.io",
        "default_language": "en",
        "default_timezone": "UTC"
    },
    "security": {
        "password_policy": {
            "min_length": 12,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_numbers": true,
            "require_special": true,
            "max_age": 90,
            "history": 5
        },
        "session_timeout": 30,
        "max_failed_logins": 5,
        "lockout_duration": 15,
        "require_mfa": false,
        "blocked_countries": []
    },
    "authentication": {
        "allow_registration": true,
        "require_email_verify": true,
        "mfa_methods": ["totp", "webauthn", "sms"]
    },
    "branding": {
        "primary_color": "#2563eb",
        "secondary_color": "#1e40af",
        "login_page_title": "Welcome to OpenIDX"
    }
}'::jsonb),
('mfa_methods', '["totp", "webauthn", "sms"]'::jsonb),
('browzer_domain_config', '{
    "domain": "browzer.localtest.me",
    "cert_type": "self_signed",
    "cert_subject": "",
    "cert_issuer": "",
    "cert_not_before": "",
    "cert_not_after": "",
    "cert_fingerprint": "",
    "cert_san": [],
    "custom_cert_uploaded_at": null,
    "previous_domain": null,
    "domain_changed_at": null
}'::jsonb)
ON CONFLICT (key) DO NOTHING;
