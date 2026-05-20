-- 202605150002: Tag posture_checks with the platforms they apply to and seed the
-- Android-native checks shipped with the unified Android client. Config delivery
-- (HandleConfig in /internal/access/agent_api.go) filters by the agent's
-- "platform" column so each client only sees its applicable checks.

ALTER TABLE posture_checks
    ADD COLUMN IF NOT EXISTS platforms JSONB
        NOT NULL DEFAULT '["linux","macos","windows"]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_posture_checks_platforms
    ON posture_checks USING GIN (platforms);

-- Tag existing seeded checks that don't apply to Android.
UPDATE posture_checks
   SET platforms = '["linux","macos","windows"]'::jsonb
 WHERE check_type IN ('firewall', 'antivirus', 'process_running', 'process');

-- Cross-platform checks (already correct by default for the three desktop OSes).
-- Re-tag explicitly so future migrations / seed scripts know they cover Android too.
UPDATE posture_checks
   SET platforms = '["linux","macos","windows","android","ios"]'::jsonb
 WHERE check_type IN ('os_version', 'screen_lock', 'disk_encryption', 'agent_version');

UPDATE posture_checks
   SET platforms = '["linux","macos","windows","android"]'::jsonb
 WHERE check_type IN ('patch_level');

-- Seed Android-specific checks. ON CONFLICT (name) keeps the migration idempotent
-- when reseeded; the unique constraint on posture_checks.name is enforced via
-- a partial unique index added below if it doesn't already exist.
CREATE UNIQUE INDEX IF NOT EXISTS uq_posture_checks_name
    ON posture_checks(name);

INSERT INTO posture_checks (name, check_type, parameters, enabled, severity, remediation_hint, platforms)
VALUES
    ('Android: Play Integrity',
     'play_integrity',
     '{"require_meets_device_integrity": true, "require_meets_basic_integrity": true}'::jsonb,
     true,
     'critical',
     'Device fails Google Play Integrity attestation. Possible root, custom ROM, or compromised state.',
     '["android"]'::jsonb),

    ('Android: Play Protect',
     'play_protect',
     '{"require_enabled": true}'::jsonb,
     true,
     'high',
     'Enable Google Play Protect in Play Store settings to receive app-scanning protection.',
     '["android"]'::jsonb),

    ('Android: Developer options disabled',
     'developer_options',
     '{"allow_when": "device_owner"}'::jsonb,
     true,
     'medium',
     'Disable Developer options unless explicitly required by IT.',
     '["android"]'::jsonb),

    ('Android: Unknown sources blocked',
     'unknown_sources',
     '{}'::jsonb,
     true,
     'high',
     'Disable installation from unknown sources for all user app stores.',
     '["android"]'::jsonb),

    ('Android: Enterprise managed',
     'enterprise_managed',
     '{"require_device_owner_or_profile_owner": true}'::jsonb,
     true,
     'medium',
     'Device is not enrolled as Device Owner or Profile Owner. Re-enroll via QR or work-profile setup.',
     '["android","ios"]'::jsonb),

    ('Android: Accessibility services audit',
     'accessibility_audit',
     '{"allowlist_packages": ["com.openidx.agent"]}'::jsonb,
     true,
     'medium',
     'Unexpected Accessibility Service detected. Verify the app is approved by IT.',
     '["android"]'::jsonb)

ON CONFLICT (name) DO UPDATE
    SET platforms = EXCLUDED.platforms,
        parameters = EXCLUDED.parameters,
        severity = EXCLUDED.severity,
        remediation_hint = EXCLUDED.remediation_hint,
        updated_at = NOW();
