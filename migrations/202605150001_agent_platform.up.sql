-- 202605150001: Add platform / form factor / Device Owner / OAuth-enrollment columns
-- to enrolled_agents so a single records table can serve all client types
-- (Go agent on Linux/macOS/Windows + native Android client + future iOS/etc.).

ALTER TABLE enrolled_agents
    ADD COLUMN IF NOT EXISTS platform              VARCHAR(32),
    ADD COLUMN IF NOT EXISTS form_factor           VARCHAR(32),
    ADD COLUMN IF NOT EXISTS is_device_owner       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS enrollment_method     VARCHAR(32),
    ADD COLUMN IF NOT EXISTS enrolled_by_user_id   UUID REFERENCES users(id) ON DELETE SET NULL;

-- Backfill platform from existing metadata JSONB when present.
UPDATE enrolled_agents
   SET platform = LOWER(metadata->>'platform')
 WHERE platform IS NULL
   AND metadata ? 'platform'
   AND metadata->>'platform' <> '';

-- Normalize any legacy values to a known set; everything unrecognised becomes 'unknown'.
UPDATE enrolled_agents
   SET platform = CASE LOWER(platform)
       WHEN 'linux'   THEN 'linux'
       WHEN 'darwin'  THEN 'macos'
       WHEN 'macos'   THEN 'macos'
       WHEN 'windows' THEN 'windows'
       WHEN 'android' THEN 'android'
       WHEN 'ios'     THEN 'ios'
       ELSE 'unknown'
   END
 WHERE platform IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_platform
    ON enrolled_agents(platform);

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_enrolled_by_user
    ON enrolled_agents(enrolled_by_user_id);
