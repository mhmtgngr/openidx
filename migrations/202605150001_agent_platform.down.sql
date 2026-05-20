DROP INDEX IF EXISTS idx_enrolled_agents_enrolled_by_user;
DROP INDEX IF EXISTS idx_enrolled_agents_platform;

ALTER TABLE enrolled_agents
    DROP COLUMN IF EXISTS enrolled_by_user_id,
    DROP COLUMN IF EXISTS enrollment_method,
    DROP COLUMN IF EXISTS is_device_owner,
    DROP COLUMN IF EXISTS form_factor,
    DROP COLUMN IF EXISTS platform;
