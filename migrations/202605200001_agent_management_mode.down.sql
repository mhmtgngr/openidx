DROP INDEX IF EXISTS idx_enrolled_agents_management_mode;

ALTER TABLE enrolled_agents
    DROP COLUMN IF EXISTS management_mode;
