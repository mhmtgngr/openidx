DELETE FROM posture_checks
 WHERE check_type IN (
    'play_integrity',
    'play_protect',
    'developer_options',
    'unknown_sources',
    'enterprise_managed',
    'accessibility_audit'
 );

DROP INDEX IF EXISTS uq_posture_checks_name;
DROP INDEX IF EXISTS idx_posture_checks_platforms;

ALTER TABLE posture_checks
    DROP COLUMN IF EXISTS platforms;
