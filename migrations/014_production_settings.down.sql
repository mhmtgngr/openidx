-- OpenIDX Production Settings Rollback
-- Version: 014
-- Description: Rollback production settings

-- ============================================================================
-- DROP FUNCTIONS
-- ============================================================================

DROP FUNCTION IF EXISTS get_user_security_policy(UUID);
DROP FUNCTION IF EXISTS is_feature_enabled(VARCHAR, UUID);

-- ============================================================================
-- DROP INDEXES
-- ============================================================================

DROP INDEX IF EXISTS idx_group_policy_assignments_policy;
DROP INDEX IF EXISTS idx_group_policy_assignments_group;
DROP INDEX IF EXISTS idx_user_policy_assignments_policy;
DROP INDEX IF EXISTS idx_user_policy_assignments_user;
DROP INDEX IF EXISTS idx_security_policies_priority;
DROP INDEX IF EXISTS idx_security_policies_enabled;
DROP INDEX IF EXISTS idx_compliance_jurisdiction;
DROP INDEX IF EXISTS idx_feature_flags_name;
DROP INDEX IF EXISTS idx_feature_flags_enabled;

-- ============================================================================
-- DROP TABLES
-- ============================================================================

DROP TABLE IF EXISTS group_policy_assignments;
DROP TABLE IF EXISTS user_policy_assignments;
DROP TABLE IF EXISTS security_policies;
DROP TABLE IF EXISTS compliance_settings;
DROP TABLE IF EXISTS feature_flags;
