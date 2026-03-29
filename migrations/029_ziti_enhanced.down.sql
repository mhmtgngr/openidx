-- Rollback 029: OpenZiti Enhanced Features

DROP INDEX IF EXISTS idx_ziti_certificates_expires;
DROP INDEX IF EXISTS idx_ziti_certificates_identity;
DROP TABLE IF EXISTS ziti_certificates;
DROP INDEX IF EXISTS idx_policy_sync_status;
DROP INDEX IF EXISTS idx_policy_sync_governance;
DROP TABLE IF EXISTS policy_sync_state;
DROP INDEX IF EXISTS idx_posture_results_check;
DROP INDEX IF EXISTS idx_posture_results_identity;
DROP TABLE IF EXISTS device_posture_results;
DROP TABLE IF EXISTS posture_checks;
DROP TABLE IF NOT EXISTS posture_check_types;
