-- Rollback: Remove GenAI Attack Detection, Passwordless Auth, Continuous Auth, and IBDR tables
-- Version: 017

-- Drop tables in reverse order of creation due to dependencies

DROP TABLE IF EXISTS quarantine_actions CASCADE;
DROP TABLE IF EXISTS user_monitoring CASCADE;
DROP TABLE IF EXISTS blocked_ips CASCADE;
DROP TABLE IF EXISTS breach_alerts CASCADE;
DROP TABLE IF EXISTS breach_incidents CASCADE;
DROP TABLE IF EXISTS risk_factors CASCADE;
DROP TABLE IF EXISTS session_risks CASCADE;
DROP TABLE IF EXISTS user_devices CASCADE;
DROP TABLE IF EXISTS auth_contexts CASCADE;
DROP TABLE IF EXISTS passwordless_sessions CASCADE;
DROP TABLE IF EXISTS push_notifications CASCADE;
DROP TABLE IF EXISTS sms_otps CASCADE;
DROP TABLE IF EXISTS magic_links CASCADE;
DROP TABLE IF EXISTS passkey_credentials CASCADE;
DROP TABLE IF EXISTS passwordless_challenges CASCADE;
DROP TABLE IF EXISTS compliance_gaps CASCADE;
DROP TABLE IF EXISTS policy_recommendations CASCADE;
DROP TABLE IF EXISTS access_patterns CASCADE;
DROP TABLE IF EXISTS genai_security_rules CASCADE;
DROP TABLE IF EXISTS genai_attack_incidents CASCADE;
DROP TABLE IF EXISTS genai_audit_logs CASCADE;
