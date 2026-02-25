-- Rollback: WebAuthn Security Hardening
-- Description: Removes the WebAuthn security tables and triggers

-- Drop triggers first
DROP TRIGGER IF EXISTS webauthn_audit_trigger ON webauthn_credentials;

-- Drop function
DROP FUNCTION IF EXISTS webauthn_audit_trigger_func();

-- Drop views
DROP VIEW IF EXISTS webauthn_suspicious_activity CASCADE;
DROP VIEW IF EXISTS user_webauthn_security_summary CASCADE;
DROP VIEW IF EXISTS active_webauthn_credentials CASCADE;

-- Drop tables
DROP TABLE IF EXISTS webauthn_failed_attempts CASCADE;
DROP TABLE IF EXISTS webauthn_audit_log CASCADE;
DROP TABLE IF EXISTS webauthn_sessions CASCADE;
DROP TABLE IF EXISTS webauthn_credentials CASCADE;
