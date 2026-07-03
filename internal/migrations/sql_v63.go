package migrations

// Migration v63 — reconcile init-db<->migrations COLUMN drift (readiness W2.9).
//
// The table-level TestInitDBParity guard (v54/#257) closed table drift, but
// columns could still diverge: init-db.sql accumulated `ALTER TABLE ... ADD COLUMN
// IF NOT EXISTS` patches over time that were never mirrored into a migration, so
// migrate-only installs (RDS/Helm/`migrate up`, which never run init-db.sql) were
// missing columns the code and init-db expect. TestInitDBColumnParity (added with
// this migration) now fails CI on any such drift. This reconciles every column the
// column-parity guard flagged:
//
//   - ziti_certificates: the original migration schema (cert_data NOT NULL,
//     private_key_encrypted, ca_chain, expires_at, identity_id) diverged wholesale
//     from the code/init-db schema; internal/access/ziti_hardening.go queries the
//     latter, and cert_data's NOT NULL broke the code's INSERT on migrate-only
//     installs. We add the 12 real columns + indexes and drop the 5 stale ones.
//   - application_sso_settings, directory_sync_state, ip_threat_list, oauth_clients,
//     user_roles, user_sessions, users, ziti_service_policies: add the columns
//     init-db.sql adds via ALTER but no migration did (mirrored verbatim).
//
// All statements are idempotent (ADD COLUMN IF NOT EXISTS / DROP COLUMN IF EXISTS /
// CREATE INDEX IF NOT EXISTS) and plain (splitSQL cannot handle DO $$ blocks).
// init-db.sql already defines all of these, so it needs no change and
// TestInitDB(Column)Parity is green after this migration.
var columnDriftReconcileUp = `-- Migration 063: reconcile init-db<->migrations column drift.

-- ziti_certificates: bring the stale migration schema up to the code/init-db schema.
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS cert_type              VARCHAR(50);
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS subject                VARCHAR(500);
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS issuer                 VARCHAR(500);
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS serial_number          VARCHAR(255);
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS fingerprint            VARCHAR(255) UNIQUE;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS not_before             TIMESTAMP WITH TIME ZONE;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS not_after              TIMESTAMP WITH TIME ZONE;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS auto_renew             BOOLEAN DEFAULT false;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS renewal_threshold_days INTEGER DEFAULT 30;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS pem_data               TEXT;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS status                 VARCHAR(50) DEFAULT 'active';
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS associated_identity_id UUID REFERENCES ziti_identities(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_ziti_certs_expiry ON ziti_certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_ziti_certs_status ON ziti_certificates(status);
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS cert_data;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS private_key_encrypted;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS ca_chain;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS expires_at;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS identity_id;

-- application_sso_settings: session-policy columns added only in init-db.
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS absolute_timeout                INTEGER DEFAULT 86400;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS bind_ip                         BOOLEAN DEFAULT false;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS concurrent_session_strategy     VARCHAR(20) DEFAULT 'deny_new';
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS force_logout_on_password_change BOOLEAN DEFAULT true;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS idle_timeout                    INTEGER DEFAULT 1800;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS max_concurrent_sessions         INTEGER DEFAULT 0;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS reauth_interval                 INTEGER DEFAULT 0;
ALTER TABLE application_sso_settings ADD COLUMN IF NOT EXISTS remember_me_duration            INTEGER DEFAULT 2592000;

-- directory_sync_state: Graph delta-link cursor.
ALTER TABLE directory_sync_state ADD COLUMN IF NOT EXISTS last_delta_link TEXT;

-- ip_threat_list: enable/disable flag.
ALTER TABLE ip_threat_list ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

-- oauth_clients: OIDC logout URIs.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS back_channel_logout_uri  VARCHAR(500);
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS front_channel_logout_uri VARCHAR(500);

-- user_roles: expiry-notification flag for the role-expiry cleaner.
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expiry_notified BOOLEAN DEFAULT false;

-- user_sessions: risk/device/location enrichment.
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS risk_score   INTEGER DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_name  VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_type  VARCHAR(50);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS location     VARCHAR(255);

-- users: SCIM/directory external id.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);

-- ziti_service_policies: system flag + posture-check roles.
ALTER TABLE ziti_service_policies ADD COLUMN IF NOT EXISTS is_system           BOOLEAN DEFAULT false;
ALTER TABLE ziti_service_policies ADD COLUMN IF NOT EXISTS posture_check_roles JSONB DEFAULT '[]';
`

// Down: reverse only the ziti_certificates schema swap (the one genuine change).
// The other ADD COLUMNs mirror columns init-db.sql defines independently, so
// dropping them would DIVERGE a compose/init-db install from its own schema and
// could destroy live data (e.g. users.external_id from directory sync); they are
// intentionally left in place.
var columnDriftReconcileDown = `-- Migration 063 down (ziti_certificates only; see note in sql_v63.go).
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS cert_data             TEXT;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS private_key_encrypted TEXT;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS ca_chain              TEXT;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS expires_at            TIMESTAMP WITH TIME ZONE;
ALTER TABLE ziti_certificates ADD COLUMN IF NOT EXISTS identity_id           UUID;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS associated_identity_id;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS status;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS pem_data;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS renewal_threshold_days;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS auto_renew;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS not_after;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS not_before;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS fingerprint;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS serial_number;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS issuer;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS subject;
ALTER TABLE ziti_certificates DROP COLUMN IF EXISTS cert_type;
`
