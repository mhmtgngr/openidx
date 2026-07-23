package migrations

// Migration v96 — HR-driven JML (Joiner/Mover/Leaver) user attributes.
//
// OpenIDX can already sync users from LDAP/AD and Azure AD, but the HR system
// (Workday/BambooHR/SuccessFactors) is the real source of truth for the
// employee lifecycle: it is where a joiner first appears, where a mover's
// department/title/manager changes, and where a leaver is terminated. Wiring an
// HR source lets those events drive provisioning/deprovisioning end to end.
//
// This migration adds the HR attributes to users so an HRIS connector
// (modeled as a directory-connector type) can land them, and so downstream
// consumers (outbound SCIM enterprise extension, access reviews, reporting) can
// read a real org chart. It also records, per directory, the external HR id so
// re-syncs update the right row.
//
// Additive + idempotent. NULL for every existing user; no behavior change until
// an HR source is configured.
var hrJmlUp = `-- Migration 096: HR-driven JML user attributes.
ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_number   VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title         VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS department        VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS hire_date         DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS termination_date  DATE;
-- employment_status is the HRIS lifecycle state: 'active' | 'terminated' |
-- 'on_leave' | 'pending'. NULL means "not HR-sourced".
ALTER TABLE users ADD COLUMN IF NOT EXISTS employment_status VARCHAR(32);
-- external_hr_id is the HRIS-assigned id (e.g. BambooHR employee id). Distinct
-- from ldap_dn / external_id (Azure objectId): a user could be sourced from an
-- HR system independent of a directory. Indexed per (directory_id, id) so a
-- re-sync finds the existing row without scanning.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_hr_id    VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_users_external_hr_id
    ON users(directory_id, external_hr_id)
    WHERE external_hr_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_employment_status
    ON users(employment_status)
    WHERE employment_status IS NOT NULL;
`

var hrJmlDown = `-- Rollback 096: HR-driven JML user attributes.
DROP INDEX IF EXISTS idx_users_employment_status;
DROP INDEX IF EXISTS idx_users_external_hr_id;
ALTER TABLE users DROP COLUMN IF EXISTS external_hr_id;
ALTER TABLE users DROP COLUMN IF EXISTS employment_status;
ALTER TABLE users DROP COLUMN IF EXISTS termination_date;
ALTER TABLE users DROP COLUMN IF EXISTS hire_date;
ALTER TABLE users DROP COLUMN IF EXISTS department;
ALTER TABLE users DROP COLUMN IF EXISTS job_title;
ALTER TABLE users DROP COLUMN IF EXISTS employee_number;
`
