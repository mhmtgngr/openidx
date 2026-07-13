package migrations

// Migration v83 — SAML service-provider schema reconcile.
//
// internal/oauth/saml_sp.go (list/get/create/update) reads and writes columns
// that no prior migration ever added to saml_service_providers, so the SP admin
// list/create/update paths error with SQLSTATE 42703 (column does not exist).
// This reconciles the table to what the code expects:
//
//   - description            free-text SP description (list query scans it un-COALESCEd)
//   - metadata_url           SP metadata URL
//   - want_assertions_signed require signed SAML assertions
//   - encryption_enabled     encrypt SAML assertions to the SP
//   - last_used_at           last successful SSO through this SP (nullable)
//
// Additive and idempotent (ADD COLUMN IF NOT EXISTS). TEXT columns get NOT NULL
// DEFAULT '' so existing rows satisfy the un-COALESCEd list scan; booleans
// default false; last_used_at is nullable (no default). saml_service_providers
// is already org-scoped under the FORCE-RLS belt, so no new policy is needed.
// Plain statements only (splitSQL cannot handle DO $$).
var samlSPReconcileUp = `-- Migration 083: reconcile saml_service_providers columns to the oauth code.
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS description            TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS metadata_url           TEXT NOT NULL DEFAULT '';
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS want_assertions_signed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS encryption_enabled     BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS last_used_at           TIMESTAMPTZ;`

var samlSPReconcileDown = `-- Rollback 083.
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS encryption_enabled;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS want_assertions_signed;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS metadata_url;
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS description;`
