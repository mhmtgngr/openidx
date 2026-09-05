package migrations

// Migration v140 — close fifteen gaps in the FORCE-RLS belt.
//
// The v37 belt (extended by v81, v94, v121 and v138) is what makes the tenant
// boundary a property of the database rather than a property of every query
// anyone will ever write. Tables added after each of those migrations drifted
// out of it: they carry org_id, the application filters on it, and nothing
// underneath checks. A single future query that forgets `AND org_id = $N`
// crosses tenants silently, which is precisely how the ISPM and AI tables
// v138 fixed went nine releases unnoticed.
//
// tools/orgscope counts that drift: 34 tables carried org_id with no belt when
// this was written. This migration takes the fifteen whose queries the lint
// already proves carry their org predicate, so the belt is pure defence in
// depth for them and cannot change what any existing query returns. The
// remaining nineteen need query work first and follow in their own migrations
// -- deliberately, because the lint's scoped set is derived from the belt
// (tools/orgscope/ddl.go): the moment a table leaves the needsBelt register
// every query against it comes under the missing-predicate rule in the same
// commit. Belting a table and auditing its queries are the same act.
//
// FOUR tables get org_id NOT NULL as well. They were declared nullable and are
// never written NULL by any live path, but "nullable" plus a belt means a row
// with a NULL org is invisible to every tenant instead of loudly wrong, and an
// invisible row in a billing or compliance table is the failure mode this
// programme exists to remove. Pre-existing NULLs are attributed to the oldest
// org, matching v69 and v138; there is no column DEFAULT, so a rolled-back
// binary fails loudly rather than mis-tenanting new rows.
//
// email_branding is the reason this is not a formality. Its two handlers never
// read the caller's org at all -- GET took `ORDER BY created_at LIMIT 1` and
// PUT wrote `(SELECT id FROM organizations LIMIT 1)` -- so every tenant saw and
// overwrote the same single row. Under this policy the PUT is refused by
// WITH CHECK for any tenant that is not the oldest org, which is why the
// handler fix ships in this commit and not a later one.
//
// usage_metering_daily keeps rows whose org could not be attributed at ingest
// (the worker substitutes the zero UUID). Those become invisible to tenants,
// which is the correct direction: an event nobody can attribute must not be
// counted against anybody. The roll-up worker itself runs under
// orgctx.WithBypassRLS and is unaffected.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
// Idempotent throughout: DROP POLICY IF EXISTS + CREATE POLICY, and
// ALTER ... ENABLE/FORCE is a no-op when already set.
var rlsBeltBatch1Up = `-- Migration 140: extend the FORCE-RLS belt to fifteen org-scoped tables.

-- Backfill the four nullable org_id columns before belting, so no row is
-- hidden rather than fixed. The oldest org is the same target v69 and v138
-- used for their backfills.
UPDATE scheduled_reports     SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE device_trust_settings SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE email_branding        SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE usage_metering_daily  SET org_id = '00000000-0000-0000-0000-000000000000' WHERE org_id IS NULL;

ALTER TABLE scheduled_reports     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE device_trust_settings ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE email_branding        ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE usage_metering_daily  ALTER COLUMN org_id SET NOT NULL;

-- Reporting ------------------------------------------------------------------
DROP POLICY IF EXISTS pol_scheduled_reports_org_scope ON scheduled_reports;
CREATE POLICY pol_scheduled_reports_org_scope ON scheduled_reports
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_reports FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_detailed_compliance_reports_org_scope ON detailed_compliance_reports;
CREATE POLICY pol_detailed_compliance_reports_org_scope ON detailed_compliance_reports
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE detailed_compliance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE detailed_compliance_reports FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_audit_webhook_subscriptions_org_scope ON audit_webhook_subscriptions;
CREATE POLICY pol_audit_webhook_subscriptions_org_scope ON audit_webhook_subscriptions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE audit_webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_webhook_subscriptions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_usage_metering_daily_org_scope ON usage_metering_daily;
CREATE POLICY pol_usage_metering_daily_org_scope ON usage_metering_daily
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE usage_metering_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_metering_daily FORCE  ROW LEVEL SECURITY;

-- Branding and device trust ---------------------------------------------------
DROP POLICY IF EXISTS pol_email_branding_org_scope ON email_branding;
CREATE POLICY pol_email_branding_org_scope ON email_branding
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE email_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_branding FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_device_trust_settings_org_scope ON device_trust_settings;
CREATE POLICY pol_device_trust_settings_org_scope ON device_trust_settings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE device_trust_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_trust_settings FORCE  ROW LEVEL SECURITY;

-- PAM: checkouts, brokered sessions, the SSH CA ---------------------------------
DROP POLICY IF EXISTS pol_pam_active_checkouts_org_scope ON pam_active_checkouts;
CREATE POLICY pol_pam_active_checkouts_org_scope ON pam_active_checkouts
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_active_checkouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_active_checkouts FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_pam_checkout_authorizations_org_scope ON pam_checkout_authorizations;
CREATE POLICY pol_pam_checkout_authorizations_org_scope ON pam_checkout_authorizations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE pam_checkout_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_checkout_authorizations FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_brokered_sessions_org_scope ON brokered_sessions;
CREATE POLICY pol_brokered_sessions_org_scope ON brokered_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE brokered_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE brokered_sessions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_ssh_ca_org_scope ON ssh_ca;
CREATE POLICY pol_ssh_ca_org_scope ON ssh_ca
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ssh_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_ca FORCE  ROW LEVEL SECURITY;

-- Governance: SoD, privileged discovery, the entitlement warehouse --------------
DROP POLICY IF EXISTS pol_sod_violations_org_scope ON sod_violations;
CREATE POLICY pol_sod_violations_org_scope ON sod_violations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE sod_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sod_violations FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_privileged_accounts_discovered_org_scope ON privileged_accounts_discovered;
CREATE POLICY pol_privileged_accounts_discovered_org_scope ON privileged_accounts_discovered
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE privileged_accounts_discovered ENABLE ROW LEVEL SECURITY;
ALTER TABLE privileged_accounts_discovered FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_entitlement_warehouse_org_scope ON entitlement_warehouse;
CREATE POLICY pol_entitlement_warehouse_org_scope ON entitlement_warehouse
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE entitlement_warehouse ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_warehouse FORCE  ROW LEVEL SECURITY;

-- Access: upstream pools -------------------------------------------------------
DROP POLICY IF EXISTS pol_upstream_pools_org_scope ON upstream_pools;
CREATE POLICY pol_upstream_pools_org_scope ON upstream_pools
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE upstream_pools ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_pools FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_upstream_pool_members_org_scope ON upstream_pool_members;
CREATE POLICY pol_upstream_pool_members_org_scope ON upstream_pool_members
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE upstream_pool_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_pool_members FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON scheduled_reports, detailed_compliance_reports, audit_webhook_subscriptions, usage_metering_daily, email_branding, device_trust_settings, pam_active_checkouts, pam_checkout_authorizations, brokered_sessions, ssh_ca, sod_violations, privileged_accounts_discovered, entitlement_warehouse, upstream_pools, upstream_pool_members TO openidx_app;
`

// Down lifts the belt and restores the four nullable columns. It does not undo
// the backfill: the rows it attributed were unattributed before, and putting
// them back to NULL would lose information a later re-apply cannot recover.
var rlsBeltBatch1Down = `-- Rollback 140.

ALTER TABLE scheduled_reports             NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scheduled_reports             DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_scheduled_reports_org_scope ON scheduled_reports;

ALTER TABLE detailed_compliance_reports   NO FORCE ROW LEVEL SECURITY;
ALTER TABLE detailed_compliance_reports   DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_detailed_compliance_reports_org_scope ON detailed_compliance_reports;

ALTER TABLE audit_webhook_subscriptions   NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_webhook_subscriptions   DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_audit_webhook_subscriptions_org_scope ON audit_webhook_subscriptions;

ALTER TABLE usage_metering_daily          NO FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_metering_daily          DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_usage_metering_daily_org_scope ON usage_metering_daily;

ALTER TABLE email_branding                NO FORCE ROW LEVEL SECURITY;
ALTER TABLE email_branding                DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_email_branding_org_scope ON email_branding;

ALTER TABLE device_trust_settings         NO FORCE ROW LEVEL SECURITY;
ALTER TABLE device_trust_settings         DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_device_trust_settings_org_scope ON device_trust_settings;

ALTER TABLE pam_active_checkouts          NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pam_active_checkouts          DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_pam_active_checkouts_org_scope ON pam_active_checkouts;

ALTER TABLE pam_checkout_authorizations   NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pam_checkout_authorizations   DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_pam_checkout_authorizations_org_scope ON pam_checkout_authorizations;

ALTER TABLE brokered_sessions             NO FORCE ROW LEVEL SECURITY;
ALTER TABLE brokered_sessions             DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_brokered_sessions_org_scope ON brokered_sessions;

ALTER TABLE ssh_ca                        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ssh_ca                        DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_ssh_ca_org_scope ON ssh_ca;

ALTER TABLE sod_violations                NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sod_violations                DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_sod_violations_org_scope ON sod_violations;

ALTER TABLE privileged_accounts_discovered NO FORCE ROW LEVEL SECURITY;
ALTER TABLE privileged_accounts_discovered DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_privileged_accounts_discovered_org_scope ON privileged_accounts_discovered;

ALTER TABLE entitlement_warehouse         NO FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlement_warehouse         DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_entitlement_warehouse_org_scope ON entitlement_warehouse;

ALTER TABLE upstream_pools                NO FORCE ROW LEVEL SECURITY;
ALTER TABLE upstream_pools                DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_upstream_pools_org_scope ON upstream_pools;

ALTER TABLE upstream_pool_members         NO FORCE ROW LEVEL SECURITY;
ALTER TABLE upstream_pool_members         DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_upstream_pool_members_org_scope ON upstream_pool_members;

ALTER TABLE scheduled_reports     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE device_trust_settings ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE email_branding        ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE usage_metering_daily  ALTER COLUMN org_id DROP NOT NULL;
`
