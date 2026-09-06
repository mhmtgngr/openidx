package migrations

// Migration v160 — the notification admin surface: routing rules, broadcasts
// and email templates.
//
// v54 created all three with no tenant column.
//
// A SEVENTH INSTALL-WIDE UNIQUE KEY. `email_templates.slug VARCHAR(100) UNIQUE
// NOT NULL`: one organization naming a template 'welcome' owns that slug for
// the entire installation, and the next organization to try gets a duplicate
// key reported as a bare 500 with nothing to say another tenant holds the name.
// After v138's ispm_rules.check_type and ai_agents.name, v155's
// federation_rules.email_domain and identity_providers.issuer_url, v156's
// developer_settings.setting_key and v157's admin_console_settings.key, this is
// the seventh. Re-scoped to (org_id, slug).
//
// The template list, get, update, preview and reset all address a row without
// naming an organization, so every administrator on the installation saw, and
// could rewrite, one shared set of templates -- the subject line and HTML body
// of the mail the product sends about passwords, invitations and alerts.
//
// AND THE SAME FILE ALREADY KNEW. Two functions below the last of them,
// handleGetEmailBranding and handleUpdateEmailBranding both open with
// orgctx.From -- the fix this programme made in v140, when email_branding
// turned out to be the one table in that batch actually leaking. The five
// template handlers directly above were never revisited. That is the fourth
// time in this programme that one surface in a file was scoped and its
// neighbour was not.
//
// AND NOTHING SENDS THEM. A search of the tree finds email_templates in its own
// admin handlers, in the migrations, and in the orgscope register, and nowhere
// else: internal/email and internal/notifications never read it, by slug or
// otherwise. So an administrator edits the welcome mail, saves it, previews it,
// and no message the product sends uses any of it. Fifth surface of this shape
// after v154's unscheduled lifecycle policies, v155's custom_claims_mappings,
// v156's developer_settings and v158's biometric policies, and recorded rather
// than fixed for the same reason.
//
// A DRAFT ANOTHER TENANT COULD SEND. handleSendBroadcast resolves the caller's
// organization -- it needs it to pick recipients -- and then loads the message
// itself by bare id:
//
//	SELECT title, body, channel, target_type, target_ids, status
//	FROM broadcast_messages WHERE id = $1
//
// So one administrator could take another organization's unsent draft and
// deliver it, under their own tenancy, to their own users. The scoping was
// present for the audience and absent for the message. Every other broadcast
// handler -- list, get, delete -- was unscoped outright, and delete permits
// only drafts, so an unsent announcement could be removed from another
// tenant's console without trace.
//
// The routing rules decide which channels an event reaches: list, create, get,
// update and delete all addressed them by bare id, so one tenant could switch
// another's security-alert rule from ["in_app","email"] to ["in_app"] and their
// alerts would stop arriving by mail with nothing on screen to say so.
//
// THE SEED IS HANDLED HERE, NOT LEFT TO FAIL. deployments/docker/seed.sql
// inserts three starter routing rules with no organization, and v153's own
// fix commit named this table as one of two that would need the same treatment
// when its batch arrived. The seed now names the default organization in the
// shape tenant_branding, the risk policies and the lifecycle policies already
// use, rather than this migration growing a column DEFAULT -- a default is how
// a row acquires a tenant it was never given.
//
// BACKFILL. Every one of the three carries an author: email_templates.updated_by
// and both created_by columns are foreign keys to users, so each row goes to
// the organization of the person who last touched it, and anything
// unattributed to the oldest organization.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var notificationScopeUp = `-- Migration 160: scope and belt the notification admin surface.

ALTER TABLE email_templates            ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE notification_routing_rules ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE broadcast_messages         ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE email_templates t            SET org_id = u.org_id FROM users u WHERE u.id = t.updated_by AND t.org_id IS NULL;
UPDATE notification_routing_rules r SET org_id = u.org_id FROM users u WHERE u.id = r.created_by AND r.org_id IS NULL;
UPDATE broadcast_messages b         SET org_id = u.org_id FROM users u WHERE u.id = b.created_by AND b.org_id IS NULL;

UPDATE email_templates            SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE notification_routing_rules SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE broadcast_messages         SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE email_templates            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE notification_routing_rules ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE broadcast_messages         ALTER COLUMN org_id SET NOT NULL;

-- The seventh install-wide unique key. The name is the one Postgres generates
-- for v54's inline UNIQUE.
ALTER TABLE email_templates DROP CONSTRAINT IF EXISTS email_templates_slug_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_templates_org_slug ON email_templates(org_id, slug);

CREATE INDEX IF NOT EXISTS idx_routing_rules_org_priority ON notification_routing_rules(org_id, priority, event_type);
CREATE INDEX IF NOT EXISTS idx_broadcasts_org_created     ON broadcast_messages(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_email_templates_org_scope ON email_templates;
CREATE POLICY pol_email_templates_org_scope ON email_templates
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_templates FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_notification_routing_rules_org_scope ON notification_routing_rules;
CREATE POLICY pol_notification_routing_rules_org_scope ON notification_routing_rules
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE notification_routing_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_routing_rules FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_broadcast_messages_org_scope ON broadcast_messages;
CREATE POLICY pol_broadcast_messages_org_scope ON broadcast_messages
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE broadcast_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE broadcast_messages FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON email_templates            TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_routing_rules TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON broadcast_messages         TO openidx_app;
`

// Down lifts the belt, drops the columns and restores v54's install-wide UNIQUE
// on slug. That last statement is the one that can fail: once two organizations
// have each created a template called 'welcome' -- the point of the
// migration -- the single-column constraint cannot come back, and the rollback
// stops rather than deleting somebody's templates to make itself succeed. The
// same trade v138, v155, v156 and v157 made.
var notificationScopeDown = `-- Rollback 160.

ALTER TABLE broadcast_messages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE broadcast_messages DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_broadcast_messages_org_scope ON broadcast_messages;

ALTER TABLE notification_routing_rules NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_routing_rules DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_notification_routing_rules_org_scope ON notification_routing_rules;

ALTER TABLE email_templates NO FORCE ROW LEVEL SECURITY;
ALTER TABLE email_templates DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_email_templates_org_scope ON email_templates;

DROP INDEX IF EXISTS idx_broadcasts_org_created;
DROP INDEX IF EXISTS idx_routing_rules_org_priority;
DROP INDEX IF EXISTS idx_email_templates_org_slug;

ALTER TABLE broadcast_messages         DROP COLUMN IF EXISTS org_id;
ALTER TABLE notification_routing_rules DROP COLUMN IF EXISTS org_id;
ALTER TABLE email_templates            DROP COLUMN IF EXISTS org_id;

ALTER TABLE email_templates ADD CONSTRAINT email_templates_slug_key UNIQUE (slug);
`
