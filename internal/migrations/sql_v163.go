package migrations

// Migration v163 — the last four of the non-deferred register: two get a
// tenant, two go.
//
// ENTITLEMENT METADATA. v54's `entitlement_metadata` is the governance
// annotation on a role, a group or an application: its risk level, its owner,
// its tags, whether it requires review, and when it was last reviewed. It has
// no tenant column and, worse, an install-wide
// `UNIQUE (entitlement_type, entitlement_id)`.
//
// The catalog read is scoped -- the roles, groups and applications it unions
// all carry `WHERE org_id = $1` -- and then it reaches the annotation with
//
//	LEFT JOIN entitlement_metadata em
//	       ON em.entitlement_id = c.id AND em.entitlement_type = c.type
//
// with no tenant term of any kind. The WRITE is where that matters.
// UpdateEntitlementMetadata never resolved an organization and never checked
// that the entitlement it was handed belonged to the caller: it took the type
// and the id straight from the URL and upserted on the install-wide key. So
// `PUT /entitlements/role/<another organization's role id>/metadata` wrote a
// row that appears on THAT organization's catalog -- their role's risk level,
// their role's owner (a user id, so a foreign account could be planted as the
// owner of their privileged role), their tags, and their "review required"
// badge. One tenant editing another tenant's governance record, through a
// handler that asks for nothing.
//
// A COUNT OF THINGS THAT CAN GO NEGATIVE. GetEntitlementStats counts the
// tenant's roles, groups and applications with `WHERE org_id = $1` for the
// total, and then reads the risk breakdown with
//
//	SELECT risk_level, COUNT(*) FROM entitlement_metadata GROUP BY risk_level
//
// -- no predicate at all -- before doing `ByRiskLevel["low"] += total - counted`.
// The total is one tenant's and the counted is the installation's, so on any
// install where another organization has annotated more entitlements than this
// one owns, the "low risk" figure on the Entitlement Catalog goes NEGATIVE. Not
// merely wrong: a count of things, printed below zero, beside figures that are
// correct. The same arithmetic impossibility v158 found in the passwordless
// adoption rate, from the same cause -- a scoped numerator over an unscoped
// denominator, or here the reverse.
//
// NOTIFICATION DIGESTS. v43's `notification_digests` is one row per user per
// digest type per channel. Both queries address it by `user_id` alone, and the
// user id is the CALLER'S OWN, taken from their token -- so unlike every other
// table in this programme this one was not reachable across tenants, and the
// tenant term here is defence in depth and a belt, not a leak being closed.
// Stated plainly rather than dressed up.
//
// What is worth stating is that NOTHING SENDS A DIGEST. The table carries
// `next_scheduled_at` and v43 built `idx_digests_next ON (next_scheduled_at,
// enabled)` for a worker that reads it; no such worker exists. A search of the
// tree finds `next_scheduled_at` in the settings handlers, in a list of
// sortable column names, and in an unused struct in internal/admin, and
// nowhere else. So a user opens Notification Center, chooses a daily email
// digest, saves it, and no digest is ever sent. Sixth authored-but-unconsumed
// surface this programme has found, after v154's unscheduled lifecycle
// policies, v155's custom_claims_mappings, v156's developer_settings, v158's
// biometric policies and v160's email templates -- recorded rather than fixed
// for the same reason: writing the sender is a feature.
//
// TWO TABLES THAT GO. Both are v54's.
//
// `feature_adoption` is `(id, feature_name, user_id, first_used_at,
// last_used_at, usage_count)`. Nothing in the tree has ever written to it --
// no INSERT, no UPDATE, no seed. And the one read, in the Feature Adoption
// analytics handler, is
//
//	SELECT feature_name, total_users, trend FROM feature_adoption ...
//
// against a table that has neither a `total_users` column nor a `trend` column
// and never had -- v54 created it in this shape and no migration has altered
// it. That query cannot succeed; it returns `column "total_users" does not
// exist` every time, and the handler's `if err == nil` swallows it. So the
// comment below it -- "If no rows exist in the feature_adoption table, compute
// from live data" -- describes a fallback that is in fact the only path the
// endpoint has ever taken. The live computation is org-scoped and correct, and
// is now the whole handler.
//
// `webhook_delivery_stats` is `(subscription_id PRIMARY KEY, total_deliveries,
// successful_deliveries, failed_deliveries, avg_response_time_ms,
// last_delivery_at, updated_at)`. A search of the tree finds the name in v54's
// DDL and in the orgscope register and NOWHERE else: no handler, no worker, no
// seed, no console call. It has no reader and no writer.
//
// Both are dropped rather than scoped, for the reason v157 dropped
// auth_contexts and v159 dropped v44's two orphans: giving org_id and a policy
// to a table nothing reads and nothing writes moves a name off a register and
// changes nothing. Nothing can have written a row to either, so nothing is
// lost, and Down recreates both verbatim.
//
// BACKFILL. An entitlement annotation goes to the organization of the
// entitlement it annotates, resolved by type against the three tables the
// catalog unions -- roles, groups and applications -- which is exact for every
// row the product could have written. A digest follows its user through v43's
// enforced foreign key. Anything unattributed -- an annotation naming an
// entitlement that has since been deleted, which the schema permits because
// entitlement_id carries no foreign key -- goes to the oldest organization.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var entitlementDigestScopeUp = `-- Migration 163: scope the entitlement annotations and the digest schedules; drop two orphans.

ALTER TABLE entitlement_metadata ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE notification_digests ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE entitlement_metadata m SET org_id = r.org_id FROM roles r
  WHERE m.entitlement_type = 'role' AND r.id = m.entitlement_id AND m.org_id IS NULL;
UPDATE entitlement_metadata m SET org_id = g.org_id FROM groups g
  WHERE m.entitlement_type = 'group' AND g.id = m.entitlement_id AND m.org_id IS NULL;
UPDATE entitlement_metadata m SET org_id = a.org_id FROM applications a
  WHERE m.entitlement_type = 'application' AND a.id = m.entitlement_id AND m.org_id IS NULL;
UPDATE entitlement_metadata SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

UPDATE notification_digests d SET org_id = u.org_id FROM users u WHERE u.id = d.user_id AND d.org_id IS NULL;
UPDATE notification_digests SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE entitlement_metadata ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE notification_digests ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE entitlement_metadata DROP CONSTRAINT IF EXISTS entitlement_metadata_entitlement_type_entitlement_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_entitlement_metadata_org_entitlement
  ON entitlement_metadata(org_id, entitlement_type, entitlement_id);

CREATE INDEX IF NOT EXISTS idx_notification_digests_org_user ON notification_digests(org_id, user_id);

DROP POLICY IF EXISTS pol_entitlement_metadata_org_scope ON entitlement_metadata;
CREATE POLICY pol_entitlement_metadata_org_scope ON entitlement_metadata
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE entitlement_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_metadata FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_notification_digests_org_scope ON notification_digests;
CREATE POLICY pol_notification_digests_org_scope ON notification_digests
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE notification_digests ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_digests FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON entitlement_metadata TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_digests TO openidx_app;

DROP TABLE IF EXISTS feature_adoption;
DROP TABLE IF EXISTS webhook_delivery_stats;
`

// Down lifts the belt, restores v54's install-wide unique key on the
// annotation, drops the columns, and recreates the two orphans verbatim.
//
// Restoring `UNIQUE (entitlement_type, entitlement_id)` is the statement that
// fails once two organizations have each annotated the same entitlement id --
// which needs one of them to have learned the other's role id, so it is
// unlikely rather than impossible. Refusing beats deleting an organization's
// governance annotations to make a rollback succeed, which is the same choice
// v157 and v160 made.
var entitlementDigestScopeDown = `-- Rollback 163.

ALTER TABLE notification_digests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_digests DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_notification_digests_org_scope ON notification_digests;

ALTER TABLE entitlement_metadata NO FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlement_metadata DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_entitlement_metadata_org_scope ON entitlement_metadata;

DROP INDEX IF EXISTS idx_notification_digests_org_user;
DROP INDEX IF EXISTS idx_entitlement_metadata_org_entitlement;

ALTER TABLE entitlement_metadata ADD CONSTRAINT entitlement_metadata_entitlement_type_entitlement_id_key
  UNIQUE (entitlement_type, entitlement_id);

ALTER TABLE notification_digests DROP COLUMN IF EXISTS org_id;
ALTER TABLE entitlement_metadata DROP COLUMN IF EXISTS org_id;

CREATE TABLE IF NOT EXISTS feature_adoption (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature_name VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    first_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    usage_count INT DEFAULT 1,
    UNIQUE(feature_name, user_id)
);
CREATE INDEX IF NOT EXISTS idx_feature_adoption_feature ON feature_adoption(feature_name);

CREATE TABLE IF NOT EXISTS webhook_delivery_stats (
    subscription_id VARCHAR(255) PRIMARY KEY,
    total_deliveries INT DEFAULT 0,
    successful_deliveries INT DEFAULT 0,
    failed_deliveries INT DEFAULT 0,
    avg_response_time_ms INT DEFAULT 0,
    last_delivery_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
`
