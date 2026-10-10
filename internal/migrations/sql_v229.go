package migrations

// Migration 229: one resource model.
//
// "Who may reach what" was defined in several places: application
// assignments (user_application_assignments, group_application_assignments),
// a proxy route's allowed_roles and allowed_groups, and the conditions a
// route carried (require_device_trust, max_risk_score, allowed_countries).
// The proxy read the route's roles and groups, /oauth/authorize read the
// assignments, the forward-auth path read the roles and groups only, and the
// overlay's dial policies were generated from a third reading.
//
// From here the resource is the applications row. It gains a kind (web,
// network, privileged), and resource_conditions holds the conditions that
// used to live on the route. The backfill gives every route that carried
// roles or groups an application; its groups become group assignments; a
// role that names a group of the same name becomes that group's assignment;
// a role that names no group is kept as a legacy role on the conditions row,
// and migration_notes records it so an administrator can finish the mapping.
// internal/accessdecision reads this model. The route's own columns stay for
// one release: observe mode still rules by them, and down restores nothing
// because nothing was removed.
var oneResourceModelUp = `-- Migration 229: one resource model.
ALTER TABLE applications ADD COLUMN IF NOT EXISTS kind VARCHAR(20) NOT NULL DEFAULT 'web';
ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_kind_check;
ALTER TABLE applications ADD CONSTRAINT applications_kind_check CHECK (kind IN ('web', 'network', 'privileged'));

CREATE TABLE IF NOT EXISTS resource_conditions (
  application_id UUID PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  org_id UUID NOT NULL,
  require_device_trust BOOLEAN NOT NULL DEFAULT false,
  posture_profile_id UUID,
  max_risk_score INTEGER CHECK (max_risk_score IS NULL OR (max_risk_score >= 0 AND max_risk_score <= 100)),
  allowed_countries TEXT[] NOT NULL DEFAULT '{}',
  require_step_up BOOLEAN NOT NULL DEFAULT false,
  time_window JSONB,
  legacy_roles TEXT[] NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID
);
CREATE INDEX IF NOT EXISTS idx_resource_conditions_org ON resource_conditions(org_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON resource_conditions TO openidx_app;
DROP POLICY IF EXISTS pol_resource_conditions_org_scope ON resource_conditions;
CREATE POLICY pol_resource_conditions_org_scope ON resource_conditions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE resource_conditions ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_conditions FORCE  ROW LEVEL SECURITY;

-- What a migration could not decide on its own, for an administrator to finish.
CREATE TABLE IF NOT EXISTS migration_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  migration INTEGER NOT NULL,
  org_id UUID,
  subject TEXT NOT NULL,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_migration_notes_org ON migration_notes(org_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON migration_notes TO openidx_app;
DROP POLICY IF EXISTS pol_migration_notes_org_scope ON migration_notes;
CREATE POLICY pol_migration_notes_org_scope ON migration_notes
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE migration_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_notes FORCE  ROW LEVEL SECURITY;

-- 1. Every route that carried roles or groups and has no application gets one.
INSERT INTO applications (id, client_id, name, description, type, enabled, org_id, route_id, created_at, updated_at)
SELECT gen_random_uuid(), 'route-' || r.id::text, r.name,
       'Created by migration 229 from the route''s roles and groups', 'proxy_route',
       true, r.org_id, r.id, NOW(), NOW()
  FROM proxy_routes r
 WHERE (jsonb_array_length(COALESCE(r.allowed_roles, '[]'::jsonb)) > 0
        OR jsonb_array_length(COALESCE(r.allowed_groups, '[]'::jsonb)) > 0)
   AND r.org_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.route_id = r.id);

-- 2. The route's kind.
UPDATE applications a
   SET kind = CASE WHEN LOWER(COALESCE(r.route_type, '')) IN ('ssh', 'rdp', 'vnc') THEN 'privileged' ELSE 'web' END
  FROM proxy_routes r
 WHERE r.id = a.route_id AND a.kind = 'web';

-- 3. allowed_groups (names) and allowed_roles that name a group become group assignments.
INSERT INTO group_application_assignments (group_id, application_id, org_id)
SELECT DISTINCT g.id, a.id, a.org_id
  FROM applications a
  JOIN proxy_routes r ON r.id = a.route_id
  CROSS JOIN LATERAL (
    SELECT value FROM jsonb_array_elements_text(COALESCE(r.allowed_groups, '[]'::jsonb))
    UNION
    SELECT value FROM jsonb_array_elements_text(COALESCE(r.allowed_roles, '[]'::jsonb))
  ) names(name)
  JOIN groups g ON g.name = names.name AND g.org_id = a.org_id
ON CONFLICT (group_id, application_id) DO NOTHING;

-- 4. The route's conditions, and the roles no group answered to.
INSERT INTO resource_conditions (application_id, org_id, require_device_trust, max_risk_score, allowed_countries, legacy_roles)
SELECT a.id, a.org_id,
       COALESCE(r.require_device_trust, false),
       NULLIF(COALESCE(r.max_risk_score, 100), 100),
       COALESCE((SELECT array_agg(value) FROM jsonb_array_elements_text(COALESCE(r.allowed_countries, '[]'::jsonb))), '{}'),
       COALESCE((SELECT array_agg(value) FROM jsonb_array_elements_text(COALESCE(r.allowed_roles, '[]'::jsonb)) rn
                  WHERE NOT EXISTS (SELECT 1 FROM groups g WHERE g.name = rn.value AND g.org_id = a.org_id)), '{}')
  FROM applications a
  JOIN proxy_routes r ON r.id = a.route_id
ON CONFLICT (application_id) DO NOTHING;

-- 5. A note per application whose roles could not be mapped.
INSERT INTO migration_notes (migration, org_id, subject, note)
SELECT 230, c.org_id, 'application:' || c.application_id::text,
       'route roles kept as legacy roles (no group of that name): ' || array_to_string(c.legacy_roles, ', ')
         || '. Create the groups or assign the application and clear legacy_roles.'
  FROM resource_conditions c
 WHERE cardinality(c.legacy_roles) > 0;
`

var oneResourceModelDown = `-- Migration 229 down: the route's columns were never removed; drop what was added.
DROP TABLE IF EXISTS resource_conditions;
DROP TABLE IF EXISTS migration_notes;
ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_kind_check;
ALTER TABLE applications DROP COLUMN IF EXISTS kind;
`
