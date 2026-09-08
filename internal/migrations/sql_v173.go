package migrations

// v173 — tenant-chosen names, keyed per tenant.
//
// roles.name, service_accounts.name and scim_groups.display_name are labels a
// TENANT picks, and all three were UNIQUE install-wide. Every query that reads
// them already carries the organization (roles: WHERE name = $1 AND org_id = $2
// in the identity role-grant and both bulk-import paths; service accounts and
// SCIM groups are addressed by id and never by name), and all three tables
// already have org_id NOT NULL and FORCE ROW LEVEL SECURITY. So the data has
// been per-tenant for some time and only the key disagreed.
//
// What the disagreement cost is a refusal, not a leak: the SECOND tenant to
// want a role named "developer" -- or "admin", "manager", "user", "auditor",
// which the seed creates for the default organization on every install -- gets
// `duplicate key value violates unique constraint "roles_name_key"` from a
// table their query would never have found the other row in. The same for a
// service account named "ci" and for any SCIM group an IdP provisions under a
// display name another tenant already used, which for "Engineering" or
// "All Employees" is the ordinary case rather than the unlucky one; there the
// failure lands inside directory provisioning rather than in front of an
// operator who can read it.
//
// Same shape as v138 did for ispm_rules(check_type), ispm_scores(snapshot_date)
// and ai_agents(name). Plain statements, no DO blocks, and DROP CONSTRAINT IF
// EXISTS so the migration is idempotent across installs created from
// init-db.sql (which names the constraints) and from the migration chain.
//
// NOT INCLUDED, deliberately: ziti_identities.name and ziti_services.name are
// also install-wide unique on org-scoped tables, and they stay that way. Those
// names are created in the Ziti controller, and an install has ONE controller,
// so the constraint mirrors a real external namespace. Widening the local key
// would let two tenants claim the same overlay name and move the collision from
// a clean database error into a provisioning failure against the controller.
// Per-tenant overlay naming is the ZITI_PER_ORG_ATTRIBUTES work, not this.
const tenantScopedNamesUp = `
-- roles ------------------------------------------------------------------
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
DROP INDEX IF EXISTS roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_org_name ON roles(org_id, name);

-- service_accounts --------------------------------------------------------
ALTER TABLE service_accounts DROP CONSTRAINT IF EXISTS service_accounts_name_key;
DROP INDEX IF EXISTS service_accounts_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_accounts_org_name ON service_accounts(org_id, name);

-- scim_groups -------------------------------------------------------------
ALTER TABLE scim_groups DROP CONSTRAINT IF EXISTS scim_groups_display_name_key;
DROP INDEX IF EXISTS scim_groups_display_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_org_display_name ON scim_groups(org_id, display_name);
`

// Down restores the install-wide keys. Once two organizations hold the same
// name the unique index cannot be rebuilt, so the newer of each duplicated pair
// is removed first — precisely the rows the up migration made possible. That is
// destructive, and it is the honest rollback: the alternative is a down
// migration that fails halfway and leaves the schema in neither state.
//
// roles deletes cascade into user_roles (role_id REFERENCES roles ON DELETE
// CASCADE), so a rollback strips the grants that used the dropped role.
const tenantScopedNamesDown = `
DELETE FROM roles a USING roles b
 WHERE a.name = b.name AND a.created_at > b.created_at;
DROP INDEX IF EXISTS idx_roles_org_name;
ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);

DELETE FROM service_accounts a USING service_accounts b
 WHERE a.name = b.name AND a.created_at > b.created_at;
DROP INDEX IF EXISTS idx_service_accounts_org_name;
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_name_key UNIQUE (name);

DELETE FROM scim_groups a USING scim_groups b
 WHERE a.display_name = b.display_name AND a.created_at > b.created_at;
DROP INDEX IF EXISTS idx_scim_groups_org_display_name;
ALTER TABLE scim_groups ADD CONSTRAINT scim_groups_display_name_key UNIQUE (display_name);
`
