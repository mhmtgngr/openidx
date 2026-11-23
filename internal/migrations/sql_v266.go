package migrations

// Migration 266: sign-in addresses an administrator gives an account.
//
// users.mail (migration 265) is the directory's mail attribute and the
// directory sync owns it: every run writes NULLIF(mail,''), so an address typed
// by hand there is gone within the hour, and a local account has no directory
// at all. A person whose real address is not in the directory (a lab domain, a
// mailbox on another domain, a new address not yet synced) therefore had no way
// to sign in with it.
//
//   - user_login_addresses: one row per extra address, owned by the
//     administrator who added it and never touched by a sync. Stored trimmed and
//     lower-cased (the CHECK says so) and unique within the organization, so two
//     accounts can never both claim one alias. The sign-in lookup puts it in the
//     same layer as users.email and users.mail: an address that names two
//     accounts is refused, never picked.
//   - Password reset and notifications keep using users.email; an alias only
//     answers "which account is this person signing in to".
//   - Row level security as every tenant table: forced, scoped on app.org_id.

var loginAddressesUp = `-- Migration 266: administrator-managed sign-in addresses.
CREATE TABLE IF NOT EXISTS user_login_addresses (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address    VARCHAR(255) NOT NULL
               CHECK (address = lower(btrim(address)) AND address LIKE '%@%'),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_login_addresses_org_address ON user_login_addresses (org_id, address);
CREATE INDEX IF NOT EXISTS idx_user_login_addresses_user ON user_login_addresses (user_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON user_login_addresses TO openidx_app;
DROP POLICY IF EXISTS pol_user_login_addresses_org_scope ON user_login_addresses;
CREATE POLICY pol_user_login_addresses_org_scope ON user_login_addresses
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE user_login_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_login_addresses FORCE  ROW LEVEL SECURITY;
`

var loginAddressesDown = `-- Rollback migration 266.
DROP TABLE IF EXISTS user_login_addresses;
`
