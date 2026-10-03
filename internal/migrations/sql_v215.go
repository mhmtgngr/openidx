package migrations

// Migration v215 -- an external user's grants end when the account does.
//
// Invariant I8 of the third-party access framework: no grant an external
// (vendor) user holds outlives the account. The request path refuses a window
// past the account (internal/externalid.CheckWindow). The grants an
// administrator writes directly are bounded here, where every writer meets
// them, the way v214's guard bounds what an external user may hold:
//
//   - user_roles (a time-bound role),
//   - pam_entry_grants with principal_type 'user',
//   - vault_access_grants with principal_type 'user'.
//
// external_grant_window() sets expires_at to the account's expiry when the
// grant has none or a later one. It never lengthens a grant, so it can only
// end access earlier than the writer asked, never later; a grant with an
// earlier expiry is untouched. Extending an account later does not extend the
// grants written before: they are re-granted, deliberately, by someone who
// can see the new date.
//
// The other direction is external_account_end_moved(), after an update of
// users.account_expires_at: when an external account's end moves earlier,
// every grant of the three kinds that now ends after it, or never, is cut to
// the new end. Without it an account shortened from 60 days to 10 would keep
// grants that read 60.
//
// A grant to a role or a group is not bounded here: it is not the external
// user's grant, and an external user cannot hold a role above "user" or join
// a group not open to external users (v214). The account's end severs those
// memberships' effect with the account itself.
//
// Down drops the triggers and the functions; the expiries they wrote stay.

var externalGrantWindowUp = `-- Migration 215: an external user's grants end when the account does.
CREATE OR REPLACE FUNCTION external_grant_window() RETURNS trigger
LANGUAGE plpgsql
AS
$$
DECLARE
    grantee UUID;
    account_end TIMESTAMPTZ;
BEGIN
    IF TG_TABLE_NAME = 'user_roles' THEN
        grantee := NEW.user_id;
    ELSIF NEW.principal_type = 'user' THEN
        BEGIN
            grantee := NEW.principal_id::text::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RETURN NEW;
        END;
    ELSE
        RETURN NEW;
    END IF;
    SELECT u.account_expires_at INTO account_end
      FROM users u WHERE u.id = grantee AND u.user_type = 'external';
    IF account_end IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > account_end) THEN
        NEW.expires_at := account_end;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_user_roles_external_window ON user_roles;
CREATE TRIGGER trg_user_roles_external_window BEFORE INSERT OR UPDATE OF expires_at ON user_roles
    FOR EACH ROW EXECUTE FUNCTION external_grant_window();
DROP TRIGGER IF EXISTS trg_pam_entry_grants_external_window ON pam_entry_grants;
CREATE TRIGGER trg_pam_entry_grants_external_window BEFORE INSERT OR UPDATE OF expires_at, principal_id ON pam_entry_grants
    FOR EACH ROW EXECUTE FUNCTION external_grant_window();
DROP TRIGGER IF EXISTS trg_vault_access_grants_external_window ON vault_access_grants;
CREATE TRIGGER trg_vault_access_grants_external_window BEFORE INSERT OR UPDATE OF expires_at, principal_id ON vault_access_grants
    FOR EACH ROW EXECUTE FUNCTION external_grant_window();
CREATE OR REPLACE FUNCTION external_account_end_moved() RETURNS trigger
LANGUAGE plpgsql
AS
$$
BEGIN
    IF NEW.user_type = 'external' AND NEW.account_expires_at IS NOT NULL
       AND (OLD.account_expires_at IS NULL OR NEW.account_expires_at < OLD.account_expires_at) THEN
        UPDATE user_roles SET expires_at = NEW.account_expires_at
         WHERE user_id = NEW.id AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
        UPDATE pam_entry_grants SET expires_at = NEW.account_expires_at
         WHERE principal_type = 'user' AND principal_id = NEW.id::text AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
        UPDATE vault_access_grants SET expires_at = NEW.account_expires_at
         WHERE principal_type = 'user' AND principal_id = NEW.id AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
    END IF;
    RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS trg_users_external_account_end ON users;
CREATE TRIGGER trg_users_external_account_end AFTER UPDATE OF account_expires_at ON users
    FOR EACH ROW EXECUTE FUNCTION external_account_end_moved();
`

var externalGrantWindowDown = `-- Migration 215 down: drop the grant window triggers.
DROP TRIGGER IF EXISTS trg_users_external_account_end ON users;
DROP FUNCTION IF EXISTS external_account_end_moved();
DROP TRIGGER IF EXISTS trg_vault_access_grants_external_window ON vault_access_grants;
DROP TRIGGER IF EXISTS trg_pam_entry_grants_external_window ON pam_entry_grants;
DROP TRIGGER IF EXISTS trg_user_roles_external_window ON user_roles;
DROP FUNCTION IF EXISTS external_grant_window();
`
