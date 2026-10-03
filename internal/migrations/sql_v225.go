package migrations

// Migration v225 -- an external user's group membership ends no later than the
// account, as the user's roles, application assignments and PAM and vault
// grants already do (invariant I8 of the third-party access framework, v215
// and v222).
//
// A group membership had no window until v224, so v215's triggers could not
// hold it. external_grant_window() now caps a membership written for an
// external user at the account's end, and external_account_end_moved() cuts
// the user's memberships again when the account's end moves earlier. The
// identity expiry sweep removes a membership at its end and cuts the tokens
// that name the group, so the group leaves the user when the account does,
// as a role does.
//
// The backfill caps the memberships external users already hold. A membership
// of an account whose end has passed gets that end, and the sweep removes it;
// the account itself was disabled at its end.
//
// Down puts back v222's functions and drops the trigger. The windows stay:
// v224's column outlives this migration, and a capped membership ends no
// later than the account it belongs to.

var externalGroupWindowUp = `-- Migration 225: hold an external user's group membership to the account's end.
UPDATE group_memberships gm SET expires_at = u.account_expires_at
  FROM users u
 WHERE gm.user_id = u.id AND gm.org_id = u.org_id
   AND u.user_type = 'external' AND u.account_expires_at IS NOT NULL
   AND (gm.expires_at IS NULL OR gm.expires_at > u.account_expires_at);
CREATE OR REPLACE FUNCTION external_grant_window() RETURNS trigger
LANGUAGE plpgsql
AS
$$
DECLARE
    grantee UUID;
    account_end TIMESTAMPTZ;
BEGIN
    IF TG_TABLE_NAME IN ('user_roles', 'user_application_assignments', 'group_memberships') THEN
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
DROP TRIGGER IF EXISTS trg_user_app_assignments_external_window ON user_application_assignments;
CREATE TRIGGER trg_user_app_assignments_external_window BEFORE INSERT OR UPDATE OF expires_at, user_id ON user_application_assignments
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
        UPDATE user_application_assignments SET expires_at = NEW.account_expires_at
         WHERE user_id = NEW.id AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
        UPDATE group_memberships SET expires_at = NEW.account_expires_at
         WHERE user_id = NEW.id AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_group_memberships_external_window ON group_memberships;
CREATE TRIGGER trg_group_memberships_external_window BEFORE INSERT OR UPDATE OF expires_at, user_id ON group_memberships
    FOR EACH ROW EXECUTE FUNCTION external_grant_window();
`

var externalGroupWindowDown = `-- Migration 225 down: v222's functions, and no trigger on group_memberships.
DROP TRIGGER IF EXISTS trg_group_memberships_external_window ON group_memberships;
CREATE OR REPLACE FUNCTION external_grant_window() RETURNS trigger
LANGUAGE plpgsql
AS
$$
DECLARE
    grantee UUID;
    account_end TIMESTAMPTZ;
BEGIN
    IF TG_TABLE_NAME IN ('user_roles', 'user_application_assignments') THEN
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
DROP TRIGGER IF EXISTS trg_user_app_assignments_external_window ON user_application_assignments;
CREATE TRIGGER trg_user_app_assignments_external_window BEFORE INSERT OR UPDATE OF expires_at, user_id ON user_application_assignments
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
        UPDATE user_application_assignments SET expires_at = NEW.account_expires_at
         WHERE user_id = NEW.id AND org_id = NEW.org_id
           AND (expires_at IS NULL OR expires_at > NEW.account_expires_at);
    END IF;
    RETURN NULL;
END;
$$;

`
