package migrations

// Migration v222 -- an application assignment carries the window it was
// granted for.
//
// An approved access request for an application wrote a plain
// user_application_assignments row, and the governance expiry sweep deleted
// it. The sweep runs every five minutes, so a window ended at the next tick
// rather than at its end, and until then /oauth/authorize, the proxy and the
// overlay still admitted the requester. The acceptance test of the
// third-party access framework (#975) recorded it. expires_at puts the end on
// the row, as user_roles and pam_entry_grants carry theirs: internal/appaccess
// reads it, so every enforcement point refuses once the window is over. NULL
// is a standing assignment, as before.
//
// The backfill gives a row the latest window of the fulfilled requests for its
// user and application, so an assignment granted before this migration ends
// with its request as it did. An assignment an administrator had also made
// before the request becomes timed by it: the sweep deleted that row at the
// request's end before this migration too.
//
// An external user's assignment joins v215's I8 triggers: it ends no later
// than the account, and is cut again when the account's end moves earlier.
//
// Down puts back v215's functions and drops the trigger and the column. An
// assignment past its window then counts until the sweep removes it, as
// before.

var applicationAssignmentWindowUp = `-- Migration 222: user_application_assignments.expires_at.
ALTER TABLE user_application_assignments ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_user_app_assignments_expires
    ON user_application_assignments (expires_at) WHERE expires_at IS NOT NULL;
UPDATE user_application_assignments uaa SET expires_at = w.window_end
  FROM (SELECT requester_id, resource_id, org_id, MAX(expires_at) AS window_end
          FROM access_requests
         WHERE resource_type = 'application' AND status = 'fulfilled' AND expires_at IS NOT NULL
         GROUP BY requester_id, resource_id, org_id) w
 WHERE uaa.user_id = w.requester_id AND uaa.application_id = w.resource_id AND uaa.org_id = w.org_id
   AND uaa.expires_at IS NULL;
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

var applicationAssignmentWindowDown = `-- Migration 222 down.
DROP TRIGGER IF EXISTS trg_user_app_assignments_external_window ON user_application_assignments;
` + externalGrantWindowUp + `
DROP INDEX IF EXISTS idx_user_app_assignments_expires;
ALTER TABLE user_application_assignments DROP COLUMN IF EXISTS expires_at;
`
