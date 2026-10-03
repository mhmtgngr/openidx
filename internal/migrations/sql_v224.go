package migrations

// Migration v224 -- a group membership an access request gave carries the
// request's window.
//
// An approved access request for a group wrote a plain group_memberships row,
// with no window, and the request's end deleted the (user, group) row
// whatever had made it. The two failures v223 fixed for roles held for groups:
//
//   - the membership outlived its window until the governance sweep's next
//     tick, and a token issued in the meantime carried the group for the
//     client's full lifetime;
//   - the request's end took a membership the user held before the request
//     with it, and the first of two requests cut the second one short.
//
// expires_at puts the window on the row, as user_roles and
// user_application_assignments carry theirs. Fulfilment writes it; the token
// builder reads only a live membership and ends a token with it; the identity
// expiry sweep removes it at its end; and the request's end removes the row
// only when its window is the request's (internal/jitgrant RevokeRequest).
// NULL is a standing membership, as before.
//
// The backfill gives the rows already made by a live request the window they
// would have been written with: the latest window of the fulfilled requests
// for the user and the group. A membership an administrator had made before
// the request becomes timed by it; the request's end deleted that row before
// this migration too, so nothing ends sooner than it did.
//
// Down drops the index and the column. The code before this migration deletes
// a requested membership at the request's end and reads no window.

var groupMembershipWindowUp = `-- Migration 224: group_memberships.expires_at.
ALTER TABLE group_memberships ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_group_memberships_expires
    ON group_memberships (expires_at) WHERE expires_at IS NOT NULL;
UPDATE group_memberships gm SET expires_at = w.window_end
  FROM (SELECT requester_id, resource_id, org_id, MAX(expires_at) AS window_end
          FROM access_requests
         WHERE resource_type = 'group' AND status = 'fulfilled' AND expires_at IS NOT NULL
         GROUP BY requester_id, resource_id, org_id) w
 WHERE gm.user_id = w.requester_id AND gm.group_id = w.resource_id AND gm.org_id = w.org_id
   AND gm.expires_at IS NULL;
`

var groupMembershipWindowDown = `-- Migration 224 down.
DROP INDEX IF EXISTS idx_group_memberships_expires;
ALTER TABLE group_memberships DROP COLUMN IF EXISTS expires_at;
`
