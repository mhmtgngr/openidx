package migrations

// Migration v223 -- a role an access request gave carries the request's
// window.
//
// An approved access request for a role wrote a plain user_roles row, with no
// expires_at, and the governance expiry sweep deleted the (user, role) row at
// the request's end, every five minutes. Two things followed:
//
//   - the role outlived its window until the next tick: a token issued in
//     the meantime still carried it, though user_roles.expires_at is exactly
//     what the token builder and the role-expiry sweep read;
//   - the sweep removed the row whatever had made it. A request's end took an
//     administrator's standing assignment of the same role with it, and the
//     first of two requests cut the second one short.
//
// Fulfilment now writes the request's window on the row, and the request's
// end removes the row only when its window is the request's (internal/jitgrant
// RevokeRequest). This migration gives the rows already made by a live
// request the window they would have been written with: the latest window of
// the fulfilled requests for the user and the role. Without it, those rows
// would read as standing, and the sweep, which now leaves a standing role
// alone, would never end them.
//
// A row an administrator had made before the request becomes timed by it.
// The sweep deleted that row at the request's end before this migration too,
// so nothing ends sooner than it did. An external user's row is held to the
// account's end by v215's trigger, as every write to user_roles is.
//
// Down is a no-op: the windows stay. The code before this migration deletes
// the row at the request's end whatever its expires_at says, and until then a
// window on the row only stops a token from carrying the role after its end.

var roleAssignmentWindowUp = `-- Migration 223: the window of a requested role, on user_roles.
UPDATE user_roles ur SET expires_at = w.window_end
  FROM (SELECT requester_id, resource_id, org_id, MAX(expires_at) AS window_end
          FROM access_requests
         WHERE resource_type = 'role' AND status = 'fulfilled' AND expires_at IS NOT NULL
         GROUP BY requester_id, resource_id, org_id) w
 WHERE ur.user_id = w.requester_id AND ur.role_id = w.resource_id AND ur.org_id = w.org_id
   AND ur.expires_at IS NULL;
`

var roleAssignmentWindowDown = `-- Migration 223 down: no-op. The windows the backfill wrote stay on their
-- rows: the code before v223 removes a requested role at the request's end
-- whatever expires_at says, and a window only stops a token from carrying the
-- role once it is over.
SELECT 1;
`
