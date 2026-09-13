package provisioning

// SCIM PAGING IS INDEX-BASED, AND THAT DECIDES WHAT CAN BE FIXED HERE.
//
// RFC 7644 §3.4.2.4 pages a ListResponse by `startIndex` (1-based) and requires
// `totalResults` in every response. A client may ask for any startIndex it
// likes, so this cannot become a cursor the way the audit event list did in
// task 2.5 -- there is no opaque position to hand back, and dropping the count
// would break the protocol rather than save a scan.
//
// What CAN be fixed, and is, is the ordering.
//
// `ORDER BY created_at` alone is not a total order, and in this schema the ties
// are not a rare coincidence: created_at defaults to NOW(), which in Postgres
// is the TRANSACTION timestamp, so every row written by one transaction carries
// the identical value. A SCIM bulk create, a directory sync, an import -- each
// produces a block of rows that tie exactly. Measured on a real server: two
// hundred rows inserted in one transaction share ONE distinct created_at.
//
// With ties and no tie-break, which row falls on which side of a page boundary
// is not decided by the query. Postgres may return tied rows in any order and
// is not required to repeat it between executions, so a client walking the
// directory can see a user twice or not at all. On a provisioning API that is
// an account that never reaches a downstream application, or one provisioned
// twice -- and nothing logs it, because every page was a valid answer.
//
// So the ordering carries id, and it lives in one place rather than being
// spelled at each call site: TestSCIMOrderingIsTotal pins it as a decision.
// Migration v191 indexes (org_id, created_at, id) on both tables so the
// ordering is a seek rather than a sort.
//
// WHAT THIS STILL DOES NOT FIX, because the protocol does not allow it: a row
// inserted ahead of the client's position between two pages shifts every later
// OFFSET by one, and the row that was at the boundary is never returned. That
// is a property of index-based paging, not of this implementation -- measured
// the same way, one user in two hundred silently missing after a single
// concurrent insert. A cursor is what removes it, and SCIM has nowhere to put
// one.
const (
	// scimUserOrdering and scimGroupOrdering are the total orders the list
	// endpoints page by. created_at first because that is the order the API has
	// always presented; id second because created_at alone is not unique.
	scimUserOrdering  = "ORDER BY created_at, id"
	scimGroupOrdering = "ORDER BY created_at, id"
)
