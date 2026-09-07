package main

// knownUnwritten is the backlog: tables the schema creates that no production
// code writes, each with the verdict from reading the code around it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the table gains a writer or the table goes.
//
// Two verdicts recur and they are not the same thing:
//
//   - "read, never written" is a measurement that cannot measure. A user is
//     shown a number derived from an empty table and has no way to tell it from
//     a measured zero. These are defects.
//   - "neither read nor written" is dead schema: DDL, indexes and grants for a
//     table no code has ever touched. Harmless to a running install, and a
//     standing invitation to write a query against a table that will never have
//     rows -- which is how the first kind is born.
var knownUnwritten = map[string]string{
	"ai_agent_activity": "the AI-agent registry has no runtime. Nothing outside internal/admin so much as reads ai_agent_credentials, so no agent ever acts through this product and there is no moment at which activity could be recorded. Three reads present the absence as measurement -- the per-agent activity list (LIMIT 100, always empty), the 24-hour top-agents ranking (every agent 0) and the recent-failures count (always 0). Recorded rather than fixed: what is missing is the agent runtime, and writing it is a feature.",

	// upstream_pools and upstream_pool_members have left this register: both are
	// written now, by the CRUD surface in internal/access/upstream_pools_handlers.go.
	//
	// Their entry said the missing half was "a CRUD surface with its own console
	// page, which is a feature", and that was right as far as it went. Building
	// it turned up a third layer neither register had named:
	// BuildEdgeRoutesForPools, the function that renders a pool into an APISIX
	// route, was called by nothing. So even a pool inserted by hand, linked to a
	// route by hand, would never have reached the data plane. The reconciler
	// converges both sets now, and TestReconcileSendsPoolBackedRoutesToTheDataPlane
	// fails if that call is removed again.
}
