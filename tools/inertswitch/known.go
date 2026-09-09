package main

// knownInert is the backlog: bool fields an API caller can set that nothing in
// the product decides on, each with the verdict from reading the code around it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the switch gains a decider or the switch goes.
//
// A SWITCH THAT DOES NOTHING DOES NOT BELONG HERE. There are two honest
// destinations for one, and neither is a register entry. Either the product
// starts deciding on it — which is what `notify_on_use` got — or the field is
// withdrawn from the request and the response, which is what `require_mfa` and
// `sandbox_enabled` got, so a caller who still sends it is ignored explicitly
// rather than stored as a promise. An entry that merely says "yes, it does
// nothing" leaves the operator's belief intact and only records that we know
// better.
//
// So an entry means one of two things, and says which:
//
//   - a switch that cannot be withdrawn yet because something outside this
//     repository still sends it; or
//   - a switch that IS decided on, through a path the analysis cannot see, with
//     the file and line where the decision happens so a reviewer can check.
//     Suppressions belong in the tool when they generalise; when the shape is a
//     one-off, an entry naming the code is more honest than widening a rule
//     until it hides real findings too.
var knownInert = map[string]string{
	"vault.createReq.RequireStepUp": "Decided, through a path this census cannot follow. " +
		"require_step_up is stored on vault_secrets and read back by " +
		"internal/vault/store.go:534 secretRequiresStepUp — SELECT into a LOCAL bool, " +
		"returned, and tested at store.go:501, where a reveal without a step-up completed " +
		"in the last five minutes is refused with ErrStepUpRequired. Neither suppression " +
		"reaches it: no field in the tree shares the name (the scan target is a local), and " +
		"the column sits in that query's SELECT list rather than after its WHERE. " +
		"internal/vault/reveal_handler_test.go drives the refusal end to end.",
}
