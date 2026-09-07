package main

// knownUnread is the backlog: operator-settable configuration fields nothing in
// the product reads, each with the verdict from reading the code around it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the field gains a reader or the field goes.
//
// EMPTY IS THE ANSWER, and it is the answer because the destination for a field
// with no reader is not this register. It is internal/common/config/retired.go:
// delete the field, the default and the binding, and add the environment
// variable to retiredSettings so that an operator who still sets it is told at
// startup that it does nothing and what to set instead. A register entry leaves
// the operator's belief intact and only records that we know better.
//
// So an entry here means one thing: a field that cannot be retired yet because
// something outside this repository still depends on the name. There is nothing
// in that position today.
var knownUnread = map[string]string{}

// knownExternal names environment variables the documentation mentions that
// belong to something other than OpenIDX — GitHub Actions, Docker, the Android
// toolchain, a cloud provider's SDK. They are not settings this product binds
// and never will be, so a documented row naming one is correct.
//
// This is the one written list in the tool, and it is written because the set it
// holds genuinely is not derivable from this tree: only a human knows that
// GITHUB_TOKEN is Actions'. Each entry says whose it is, so an entry that is
// really ours has nowhere to hide.
var knownExternal = map[string]string{
	"POSTGRES_PASSWORD": "PostgreSQL's own image variable: the compose stack passes it to the postgres container, " +
		"which uses it to create the role. OpenIDX reads the credential from DATABASE_URL.",
	"REDIS_PASSWORD": "Redis's own image variable: the compose stack passes it to the redis container as its " +
		"requirepass. OpenIDX reads the credential from REDIS_URL.",
	"GRAFANA_ADMIN_PASSWORD": "Grafana's own image variable (GF_SECURITY_ADMIN_PASSWORD in the container), set so " +
		"the bundled dashboards do not ship with admin/admin. No OpenIDX service reads it.",
}
