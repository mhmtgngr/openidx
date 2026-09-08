package main

// knownBroken is the backlog: statements PostgreSQL has already refused, each
// with the verdict from reading it against the schema the migrations create.
//
// Keys are the file plus a hash of the statement's normalized text. Moving a
// query down a file keeps its entry; EDITING the query does not, because an
// edited query has to be re-verified -- which is the behaviour wanted from a
// list whose whole purpose is to stop being needed.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so the
// only way an entry leaves is the query being fixed. Line numbers in the
// comments are from the sweep that seeded it and are not used for matching.
// The register is EMPTY, and that is the point: every SQL literal in this
// repository now plans against the schema the migrations create. It opened at
// 39 findings -- a security-alert writer whose every INSERT failed, a SIEM
// cursor no migration created, a GDPR export that silently omitted sections and
// an erasure that never ran, four compliance controls that reported compliant
// because their queries could not run, a tenant switcher that answered 404 for
// every tenant, and a joiner rule that granted nothing -- and each entry left
// only when the query was fixed or the table it read was dropped.
//
// An empty map is not a disabled check. `sqlprepare -fail` fails on any new
// finding, so the next query that names a column the schema does not have stops
// the build rather than joining a list.
var knownBroken = map[string]string{}
