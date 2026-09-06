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
var knownBroken = map[string]string{
	// internal/access/browzer_config.go:350  [42883] function unnest(jsonb) does not exist
	"internal/access/browzer_config.go#8871328c5b6e": "browzer_targets.paths is JSONB and the query calls unnest() on it; the BrowZer path list is never expanded, so the generated nginx config loses per-path rules.",

	// internal/audit/anomaly.go:337  [42703] column "resource_type" does not exist
	"internal/audit/anomaly.go#44c7545bd70d": "the anomaly sweep groups by a resource_type column the audit table does not have; that detector never fires.",

	// internal/governance/service.go:495  [42803] column "ar.id" must appear in the GROUP BY clause or be used in an aggregate function
	"internal/governance/service.go#d3a7d5f31586": "an aggregate query selects ar.id without grouping by it; the campaign roll-up never runs.",

	// internal/oauth/saml_metadata.go:378  [42703] column "metadata_xml" of relation "saml_service_providers" does not exist
	"internal/oauth/saml_metadata.go#3ecaefc538a0": "saml_service_providers stores metadata under a different column; the SAML SP metadata refresh writes nothing.",
}
