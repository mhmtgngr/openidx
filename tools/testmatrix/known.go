package main

// elsewhere is the register: packages that hold tests, are not in the unit
// matrix, and are nonetheless run by a named CI job.
//
// It exists so that "this package has no matrix entry" is a decision somebody
// wrote down rather than an omission nobody noticed -- which is exactly what
// cmd/ was. Each reason must name the job that runs the tests, in double
// quotes, and TestEveryRegisterEntryNamesARealJob requires a job with that
// name to exist in .github/workflows. A register whose entries cite jobs that
// were renamed or deleted is worse than no register: it reads as coverage and
// is not.
//
// "test-race runs the whole module" is NOT a reason to put a package here.
// That is true of every package in the tree, so accepting it would empty the
// gate. The register is for tests a job runs *deliberately* and by name.
var elsewhere = map[string]string{
	"test/integration": `Run by the "Integration Tests" job, which is the only ` +
		`one that can: these files are behind the "integration" build tag, so ` +
		`the unit matrix would compile zero tests and report success. That job ` +
		`passes -tags=integration and brings up Postgres, Redis and ` +
		`Elasticsearch first.`,

	// cmd/rekey WAS here, with the reason that its only test file sat behind
	// the "integration" build tag while the package sat under the matrix's
	// ./cmd/... entry -- so the entry looked like coverage and compiled zero
	// tests. The package now also carries untagged tests
	// (bypass_testdb_test.go), so the matrix really does run it and the line
	// stopped excusing anything. TestTheRegisterCarriesNothingTheMatrixAlreadyRuns
	// is what said so, on the first run after those tests were added.
}
