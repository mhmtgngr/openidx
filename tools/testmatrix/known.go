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

	"cmd/rekey": `Run by the "Integration Tests" job, which now names ` +
		`./cmd/rekey/... alongside ./test/integration/.... Its one test file ` +
		`is behind the "integration" tag while the package itself sits under ` +
		`the matrix's ./cmd/... entry, so for as long as that entry looked ` +
		`like coverage the package went through CI compiling zero tests: a ` +
		`294-line proof that a KEK rotation re-seals every encrypted value ` +
		`and leaves the plaintext readable, never once executed.`,
}
