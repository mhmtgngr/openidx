// Package racecost answers one question for the gate tools: is this test binary
// built with the race detector?
//
// Two of this repository's gates -- deadconfig and deadservice -- answer a
// question about the WHOLE MODULE, so their tests load and type-check every
// package in it, and deadservice then builds SSA and runs rapid type analysis
// over every binary. That is expensive uninstrumented. Under -race it is
// ruinous, because the detector carries shadow state for the memory the
// type-checker and the SSA builder allocate, and those allocate a lot.
//
// Measured on a 4-CPU / 16 GB machine -- the shape of a GitHub-hosted runner:
//
//	go test -race ./tools/deadconfig/     8.04 GB peak,  54s
//	go test -race ./tools/deadservice/   13.03 GB peak, 126s
//	both at once, which -p 4 permits     14.22 GB peak, then the kernel OOM
//	                                     killer took both test binaries at 619s
//
// `go test -race ./...` runs four packages at a time. Either of those two
// beside anything else is most of a runner; the two together is more than one.
//
// WHAT THAT LOOKS LIKE IN CI IS NOT A TEST FAILURE. There is no FAIL line and
// no "WARNING: DATA RACE". The process is killed, the runner goes with it, and
// the log ends:
//
//	##[error]The runner has received a shutdown signal.
//	##[error]Process completed with exit code 143.
//
// under a check named "Race Detector" -- a control reporting a diagnosis it did
// not make, which is the same failure the explicit -timeout on that job was
// added to stop.
//
// So the whole-module half of those tests does not run under the race detector.
// Nothing stops being proven: both tools have a dedicated CI job that runs
// `go test -short ./tools/X/` and then the tool itself over the whole module as
// a hard gate, uninstrumented, on every push, and both jobs are in the
// Required Checks list. The analysis runs exactly where it ran before; it stops
// running in the one place it could only report as infrastructure.
//
// The skip is keyed on the build tag rather than on -short alone because the
// cost belongs to the instrumentation, not to a flag: `go test -race ./...`
// typed by hand on a 16 GB laptop is the same command, and it OOMs the same
// way. racecost_test.go keeps the two facts from drifting apart.
package racecost
