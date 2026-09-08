package main

// knownFindings is the register: every coverage collision the tree currently
// has, with the reason it is tolerated. A finding absent from here fails the
// run; an entry that no longer reproduces fails it too, so the register can
// only shrink.
//
// It starts with one entry. The others the first run found were not collisions
// to tolerate but defects to fix, and they were fixed rather than registered:
// os_version claimed Android while reporting the Linux kernel release where
// the policy means the Android version, and process_running claimed every
// platform while globbing /proc, which is the process table on Linux alone.
// Both now decline to answer where they cannot, which is what leaves one
// implementation per check per platform.
//
// The key is "<kind>:<check_type>:<platform>".
var knownFindings = map[string]string{
	"claimed_twice:agent_version:android": "agent_version reports the client's own version string. " +
		"The Go engine's implementation is platform-independent and answers for the companion app; " +
		"the Kotlin agent's answers for the managed-device agent. They describe DIFFERENT binaries " +
		"that install side by side on the same handset, so one implementation could not serve both " +
		"— this is the one collision that is correct. It stays until the two clients stop shipping " +
		"as separate packages, which is a product decision rather than a code cleanup.",
}
