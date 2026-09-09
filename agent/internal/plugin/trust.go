package plugin

// Whether a path is safe to execute from.
//
// WHY THIS EXISTS. Discover() walks plugin_dir, finds any file that is
// executable, and hands it to exec.CommandContext. Both callers of LoadPlugins
// are long-running daemons — `openidx-agent serve` and, on Windows, the service,
// which runs as SYSTEM. Nothing checked who could write what it was about to
// run.
//
// That is the oldest rule in this shape and every tool that faces it keeps it:
// sudo refuses a world-writable sudoers, ssh refuses a group-writable private
// key, git refuses a repository owned by somebody else. The reason is the same
// each time — a privileged process that executes a file anyone can replace is
// not running the operator's code, it is running whoever got there last.
//
// The agent's own config directory ACL is a separate open question, recorded in
// agent/internal/secretfile's package doc: agent.json holds plugin_dir, so an
// account that can write that file chooses the directory this reads. Closing
// one without the other leaves the chain intact, which is why this refuses
// rather than warns, and why the Windows half refuses outright (see
// trust_windows.go) rather than pretending to a check it does not implement.
//
// WHAT IS CHECKED, and it is deliberately not the whole ancestry: the plugin
// root, the individual plugin's directory, and the executable. Those are the
// three places a swap actually happens. Walking to the filesystem root would
// catch a world-writable /opt but would also refuse a great many legitimate
// layouts for a threat that is already game over, and a control that is
// switched off because it is too noisy protects nothing.

// requireTrustedPath reports why path must not be executed from, or nil when it
// is safe. Implemented per platform: the mode bits are the control on Unix and
// mean nothing on Windows.
func requireTrustedPath(path string) error { return checkTrustedPath(path) }
