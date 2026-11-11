//go:build !windows

package transport

// machineProxy: only Windows has a machine-wide proxy setting outside the
// environment; elsewhere HTTPS_PROXY/NO_PROXY (e.g. systemd EnvironmentFile)
// is the configuration.
func machineProxy() *winHTTPProxy { return nil }
