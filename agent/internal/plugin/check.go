package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
)

// PluginCheck wraps an external plugin executable as a checks.Check.
type PluginCheck struct {
	manifest *Manifest
	execPath string
	// execSHA256 is the executable's digest when it was loaded: the bytes the
	// signature and the permission checks were applied to. A plugin runs on
	// every check interval for as long as the agent runs, so a check made once
	// at discovery would say nothing about the file executed a week later.
	execSHA256 string
	checkType  string
}

// NewPluginCheck creates a Check adapter for a plugin. execSHA256 is the
// lowercase hex SHA-256 the executable had when it was verified; Run refuses to
// execute anything else, and refuses everything when it is empty.
func NewPluginCheck(manifest *Manifest, execPath, execSHA256, checkType string) *PluginCheck {
	return &PluginCheck{
		manifest:   manifest,
		execPath:   execPath,
		execSHA256: execSHA256,
		checkType:  checkType,
	}
}

func (p *PluginCheck) Name() string { return p.checkType }

func (p *PluginCheck) Run(ctx context.Context, params map[string]interface{}) *checks.CheckResult {
	if err := p.verifyExecutable(); err != nil {
		return &checks.CheckResult{
			Status:  checks.StatusError,
			Score:   0,
			Message: "plugin error: " + err.Error(),
		}
	}

	timeout := time.Duration(p.manifest.TimeoutSeconds) * time.Second

	req := &Request{
		Action: "check",
		Type:   p.checkType,
		Params: params,
	}

	resp, err := Execute(ctx, p.execPath, req, timeout)
	if err != nil {
		return &checks.CheckResult{
			Status:  checks.StatusError,
			Score:   0,
			Message: "plugin error: " + err.Error(),
		}
	}

	return &checks.CheckResult{
		Status:      mapStatus(resp.Status),
		Score:       resp.Score,
		Details:     resp.Details,
		Message:     resp.Message,
		Remediation: resp.Remediation,
	}
}

// verifyExecutable refuses to run the executable unless it still has the
// digest it was loaded with.
//
// This narrows the gap between check and use to the time one hash takes, and
// does not close it: the file is opened again by exec after this returns.
// Replacing it inside that window needs write access to a path the permission
// checks have already established only trusted accounts hold. Closing it fully
// would mean executing from the handle that was hashed, which neither Windows
// nor os/exec offers portably.
func (p *PluginCheck) verifyExecutable() error {
	if p.execSHA256 == "" {
		return fmt.Errorf("no digest was recorded for %s when it was loaded, so there is nothing "+
			"to check it against and it is not run", p.execPath)
	}
	got, err := sha256File(p.execPath)
	if err != nil {
		return fmt.Errorf("cannot verify %s before running it: %w", p.execPath, err)
	}
	if got != p.execSHA256 {
		return fmt.Errorf("%s has changed since it was loaded (sha256 %s, loaded as %s), so it is "+
			"not run. Restart the agent to load and verify the new file", p.execPath, got, p.execSHA256)
	}
	return nil
}

func mapStatus(s string) checks.Status {
	switch s {
	case "pass":
		return checks.StatusPass
	case "fail":
		return checks.StatusFail
	case "warn":
		return checks.StatusWarn
	case "error":
		return checks.StatusError
	default:
		return checks.StatusError
	}
}
