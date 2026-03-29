package plugin

import (
	"context"
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
)

// PluginCheck wraps an external plugin executable as a checks.Check.
type PluginCheck struct {
	manifest  *Manifest
	execPath  string
	checkType string
}

// NewPluginCheck creates a Check adapter for a plugin.
func NewPluginCheck(manifest *Manifest, execPath, checkType string) *PluginCheck {
	return &PluginCheck{
		manifest:  manifest,
		execPath:  execPath,
		checkType: checkType,
	}
}

func (p *PluginCheck) Name() string { return p.checkType }

func (p *PluginCheck) Run(ctx context.Context, params map[string]interface{}) *checks.CheckResult {
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
