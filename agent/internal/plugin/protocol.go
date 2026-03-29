package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Request is sent to a plugin via stdin.
type Request struct {
	Action string                 `json:"action"`
	Type   string                 `json:"type,omitempty"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Response is received from a plugin via stdout.
type Response struct {
	Status      string                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	// For info action
	Name       string   `json:"name,omitempty"`
	Version    string   `json:"version,omitempty"`
	CheckTypes []string `json:"check_types,omitempty"`
}

// Execute runs a plugin executable with a request and returns the response.
func Execute(ctx context.Context, execPath string, req *Request, timeout time.Duration) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	input, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	cmd := exec.CommandContext(ctx, execPath)
	cmd.Stdin = bytes.NewReader(input)
	cmd.WaitDelay = timeout // unblock I/O goroutines after context cancel

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("plugin timed out after %s", timeout)
		}
		return nil, fmt.Errorf("plugin execution failed: %w (stderr: %s)", err, stderr.String())
	}

	var resp Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse plugin response: %w (stdout: %s)", err, stdout.String())
	}

	return &resp, nil
}
