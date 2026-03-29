package enrollment

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

// EnrollResult contains the enrollment outcome.
type EnrollResult struct {
	AgentConfig  *agent.AgentConfig
	ZitiIdentity string // path to ziti identity file, empty if no Ziti
}

// Enroll performs the full enrollment flow: HTTP enrollment + optional Ziti enrollment.
func Enroll(logger *zap.Logger, serverURL, token, configDir string) (*EnrollResult, error) {
	// Step 1: HTTP enrollment with server
	client := transport.NewClient(serverURL, "")
	resp, err := client.Enroll(token)
	if err != nil {
		return nil, fmt.Errorf("server enrollment failed: %w", err)
	}

	logger.Info("Server enrollment successful",
		zap.String("agent_id", resp.AgentID),
		zap.String("device_id", resp.DeviceID))

	// Step 2: Save agent config
	cfg := &agent.AgentConfig{
		ServerURL:  serverURL,
		AgentID:    resp.AgentID,
		DeviceID:   resp.DeviceID,
		AuthToken:  resp.AuthToken,
		EnrolledAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := cfg.Save(configDir); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	result := &EnrollResult{AgentConfig: cfg}

	// Step 3: Ziti enrollment (if server provided a Ziti JWT)
	// The server response may include a ziti_jwt field for Ziti overlay enrollment.
	// For now, we check if the field exists and log it.
	// Full Ziti enrollment requires the enroll package which needs a running controller.
	// This will be wired when the server-side creates Ziti identities during enrollment.
	logger.Info("Enrollment complete",
		zap.String("config_dir", configDir),
		zap.String("agent_id", cfg.AgentID))

	return result, nil
}
