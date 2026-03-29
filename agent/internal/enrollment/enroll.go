package enrollment

import (
	"fmt"
	"os"
	"path/filepath"
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
	client := transport.NewClient(serverURL, "", "")
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
	// Save the JWT to disk so the operator (or a future automated step) can
	// complete Ziti identity enrollment against a running controller.
	// The transport factory picks up ziti-identity.json on the next run once
	// enrollment has been completed.
	if resp.ZitiJWT != "" {
		jwtPath := filepath.Join(configDir, "ziti-enrollment.jwt")
		if err := os.WriteFile(jwtPath, []byte(resp.ZitiJWT), 0600); err != nil {
			logger.Warn("Failed to save Ziti JWT", zap.Error(err))
		} else {
			logger.Info("Ziti enrollment JWT saved", zap.String("path", jwtPath))
			// Update config with the identity file path (will exist after ziti enrollment).
			cfg.ZitiIdentityFile = filepath.Join(configDir, "ziti-identity.json")
			result.ZitiIdentity = cfg.ZitiIdentityFile
			if err := cfg.Save(configDir); err != nil {
				logger.Warn("Failed to update config with Ziti identity path", zap.Error(err))
			}
		}
	}

	logger.Info("Enrollment complete",
		zap.String("config_dir", configDir),
		zap.String("agent_id", cfg.AgentID))

	return result, nil
}
