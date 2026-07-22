package transport

import (
	"os"

	"go.uber.org/zap"
)

// NewTransport creates the appropriate transport based on available identity.
// When a Ziti identity file exists, it returns a ResilientTransport that prefers
// the Ziti overlay but automatically falls back to plain HTTPS whenever the
// overlay is unreachable (no edge routers, controller restart, transient network
// loss). This keeps the agent connected through control-plane hiccups without
// crashing or needing a re-enroll, and transparently resumes over Ziti when it
// recovers. Without a Ziti identity it returns a plain HTTPS client.
func NewTransport(serverURL, authToken, agentID, zitiIdentityFile, zitiServiceName string, logger *zap.Logger) Transport {
	https := NewClient(serverURL, authToken, agentID)
	if zitiIdentityFile != "" {
		if _, err := os.Stat(zitiIdentityFile); err == nil {
			ziti, err := NewZitiClient(zitiIdentityFile, zitiServiceName, serverURL, authToken, agentID)
			if err != nil {
				logger.Warn("Failed to create Ziti transport, using HTTPS only",
					zap.Error(err))
				return https
			}
			logger.Info("Using resilient transport (Ziti overlay with HTTPS fallback)",
				zap.String("service", zitiServiceName))
			return NewResilientTransport(ziti, https, logger)
		}
	}
	logger.Info("Using HTTPS transport", zap.String("server", serverURL))
	return https
}
