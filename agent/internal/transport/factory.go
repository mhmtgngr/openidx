package transport

import (
	"os"

	"go.uber.org/zap"
)

// NewTransport creates the appropriate transport based on available identity.
// If a Ziti identity file is provided and exists on disk, a ZitiClient is
// returned. Otherwise it falls back to a plain HTTPS Client.
func NewTransport(serverURL, authToken, zitiIdentityFile, zitiServiceName string, logger *zap.Logger) Transport {
	if zitiIdentityFile != "" {
		if _, err := os.Stat(zitiIdentityFile); err == nil {
			client, err := NewZitiClient(zitiIdentityFile, zitiServiceName, serverURL, authToken)
			if err != nil {
				logger.Warn("Failed to create Ziti transport, falling back to HTTPS",
					zap.Error(err))
			} else {
				logger.Info("Using Ziti transport",
					zap.String("service", zitiServiceName))
				return client
			}
		}
	}
	logger.Info("Using HTTPS transport", zap.String("server", serverURL))
	return NewClient(serverURL, authToken)
}
