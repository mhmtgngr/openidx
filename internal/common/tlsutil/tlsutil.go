// Package tlsutil provides TLS helpers for OpenIDX service HTTP servers.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// NewTLSConfig builds a *tls.Config from the provided configuration.
// If CAFile is set, client certificate verification is enabled (mTLS).
func NewTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", cfg.CAFile)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsCfg, nil
}

// ListenAndServe starts the HTTP server with TLS if enabled, or plain HTTP otherwise.
// This is a drop-in replacement for server.ListenAndServe() that respects TLS config.
func ListenAndServe(server *http.Server, cfg config.TLSConfig, log *zap.Logger) error {
	if !cfg.Enabled {
		return server.ListenAndServe()
	}

	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return fmt.Errorf("TLS enabled but cert_file and key_file are required")
	}

	tlsCfg, err := NewTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}
	server.TLSConfig = tlsCfg

	log.Info("Starting server with TLS",
		zap.String("addr", server.Addr),
		zap.String("cert", cfg.CertFile),
		zap.Bool("mtls", cfg.CAFile != ""),
	)

	return server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
}
