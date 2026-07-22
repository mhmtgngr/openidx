package enrollment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
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
	return EnrollWithManifest(logger, serverURL, token, configDir, "")
}

// EnrollWithManifest is Enroll plus an optional update_manifest_url persisted to
// config so the service's self-updater is wired at enroll time (e.g. the MSI's
// UPDATE_MANIFEST_URL property). Empty manifestURL keeps auto-update disabled.
func EnrollWithManifest(logger *zap.Logger, serverURL, token, configDir, manifestURL string) (*EnrollResult, error) {
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
		ServerURL:         serverURL,
		AgentID:           resp.AgentID,
		DeviceID:          resp.DeviceID,
		AuthToken:         resp.AuthToken,
		EnrolledAt:        time.Now().UTC().Format(time.RFC3339),
		UpdateManifestURL: manifestURL,
	}

	// If the server advertises a Ziti overlay service and an identity file is
	// already present on disk (the device enrolled its identity on a prior run),
	// wire the Ziti transport now — even without a fresh JWT. Otherwise a device
	// that already enrolled its identity would keep dialing an empty service.
	identityPath := filepath.Join(configDir, "ziti-identity.json")
	if resp.ZitiService != "" {
		if _, statErr := os.Stat(identityPath); statErr == nil {
			cfg.ZitiIdentityFile = identityPath
			cfg.ZitiServiceName = resp.ZitiService
		}
	}

	if err := cfg.Save(configDir); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	result := &EnrollResult{AgentConfig: cfg}

	// Step 3: Ziti enrollment (if server provided a Ziti JWT). The JWT is
	// exchanged for a Ziti identity right here — no operator step — and the
	// transport factory picks up ziti-identity.json on the next run. The JWT
	// is also kept on disk so a failed exchange can be retried manually
	// (`ziti edge enroll ziti-enrollment.jwt`).
	if resp.ZitiJWT != "" {
		jwtPath := filepath.Join(configDir, "ziti-enrollment.jwt")
		if err := os.WriteFile(jwtPath, []byte(resp.ZitiJWT), 0600); err != nil {
			logger.Warn("Failed to save Ziti JWT", zap.Error(err))
		} else {
			logger.Info("Ziti enrollment JWT saved", zap.String("path", jwtPath))
			cfg.ZitiIdentityFile = identityPath
			// Persist the base-API service so the Ziti transport dials the right
			// service (defaults to openidx-access when the server didn't say).
			if resp.ZitiService != "" {
				cfg.ZitiServiceName = resp.ZitiService
			} else {
				cfg.ZitiServiceName = "openidx-access"
			}
			if err := cfg.Save(configDir); err != nil {
				logger.Warn("Failed to update config with Ziti identity path", zap.Error(err))
			}
			if err := enrollZitiIdentity(resp.ZitiJWT, identityPath); err != nil {
				// Not fatal: the agent still works over HTTPS, and the saved
				// JWT allows a later retry while it is still valid.
				logger.Warn("Ziti identity enrollment failed; agent will use HTTPS transport",
					zap.Error(err), zap.String("jwt", jwtPath))
			} else {
				logger.Info("Ziti identity enrolled", zap.String("path", identityPath))
				result.ZitiIdentity = identityPath
			}
		}
	}

	logger.Info("Enrollment complete",
		zap.String("config_dir", configDir),
		zap.String("agent_id", cfg.AgentID))

	return result, nil
}

// enrollZitiIdentity exchanges a one-time enrollment JWT for a Ziti identity
// (key + certs) and writes it to identityPath. Mirrors the access-service's
// own SDK enrollment flow.
func enrollZitiIdentity(jwtStr, identityPath string) error {
	claims, jwtToken, err := enroll.ParseToken(jwtStr)
	if err != nil {
		return fmt.Errorf("parse enrollment JWT: %w", err)
	}

	var keyAlg ziti.KeyAlgVar
	if err := keyAlg.Set("EC"); err != nil {
		return fmt.Errorf("set key algorithm: %w", err)
	}

	zitiCfg, err := enroll.Enroll(enroll.EnrollmentFlags{
		Token:     claims,
		JwtToken:  jwtToken,
		JwtString: jwtStr,
		KeyAlg:    keyAlg,
	})
	if err != nil {
		// The SDK enrolls by connecting to the controller address embedded in
		// the JWT (its "iss"). The common failures are the controller being
		// unreachable from this host, or advertising an address whose TLS cert
		// doesn't match the enrollment signer — e.g. a local-dev controller
		// (a *.localtest.me / localhost address, which resolves to 127.0.0.1)
		// reached from a remote agent. Both surface as a signature/verification
		// error. The agent still works over HTTPS; the Ziti overlay just won't
		// be available until the controller advertises a reachable address.
		return fmt.Errorf("enroll identity against controller %q "+
			"(the controller must be reachable from this host and advertise a "+
			"publicly-resolvable address whose cert matches the JWT signer): %w",
			claims.Issuer, err)
	}

	data, err := json.MarshalIndent(zitiCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	if err := os.WriteFile(identityPath, data, 0600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}
