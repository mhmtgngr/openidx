package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/devicekey"
	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/transport"
)

// The sealed enrollment token (Faz B8.4).
//
// A device installed with a fleet token (MSI ENROLL_TOKEN, Intune, GPO, the
// enroll command's --token) keeps that token sealed next to agent.json. When
// the server stops accepting the device's credential for good (authFailThreshold
// 401s in a row: its row was replaced, a restore lost it) the service enrols
// again with the sealed token. The server finds the row by the device's
// fingerprint and rotates its credential, so the device comes back as itself
// without anyone at the keyboard.
//
// A revoke is different: an administrator took the device off the network,
// and the server answers it 403. The agent then deletes the sealed token, so
// nothing on the device can bring it back on its own; an administrator who
// reinstates it enrols it again by hand.

const sealedTokenFileName = "enroll-token"

// SealedTokenPath is where the sealed enrollment token lives in dir.
func SealedTokenPath(dir string) string { return filepath.Join(dir, sealedTokenFileName) }

// SaveSealedToken seals token in dir for later re-enrolment. It is sealed as
// agent.json is (WriteShared): the enrolment may run as an administrator and
// the service reads it as SYSTEM.
func SaveSealedToken(dir, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	return secretfile.WriteShared(SealedTokenPath(dir), []byte(token))
}

// LoadSealedToken reads the sealed enrollment token, or "" when there is none.
func LoadSealedToken(dir string) string {
	b, err := secretfile.Read(SealedTokenPath(dir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// RemoveSealedToken deletes the sealed enrollment token.
func RemoveSealedToken(dir string) error { return secretfile.Remove(SealedTokenPath(dir)) }

// forgetSealedToken is the agent's answer to a revoke.
func (a *Agent) forgetSealedToken() {
	if LoadSealedToken(a.configDir) == "" {
		return
	}
	if err := RemoveSealedToken(a.configDir); err != nil {
		a.logger.Warn("could not delete the sealed enrollment token after a revoke", zap.Error(err))
		return
	}
	a.logger.Info("the device was revoked; its sealed enrollment token is deleted")
}

// reenrolFromSealedToken enrols the device again with its sealed token and
// switches to the credential that enrolment returns. It reports whether it
// did. Only the service does this (DisableRemoteSupport, as in
// reloadIfReenrolled): no other goroutine of it holds the client.
func (a *Agent) reenrolFromSealedToken() bool {
	if !a.DisableRemoteSupport {
		return false
	}
	token := LoadSealedToken(a.configDir)
	if token == "" || a.config == nil || a.config.ServerURL == "" {
		return false
	}
	client := transport.NewClient(a.config.ServerURL, "", "")
	if a.deviceKey != nil {
		if pub, err := devicekey.PublicKeyBase64(a.deviceKey); err == nil {
			client.SetEnrollmentDeviceKey(pub, a.deviceKey.Kind())
		}
	}
	resp, err := client.Enroll(token)
	if err != nil {
		if errors.Is(err, transport.ErrAgentRevoked) {
			a.revoked.Store(true)
			a.forgetSealedToken()
		}
		a.logger.Warn("re-enrolling with the sealed enrollment token failed", zap.Error(err))
		return false
	}
	cfg := *a.config
	cfg.AgentID, cfg.DeviceID, cfg.AuthToken = resp.AgentID, resp.DeviceID, resp.AuthToken
	cfg.DeviceKeyBound = resp.DeviceKeyBound
	if err := cfg.Save(a.configDir); err != nil {
		a.logger.Error("re-enrolled but could not save agent.json", zap.Error(fmt.Errorf("save: %w", err)))
		return false
	}
	a.config = &cfg
	a.client = transport.NewTransport(cfg.ServerURL, cfg.AuthToken, cfg.AgentID,
		cfg.ZitiIdentityFile, cfg.ZitiServiceName, a.logger)
	if a.deviceKey != nil {
		transport.SetSigner(a.client, devicekey.Signer{Key: a.deviceKey, AgentID: cfg.AgentID})
	}
	a.logger.Info("the device enrolled itself again with its sealed enrollment token",
		zap.String("agent_id", cfg.AgentID))
	return true
}
