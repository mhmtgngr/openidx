package enrollment

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

// SealedTokenFile is where --keep-token keeps the fleet enrolment token.
//
// It exists for the silent installer. msiexec runs the enrol action once,
// often before the network is up (Autopilot, a GPO install at boot), and a
// failed enrolment used to leave a device with an agent and no identity until
// somebody ran the command again. With the token kept, the service finishes
// the enrolment itself (RetryEnroll), and a later re-enrolment needs nothing
// from the installer.
//
// Protection is secretfile's: DPAPI plus an owner-only DACL on Windows, a 0600
// file elsewhere. The MSI's deferred action and the service both run as
// LocalSystem, so the DPAPI key that seals it is the one that opens it.
const SealedTokenFile = "enroll-token.sealed"

// SealedToken is what is kept: the token and the settings the enrolment that
// carried it was given, so a retried enrolment is the same enrolment.
type SealedToken struct {
	ServerURL   string `json:"server_url"`
	Token       string `json:"token"`
	ManifestURL string `json:"manifest_url,omitempty"`
	// ManifestExplicit records that the installer named the manifest URL
	// (possibly empty, which turns self-update off).
	ManifestExplicit bool   `json:"manifest_explicit,omitempty"`
	Tunnel           *bool  `json:"tunnel,omitempty"`
	ProxyURL         string `json:"proxy_url,omitempty"`
	ServerCA         string `json:"server_ca,omitempty"`
	LogLevel         string `json:"log_level,omitempty"`
}

// SealedTokenPath is the sealed token's path under configDir.
func SealedTokenPath(configDir string) string { return filepath.Join(configDir, SealedTokenFile) }

// SealToken writes t, protected, to configDir.
func SealToken(configDir string, t SealedToken) error {
	if strings.TrimSpace(t.Token) == "" || strings.TrimSpace(t.ServerURL) == "" {
		return errors.New("a sealed token needs a server URL and a token")
	}
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	if err := secretfile.Write(SealedTokenPath(configDir), data); err != nil {
		return fmt.Errorf("seal the enrolment token: %w", err)
	}
	return nil
}

// LoadSealedToken reads the sealed token. A missing file is (nil, nil).
func LoadSealedToken(configDir string) (*SealedToken, error) {
	data, err := secretfile.Read(SealedTokenPath(configDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var t SealedToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse the sealed enrolment token: %w", err)
	}
	if t.Token == "" || t.ServerURL == "" {
		return nil, errors.New("the sealed enrolment token is incomplete")
	}
	return &t, nil
}

// DeleteSealedToken removes the sealed token; a missing one is not an error.
func DeleteSealedToken(configDir string) error {
	return secretfile.Remove(SealedTokenPath(configDir))
}

// Options are the inputs of one enrolment.
type Options struct {
	ServerURL   string
	Token       string
	ConfigDir   string
	ManifestURL string
	// ManifestExplicit is true when the caller named ManifestURL.
	ManifestExplicit bool
	// Tunnel, when set, writes agent.json's tunnel.enabled.
	Tunnel   *bool
	ProxyURL string
	ServerCA string
	LogLevel string
	// KeepToken seals Token before enrolling, so the service can finish or
	// redo the enrolment later.
	KeepToken bool
}

func (o Options) sealed() SealedToken {
	return SealedToken{
		ServerURL: o.ServerURL, Token: o.Token,
		ManifestURL: o.ManifestURL, ManifestExplicit: o.ManifestExplicit,
		Tunnel: o.Tunnel, ProxyURL: o.ProxyURL, ServerCA: o.ServerCA, LogLevel: o.LogLevel,
	}
}

// OptionsFromSealed turns a sealed token back into enrolment options.
func OptionsFromSealed(configDir string, t SealedToken) Options {
	return Options{
		ServerURL: t.ServerURL, Token: t.Token, ConfigDir: configDir,
		ManifestURL: t.ManifestURL, ManifestExplicit: t.ManifestExplicit,
		Tunnel: t.Tunnel, ProxyURL: t.ProxyURL, ServerCA: t.ServerCA, LogLevel: t.LogLevel,
		KeepToken: true,
	}
}
