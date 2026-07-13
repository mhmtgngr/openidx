// Package authstore persists the end-user OAuth tokens for the tray/desktop
// session. MVP: a 0600 JSON file in the config dir. Hardening follow-up: move
// secrets to the Windows Credential Manager / DPAPI (per-user).
package authstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openidx/openidx/agent/internal/sso"
)

const tokenFileName = "user-tokens.json"

// Save writes the tokens to <dir>/user-tokens.json (0600).
func Save(dir string, t *sso.Tokens) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, tokenFileName), data, 0600)
}

// Load reads the persisted tokens, or returns (nil, nil) if none exist.
func Load(dir string) (*sso.Tokens, error) {
	data, err := os.ReadFile(filepath.Join(dir, tokenFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var t sso.Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}
	return &t, nil
}

// Clear removes the persisted tokens (sign-out).
func Clear(dir string) error {
	err := os.Remove(filepath.Join(dir, tokenFileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
