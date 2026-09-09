// Package authstore persists the end-user OAuth tokens for the tray/desktop
// session: the access token and the 30-day refresh token behind it.
//
// The file used to be written with os.WriteFile(..., 0600) and a comment
// promising DPAPI as a "hardening follow-up". On Windows that mode is
// discarded, so the promise was the only protection there and the file
// inherited %ProgramData%'s ACL, where every local account can read.
// agent/internal/secretfile now applies what each platform actually enforces —
// DPAPI plus an explicit file ACL on Windows, the 0600 mode elsewhere.
package authstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/sso"
)

const tokenFileName = "user-tokens.json"

// Path is where the tokens live for a given config dir.
func Path(dir string) string { return filepath.Join(dir, tokenFileName) }

// Save writes the tokens to <dir>/user-tokens.json, protected per platform.
func Save(dir string, t *sso.Tokens) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if err := secretfile.Write(Path(dir), data); err != nil {
		return fmt.Errorf("saving session: %w", err)
	}
	return nil
}

// Load reads the persisted tokens, or returns (nil, nil) if none exist.
func Load(dir string) (*sso.Tokens, error) {
	data, err := secretfile.Read(Path(dir))
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
	return secretfile.Remove(Path(dir))
}
