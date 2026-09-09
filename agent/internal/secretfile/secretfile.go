// Package secretfile writes and reads the agent's on-disk secrets with the
// protection the running platform actually enforces.
//
// WHY IT EXISTS. Two files under the agent's config directory are credentials:
//
//	user-tokens.json        the signed-in user's access token and their 30-day
//	                        refresh token (agent/internal/authstore)
//	control-endpoint.json   the loopback address and the bearer that fully
//	                        drives the control engine — sign-in, enrolment, PAM
//	                        launch, Ziti dial (agent/internal/control)
//
// Both were written with os.WriteFile(..., 0600). On Linux and macOS that is
// the control it looks like. ON WINDOWS THE MODE BITS ARE DISCARDED: the Go
// runtime maps 0600 to "not read-only" and nothing else, so the file simply
// inherits the ACL of %ProgramData%\OpenIDX\agent — which inherits
// %ProgramData%, where BUILTIN\Users can read. Every local account on the
// machine could read the refresh token and the control bearer, and the code
// said 0600 in both places, which is what made it invisible.
//
// WHAT THIS DOES. On Windows: DPAPI (CryptProtectData, per-user scope, so the
// ciphertext is useless to another account even with the bytes) plus an
// explicit DACL on the file itself — SYSTEM, Administrators, and the user that
// wrote it, with inheritance switched off so the ProgramData ACL stops
// applying. On Linux and macOS: exactly what happened before, a 0600 file,
// because there the mode is the control.
//
// ON ANDROID AND iOS THE MODE IS NOT THE CONTROL EITHER, and it took a second
// look to see it. This package builds for both — the engine is bound with
// gomobile into the companion app — and 0600 inside an app sandbox is not
// protection that was added, it is protection that was already there: every
// file in the container is private to the app's own UID whatever its mode. What
// the mode does not touch is the one way those bytes leave the device, which is
// the platform backup. Android Auto Backup copies getFilesDir() to the user's
// Google Drive unless the manifest says otherwise, and iOS backs up
// Library/Application Support to iCloud unless the directory is flagged. The
// engine's config directory is exactly those two paths, and it holds three
// credentials rather than the two above: user-tokens.json, agent.json (the
// agent's own auth token) and ziti-identity.json (the private key that puts the
// device on the overlay).
//
// So the control on mobile is not in this package at all — it is
// android:allowBackup="false" plus dataExtractionRules in the client's manifest,
// and isExcludedFromBackup on the config directory in the iOS plugin. It is
// named here because this is the file someone reads when they ask what protects
// the agent's secrets, and the answer for two of the five platforms is
// elsewhere. scripts/check-mobile-secrets-at-rest.sh fails the build if either
// half goes missing.
//
// The two files this guards belong to the interactive user: the tray, the CLI
// and `openidx-agent serve` all run in that session (the Windows SERVICE runs
// posture, enrolment and self-update, and talks to the tray over a named pipe —
// it never reads these two). That is what makes per-user DPAPI the right scope
// rather than machine scope.
//
// NOT COVERED, and said rather than implied: agent.json in the same directory
// carries the agent's own auth_token, and both the SYSTEM service and the
// user's tray read it. A per-user DPAPI blob would break one of those two, so
// it stays plaintext and needs a directory ACL decision (which account is "the
// enrolled user" when the service writes first?) rather than this. It is
// recorded in docs/CLIENT-ACCESS-DESIGN.md §4.
package secretfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// magic marks a payload this package encrypted. Without it, a reader cannot
// tell an encrypted blob from a plaintext file written by an older agent, and
// would hand the caller garbage to parse. With it, the upgrade path is a
// branch rather than a guess, and a Windows-written file copied to another
// platform produces a clear error instead of nonsense.
var magic = []byte("OPENIDX-SECRETFILE-DPAPI-v1\n")

// Write stores data at path, protected as the platform allows. The parent
// directory is created 0700 if missing.
func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating secret directory: %w", err)
	}

	blob, protected, err := protect(data)
	if err != nil {
		return fmt.Errorf("protecting %s: %w", filepath.Base(path), err)
	}
	if protected {
		blob = append(append([]byte{}, magic...), blob...)
	}

	// 0600 still: it is the whole control on Unix and harmless on Windows,
	// where harden() applies the DACL that actually enforces.
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return err
	}
	return harden(path)
}

// Read returns the plaintext contents of a file written by Write. A file with
// no marker is returned as-is — that is an agent upgraded from before this
// package existed, and refusing it would sign every user out on upgrade.
func Read(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is the agent's own config dir
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, magic) {
		return raw, nil
	}
	return unprotect(raw[len(magic):])
}

// Remove deletes the file, tolerating one that is already gone.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsProtected reports whether the bytes carry this package's marker. Exported
// for the tests that assert a Windows-written file is not left in the clear.
func IsProtected(raw []byte) bool { return bytes.HasPrefix(raw, magic) }
