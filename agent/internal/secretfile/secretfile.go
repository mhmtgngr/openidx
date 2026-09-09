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
// file in the container is private to the app's own UID whatever its mode. The
// engine's config directory holds three credentials rather than the two above:
// user-tokens.json, agent.json (the agent's own auth token) and
// ziti-identity.json (the private key that puts the device on the overlay).
//
// Two things get those bytes off a phone, and they need different answers.
//
// THE PLATFORM BACKUP. Android Auto Backup copies getFilesDir() to the user's
// Google Drive unless the manifest says otherwise, and iOS backs up
// Library/Application Support to iCloud unless the directory is flagged. That
// control is not in this package at all — it is android:allowBackup="false"
// plus dataExtractionRules in the client's manifest, and isExcludedFromBackup
// on the config directory in the iOS plugin. It is named here because this is
// the file someone reads when they ask what protects the agent's secrets.
// scripts/check-mobile-secrets-at-rest.sh fails the build if either half goes
// missing.
//
// ANYTHING THAT READS THE FILE SYSTEM. Closing the backup does nothing about a
// rooted phone, a jailbroken one, or an extraction from a device that is merely
// unlocked — and both platforms leave app storage decrypted from the first
// unlock after boot onwards, so "at rest" there means "readable". A mode bit
// answers none of it, and neither does the sandbox. The answer is a key the
// file system does not hold: Keystore, this package's seam onto the Android
// Keystore and the iOS Keychain. Register one with Use and every Write seals
// with it; register none and the platform default above is what applies, which
// is the right behaviour on a desktop where no such keystore exists.
//
// The two files Write guards belong to the interactive user: the tray, the CLI
// and `openidx-agent serve` all run in that session (the Windows SERVICE runs
// posture, enrolment and self-update, and talks to the tray over a named pipe —
// it never reads these two). That is what makes per-user DPAPI the right scope
// rather than machine scope.
//
// agent.json is the one file more than one local identity must read: both the
// SYSTEM service and the user's tray load it, so a per-user DPAPI blob would
// lock one of them out. WriteShared is that case — it takes the keystore seal,
// which has no such conflict because a phone has exactly one identity, and
// skips the per-user Windows layer. On a desktop, where no keystore is
// registered, it is byte-for-byte the os.WriteFile(0600) that file has always
// had. The directory-ACL question it still needs (which account is "the
// enrolled user" when the service writes first?) is recorded in
// docs/CLIENT-ACCESS-DESIGN.md §4.
//
// NOT COVERED, and said rather than implied: ziti-identity.json is written by
// the OpenZiti SDK's own enrolment call and read back by the SDK's transport,
// neither of which goes through this package. Sealing it would hand the SDK
// ciphertext, and unsealing it to a temporary file to hand over would put the
// private key back on disk to no purpose. It needs an SDK-side change and is
// recorded in docs/CLIENT-ACCESS-DESIGN.md §4 rather than half-done here.
package secretfile

import (
	"bytes"
	"errors"
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
func Write(path string, data []byte) error { return write(path, data, false) }

// WriteShared stores data at path for a file that more than one identity on the
// machine must be able to read — agent.json, which both the Windows SERVICE and
// the user's tray load. It takes the keystore seal when one is registered (a
// phone has one identity, so there is nothing to lock out) and skips the
// per-user Windows layer, which would lock out whichever of the two did not
// write the file.
func WriteShared(path string, data []byte) error { return write(path, data, true) }

func write(path string, data []byte, shared bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating secret directory: %w", err)
	}

	blob, marker, err := seal(data, shared)
	if err != nil {
		return fmt.Errorf("protecting %s: %w", filepath.Base(path), err)
	}
	if marker != nil {
		blob = append(append([]byte{}, marker...), blob...)
	}

	// 0600 still: it is the whole control on Unix and harmless on Windows,
	// where harden() applies the DACL that actually enforces.
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return err
	}
	if shared {
		return hardenShared(path)
	}
	return harden(path)
}

// seal applies the strongest protection available for this file, and returns
// the marker that says which one a reader will have to undo.
//
// A registered keystore wins outright rather than layering with DPAPI: the two
// never coexist — a keystore is registered by the gomobile boundary and DPAPI
// exists only on Windows — and stacking them would produce a blob whose reader
// has to guess the order.
func seal(data []byte, shared bool) (blob, marker []byte, err error) {
	if k := keystore(); k != nil {
		sealed, err := k.Wrap(data)
		if err != nil {
			return nil, nil, err
		}
		if len(sealed) == 0 {
			return nil, nil, errors.New("the keystore returned an empty seal")
		}
		return sealed, keystoreMagic, nil
	}
	if shared {
		// The per-user layer is exactly what "shared" opts out of.
		return data, nil, nil
	}
	sealed, protected, err := protect(data)
	if err != nil || !protected {
		return sealed, nil, err
	}
	return sealed, magic, nil
}

// Read returns the plaintext contents of a file written by Write or
// WriteShared. A file with no marker is returned as-is — that is an agent
// upgraded from before this package existed, and refusing it would sign every
// user out on upgrade.
func Read(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is the agent's own config dir
	if err != nil {
		return nil, err
	}
	// A failure to OPEN is wrapped as ErrUnsealable, whichever layer sealed it.
	// The bytes arrived; they mean nothing here; the caller's move is to ask for
	// the credential again rather than report a fault the user cannot act on.
	switch {
	case bytes.HasPrefix(raw, keystoreMagic):
		k := keystore()
		if k == nil {
			return nil, ErrNoKeystore
		}
		out, err := k.Unwrap(raw[len(keystoreMagic):])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsealable, err)
		}
		return out, nil
	case bytes.HasPrefix(raw, magic):
		out, err := unprotect(raw[len(magic):])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsealable, err)
		}
		return out, nil
	default:
		return raw, nil
	}
}

// Reseal rewrites a file that predates the protection now in force, using the
// writer that file's callers use (Write or WriteShared).
//
// It exists because registering a keystore protects what is written NEXT, and
// the file already sitting in the sandbox is the one holding the 30-day refresh
// token. Without this the control arrives on upgrade and the credential it was
// added for stays in the clear until something happens to rewrite it — which is
// a control that displays without enforcing, on a timer nobody is watching.
//
// A file that is absent, or already carries a marker, is left alone.
func Reseal(path string, write func(string, []byte) error) error {
	raw, err := os.ReadFile(path) //nolint:gosec // path is the agent's own config dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if IsProtected(raw) {
		return nil
	}
	return write(path, raw)
}

// Remove deletes the file, tolerating one that is already gone.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsProtected reports whether the bytes carry either of this package's markers
// — DPAPI or keystore. Exported for the tests that assert a file is not left in
// the clear, and used by Reseal to leave an already-sealed file alone.
func IsProtected(raw []byte) bool {
	return bytes.HasPrefix(raw, magic) || bytes.HasPrefix(raw, keystoreMagic)
}
