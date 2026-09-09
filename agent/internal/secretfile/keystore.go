package secretfile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// Keystore seals bytes with a key this process cannot read.
//
// WHY AN ORACLE AND NOT A KEY. The obvious shape for this is "the host fetches
// a key and hands Go 32 bytes, Go does the AES-GCM". That shape cannot use a
// hardware-backed key AT ALL: an AndroidKeyStore key is non-exportable by
// construction — SecretKey.getEncoded() returns null for one — and the whole
// property being bought here is that the key is somewhere the file system is
// not. A key Go can hold is a key that was in a file a moment ago. So what
// crosses is the operation, not the material.
//
// The implementation lives outside Go, because the only keystores that answer
// the question are the platform's: the Android Keystore (a TEE or StrongBox key
// on hardware that has one) and the iOS Keychain (protected by a
// hardware-derived class key, and marked so it cannot be restored to another
// device). agent/mobile carries the gomobile boundary that reaches them.
//
// The contract an implementation must meet, and which SelfTest checks:
//
//   - Unwrap(Wrap(x)) == x.
//   - Wrap is randomised: Wrap(x) twice gives two different answers, so the
//     file does not leak that two secrets are equal.
//   - Wrap(x) does not CONTAIN x. This is the one that catches the plausible
//     fake — a "wrap" that returns header||plaintext round-trips perfectly and
//     leaves the secret on disk in full.
//   - The key is bound to this device and this app. Go cannot check that one;
//     it is the host's, and scripts/check-mobile-keystore.sh reads the host
//     sources for it.
type Keystore interface {
	// Wrap seals plaintext. The returned bytes are what lands on disk.
	Wrap(plaintext []byte) ([]byte, error)
	// Unwrap recovers what Wrap sealed.
	Unwrap(sealed []byte) ([]byte, error)
}

// keystoreMagic marks a payload sealed by a Keystore, distinct from the DPAPI
// marker for the same reason that one exists: a reader has to know which of
// three shapes it is holding — keystore-sealed, DPAPI-sealed, or a plaintext
// file written by a build from before either.
var keystoreMagic = []byte("OPENIDX-SECRETFILE-KEYSTORE-v1\n")

var (
	ksMu     sync.RWMutex
	ksActive Keystore
)

// ErrUnsealable means the bytes are there and cannot be opened: the keystore
// refused them, or the DPAPI blob belongs to another user or machine.
//
// It is a sentinel because the right response is different from every other
// read failure. A file that cannot be read is a problem; a SECRET that cannot
// be opened is a session that no longer exists, and the caller's move is to ask
// the user to sign in again rather than to report a fault they cannot act on.
// Callers match with errors.Is.
var ErrUnsealable = errors.New("this secret cannot be opened on this device")

// ErrNoKeystore is the case where nothing is registered to open a
// keystore-sealed file — a phone's config directory copied to a desktop, or a
// build that stopped registering one. It is an ErrUnsealable: same outcome, and
// the extra detail is for the person reading the message.
var ErrNoKeystore = fmt.Errorf("%w: it was sealed by the device keystore and no keystore is registered", ErrUnsealable)

// Use registers k as the keystore for every subsequent Write and Read, after
// proving it actually seals. A keystore that fails SelfTest is not registered
// and the error says which property it broke: the caller's move is to refuse to
// start, not to carry on writing credentials in the clear.
func Use(k Keystore) error {
	if k == nil {
		return errors.New("nil keystore")
	}
	if err := SelfTest(k); err != nil {
		return err
	}
	ksMu.Lock()
	ksActive = k
	ksMu.Unlock()
	return nil
}

// Forget unregisters the keystore, so a process looks like one that has just
// launched. It exists for tests — the registration is process-wide and a test
// that leaves one behind changes what every later test writes — and touches no
// file: a secret already sealed on disk stays sealed and becomes unreadable
// until a keystore is registered again.
func Forget() {
	ksMu.Lock()
	ksActive = nil
	ksMu.Unlock()
}

// Active reports whether a keystore is registered. Exported for the tests and
// for callers that need to state what protects a file rather than assume.
func Active() bool {
	ksMu.RLock()
	defer ksMu.RUnlock()
	return ksActive != nil
}

// keystore returns the registered keystore, or nil.
func keystore() Keystore {
	ksMu.RLock()
	defer ksMu.RUnlock()
	return ksActive
}

// SelfTest exercises k against a probe and reports the first property it fails.
//
// It exists because every other check on this control is a compile-time one,
// and the failures worth catching all compile: a stub returning its argument, a
// wrap with a static IV, a "seal" that prefixes a header. Each of those ships a
// build that runs, signs in, and stores the 30-day refresh token in a form the
// next reader of the file can use.
//
// A panic from the host implementation is turned into an error rather than
// taking the process down: this is a call into another language whose failure
// modes are not Go's, and the honest outcome of "the keystore misbehaved" is a
// refusal to start with a message, not a crash on launch.
func SelfTest(k Keystore) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the keystore panicked during its self-test: %v", r)
		}
	}()

	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return fmt.Errorf("generating a self-test probe: %w", err)
	}

	first, err := k.Wrap(probe)
	if err != nil {
		return fmt.Errorf("the keystore could not wrap a 32-byte probe: %w", err)
	}
	if len(first) == 0 {
		return errors.New("the keystore returned an empty seal for a 32-byte probe")
	}
	if bytes.Equal(first, probe) {
		return errors.New("the keystore returned the plaintext unchanged, so nothing is sealed")
	}
	if bytes.Contains(first, probe) {
		return errors.New("the seal CONTAINS the plaintext in full — this is a header around the " +
			"secret, not an encryption of it, and it round-trips perfectly while leaving the " +
			"credential readable on disk")
	}

	back, err := k.Unwrap(first)
	if err != nil {
		return fmt.Errorf("the keystore could not unwrap what it had just wrapped: %w", err)
	}
	if !bytes.Equal(back, probe) {
		return errors.New("unwrapping the keystore's own seal did not return the plaintext")
	}

	second, err := k.Wrap(probe)
	if err != nil {
		return fmt.Errorf("the keystore could not wrap the probe a second time: %w", err)
	}
	if bytes.Equal(first, second) {
		return errors.New("wrapping the same plaintext twice gave the same bytes: the wrap is " +
			"deterministic, so the file reveals when two secrets are equal and the nonce is " +
			"either absent or fixed")
	}

	return nil
}
