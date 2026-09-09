package mobile

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

// Keystore is implemented by the HOST — Kotlin against the Android Keystore,
// Swift against the iOS Keychain — and handed to Start. It is how the engine's
// credentials get a key that is not in the file system.
//
// WHAT IT IS FOR. Everything the engine writes into the app sandbox is a
// credential: user-tokens.json holds the 30-day refresh token, agent.json the
// agent's own auth token. The sandbox keeps other apps out and
// allowBackup="false" keeps them out of the cloud, but both platforms decrypt
// app storage at the first unlock after boot and leave it decrypted, so a
// rooted phone, a jailbroken one, or an extraction from a merely unlocked
// device reads them as text. A key held by the platform keystore is the control
// for that, and Go cannot reach one: it is JNI on Android and the Security
// framework on iOS.
//
// WHY THE KEY DOES NOT CROSS. The shape that suggests itself is "the host
// fetches 32 bytes and hands them to Go". That shape cannot use a
// hardware-backed key at all — an AndroidKeyStore key is non-exportable by
// construction — so it would trade the whole property for convenience. What
// crosses is the operation.
//
// WHY ONE STRING IN AND ONE STRING OUT. gomobile binds a Go interface into a
// Java interface and an ObjC protocol so the host can implement it, but the
// generated shape for a method returning (string, error) differs between the
// two: Java gets `String wrap(String) throws Exception`, ObjC gets a BOOL, an
// out-parameter and an NSError**. A single String -> String method has exactly
// one spelling in both, and this is a security control whose host halves are
// only ever compiled by CI — a binding surprise here is either a broken build
// or, worse, a call that compiles and does the wrong thing. So the reply is
// tagged instead:
//
//	"ok:" + standard base64 of the result
//	"error:" + a message
//
// Anything else is a malformed reply and fails the call. base64 because the
// boundary carries strings, and this package's contract (see the package doc)
// is that only string and error cross it.
type Keystore interface {
	// Wrap seals the standard-base64 plaintext and returns "ok:<base64>" or
	// "error:<message>". The seal must be randomised — the same plaintext
	// twice must give two different answers — and must not contain the
	// plaintext. Start checks both before the engine touches a credential.
	Wrap(plaintextBase64 string) string
	// Unwrap reverses Wrap: it takes "the base64 of the sealed bytes" and
	// returns "ok:<base64 of the plaintext>" or "error:<message>".
	Unwrap(sealedBase64 string) string
}

// hostKeystore adapts the host's string boundary to the byte-oriented
// secretfile.Keystore the rest of the agent uses. The base64 lives here rather
// than in secretfile because the constraint that produced it — what gomobile
// can carry — belongs to this boundary and nowhere else.
type hostKeystore struct{ host Keystore }

func (k hostKeystore) Wrap(plaintext []byte) ([]byte, error) {
	return reply(k.host.Wrap(base64.StdEncoding.EncodeToString(plaintext)), "Wrap")
}

func (k hostKeystore) Unwrap(sealed []byte) ([]byte, error) {
	return reply(k.host.Unwrap(base64.StdEncoding.EncodeToString(sealed)), "Unwrap")
}

// reply decodes the host's tagged answer.
//
// A malformed reply is reported by its shape and its length, never by echoing
// it: the most likely thing a host returns when it has misunderstood the
// contract is the plaintext, and putting that in an error message writes the
// credential to the log the engine keeps on disk.
func reply(raw, op string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return nil, fmt.Errorf("the host keystore's %s returned an empty string; "+
			"the contract is \"ok:<base64>\" or \"error:<message>\"", op)
	case strings.HasPrefix(s, "error:"):
		return nil, fmt.Errorf("the host keystore's %s failed: %s", op,
			strings.TrimSpace(strings.TrimPrefix(s, "error:")))
	case strings.HasPrefix(s, "ok:"):
		payload := strings.Map(dropSpace, strings.TrimPrefix(s, "ok:"))
		out, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("the host keystore's %s returned an \"ok:\" payload that is "+
				"not standard base64: %w", op, err)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("the host keystore's %s returned \"ok:\" with an empty payload", op)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("the host keystore's %s returned %d bytes starting with neither "+
			"\"ok:\" nor \"error:\"; the value is not shown because a host that has misread the "+
			"contract most likely returned the plaintext", op, len(s))
	}
}

// dropSpace strips whitespace from a base64 payload: a host base64 encoder that
// line-wraps (Android's Base64 does unless NO_WRAP is passed) would otherwise
// fail to decode, and that failure would arrive as "the keystore is broken"
// rather than "the encoder wrapped".
func dropSpace(r rune) rune {
	switch r {
	case ' ', '\t', '\n', '\r':
		return -1
	}
	return r
}

// errNoKeystore is what Start says when it is handed nothing to seal with.
var errNoKeystore = errors.New(
	"Start requires a device keystore: the engine will not write the refresh token and the " +
		"agent's auth token into the app sandbox in the clear. Pass an implementation backed by " +
		"the Android Keystore or the iOS Keychain")

// useKeystore registers the host's keystore for every secret the engine writes,
// after secretfile.SelfTest has proved it actually seals.
//
// The refusal is the control. There is no report mode and no "start anyway with
// a warning": a warning at launch is read by nobody, and the outcome it permits
// is a phone holding a 30-day refresh token in plaintext while the app reports
// itself enrolled and protected.
func useKeystore(host Keystore) error {
	if host == nil {
		return errNoKeystore
	}
	if err := secretfile.Use(hostKeystore{host}); err != nil {
		return fmt.Errorf("the device keystore did not pass its self-test, so the engine has not "+
			"started rather than write credentials in the clear: %w", err)
	}
	return nil
}
