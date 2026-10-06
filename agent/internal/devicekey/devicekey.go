// Package devicekey holds the agent's device key: an ECDSA P-256 key the
// device proves itself with, kept where it cannot be copied off the machine.
//
// WHY IT EXISTS. After enrolment a device proved itself with one bearer token
// in agent.json, and nothing else. Whoever read that file (every signed-in
// Windows user can, by design, since the tray reads it) could report posture
// as this device from any machine, for as long as the token lived, which is
// until the device enrols again. A token can be copied; a key that never
// leaves the device's TPM cannot.
//
// WHERE THE KEY LIVES. On Windows it is a persisted machine key in the
// Microsoft Platform Crypto Provider, which is the TPM: non-exportable, used
// by the service (SYSTEM) and administrators only. A machine with no usable
// TPM gets the same kind of key in the Microsoft Software Key Storage
// Provider instead, which is non-exportable through the API but protected by
// the operating system rather than by hardware; the server is told which,
// so an administrator can see it. Elsewhere the key is a PEM file in the
// config directory, readable by its owner only.
//
// WHAT IT SIGNS. A request's method, path, the agent id, a timestamp and the
// SHA-256 of its body, under a versioned domain line (RequestSigningInput).
// The server holds the public key from enrolment (or from the device's first
// registration) and, once it has one, refuses a posture report without a
// valid signature.
package devicekey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Kinds of key, as the server records them.
const (
	// KindTPM is a key in the Platform Crypto Provider (the TPM).
	KindTPM = "tpm"
	// KindSoftware is a non-exportable key in the software key storage
	// provider, on a Windows machine without a usable TPM.
	KindSoftware = "software"
	// KindFile is a key in a file, off Windows.
	KindFile = "file"
)

// Header names that carry a request's signature.
const (
	HeaderTimestamp = "X-Agent-Key-Timestamp"
	HeaderSignature = "X-Agent-Key-Signature"
)

// ErrNoKey is returned by Open when this device has no key yet.
var ErrNoKey = errors.New("this device has no device key yet")

// Key is the device key.
type Key interface {
	// Public is the key's public half.
	Public() *ecdsa.PublicKey
	// Kind is KindTPM, KindSoftware or KindFile.
	Kind() string
	// Sign signs a SHA-256 digest and returns an ASN.1 DER ECDSA signature.
	Sign(digest []byte) ([]byte, error)
	// Close releases the key handle.
	Close()
}

// PublicKeyBase64 is the key's public half as base64 of its PKIX DER
// encoding, the form the server stores.
func PublicKeyBase64(k Key) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return "", fmt.Errorf("encode the device public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// requestDomain separates a request signature from anything else the key
// might ever sign. Changing it invalidates every signature, so it is versioned.
const requestDomain = "openidx-agent-request/v1"

// RequestSigningInput is the exact byte string a request's signature covers.
// The server builds the same bytes from what it received. Each value sits on
// its own line; a value with a line break is refused, so one signed message
// can never be read as another.
func RequestSigningInput(method, path, agentID string, unixTime int64, body []byte) ([]byte, error) {
	for name, v := range map[string]string{"method": method, "path": path, "agent_id": agentID} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("request %s contains a line break; refusing to sign an ambiguous message", name)
		}
	}
	sum := sha256.Sum256(body)
	return []byte(requestDomain + "\n" + method + "\n" + path + "\n" + agentID + "\n" +
		strconv.FormatInt(unixTime, 10) + "\n" + hex.EncodeToString(sum[:]) + "\n"), nil
}

// Signer signs this agent's requests with its device key.
type Signer struct {
	Key     Key
	AgentID string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// SignRequest returns the timestamp and signature header values for one
// request.
func (s Signer) SignRequest(method, path string, body []byte) (timestamp, signature string, err error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ts := now().Unix()
	input, err := RequestSigningInput(method, path, s.AgentID, ts, body)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(input)
	sig, err := s.Key.Sign(digest[:])
	if err != nil {
		return "", "", fmt.Errorf("sign with the device key: %w", err)
	}
	return strconv.FormatInt(ts, 10), base64.StdEncoding.EncodeToString(sig), nil
}
