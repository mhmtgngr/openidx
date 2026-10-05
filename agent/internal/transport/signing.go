package transport

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// RequestSigner signs one agent request with the device key. The values go in
// the X-Agent-Key-Timestamp and X-Agent-Key-Signature headers
// (agent/internal/devicekey). A transport without one sends no signature,
// which a server that has no key for the device accepts as before.
type RequestSigner interface {
	SignRequest(method, path string, body []byte) (timestamp, signature string, err error)
}

// Header names a signed request carries. They match devicekey.HeaderTimestamp
// and devicekey.HeaderSignature; transport does not import devicekey so the
// key storage stays out of every transport consumer's build.
const (
	headerKeyTimestamp = "X-Agent-Key-Timestamp"
	headerKeySignature = "X-Agent-Key-Signature"
)

// signerSetter is implemented by every transport that can carry signatures.
type signerSetter interface{ SetSigner(RequestSigner) }

// SetSigner installs signer on t when t can carry signatures. It reports
// whether it did.
func SetSigner(t Transport, signer RequestSigner) bool {
	s, ok := t.(signerSetter)
	if ok {
		s.SetSigner(signer)
	}
	return ok
}

// sign adds the device-key headers to req when a signer is installed. The
// path signed is the request's own, so a request re-routed over the overlay
// (http:// to the same path) signs the same bytes the server reads.
func sign(req *http.Request, signer RequestSigner, body []byte) error {
	if signer == nil {
		return nil
	}
	ts, sig, err := signer.SignRequest(req.Method, req.URL.EscapedPath(), body)
	if err != nil {
		return fmt.Errorf("sign the request with the device key: %w", err)
	}
	req.Header.Set(headerKeyTimestamp, ts)
	req.Header.Set(headerKeySignature, sig)
	return nil
}

// Errors from RegisterDeviceKey.
var (
	// ErrDeviceKeyUnsupported: the server has no device-key endpoint (an
	// older release). The agent carries on unsigned-for-the-server and tries
	// again later.
	ErrDeviceKeyUnsupported = errors.New("the server does not support device keys yet")
	// ErrDeviceKeyConflict: the server already holds a different key for
	// this device. Only enrolling again replaces it.
	ErrDeviceKeyConflict = errors.New("the server holds a different device key for this agent; enrol the device again to replace it")
)

// RegisterDeviceKey tells the server the device's public key, for a device
// that enrolled before it had one. The request is signed with that same key,
// so the server stores a key the caller can prove it holds. The server
// accepts it only when it holds no key for the device yet.
func (c *Client) RegisterDeviceKey(publicKeyB64, kind string, signer RequestSigner) error {
	if signer == nil {
		return errors.New("registering a device key needs the key to sign with")
	}
	body := []byte(fmt.Sprintf(`{"public_key":%q,"kind":%q}`, publicKeyB64, kind))
	u, err := url.JoinPath(c.baseURL, "/api/v1/access/agent/device-key")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)
	if err := sign(req, signer, body); err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("register the device key: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return ErrDeviceKeyUnsupported
	case resp.StatusCode == http.StatusConflict:
		return ErrDeviceKeyConflict
	case resp.StatusCode == http.StatusForbidden:
		return ErrAgentRevoked
	}
	return fmt.Errorf("register the device key: server answered %d", resp.StatusCode)
}
