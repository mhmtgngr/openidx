// Package access — short-lived TURN credentials for remote-support
// WebRTC sessions.
//
// Pattern follows draft-uberti-rtcweb-turn-rest-00 / coturn's
// "use-auth-secret" mode: the TURN server and OpenIDX share a static
// secret; OpenIDX mints a username that embeds an absolute expiration
// timestamp and a session identifier, then derives the password as
// base64(HMAC-SHA1(secret, username)). The TURN server validates by
// computing the same HMAC and rejecting requests once the expiry has
// passed — no shared state, no per-credential storage.
//
// The minter is optional. When unconfigured (no URIs / no shared secret),
// HandleStartSession passes through any admin-supplied ice_servers as
// before, or returns an empty array.
package access

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// TurnConfig holds the inputs needed to mint short-lived TURN credentials.
// Populated from common/config.Config by service.go at startup.
type TurnConfig struct {
	// URIs is the list of TURN/TURNS URIs handed to each peer. Each entry
	// is a fully-qualified URI like:
	//   turn:turn.example.org:3478
	//   turn:turn.example.org:3478?transport=tcp
	//   turns:turn.example.org:5349?transport=tcp
	URIs []string

	// StaticSecret is the shared secret configured on the TURN server
	// (coturn's `static-auth-secret` value). Treat as a credential —
	// rotate by changing both sides together.
	StaticSecret string

	// Realm matches the TURN server's realm. Optional; coturn doesn't
	// require it in the username for use-auth-secret mode, but some
	// clients echo it back for compatibility. We expose it on the wire
	// for completeness.
	Realm string

	// TTL is how long the minted credential remains valid. Defaults to
	// 2 h if zero. The username always encodes the absolute expiration
	// time, so this just shapes the upper bound of session length.
	TTL time.Duration
}

// Enabled returns true iff the config carries enough information to mint
// credentials. Callers should check this before invoking [Mint].
func (c TurnConfig) Enabled() bool {
	return c.StaticSecret != "" && len(c.URIs) > 0
}

// ICEServer is the wire shape WebRTC clients consume. Encodes JSON keys
// that match the IETF / Chromium spec so both the admin browser and the
// Android client can parse it without translation.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// TurnMinter wraps a TurnConfig with a clock so tests can control the
// expiration timestamp embedded in the username.
type TurnMinter struct {
	cfg TurnConfig
	now func() time.Time
}

// NewTurnMinter returns a minter or nil when cfg is incomplete. Returning
// nil rather than an error lets callers construct unconditionally and
// then test `if m != nil` at use sites.
func NewTurnMinter(cfg TurnConfig) *TurnMinter {
	if !cfg.Enabled() {
		return nil
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 2 * time.Hour
	}
	return &TurnMinter{cfg: cfg, now: time.Now}
}

// Mint produces a per-session set of ICE servers (TURN + any prior STUN
// entries the caller bundles in). usernameSuffix should be a session ID
// or other short identifier — it lands in the TURN log so operators can
// correlate TURN activity with OpenIDX sessions.
//
// The minter does not include STUN servers by default; callers that want
// STUN entries should add them to the returned slice (or include them in
// the configured TURN URIs since coturn answers STUN on the same port).
func (m *TurnMinter) Mint(usernameSuffix string) ([]ICEServer, error) {
	if m == nil {
		return nil, errors.New("turn minter not configured")
	}
	expiry := m.now().Add(m.cfg.TTL).Unix()
	// username = "<expiry>:<suffix>" — coturn's documented format.
	// Sanitize suffix so a stray colon doesn't change the parse on the
	// TURN-server side.
	clean := strings.ReplaceAll(usernameSuffix, ":", "_")
	username := strconv.FormatInt(expiry, 10) + ":" + clean
	credential := hmacBase64(m.cfg.StaticSecret, username)
	return []ICEServer{
		{
			URLs:       append([]string(nil), m.cfg.URIs...),
			Username:   username,
			Credential: credential,
		},
	}, nil
}

// MintAsRawJSON wraps [Mint] and returns the marshaled JSON, which is the
// shape persisted in remote_support_sessions.ice_servers. Convenience
// helper for the HTTP handler.
func (m *TurnMinter) MintAsRawJSON(usernameSuffix string) (json.RawMessage, error) {
	servers, err := m.Mint(usernameSuffix)
	if err != nil {
		return nil, err
	}
	return json.Marshal(servers)
}

// Realm reports the configured TURN realm (empty when unset). Exposed so
// audit / admin-API surfaces can surface it without poking at the config.
func (m *TurnMinter) Realm() string {
	if m == nil {
		return ""
	}
	return m.cfg.Realm
}

// hmacBase64 computes base64(HMAC-SHA1(secret, message)). coturn validates
// credentials with exactly this construction in use-auth-secret mode, so
// the encoding (standard base64 with padding) and digest (SHA-1) are
// load-bearing — don't change them.
func hmacBase64(secret, message string) string {
	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
