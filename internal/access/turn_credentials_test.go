package access

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClock returns a deterministic time for the minter so HMAC outputs
// are byte-equal across runs and easy to diff against a reference
// computation.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestTurnMinter_DisabledWhenSecretMissing(t *testing.T) {
	m := NewTurnMinter(TurnConfig{URIs: []string{"turn:host:3478"}})
	assert.Nil(t, m, "missing secret should produce a nil minter")
}

func TestTurnMinter_DisabledWhenURIsEmpty(t *testing.T) {
	m := NewTurnMinter(TurnConfig{StaticSecret: "shh"})
	assert.Nil(t, m, "empty URIs should produce a nil minter")
}

func TestTurnMinter_NilMintFails(t *testing.T) {
	var m *TurnMinter
	_, err := m.Mint("sess-1")
	require.Error(t, err)
}

func TestTurnMinter_DefaultTTLAppliedWhenZero(t *testing.T) {
	m := NewTurnMinter(TurnConfig{
		URIs:         []string{"turn:host:3478"},
		StaticSecret: "shh",
	})
	require.NotNil(t, m)
	assert.Equal(t, 2*time.Hour, m.cfg.TTL)
}

func TestTurnMinter_UsernameEmbedsExpiryAndSuffix(t *testing.T) {
	fixed := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	m := NewTurnMinter(TurnConfig{
		URIs:         []string{"turn:host:3478"},
		StaticSecret: "shh",
		TTL:          time.Hour,
	})
	require.NotNil(t, m)
	m.now = fixedClock(fixed)
	servers, err := m.Mint("session-42")
	require.NoError(t, err)
	require.Len(t, servers, 1)
	expectedExpiry := fixed.Add(time.Hour).Unix()
	wantPrefix := strconv.FormatInt(expectedExpiry, 10) + ":"
	assert.True(t, strings.HasPrefix(servers[0].Username, wantPrefix),
		"username should start with %q, got %q", wantPrefix, servers[0].Username)
	assert.Contains(t, servers[0].Username, "session-42")
}

func TestTurnMinter_CredentialMatchesHMACSHA1Base64(t *testing.T) {
	// Independently recompute the credential the way coturn does and
	// compare. If this test breaks, the TURN server will start rejecting
	// every credential we mint.
	fixed := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	secret := "verysecret"
	m := NewTurnMinter(TurnConfig{
		URIs:         []string{"turn:host:3478"},
		StaticSecret: secret,
		TTL:          30 * time.Minute,
	})
	require.NotNil(t, m)
	m.now = fixedClock(fixed)

	servers, err := m.Mint("agent-abcd")
	require.NoError(t, err)
	require.Len(t, servers, 1)

	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(servers[0].Username))
	expected := base64.StdEncoding.EncodeToString(h.Sum(nil))
	assert.Equal(t, expected, servers[0].Credential)
}

func TestTurnMinter_StripsColonsFromSuffix(t *testing.T) {
	m := NewTurnMinter(TurnConfig{
		URIs:         []string{"turn:host:3478"},
		StaticSecret: "shh",
	})
	require.NotNil(t, m)
	servers, _ := m.Mint("agent:42:weird")
	username := servers[0].Username
	// Exactly one colon between expiry and suffix; suffix's own colons
	// must have been replaced.
	assert.Equal(t, 1, strings.Count(username, ":"), "username=%s", username)
	assert.Contains(t, username, "agent_42_weird")
}

func TestTurnMinter_MintAsRawJSON_ProducesValidICE(t *testing.T) {
	m := NewTurnMinter(TurnConfig{
		URIs: []string{
			"turn:turn.example.org:3478?transport=udp",
			"turns:turn.example.org:5349?transport=tcp",
		},
		StaticSecret: "shh",
	})
	require.NotNil(t, m)
	raw, err := m.MintAsRawJSON("sess")
	require.NoError(t, err)

	var decoded []ICEServer
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded, 1)
	assert.Len(t, decoded[0].URLs, 2)
	assert.Contains(t, decoded[0].URLs, "turn:turn.example.org:3478?transport=udp")
	assert.Contains(t, decoded[0].URLs, "turns:turn.example.org:5349?transport=tcp")
	assert.NotEmpty(t, decoded[0].Username)
	assert.NotEmpty(t, decoded[0].Credential)
}

func TestTurnMinter_RealmExposed(t *testing.T) {
	m := NewTurnMinter(TurnConfig{
		URIs:         []string{"turn:host:3478"},
		StaticSecret: "shh",
		Realm:        "openidx.local",
	})
	require.NotNil(t, m)
	assert.Equal(t, "openidx.local", m.Realm())

	var nilMinter *TurnMinter
	assert.Equal(t, "", nilMinter.Realm(),
		"nil minter must not panic on Realm()")
}
