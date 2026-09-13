package botgate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGate(t *testing.T, mode Mode, verifier ChallengeVerifier) (*Gate, *miniredis.Miniredis) {
	t.Helper()
	m, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(m.Close)
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, Config{Mode: mode, ChallengeAfter: 5, Window: 15 * time.Minute}, verifier), m
}

// The acceptance case from the plan: a spray from ten thousand addresses makes
// three attempts each against one account. No per-IP bucket fills; the account
// counter does, and the fifth attempt onward is a challenge — wherever it
// comes from.
func TestGate_SprayAcrossAddressesIsChallengedByTheFifthAttempt(t *testing.T) {
	g, _ := newGate(t, ModeEnforce, nil)
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		d := g.Check(ctx, "org1", "alice", "", "", "")
		assert.False(t, d.Challenge, "attempt %d is password-checked", i)
		g.RecordFailure(ctx, "org1", "alice")
	}
	d := g.Check(ctx, "org1", "alice", "", "", "10.0.0.1")
	assert.False(t, d.Challenge, "the fifth attempt is still checked (four failures so far)")
	g.RecordFailure(ctx, "org1", "alice")

	d = g.Check(ctx, "org1", "alice", "", "", "203.0.113.9")
	assert.True(t, d.Challenge, "sixth attempt, from a new address, is challenged")
	assert.Equal(t, ReasonFailures, d.Reason)
	assert.EqualValues(t, 5, d.Failures)

	// Case-insensitive: the spray cannot dodge the counter by re-casing.
	d = g.Check(ctx, "org1", "ALICE", "", "", "")
	assert.True(t, d.Challenge)

	// A different account in the same org, and the same name in another org,
	// are untouched.
	assert.False(t, g.Check(ctx, "org1", "bob", "", "", "").Challenge)
	assert.False(t, g.Check(ctx, "org2", "alice", "", "", "").Challenge)
}

// A legitimate user who types the right password never sees a challenge, and
// their success wipes whatever a spray had accumulated against their name.
func TestGate_CorrectPasswordNeverSeesAChallengeAndResetsTheCounter(t *testing.T) {
	g, m := newGate(t, ModeEnforce, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		g.RecordFailure(ctx, "org1", "alice")
	}
	assert.False(t, g.Check(ctx, "org1", "alice", "", "", "").Challenge)
	g.RecordSuccess(ctx, "org1", "alice")
	assert.False(t, m.Exists(Key("org1", "alice")), "counter cleared on success")
	assert.EqualValues(t, 0, g.Check(ctx, "org1", "alice", "", "", "").Failures)
}

// The window is a TTL on the counter: after it the account starts clean.
func TestGate_CounterExpiresWithTheWindow(t *testing.T) {
	g, m := newGate(t, ModeEnforce, nil)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		g.RecordFailure(ctx, "org1", "alice")
	}
	assert.True(t, g.Check(ctx, "org1", "alice", "", "", "").Challenge)
	assert.InDelta(t, 15*time.Minute, m.TTL(Key("org1", "alice")), float64(time.Second))
	m.FastForward(16 * time.Minute)
	assert.False(t, g.Check(ctx, "org1", "alice", "", "", "").Challenge)
}

// Observe mode decides exactly as enforce would and the caller records it;
// off mode never touches Redis at all.
func TestGate_ObserveDecidesOffDoesNothing(t *testing.T) {
	g, m := newGate(t, ModeObserve, nil)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		g.RecordFailure(ctx, "org1", "alice")
	}
	d := g.Check(ctx, "org1", "alice", "", "", "")
	assert.True(t, d.Challenge)
	meta := g.AuditMetadata(d, false)
	assert.Equal(t, "would_challenge", meta["verdict"])
	assert.Equal(t, "observe", meta["mode"])

	off, m2 := newGate(t, ModeOff, nil)
	off.RecordFailure(ctx, "org1", "alice")
	assert.Empty(t, m2.Keys(), "off mode writes nothing")
	assert.False(t, off.Check(ctx, "org1", "alice", "", "", "").Challenge)
	_ = m
}

// The edge's verdict is a challenge before the first failure; an absent or
// garbage header is ignored rather than trusted either way.
func TestGate_EdgeBotScoreChallengesLowScores(t *testing.T) {
	g, _ := newGate(t, ModeEnforce, nil)
	ctx := context.Background()

	d := g.Check(ctx, "org1", "alice", "12", "", "")
	assert.True(t, d.Challenge)
	assert.Equal(t, ReasonEdgeBotScore, d.Reason)
	assert.Equal(t, 12, d.EdgeScore)

	d = g.Check(ctx, "org1", "alice", "85", "", "")
	assert.False(t, d.Challenge)
	assert.Equal(t, 85, d.EdgeScore)

	d = g.Check(ctx, "org1", "alice", "not-a-number", "", "")
	assert.False(t, d.Challenge)
	assert.Equal(t, -1, d.EdgeScore)
}

// A counter that cannot be read is a defence lost, not a login lost: the
// attempt proceeds to the password check and the decision says why.
func TestGate_CounterOutageFailsOpenAndSaysSo(t *testing.T) {
	g, m := newGate(t, ModeEnforce, nil)
	m.Close()
	d := g.Check(context.Background(), "org1", "alice", "", "", "")
	assert.False(t, d.Challenge)
	assert.Equal(t, ReasonBackendDown, d.Reason)
}

type fakeVerifier struct{ ok bool }

func (f fakeVerifier) Verify(context.Context, string, string) (bool, error) { return f.ok, nil }

// A solved challenge admits the attempt and clears the counter; a failed one
// is refused even for an account with no failures at all.
func TestGate_ChallengeTokenClearsOrRefuses(t *testing.T) {
	g, m := newGate(t, ModeEnforce, fakeVerifier{ok: true})
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		g.RecordFailure(ctx, "org1", "alice")
	}
	d := g.Check(ctx, "org1", "alice", "5", "solved-token", "10.0.0.1")
	assert.False(t, d.Challenge, "a solved challenge beats both the counter and the edge score")
	assert.Equal(t, ReasonChallengeGood, d.Reason)
	assert.False(t, m.Exists(Key("org1", "alice")))

	bad, _ := newGate(t, ModeEnforce, fakeVerifier{ok: false})
	d = bad.Check(ctx, "org1", "bob", "", "forged", "")
	assert.True(t, d.Challenge)
	assert.Equal(t, ReasonChallengeBad, d.Reason)
}

// Turnstile: the token goes to siteverify with the secret; success means what
// Cloudflare says, and an unreachable or non-2xx verifier is a rejection.
func TestTurnstileVerifier(t *testing.T) {
	var gotSecret, gotToken, gotIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotSecret, gotToken, gotIP = r.Form.Get("secret"), r.Form.Get("response"), r.Form.Get("remoteip")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": gotToken == "good"})
	}))
	defer srv.Close()

	v := NewTurnstileVerifier("s3cret").(*TurnstileVerifier)
	v.endpoint = srv.URL
	ok, err := v.Verify(context.Background(), "good", "203.0.113.4")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "s3cret", gotSecret)
	assert.Equal(t, "good", gotToken)
	assert.Equal(t, "203.0.113.4", gotIP)

	ok, err = v.Verify(context.Background(), "bad", "")
	require.NoError(t, err)
	assert.False(t, ok)

	srv.Close()
	ok, err = v.Verify(context.Background(), "good", "")
	assert.Error(t, err)
	assert.False(t, ok, "an unreachable verifier never accepts")

	assert.Nil(t, NewTurnstileVerifier("  "), "no secret, no verifier")
}

func TestParseMode(t *testing.T) {
	assert.Equal(t, ModeOff, ParseMode(""))
	assert.Equal(t, ModeOff, ParseMode("enforcee"))
	assert.Equal(t, ModeObserve, ParseMode(" Observe "))
	assert.Equal(t, ModeEnforce, ParseMode("ENFORCE"))
}

func TestKey_HashesAndFoldsTheName(t *testing.T) {
	assert.Equal(t, Key("o", "Alice"), Key("o", " alice "))
	assert.NotContains(t, Key("o", "alice"), "alice")
	assert.Contains(t, Key("", "alice"), "login_fail:_:")
}
