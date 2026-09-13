// Package botgate answers one question at the login door: "should this attempt
// have to prove a human is behind it before we check the password?"
//
// The per-IP rate limiter cannot answer it. A credential-stuffing run spread
// across ten thousand addresses makes three attempts from each; no per-IP
// bucket ever fills, and the account being guessed sees thirty thousand tries.
// The database lockout (identity.RecordFailedLogin) counts per ACCOUNT, but it
// counts only accounts that exist and it locks — the attacker who wanted to
// lock a victim out gets exactly that. The gap between those two controls is
// this package: a counter keyed on the account NAME as typed (existing or not,
// so enumeration learns nothing), independent of source address, that after a
// few failures asks for a challenge instead of a lock. A legitimate user who
// types the right password never sees it; a legitimate user who mistyped a few
// times solves a challenge and carries on; a bot solves nothing.
//
// The gate also reads the edge's verdict. An anycast edge that scores requests
// (Cloudflare bot management, AWS Bot Control, Front Door bot rules) can hand
// the score down in a header; a low score is a challenge before the first
// failure. The header is trusted only because the edge is the only hop that
// can reach the origin (task 1.2) — behind an untrusted edge it must stay
// unset.
//
// Tri-state like every other gate in the product (STEPUP_GATE, ABAC_ENFORCE):
// off is the default, observe records who WOULD be challenged into the audit
// trail so the threshold is chosen from data, enforce refuses. See the
// global-scale plan task 1.4.
package botgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Mode is the tri-state BOT_GATE.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// ParseMode reads a configured value. Anything unrecognised is off: a typo in
// a deployment variable must fail toward today's behaviour.
func ParseMode(v string) Mode {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "observe":
		return ModeObserve
	case "enforce":
		return ModeEnforce
	default:
		return ModeOff
	}
}

// Defaults. Five failures in fifteen minutes is well above what a person
// produces mistyping a password and well below what a spray needs.
const (
	DefaultChallengeAfter = 5
	DefaultWindow         = 15 * time.Minute
	DefaultScoreHeader    = "X-Edge-Bot-Score"
	// DefaultChallengeBelow follows the Cloudflare convention: 1..99, lower is
	// more likely automated; 30 is the documented "likely bot" line.
	DefaultChallengeBelow = 30
	keyPrefix             = "login_fail:"
)

// Reason says why a challenge was asked for, for the audit row and the client.
type Reason string

const (
	ReasonNone          Reason = ""
	ReasonFailures      Reason = "repeated_failures"
	ReasonEdgeBotScore  Reason = "edge_bot_score"
	ReasonBackendDown   Reason = "counter_unavailable"
	ReasonChallengeBad  Reason = "challenge_rejected"
	ReasonChallengeGood Reason = "challenge_passed"
)

// Decision is what the login handler acts on.
type Decision struct {
	// Challenge is true when this attempt should be refused until a challenge
	// is solved (enforce) or would have been (observe).
	Challenge bool
	Reason    Reason
	// Failures is the account's failure count in the window at decision time.
	Failures int64
	// EdgeScore is the parsed edge header, -1 when absent or unparseable.
	EdgeScore int
}

// ChallengeVerifier validates a challenge token the client obtained from the
// edge (Cloudflare Turnstile, hCaptcha, ...). A nil verifier means challenges
// cannot be satisfied by token: in enforce mode the account waits out the
// window, which is a soft lockout keyed on the typed name rather than on the
// database row.
type ChallengeVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// Config is the operator's knobs.
type Config struct {
	Mode           Mode
	ChallengeAfter int
	Window         time.Duration
	ScoreHeader    string
	ChallengeBelow int
}

// Gate is the login-door decision maker. Safe for concurrent use.
type Gate struct {
	rdb      redis.UniversalClient
	cfg      Config
	verifier ChallengeVerifier
}

// New builds a gate. rdb is the SESSION-role Redis (the counter must not be
// evicted by a rate-limit key flood; see task 0.1) and may be nil in tests.
func New(rdb redis.UniversalClient, cfg Config, verifier ChallengeVerifier) *Gate {
	if cfg.ChallengeAfter <= 0 {
		cfg.ChallengeAfter = DefaultChallengeAfter
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.ScoreHeader == "" {
		cfg.ScoreHeader = DefaultScoreHeader
	}
	if cfg.ChallengeBelow <= 0 {
		cfg.ChallengeBelow = DefaultChallengeBelow
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	return &Gate{rdb: rdb, cfg: cfg, verifier: verifier}
}

// Mode reports the configured mode.
func (g *Gate) Mode() Mode { return g.cfg.Mode }

// ScoreHeader is the request header the gate reads the edge verdict from.
func (g *Gate) ScoreHeader() string { return g.cfg.ScoreHeader }

// Key is the Redis key for an account name in an org. The name is hashed:
// the key must not be a list of usernames anyone with Redis access can read,
// and case-folded so "Alice" and "alice" are one account.
func Key(orgID, username string) string {
	if orgID == "" {
		orgID = "_"
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return keyPrefix + orgID + ":" + hex.EncodeToString(sum[:16])
}

// Check decides before the password is checked. edgeScoreHeader is the raw
// header value (empty when absent); challengeToken is what the client sent
// after solving a challenge (empty when none).
//
// Order matters: a valid challenge token clears the account's counter and
// admits the attempt regardless of score, because the person just proved
// they are one. Otherwise the edge score is consulted, then the counter.
func (g *Gate) Check(ctx context.Context, orgID, username, edgeScoreHeader, challengeToken, remoteIP string) Decision {
	d := Decision{EdgeScore: -1}
	if g.cfg.Mode == ModeOff {
		return d
	}

	if challengeToken != "" && g.verifier != nil {
		ok, err := g.verifier.Verify(ctx, challengeToken, remoteIP)
		if err == nil && ok {
			g.RecordSuccess(ctx, orgID, username)
			d.Reason = ReasonChallengeGood
			return d
		}
		d.Challenge = true
		d.Reason = ReasonChallengeBad
		return d
	}

	if edgeScoreHeader != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(edgeScoreHeader)); err == nil {
			d.EdgeScore = n
			if n >= 0 && n < g.cfg.ChallengeBelow {
				d.Challenge = true
				d.Reason = ReasonEdgeBotScore
				return d
			}
		}
	}

	if g.rdb == nil {
		return d
	}
	n, err := g.rdb.Get(ctx, Key(orgID, username)).Int64()
	if err != nil && err != redis.Nil {
		// The counter is a defence, not a dependency: without it the attempt
		// is still password-checked and still subject to the database lockout.
		// Say so on the decision so observe mode can count how often that
		// happens.
		d.Reason = ReasonBackendDown
		return d
	}
	d.Failures = n
	if n >= int64(g.cfg.ChallengeAfter) {
		d.Challenge = true
		d.Reason = ReasonFailures
	}
	return d
}

// RecordFailure counts a failed password check against the typed account name.
// Returns the new count (0 when the counter is unavailable).
func (g *Gate) RecordFailure(ctx context.Context, orgID, username string) int64 {
	if g.rdb == nil || g.cfg.Mode == ModeOff {
		return 0
	}
	key := Key(orgID, username)
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0
	}
	if n == 1 {
		g.rdb.Expire(ctx, key, g.cfg.Window)
	}
	return n
}

// RecordSuccess clears the counter: a correct password is the strongest
// evidence the person is who they say, and the next mistyped attempt starts
// from zero rather than from the tail of someone else's spray.
func (g *Gate) RecordSuccess(ctx context.Context, orgID, username string) {
	if g.rdb == nil || g.cfg.Mode == ModeOff {
		return
	}
	g.rdb.Del(ctx, Key(orgID, username))
}

// AuditMetadata renders a decision for the shared decision-audit shape used by
// the other gates: mode, verdict and the facts it was made from.
func (g *Gate) AuditMetadata(d Decision, enforced bool) map[string]interface{} {
	verdict := "permit"
	if d.Challenge {
		if enforced {
			verdict = "challenged"
		} else {
			verdict = "would_challenge"
		}
	}
	return map[string]interface{}{
		"gate":            "BOT_GATE",
		"mode":            string(g.cfg.Mode),
		"verdict":         verdict,
		"reason":          string(d.Reason),
		"failures":        d.Failures,
		"challenge_after": g.cfg.ChallengeAfter,
		"window_seconds":  int(g.cfg.Window.Seconds()),
		"edge_bot_score":  d.EdgeScore,
	}
}

// String is for logs.
func (d Decision) String() string {
	return fmt.Sprintf("challenge=%t reason=%s failures=%d edge_score=%d", d.Challenge, d.Reason, d.Failures, d.EdgeScore)
}
