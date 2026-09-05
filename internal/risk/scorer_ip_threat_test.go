package risk

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestIPReputationSignalScoresListedIP pins the fix for the inert
// ip_reputation signal: isIPBlocked was a placeholder returning false, so an
// IP the admin console (or IBDR) had put on the threat list contributed zero
// to the login risk score that drives step-up MFA.
func TestIPReputationSignalScoresListedIP(t *testing.T) {
	scorer := NewScorer(DefaultScorerConfig(), zap.NewNop())
	scorer.SetIPThreatCheck(func(_ context.Context, ip string) (bool, string) {
		if ip == "203.0.113.7" {
			return true, "brute_force"
		}
		return false, ""
	})

	blocked := scorer.CalculateRiskScore(context.Background(), LoginContext{
		UserID: "u1", IPAddress: "203.0.113.7",
	})
	clean := scorer.CalculateRiskScore(context.Background(), LoginContext{
		UserID: "u1", IPAddress: "198.51.100.9",
	})

	sig := func(a *RiskAssessment) *Signal {
		for i := range a.Signals {
			if a.Signals[i].Name == "ip_reputation" {
				return &a.Signals[i]
			}
		}
		return nil
	}

	bs, cs := sig(blocked), sig(clean)
	if bs == nil || cs == nil {
		t.Fatal("ip_reputation signal missing from assessment")
	}
	if bs.Score <= 0 {
		t.Errorf("listed IP must contribute a positive ip_reputation score, got %v", bs.Score)
	}
	if !strings.Contains(bs.Description, "brute_force") {
		t.Errorf("signal description should carry the threat reason, got %q", bs.Description)
	}
	if cs.Score != 0 {
		t.Errorf("unlisted IP must contribute 0, got %v", cs.Score)
	}
	if blocked.Score <= clean.Score {
		t.Errorf("overall score for a listed IP (%d) must exceed a clean one (%d)", blocked.Score, clean.Score)
	}
}

// TestIPReputationSignalSafeWithoutChecker: a Scorer with no checker wired
// (standalone construction, tests) must not panic and must score the signal 0
// — the pre-fix behavior, now explicit instead of accidental.
func TestIPReputationSignalSafeWithoutChecker(t *testing.T) {
	scorer := NewScorer(DefaultScorerConfig(), zap.NewNop())
	a := scorer.CalculateRiskScore(context.Background(), LoginContext{
		UserID: "u1", IPAddress: "203.0.113.7",
	})
	for _, s := range a.Signals {
		if s.Name == "ip_reputation" && s.Score != 0 {
			t.Errorf("without a checker the ip_reputation signal must be 0, got %v", s.Score)
		}
	}
}
