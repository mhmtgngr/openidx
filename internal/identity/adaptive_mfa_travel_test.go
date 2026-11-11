package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func travelTestService() *Service {
	cfg := &config.Config{}
	cfg.AdaptiveMFA = config.AdaptiveMFAConfig{Enabled: true, ImpossibleTravelRiskScore: 50, NewLocationRiskScore: 20,
		FailedLoginRiskScore: 10, LowRiskThreshold: 30, MediumRiskThreshold: 50, HighRiskThreshold: 70}
	return &Service{cfg: cfg, logger: zap.NewNop()}
}

func hasFactor(a *RiskAssessment, prefix string) bool {
	for _, f := range a.Factors {
		if strings.HasPrefix(f, prefix) {
			return true
		}
	}
	return false
}

// B7.4: a populated LoginContext (Istanbul 30 min ago, New York now) must
// score impossible travel and force step-up.
func TestAssessLoginRisk_ImpossibleTravel(t *testing.T) {
	prev := time.Now().Add(-30 * time.Minute)
	a, err := travelTestService().AssessLoginRisk(context.Background(), &LoginContext{
		UserID: "u1", KnownDevice: true,
		Latitude: 40.7128, Longitude: -74.0060,
		LastLoginLat: 41.0082, LastLoginLon: 28.9784, LastLoginTime: &prev,
		FailedAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFactor(a, "impossible_travel") || !a.StepUpRequired || !a.RequiresMFA {
		t.Fatalf("impossible travel not flagged: %+v", a)
	}
	if !hasFactor(a, "failed_attempts: 2") {
		t.Fatalf("failed attempts not scored: %+v", a.Factors)
	}
}

func TestAssessLoginRisk_PlausibleTravelIsNewLocationOnly(t *testing.T) {
	prev := time.Now().Add(-24 * time.Hour)
	a, _ := travelTestService().AssessLoginRisk(context.Background(), &LoginContext{
		UserID: "u1", KnownDevice: true,
		Latitude: 39.9334, Longitude: 32.8597, // Ankara
		LastLoginLat: 41.0082, LastLoginLon: 28.9784, LastLoginTime: &prev,
	})
	if hasFactor(a, "impossible_travel") || !hasFactor(a, "new_location") {
		t.Fatalf("unexpected factors: %+v", a.Factors)
	}
}

func TestUserRiskLoginStats(t *testing.T) {
	now := time.Now()
	u := &User{FailedLoginCount: 0, LastLoginAt: &now}
	if f, l := u.RiskLoginStats(); f != 0 || l != &now {
		t.Fatal("stored columns expected without prior stats")
	}
	prev := now.Add(-time.Hour)
	u.HasPriorLoginStats, u.PriorFailedLoginCount, u.PriorLastLoginAt = true, 4, &prev
	if f, l := u.RiskLoginStats(); f != 4 || l != &prev {
		t.Fatal("prior stats expected")
	}
}
