package access

import (
	"strings"
	"testing"
	"time"
)

// THE ROUTE'S CONDITIONS ARE THE PRE-228 COPY; THE RESOURCE'S RULE.
//
// Migration 229 copied require_device_trust, allowed_countries and
// max_risk_score from every application's route into resource_conditions,
// and the console edits the resource from then on. The proxy judges the
// resource's conditions through the shared reach decision, with the
// request's own situation; the route's copy is judged only when the resource
// declared none (a route created after the migration with no conditions
// row) or when the decision is not enforced. Otherwise a stale copy on the
// route would overrule what the administrator set on the resource.

// The request's own score reads nothing of the route's conditions.
func TestScoringTheRequestReadsNoRouteCondition(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.RequireDeviceTrust = true
	route.AllowedCountries = []string{"TR"}
	route.MaxRiskScore = 5
	ac := &AccessContext{
		Session: baseSession(), Route: route, ClientIP: "1.2.3.4", UserAgent: baseSession().UserAgent,
		GeoCountry: "FR", DeviceTrusted: false, Timestamp: time.Now(),
	}
	risk, early := svc.scoreAccessContext(ac)
	if early != nil {
		t.Fatalf("the route's conditions refused during scoring: %+v", early)
	}
	if risk != 15 {
		t.Fatalf("an untrusted device alone scores 15, got %d", risk)
	}
	// A blocked address still refuses before anything else is read.
	ac.IPBlocked = true
	if _, early := svc.scoreAccessContext(ac); early == nil || early.Allowed || !strings.Contains(early.Reason, "blocked") {
		t.Fatalf("a blocked address must refuse during scoring: %+v", early)
	}
}

// With the route ruling, each of its conditions refuses; with the resource
// ruling, none of them is read and the request passes on the same score.
func TestRouteConditionsStepAsideWhenTheResourceDeclaredItsOwn(t *testing.T) {
	svc := newTestService()
	for name, set := range map[string]func(r *ProxyRoute){
		"device trust":    func(r *ProxyRoute) { r.RequireDeviceTrust = true },
		"allowed country": func(r *ProxyRoute) { r.AllowedCountries = []string{"TR"} },
		"risk ceiling":    func(r *ProxyRoute) { r.MaxRiskScore = 5 },
	} {
		route := baseRoute()
		set(route)
		ac := &AccessContext{
			Session: baseSession(), Route: route, ClientIP: "1.2.3.4", UserAgent: baseSession().UserAgent,
			GeoCountry: "FR", DeviceTrusted: false, Timestamp: time.Now(),
		}
		risk, _ := svc.scoreAccessContext(ac)
		if d := svc.judgeRouteContext(ac, risk, true); d.Allowed {
			t.Errorf("%s: the route's own condition must refuse when the route rules", name)
		}
		if d := svc.judgeRouteContext(ac, risk, false); !d.Allowed || d.RiskScore != risk {
			t.Errorf("%s: the route's copy must not be read when the resource rules: %+v", name, d)
		}
		// evaluateAccessContext is the two halves with the route ruling.
		if d := svc.evaluateAccessContext(ac); d.Allowed {
			t.Errorf("%s: evaluateAccessContext must still apply the route's conditions", name)
		}
	}
}

// Both proxy paths score the request first, take the shared decision with
// that situation, and judge the route's copy only when the resource left it
// to them. The order is the point: a decision taken before the situation is
// known lists the conditions unjudged.
func TestBothProxyPathsJudgeTheSituationBeforeTheDecision(t *testing.T) {
	for _, site := range []struct{ file, fn string }{
		{"service.go", "func (s *Service) handleProxy("},
		{"context_evaluator.go", "func (s *Service) handleAuthDecide("},
	} {
		src := readSource(t, site.file, site.fn)
		score := strings.Index(src, "s.scoreAccessContext(accessCtx)")
		reach := strings.Index(src, "s.reachDecision(c, route, session, appID, appOrgID,")
		judge := strings.Index(src, "s.judgeRouteContext(accessCtx, risk, !conditionsRuled)")
		if score < 0 || reach < 0 || judge < 0 {
			t.Fatalf("%s: score %d reach %d judge %d — one of the three steps is missing", site.fn, score, reach, judge)
		}
		if !(score < reach && reach < judge) {
			t.Errorf("%s: the request is scored (%d), then decided (%d), then the route's copy judged (%d)", site.fn, score, reach, judge)
		}
	}
}

// Decisions are cached per situation: the key must tell a trusted device from
// an untrusted one, one country from another, one risk from another, and the
// unknown situation (the explain endpoint) from all of them.
func TestSituationKeysDiffer(t *testing.T) {
	seen := map[string]situation{}
	for _, sit := range []situation{
		{},
		{known: true},
		{known: true, deviceTrusted: true},
		{known: true, country: "TR"},
		{known: true, country: "tr", risk: 1},
		{known: true, risk: 15},
	} {
		k := sit.key()
		if prev, dup := seen[k]; dup {
			t.Errorf("%+v and %+v share the key %q", prev, sit, k)
		}
		seen[k] = sit
	}
	if (situation{known: true, country: "tr"}).key() != (situation{known: true, country: "TR"}).key() {
		t.Error("country case must not split the cache")
	}
}
