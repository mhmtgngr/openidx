package appaccess

import (
	"sort"
	"testing"
)

// TestDecisionEventType pins the two-value mapping. Report mode and enforcement
// must BOTH produce a record — enforcement being quieter than report mode would
// mean the rollout's noisiest phase is its only observable one.
func TestDecisionEventType(t *testing.T) {
	if got := DecisionEventType(false); got != EventTypeWouldDeny {
		t.Errorf("report mode event_type = %q, want %q", got, EventTypeWouldDeny)
	}
	if got := DecisionEventType(true); got != EventTypeDenied {
		t.Errorf("enforced event_type = %q, want %q", got, EventTypeDenied)
	}
	if EventTypeWouldDeny == EventTypeDenied {
		t.Error("report-mode and enforcement records must be distinguishable by event_type")
	}
}

// TestDecisionDetailsCarriesCanonicalKeys is the anti-drift guard: the two
// enforcement points previously emitted different outcome strings and put the
// user id in different places. Every key here is one a single query over both
// sources depends on.
func TestDecisionDetailsCanonicalKeys(t *testing.T) {
	d := DecisionDetails(EnforcementPointProxy, "user-1", "app-1", false, nil)

	for _, k := range DecisionDetailKeys {
		if _, ok := d[k]; !ok {
			t.Errorf("details missing canonical key %q", k)
		}
	}

	got := make([]string, 0, len(d))
	for k := range d {
		got = append(got, k)
	}
	want := append([]string(nil), DecisionDetailKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("details keys = %v, want exactly the canonical set %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("details keys = %v, want %v", got, want)
		}
	}

	if d["user_id"] != "user-1" || d["application_id"] != "app-1" {
		t.Errorf("user/application not carried: %v", d)
	}
	if d["reason"] != ReasonNotAssigned {
		t.Errorf("reason = %v, want %q", d["reason"], ReasonNotAssigned)
	}
	if d["enforced"] != false {
		t.Errorf("enforced = %v, want false", d["enforced"])
	}
	if d["enforcement_point"] != EnforcementPointProxy {
		t.Errorf("enforcement_point = %v, want %q", d["enforcement_point"], EnforcementPointProxy)
	}
}

// TestDecisionDetailsBothPointsAgree: whichever gate builds the record, the
// canonical keys and their meanings are identical — only the point-specific
// extras differ. This is the "one query finds both" property.
func TestDecisionDetailsBothPointsAgree(t *testing.T) {
	proxy := DecisionDetails(EnforcementPointProxy, "user-1", "app-1", true,
		map[string]interface{}{"route": "app.example.com"})
	oidc := DecisionDetails(EnforcementPointOIDC, "user-1", "app-1", true,
		map[string]interface{}{"client_id": "client-1"})

	for _, k := range DecisionDetailKeys {
		if k == "enforcement_point" {
			continue
		}
		if proxy[k] != oidc[k] {
			t.Errorf("key %q disagrees: proxy=%v oidc=%v", k, proxy[k], oidc[k])
		}
	}
	if proxy["enforcement_point"] == oidc["enforcement_point"] {
		t.Error("enforcement_point must distinguish the two gates")
	}
	if proxy["route"] != "app.example.com" || oidc["client_id"] != "client-1" {
		t.Error("point-specific extras must survive the merge")
	}
	if _, leaked := proxy["client_id"]; leaked {
		t.Error("proxy record must not carry the oidc extra")
	}
}

// TestDecisionDetailsExtraCannotOverwriteCanonical: an extra key colliding with
// a canonical one would let a call site quietly change the shape, which is the
// whole thing this package is preventing.
func TestDecisionDetailsExtraCannotOverwriteCanonical(t *testing.T) {
	d := DecisionDetails(EnforcementPointOIDC, "user-1", "app-1", false, map[string]interface{}{
		"reason":   "something_else",
		"user_id":  "attacker",
		"enforced": true,
	})
	if d["reason"] != ReasonNotAssigned {
		t.Errorf("reason overwritten: %v", d["reason"])
	}
	if d["user_id"] != "user-1" {
		t.Errorf("user_id overwritten: %v", d["user_id"])
	}
	if d["enforced"] != false {
		t.Errorf("enforced overwritten: %v", d["enforced"])
	}
}

// TestSourcesAreDistinct: unified_audit_events is queried by source, and the
// proxy source must keep matching the one the access service's other healthy
// rows already use.
func TestSourcesAreDistinct(t *testing.T) {
	if SourceProxy == SourceOIDC {
		t.Fatal("the two enforcement points must be distinguishable by source")
	}
	if SourceProxy != "access-service" {
		t.Errorf("SourceProxy = %q, want access-service (the source the healthy unified rows already carry)", SourceProxy)
	}
	if SourceOIDC != "oauth" {
		t.Errorf("SourceOIDC = %q, want oauth", SourceOIDC)
	}
}
