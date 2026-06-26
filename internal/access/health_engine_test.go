package access

import (
	"context"
	"testing"
)

type stubCheck struct {
	id, domain string
	findings   []Finding
	fixed      *Finding
}

func (c *stubCheck) ID() string                                    { return c.id }
func (c *stubCheck) Domain() string                                { return c.domain }
func (c *stubCheck) Detect(ctx context.Context) ([]Finding, error) { return c.findings, nil }
func (c *stubCheck) Fix(ctx context.Context, f Finding) error      { c.fixed = &f; return nil }

func TestScanAndHealAppliesSafeOnly(t *testing.T) {
	safe := Finding{CheckID: "c1", Domain: "access", Status: "drift", Safe: true, Subject: "r1"}
	risky := Finding{CheckID: "c2", Domain: "ziti", Status: "orphan", Safe: false, Subject: "svc1"}
	c1 := &stubCheck{id: "c1", domain: "access", findings: []Finding{safe}}
	c2 := &stubCheck{id: "c2", domain: "ziti", findings: []Finding{risky}}
	e := &HealthEngine{checks: []Check{c1, c2}}

	rep := e.ScanAndHeal(context.Background(), true)
	if len(rep.Healed) != 1 || rep.Healed[0].CheckID != "c1" {
		t.Fatalf("expected c1 healed, got %+v", rep.Healed)
	}
	if len(rep.Remaining) != 1 || rep.Remaining[0].CheckID != "c2" {
		t.Fatalf("expected c2 remaining (risky), got %+v", rep.Remaining)
	}
	if c1.fixed == nil {
		t.Fatal("safe check c1 must have been fixed")
	}
	if c2.fixed != nil {
		t.Fatal("risky check c2 must NOT have been auto-fixed")
	}
}
