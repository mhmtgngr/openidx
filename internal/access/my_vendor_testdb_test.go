package access

import (
	"net/http"
	"testing"
)

// The vendor portal's view: an external user sees their vendor, their
// sponsor and the engagements naming them (or naming nobody), running or
// scheduled, with what each covers; an engagement naming someone else, a
// closed one and an ended one are not listed. An internal user is told they
// are not external.
func TestAVendorUserSeesTheirOwnEngagements(t *testing.T) {
	f := newExternalPamFixture(t)
	entry := f.entry("mv-db", "ssh", "ziti", 22, `{}`)
	vendor := f.scalar(`SELECT vendor_org_id::text FROM users WHERE id = $1`, f.external)
	sponsor := f.scalar(`SELECT sponsor_user_id::text FROM users WHERE id = $1`, f.external)
	engage := func(title, members, starts, ends, status string) string {
		id := f.scalar(`
			INSERT INTO vendor_engagements (org_id, vendor_org_id, sponsor_user_id, title, starts_at, ends_at, member_user_ids, status, closed_at)
			VALUES ($1, $2, $3, $4, NOW() + $5::interval, NOW() + $6::interval, $7::uuid[], $8::text, CASE WHEN $8::text = 'closed' THEN NOW() END)
			RETURNING id::text`, f.org, vendor, sponsor, title, starts, ends, members, status)
		f.exec(`INSERT INTO vendor_engagement_targets (engagement_id, org_id, target_type, target_id) VALUES ($1, $2, 'pam_entry', $3)`, id, f.org, entry)
		return id
	}
	mine := engage("Mine", "{"+f.external+"}", "-1 hour", "1 hour", "open")
	everyone := engage("Everyone", "{}", "1 day", "2 days", "open")
	engage("Someone else", "{"+sponsor+"}", "-1 hour", "1 hour", "open")
	engage("Closed", "{}", "-1 hour", "1 hour", "closed")
	engage("Ended", "{}", "-2 hours", "-1 hour", "open")

	code, body := f.call(f.external, http.MethodGet, "/my/vendor", "")
	if code != http.StatusOK || body["external"] != true {
		t.Fatalf("my vendor as an external user = %d %v", code, body)
	}
	got := map[string]string{}
	for _, e := range body["engagements"].([]interface{}) {
		m := e.(map[string]interface{})
		got[m["id"].(string)] = m["state"].(string)
		if targets := m["targets"].([]interface{}); len(targets) != 1 || targets[0].(map[string]interface{})["target_id"] != entry {
			t.Errorf("engagement %v targets = %v", m["title"], targets)
		}
	}
	if len(got) != 2 || got[mine] != "running" || got[everyone] != "scheduled" {
		t.Fatalf("listed engagements = %v, want mine running and everyone scheduled", got)
	}
	if code, body := f.call(f.operator, http.MethodGet, "/my/vendor", ""); code != http.StatusOK || body["external"] != false {
		t.Fatalf("my vendor as an internal user = %d %v", code, body)
	}
}
