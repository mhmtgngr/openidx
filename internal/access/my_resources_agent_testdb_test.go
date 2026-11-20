package access

import "testing"

// A dark application is listed for the people it was given to, and only them.
// It is a catalogue of what a person was given, not of what a gate happens to
// let through, so the list does not change with the enforcement flags.

func (w *darkWorld) member(userID, groupID, org string) {
	w.t.Helper()
	w.exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, userID, groupID, org)
}

func TestMyResourcesListsAPublishedDarkAppForItsAssignees(t *testing.T) {
	w := newDarkWorld(t)
	bob := w.scalar(`INSERT INTO users (username, email, first_name, last_name, enabled, org_id)
		VALUES ('bob-'||gen_random_uuid()::text, gen_random_uuid()::text||'@corp.example', 'B', 'B', true, $1::uuid) RETURNING id::text`, darkOrgA)
	carol := w.scalar(`INSERT INTO users (username, email, first_name, last_name, enabled, org_id)
		VALUES ('carol-'||gen_random_uuid()::text, gen_random_uuid()::text||'@corp.example', 'C', 'C', true, $1::uuid) RETURNING id::text`, darkOrgA)
	w.member(w.userA, w.groupA1, darkOrgA) // alice is in the group; bob is assigned directly; carol is neither

	if _, err := w.publish(w.ctxA, darkOrgA, publishRequest{
		Name: "Wiki", Address: "https://wiki.corp.example/docs", GroupIDs: []string{w.groupA1}, UserIDs: []string{bob},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	for _, who := range []string{w.userA, bob} {
		rows := w.svc.agentResources(w.ctxA, darkOrgA, who)
		if len(rows) != 1 {
			t.Fatalf("user %s sees %d agent rows, want 1: %+v", who, len(rows), rows)
		}
		r := rows[0]
		if r.Name != "Wiki" || r.Kind != resourceKindWeb || r.How != reachAgent || r.Status != statusReady ||
			r.To != "wiki.corp.example" || r.Port != 443 ||
			r.Action.Kind != "open_url" || r.Action.URL != "https://wiki.corp.example/docs" || r.Note == "" {
			t.Errorf("row = %+v", r)
		}
	}
	if rows := w.svc.agentResources(w.ctxA, darkOrgA, carol); len(rows) != 0 {
		t.Errorf("carol, who was given nothing, sees %+v", rows)
	}
}

func TestMyResourcesOmitsADisabledOrURLlessNetworkResource(t *testing.T) {
	w := newDarkWorld(t)
	res, err := w.publish(w.ctxA, darkOrgA, publishRequest{Name: "Wiki", Address: "https://wiki.corp.example", UserIDs: []string{w.userA}})
	if err != nil {
		t.Fatal(err)
	}
	if rows := w.svc.agentResources(w.ctxA, darkOrgA, w.userA); len(rows) != 1 {
		t.Fatalf("before: %d rows, want 1", len(rows))
	}
	// A CIDR-style network resource has no address to open.
	w.exec(`UPDATE applications SET base_url = NULL WHERE id = $1::uuid`, res.ID)
	if rows := w.svc.agentResources(w.ctxA, darkOrgA, w.userA); len(rows) != 0 {
		t.Errorf("a resource with no address is listed: %+v", rows)
	}
	w.exec(`UPDATE applications SET base_url = 'https://wiki.corp.example/', enabled = false WHERE id = $1::uuid`, res.ID)
	if rows := w.svc.agentResources(w.ctxA, darkOrgA, w.userA); len(rows) != 0 {
		t.Errorf("a disabled resource is listed: %+v", rows)
	}
}

func TestMyResourcesKeepsAnotherOrganizationsAppsOut(t *testing.T) {
	w := newDarkWorld(t)
	if _, err := w.publish(w.ctxB, darkOrgB, publishRequest{Name: "B wiki", Address: "https://wiki.corp.example", UserIDs: []string{w.userB}}); err != nil {
		t.Fatalf("publish in B: %v", err)
	}
	if rows := w.svc.agentResources(w.ctxB, darkOrgB, w.userB); len(rows) != 1 {
		t.Fatalf("B's own user sees %d rows, want 1", len(rows))
	}
	// The same user id asked for under organization A: nothing.
	if rows := w.svc.agentResources(w.ctxA, darkOrgA, w.userB); len(rows) != 0 {
		t.Errorf("another organization's app is listed under org A: %+v", rows)
	}
}
