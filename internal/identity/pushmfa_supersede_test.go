package identity

import (
	"sort"
	"testing"
)

// A reinstalled app mints a new device token, so its registration arrives as a
// new device. The rows the earlier installs left behind were never used to
// approve anything and can never be again: they kept push on the user's list
// of factors and took the challenge, and the new install could not answer it.
func TestRegisteringAnInstallRemovesTheNeverUsedOnesItSupersedes(t *testing.T) {
	f := newPushGateFixture(t)
	f.svc.cfg.PushMFA.Enabled = true

	// A phone that once approved a sign-in is a real authenticator and stays.
	const used = "22222222-0000-0000-0000-0000000000f4"
	if _, err := f.db.Pool.Exec(f.ctx, `INSERT INTO mfa_push_devices (id, user_id, device_token, platform, enabled, last_used_at, org_id)
		VALUES ('`+used+`','`+pushOwner+`','ntfy:used','android',true,NOW(),'`+pushOrg+`')`); err != nil {
		t.Fatal(err)
	}
	// Another platform, and another user, are not this install's to replace.
	if _, err := f.db.Pool.Exec(f.ctx, `INSERT INTO mfa_push_devices (user_id, device_token, platform, enabled, org_id) VALUES
		('`+pushOwner+`','ntfy:ios','ios',true,'`+pushOrg+`'),
		('`+pushOther+`','ntfy:other','android',true,'`+pushOrg+`')`); err != nil {
		t.Fatal(err)
	}

	dev, err := f.svc.registerPushMFADevice(f.ctx, pushOwner,
		&PushMFAEnrollment{DeviceToken: "ntfy:reinstalled", Platform: "android"}, "10.0.0.1", PushDeviceLink{})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rows, err := f.db.Pool.Query(f.ctx, `SELECT device_token FROM mfa_push_devices WHERE org_id = $1 ORDER BY device_token`, pushOrg)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var tok string
		if err := rows.Scan(&tok); err != nil {
			t.Fatal(err)
		}
		got = append(got, tok)
	}
	sort.Strings(got)
	want := []string{"ntfy:agent", "ntfy:ios", "ntfy:other", "ntfy:reinstalled", "ntfy:used"}
	if len(got) != len(want) {
		t.Fatalf("devices after registering %s = %v, want %v", dev.ID, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("devices after registering %s = %v, want %v", dev.ID, got, want)
		}
	}
}

// Re-registering a token that already exists is the same install checking in;
// it replaces nothing.
func TestReRegisteringAnInstallRemovesNothing(t *testing.T) {
	f := newPushGateFixture(t)
	f.svc.cfg.PushMFA.Enabled = true
	if _, err := f.svc.registerPushMFADevice(f.ctx, pushOwner,
		&PushMFAEnrollment{DeviceToken: "ntfy:self", Platform: "android"}, "10.0.0.1", PushDeviceLink{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	var n int
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_push_devices WHERE user_id = $1`, pushOwner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("devices after re-registering an existing token = %d, want the 3 seeded", n)
	}
}
