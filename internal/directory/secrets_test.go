package directory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// A STORED CREDENTIAL IS KEPT ONLY FOR ITS OWN TARGET.
//
// An update that leaves the credential out keeps the stored one, since no
// read returns it for the client to send back. Kept for another target, it
// would be handed to whatever answers there: the bind password to an LDAP
// server the caller names, over a connection the caller weakens, or through
// referrals the caller turns on; the API key to an endpoint the caller names.
// Each field that decides where and how the credential travels, changed on
// its own, needs the credential again; a change to anything else keeps it.
func TestAStoredCredentialIsKeptOnlyForItsOwnTarget(t *testing.T) {
	c, err := secretcrypt.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	sealed, err := c.Encrypt("the-credential")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	type change struct {
		name string
		edit func(map[string]any)
	}
	types := []struct {
		dirType  string
		stored   string
		sameAs   []change
		targetOf []change
	}{
		{
			dirType: "ldap",
			stored: `{"host":"ldap.example.test","port":636,"bind_dn":"cn=svc,dc=example,dc=test","bind_password":"` + sealed + `",
				"use_tls":true,"start_tls":false,"skip_tls_verify":false,"follow_referrals":false,"referral_hop_limit":0,
				"base_dn":"dc=example,dc=test","user_filter":"(objectClass=person)","sync_interval":60}`,
			sameAs: []change{
				{"the user filter", func(m map[string]any) { m["user_filter"] = "(objectClass=inetOrgPerson)" }},
				{"the base DN", func(m map[string]any) { m["base_dn"] = "ou=people,dc=example,dc=test" }},
				{"the sync interval", func(m map[string]any) { m["sync_interval"] = float64(15) }},
				{"the host's case and spaces", func(m map[string]any) { m["host"] = " LDAP.Example.TEST " }},
				{"the bind DN's case", func(m map[string]any) { m["bind_dn"] = "CN=svc,DC=example,DC=test" }},
			},
			targetOf: []change{
				{"the host", func(m map[string]any) { m["host"] = "ldap.attacker.test" }},
				{"the port", func(m map[string]any) { m["port"] = float64(389) }},
				{"the bind DN", func(m map[string]any) { m["bind_dn"] = "cn=admin,dc=example,dc=test" }},
				{"implicit TLS", func(m map[string]any) { m["use_tls"] = false }},
				{"StartTLS", func(m map[string]any) { m["start_tls"] = true }},
				{"certificate verification", func(m map[string]any) { m["skip_tls_verify"] = true }},
				{"referral following", func(m map[string]any) { m["follow_referrals"] = true }},
				{"the referral hop limit", func(m map[string]any) { m["referral_hop_limit"] = float64(5) }},
			},
		},
		{
			dirType: "azure_ad",
			stored:  `{"tenant_id":"tenant-1","client_id":"client-1","client_secret":"` + sealed + `","user_filter":"accountEnabled eq true"}`,
			sameAs: []change{
				{"the user filter", func(m map[string]any) { m["user_filter"] = "" }},
				{"the tenant's case", func(m map[string]any) { m["tenant_id"] = "TENANT-1" }},
			},
			targetOf: []change{
				{"the tenant", func(m map[string]any) { m["tenant_id"] = "tenant-2" }},
				{"the client", func(m map[string]any) { m["client_id"] = "client-2" }},
			},
		},
		{
			dirType: "hris",
			stored:  `{"provider":"bamboohr","subdomain":"acme","api_key":"` + sealed + `","sync_interval":60}`,
			sameAs: []change{
				{"the sync interval", func(m map[string]any) { m["sync_interval"] = float64(30) }},
				{"no provider, which is BambooHR", func(m map[string]any) { delete(m, "provider") }},
				{"the default gateway named outright", func(m map[string]any) {
					m["base_url"] = "https://api.bamboohr.com/api/gateway.php/acme/"
				}},
			},
			targetOf: []change{
				{"the subdomain", func(m map[string]any) { m["subdomain"] = "other" }},
				{"the base URL", func(m map[string]any) { m["base_url"] = "https://collector.example.test" }},
				{"the provider", func(m map[string]any) { m["provider"] = "workday" }},
			},
		},
	}

	next := func(t *testing.T, stored string, edit func(map[string]any)) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(stored), &m); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		delete(m, SecretKeyFor("ldap"))
		delete(m, SecretKeyFor("azure_ad"))
		delete(m, SecretKeyFor("hris"))
		edit(m)
		return m
	}
	for _, tc := range types {
		key := SecretKeyFor(tc.dirType)
		for _, ch := range tc.sameAs {
			t.Run(tc.dirType+": another "+ch.name+" keeps it", func(t *testing.T) {
				m := next(t, tc.stored, ch.edit)
				if errs := KeepStoredSecret(c, tc.dirType, []byte(tc.stored), tc.dirType, m); len(errs) != 0 {
					t.Fatalf("refused: %v", errs)
				}
				if m[key] != sealed {
					t.Fatalf("the stored credential was not kept: %v", m[key])
				}
			})
		}
		for _, ch := range tc.targetOf {
			t.Run(tc.dirType+": another "+ch.name+" needs it again", func(t *testing.T) {
				m := next(t, tc.stored, ch.edit)
				errs := KeepStoredSecret(c, tc.dirType, []byte(tc.stored), tc.dirType, m)
				if !strings.Contains(errs["config."+key], "kept only while") {
					t.Fatalf("not refused: %v", errs)
				}
				if _, carried := m[key]; carried {
					t.Fatal("the stored credential was carried to another target")
				}
			})
		}
	}

	t.Run("another type keeps nothing", func(t *testing.T) {
		m := next(t, types[0].stored, func(map[string]any) {})
		if errs := KeepStoredSecret(c, "ldap", []byte(types[0].stored), "active_directory", m); len(errs) != 0 {
			t.Fatalf("errors: %v", errs)
		}
		if _, carried := m["bind_password"]; carried {
			t.Fatal("the stored bind password was carried to another directory type")
		}
	})

	t.Run("one sent with the update is the one used", func(t *testing.T) {
		m := next(t, types[0].stored, func(m map[string]any) { m["host"] = "ldap2.example.test"; m["bind_password"] = "new" })
		if errs := KeepStoredSecret(c, "ldap", []byte(types[0].stored), "ldap", m); len(errs) != 0 || m["bind_password"] != "new" {
			t.Fatalf("errors %v, bind_password %v", errs, m["bind_password"])
		}
	})
}

// A CREDENTIAL IS OPENED ONLY WITH THE KEY IT WAS SEALED WITH, AND ONE THAT
// CANNOT BE OPENED IS NEVER SENT.
func TestADirectoryCredentialOpensOnlyWithItsKey(t *testing.T) {
	c, _ := secretcrypt.New("0123456789abcdef0123456789abcdef")
	other, _ := secretcrypt.New("fedcba9876543210fedcba9876543210")
	sealed, _ := c.Encrypt("pw")
	foreign, _ := other.Encrypt("pw")

	cfg := map[string]any{"bind_password": "pw", "client_secret": "", "host": "h"}
	if err := SealSecrets(secretcrypt.NewNoop(), cfg); err != nil || cfg["bind_password"] != "pw" {
		t.Fatalf("without a key the credential is stored as it came: %v %v", cfg["bind_password"], err)
	}
	if err := SealSecrets(c, cfg); err != nil || !secretcrypt.IsEncrypted(cfg["bind_password"].(string)) || cfg["client_secret"] != "" {
		t.Fatalf("sealed: %v, %v", cfg, err)
	}

	for name, tc := range map[string]struct {
		cipher *secretcrypt.Cipher
		stored string
		want   string
	}{
		"sealed, with the key":         {c, sealed, "pw"},
		"stored in plaintext":          {c, "legacy", "legacy"},
		"stored in plaintext, keyless": {secretcrypt.NewNoop(), "legacy", "legacy"},
		"sealed with another key":      {c, foreign, ""},
		"sealed, and this one keyless": {secretcrypt.NewNoop(), sealed, ""},
		"sealed, and no cipher at all": {nil, sealed, ""},
		"sealed twice (from a client)": {c, mustSeal(t, c, sealed), ""},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"api_key": tc.stored, "port": json.Number("636")})
			opened, err := OpenSecrets(tc.cipher, raw)
			var unopenable *UnopenableSecretError
			if tc.want == "" {
				if !errors.As(err, &unopenable) || !strings.Contains(err.Error(), "cannot be decrypted") {
					t.Fatalf("opened %s (%v); want it refused", opened, err)
				}
				// And the connectors refuse it too, should a caller skip opening.
				if refuseSealed(raw) == nil {
					t.Fatal("a sealed credential reached a connector")
				}
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			var m map[string]any
			_ = json.Unmarshal(opened, &m)
			if m["api_key"] != tc.want || m["port"] != float64(636) {
				t.Fatalf("opened as %s", opened)
			}
		})
	}

	t.Run("a read carries whether one is stored, not the value", func(t *testing.T) {
		m := map[string]any{"bind_password": sealed, "api_key": "", "host": "h"}
		RedactSecrets(m)
		if _, ok := m["bind_password"]; ok {
			t.Fatal("the bind password was returned")
		}
		if m["bind_password_set"] != true || m["api_key_set"] != false || m["host"] != "h" {
			t.Fatalf("redacted as %v", m)
		}
		if _, ok := m["client_secret_set"]; ok {
			t.Fatal("a flag for a credential the config does not hold")
		}
	})
}

func mustSeal(t *testing.T, c *secretcrypt.Cipher, s string) string {
	t.Helper()
	out, err := c.Encrypt(s)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return out
}

// THE STARTUP SWEEP OVERWRITES NOTHING SAVED SINCE IT READ THE ROW.
//
// admin-api seals plaintext credentials at startup, row by row, from what it
// read. An administrator who saves a directory in between has stored a new
// credential, sealed; writing the sweep's copy over it would put back the
// credential that was replaced. Replicas starting together read the same rows,
// and each row is sealed by one of them.
func TestTheSweepLeavesARowSavedSinceItWasRead(t *testing.T) {
	db, cleanup := routingSetupDB(t)
	defer cleanup()
	ctx := routingCtx()
	bypass := orgctx.WithBypassRLS(context.Background())
	c, err := secretcrypt.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := &Service{db: db, logger: zap.NewNop(), cipher: c}
	read := func(id string) []byte {
		t.Helper()
		var raw []byte
		if err := db.Pool.QueryRow(ctx, `SELECT config FROM directory_integrations WHERE id = $1`, id).Scan(&raw); err != nil {
			t.Fatalf("read: %v", err)
		}
		return raw
	}
	storedKey := func(id string) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, `SELECT config ->> 'api_key' FROM directory_integrations WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatalf("read: %v", err)
		}
		return v
	}

	id := seedDirectory(t, db, ctx, "hris", `{"subdomain":"acme","api_key":"Old-K3y"}`, true)
	stale := read(id)
	saved, _ := c.Encrypt("New-K3y")
	if _, err := db.Pool.Exec(ctx, `UPDATE directory_integrations SET config = $2::jsonb WHERE id = $1`,
		id, `{"subdomain":"acme","api_key":"`+saved+`"}`); err != nil {
		t.Fatalf("save: %v", err)
	}
	if done, err := svc.sealStoredRow(bypass, id, routingOrgID, stale); err != nil || done {
		t.Fatalf("the sweep wrote over a save made since it read the row (%v, %v)", done, err)
	}
	if got := storedKey(id); got != saved {
		t.Fatalf("the saved credential became %q", got)
	}

	other := seedDirectory(t, db, ctx, "hris", `{"subdomain":"acme","api_key":"Plain-K3y"}`, true)
	seen := read(other)
	if done, err := svc.sealStoredRow(bypass, other, routingOrgID, seen); err != nil || !done {
		t.Fatalf("the first replica did not seal the row (%v, %v)", done, err)
	}
	first := storedKey(other)
	if got, err := c.Decrypt(first); err != nil || got != "Plain-K3y" || !secretcrypt.IsEncrypted(first) {
		t.Fatalf("sealed as %q (%v)", first, err)
	}
	if done, err := svc.sealStoredRow(bypass, other, routingOrgID, seen); err != nil || done {
		t.Fatalf("a second replica sealed the row again (%v, %v)", done, err)
	}
	if storedKey(other) != first {
		t.Fatal("a second replica rewrote the sealed row")
	}
}
