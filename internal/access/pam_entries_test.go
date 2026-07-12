package access

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every catalog record must be internally consistent: a known kind, a
// non-empty label, protocols only on session types, and unique type names.
func TestPamEntryTypeCatalogConsistency(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for _, typ := range pamEntryTypeCatalog {
		if seen[typ.Type] {
			t.Fatalf("duplicate entry type %q in catalog", typ.Type)
		}
		seen[typ.Type] = true

		switch typ.Kind {
		case "session", "credential", "info":
		default:
			t.Fatalf("entry type %q has unknown kind %q", typ.Type, typ.Kind)
		}
		if typ.Label == "" {
			t.Fatalf("entry type %q has no label", typ.Type)
		}
		if typ.Protocol != "" && typ.Kind != "session" {
			t.Fatalf("entry type %q has protocol %q but kind %q", typ.Type, typ.Protocol, typ.Kind)
		}
	}

	// RDM-parity floor: the brokered protocols, website, reusable credentials,
	// and the core information records must all exist.
	for _, required := range []string{
		"rdp", "ssh", "vnc", "telnet", "website",
		"credential", "ssh_key", "api_key",
		"secure_note", "credit_card", "bank_account", "software_license",
		"serial_number", "email_account", "alarm_code", "passport", "drivers_license",
	} {
		if !seen[required] {
			t.Fatalf("catalog is missing required RDM-parity type %q", required)
		}
	}
}

func TestValidatePamEntry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		req     pamEntryUpsertReq
		wantErr bool
	}{
		{"valid rdp", pamEntryUpsertReq{Name: "DC01", EntryType: "rdp", Hostname: "dc01.corp"}, false},
		{"valid credential", pamEntryUpsertReq{Name: "svc-sql", EntryType: "credential"}, false},
		{"valid info", pamEntryUpsertReq{Name: "Visa", EntryType: "credit_card"}, false},
		{"valid website", pamEntryUpsertReq{Name: "Portal", EntryType: "website", URL: "https://x"}, false},
		{"missing name", pamEntryUpsertReq{EntryType: "rdp", Hostname: "h"}, true},
		{"whitespace name", pamEntryUpsertReq{Name: "   ", EntryType: "rdp", Hostname: "h"}, true},
		{"unknown type", pamEntryUpsertReq{Name: "x", EntryType: "warp-drive"}, true},
		{"session without hostname", pamEntryUpsertReq{Name: "x", EntryType: "ssh"}, true},
		{"website without url", pamEntryUpsertReq{Name: "x", EntryType: "website"}, true},
		{"port out of range", pamEntryUpsertReq{Name: "x", EntryType: "rdp", Hostname: "h", Port: 99999}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validatePamEntry(&tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePamEntry(%+v) error = %v, wantErr %v", tc.req, err, tc.wantErr)
			}
		})
	}
}

func TestPamDefaultPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		entryType string
		port      int
		want      int
	}{
		{"rdp", 0, 3389},
		{"ssh", 0, 22},
		{"vnc", 0, 5900},
		{"telnet", 0, 23},
		{"rdp", 13389, 13389}, // explicit port wins
		{"website", 0, 0},     // no default for non-brokered types
		{"credential", 0, 0},
	} {
		if got := pamDefaultPort(tc.entryType, tc.port); got != tc.want {
			t.Fatalf("pamDefaultPort(%q, %d) = %d, want %d", tc.entryType, tc.port, got, tc.want)
		}
	}
}

// The vault secret type steers the launch-time injection parameter: only
// ssh_key secrets may inject as private-key; everything launchable must store
// as password.
func TestPamVaultSecretType(t *testing.T) {
	t.Parallel()

	if got := pamVaultSecretType("ssh_key"); got != "ssh_key" {
		t.Fatalf("ssh_key secret type = %q", got)
	}
	for _, launchable := range []string{"rdp", "ssh", "vnc", "telnet", "credential"} {
		if got := pamVaultSecretType(launchable); got != "password" {
			t.Fatalf("pamVaultSecretType(%q) = %q, want password", launchable, got)
		}
	}
	if got := pamVaultSecretType("credit_card"); got != "pam_data" {
		t.Fatalf("info secret type = %q, want pam_data", got)
	}
}

// The entry DTO must never expose vault ids or secret material — HasSecret is
// the only secret-adjacent field the console gets.
func TestPamEntryDTOHidesSecretMaterial(t *testing.T) {
	t.Parallel()

	b, _ := json.Marshal(PamEntry{})
	lower := strings.ToLower(string(b))
	for _, forbidden := range []string{"vault_secret_id", "secret_value", "password", "private_key", "guacamole_connection_id"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("PamEntry exposes %q: %s", forbidden, b)
		}
	}
	if !strings.Contains(lower, "has_secret") {
		t.Fatalf("PamEntry is missing has_secret: %s", b)
	}
}
