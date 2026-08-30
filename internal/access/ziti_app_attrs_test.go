package access

import (
	"strings"
	"testing"
)

// TestAssembleAttributesCarriesAppMarkers: a per-app attribute is how an
// assignment reaches the overlay. The dial policy for an app-backed service
// grants #app-<uuid>, so an identity without the marker cannot dial it.
func TestAssembleAttributesCarriesAppMarkers(t *testing.T) {
	got := assembleAttributes([]string{"Engineering"}, true, false,
		[]string{appMarkerAttr("11111111-2222-3333-4444-555555555555")})

	want := map[string]bool{
		"Engineering":                              true,
		"enrolled-users":                           true,
		"device-trusted":                           true,
		"app-11111111-2222-3333-4444-555555555555": true,
	}
	if len(got) != len(want) {
		t.Fatalf("attributes = %v, want exactly %d entries", got, len(want))
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("unexpected attribute %q", a)
		}
	}
}

// TestAppMarkerUsesTheUUID: the attribute set is wholesale-replaced on every
// sync, so keying on a renameable name would silently drop reach on rename.
func TestAppMarkerUsesTheUUID(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	got := appMarkerAttr(id)
	if got != "app-"+id {
		t.Errorf("appMarkerAttr = %q, want %q", got, "app-"+id)
	}
	if strings.ContainsAny(got, " #") {
		t.Errorf("attribute %q must not contain a space or a leading hash (the hash is added by the policy)", got)
	}
}

// TestAssembleAttributesWithoutApps keeps the pre-existing shape intact for a
// user with no assignments.
func TestAssembleAttributesWithoutApps(t *testing.T) {
	got := assembleAttributes([]string{"Sales"}, false, true, nil)
	if len(got) != 3 {
		t.Fatalf("attributes = %v, want [Sales enrolled-users browzer-users]", got)
	}
}
