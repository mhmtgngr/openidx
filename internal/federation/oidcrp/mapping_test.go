package oidcrp

import (
	"reflect"
	"testing"
)

func TestDefaultMappingReadsTheStandardClaims(t *testing.T) {
	m := ApplyClaimsMapping(map[string]any{
		"sub": "s1", "email": "a@x.org", "preferred_username": "a@x.org",
		"given_name": "Ayşe", "family_name": "Yılmaz",
		"groups": []any{"g1", "g2"}, "roles": []any{"r1"},
	}, nil)
	want := Mapped{ExternalID: "s1", Email: "a@x.org", Username: "a@x.org", FirstName: "Ayşe", LastName: "Yılmaz",
		Groups: []string{"g1", "g2"}, Roles: []string{"r1"}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %+v\nwant %+v", m, want)
	}
}

func TestDefaultMappingFallsBackToUPNForEmailAndSplitsName(t *testing.T) {
	// ADFS tokens often carry upn and name but no email/given_name.
	m := ApplyClaimsMapping(map[string]any{"sub": "s1", "upn": "a@x.org", "name": "Ayşe Nur Yılmaz"}, nil)
	if m.Email != "a@x.org" || m.Username != "a@x.org" || m.FirstName != "Ayşe Nur" || m.LastName != "Yılmaz" {
		t.Errorf("got %+v", m)
	}
}

func TestAMappingNamesTheClaimToRead(t *testing.T) {
	m := ApplyClaimsMapping(map[string]any{
		"sub": "s1", "oid": "o1", "mail": "a@x.org", "wids": []any{"admin"},
	}, ClaimsMapping{"external_id": "oid", "email": "mail", "roles": "wids"})
	if m.ExternalID != "o1" || m.Email != "a@x.org" || !reflect.DeepEqual(m.Roles, []string{"admin"}) {
		t.Errorf("got %+v", m)
	}
}

func TestAMappedClaimThatIsAbsentLeavesTheFieldEmptyRatherThanFallingBack(t *testing.T) {
	// An operator who said "email comes from mail" does not want the sub or
	// upn silently used when mail is missing: that would link the wrong user.
	m := ApplyClaimsMapping(map[string]any{"sub": "s1", "email": "a@x.org"}, ClaimsMapping{"email": "mail"})
	if m.Email != "" {
		t.Errorf("email = %q, want empty", m.Email)
	}
}

func TestAListClaimMayArriveAsASpaceSeparatedString(t *testing.T) {
	m := ApplyClaimsMapping(map[string]any{"sub": "s1", "groups": "g1 g2"}, nil)
	if !reflect.DeepEqual(m.Groups, []string{"g1", "g2"}) {
		t.Errorf("groups = %v", m.Groups)
	}
}

func TestClaimsMappingValidationNamesTheBadKey(t *testing.T) {
	if err := (ClaimsMapping{"email": "mail", "colour": "x"}).Validate(); err == nil {
		t.Error("unknown key accepted")
	}
	if err := (ClaimsMapping{"email": ""}).Validate(); err == nil {
		t.Error("empty claim name accepted")
	}
	if err := (ClaimsMapping{"email": "mail", "groups": "groups"}).Validate(); err != nil {
		t.Errorf("valid mapping refused: %v", err)
	}
}
