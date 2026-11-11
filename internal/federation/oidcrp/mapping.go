package oidcrp

import (
	"fmt"
	"sort"
	"strings"
)

// ClaimsMapping says which claim of the provider's ID token fills each field
// of a user. The keys are the fields; the values are claim names. A field
// that is not mapped is read from the standard claims (see ApplyClaimsMapping).
// It is stored as JSONB on identity_providers.claims_mapping and shares its
// shape with social_providers.attribute_mapping, so the console edits both
// with one component.
type ClaimsMapping map[string]string

// Fields a mapping may name.
const (
	FieldEmail      = "email"
	FieldUsername   = "username"
	FieldFirstName  = "first_name"
	FieldLastName   = "last_name"
	FieldExternalID = "external_id"
	FieldGroups     = "groups"
	FieldRoles      = "roles"
)

var mappingFields = map[string]bool{
	FieldEmail: true, FieldUsername: true, FieldFirstName: true, FieldLastName: true,
	FieldExternalID: true, FieldGroups: true, FieldRoles: true,
}

// Validate refuses a mapping that names an unknown field or an empty claim.
func (m ClaimsMapping) Validate() error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !mappingFields[k] {
			return fmt.Errorf("claims mapping: %q is not a user field (email, username, first_name, last_name, external_id, groups, roles)", k)
		}
		if strings.TrimSpace(m[k]) == "" {
			return fmt.Errorf("claims mapping: %q names no claim", k)
		}
	}
	return nil
}

// Mapped is a user as the provider describes them.
type Mapped struct {
	ExternalID string
	Email      string
	Username   string
	FirstName  string
	LastName   string
	Groups     []string
	Roles      []string
}

// ApplyClaimsMapping reads a user from raw claims. A field the mapping names
// is read from exactly that claim and from nowhere else: an operator who said
// the email is in `mail` does not want `upn` used when `mail` is absent,
// because that is how the wrong account gets linked. A field the mapping does
// not name falls back through the standard claims: email from email, then a
// preferred_username that looks like an address, then upn; username from
// preferred_username, upn, email; names from given_name/family_name, else a
// split of name; external_id from sub; groups and roles from the claims of
// those names.
func ApplyClaimsMapping(raw map[string]any, m ClaimsMapping) Mapped {
	pick := func(field string, fallback func() string) string {
		if claim, ok := m[field]; ok {
			return str(raw, claim)
		}
		return fallback()
	}
	pickList := func(field string, fallback func() []string) []string {
		if claim, ok := m[field]; ok {
			return stringList(raw[claim])
		}
		return fallback()
	}

	email := pick(FieldEmail, func() string {
		if e := str(raw, "email"); e != "" {
			return e
		}
		if pu := str(raw, "preferred_username"); strings.Contains(pu, "@") {
			return pu
		}
		return str(raw, "upn")
	})
	username := pick(FieldUsername, func() string {
		for _, k := range []string{"preferred_username", "upn", "email"} {
			if v := str(raw, k); v != "" {
				return v
			}
		}
		return email
	})
	first := pick(FieldFirstName, func() string {
		if g := str(raw, "given_name"); g != "" {
			return g
		}
		f, _ := splitName(str(raw, "name"))
		return f
	})
	last := pick(FieldLastName, func() string {
		if f := str(raw, "family_name"); f != "" {
			return f
		}
		if str(raw, "given_name") != "" {
			return ""
		}
		_, l := splitName(str(raw, "name"))
		return l
	})

	return Mapped{
		ExternalID: pick(FieldExternalID, func() string { return str(raw, "sub") }),
		Email:      email,
		Username:   username,
		FirstName:  first,
		LastName:   last,
		Groups:     pickList(FieldGroups, func() []string { return stringList(raw["groups"]) }),
		Roles:      pickList(FieldRoles, func() []string { return stringList(raw["roles"]) }),
	}
}

// splitName takes the last word as the family name and the rest as given
// names: "Ayşe Nur Yılmaz" is Ayşe Nur / Yılmaz. One word is a given name.
func splitName(name string) (first, last string) {
	words := strings.Fields(name)
	switch len(words) {
	case 0:
		return "", ""
	case 1:
		return words[0], ""
	}
	return strings.Join(words[:len(words)-1], " "), words[len(words)-1]
}
