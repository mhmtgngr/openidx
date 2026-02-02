package directory

import (
	"github.com/go-ldap/ldap/v3"
)

// GetDefaultMapping returns sensible default attribute mappings per directory type
func GetDefaultMapping(directoryType string) AttributeMapping {
	switch directoryType {
	case "active_directory":
		return AttributeMapping{
			Username:    "sAMAccountName",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			GroupName:   "cn",
		}
	default: // "ldap"
		return AttributeMapping{
			Username:    "uid",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "cn",
			GroupName:   "cn",
		}
	}
}

// MapUserEntry maps an LDAP entry to a UserRecord using the given attribute mapping
func MapUserEntry(entry *ldap.Entry, mapping AttributeMapping) UserRecord {
	m := fillDefaults(mapping)

	return UserRecord{
		DN:          entry.DN,
		Username:    entry.GetAttributeValue(m.Username),
		Email:       entry.GetAttributeValue(m.Email),
		FirstName:   entry.GetAttributeValue(m.FirstName),
		LastName:    entry.GetAttributeValue(m.LastName),
		DisplayName: entry.GetAttributeValue(m.DisplayName),
	}
}

// MapGroupEntry maps an LDAP entry to a GroupRecord
func MapGroupEntry(entry *ldap.Entry, mapping AttributeMapping, memberAttr string) GroupRecord {
	groupName := mapping.GroupName
	if groupName == "" {
		groupName = "cn"
	}
	if memberAttr == "" {
		memberAttr = "member"
	}

	return GroupRecord{
		DN:          entry.DN,
		Name:        entry.GetAttributeValue(groupName),
		Description: entry.GetAttributeValue("description"),
		MemberDNs:   entry.GetAttributeValues(memberAttr),
	}
}

// fillDefaults fills empty mapping fields with defaults
func fillDefaults(m AttributeMapping) AttributeMapping {
	if m.Username == "" {
		m.Username = "uid"
	}
	if m.Email == "" {
		m.Email = "mail"
	}
	if m.FirstName == "" {
		m.FirstName = "givenName"
	}
	if m.LastName == "" {
		m.LastName = "sn"
	}
	if m.DisplayName == "" {
		m.DisplayName = "cn"
	}
	return m
}
