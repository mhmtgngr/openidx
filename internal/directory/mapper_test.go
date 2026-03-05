package directory

import (
	"testing"
)

func TestGetDefaultMappingActiveDirectory(t *testing.T) {
	mapping := GetDefaultMapping("active_directory")

	if mapping.Username != "sAMAccountName" {
		t.Errorf("expected Username=sAMAccountName, got %s", mapping.Username)
	}
	if mapping.Email != "mail" {
		t.Errorf("expected Email=mail, got %s", mapping.Email)
	}
	if mapping.FirstName != "givenName" {
		t.Errorf("expected FirstName=givenName, got %s", mapping.FirstName)
	}
	if mapping.LastName != "sn" {
		t.Errorf("expected LastName=sn, got %s", mapping.LastName)
	}
	if mapping.DisplayName != "displayName" {
		t.Errorf("expected DisplayName=displayName, got %s", mapping.DisplayName)
	}
	if mapping.GroupName != "cn" {
		t.Errorf("expected GroupName=cn, got %s", mapping.GroupName)
	}
}

func TestGetDefaultMappingLDAP(t *testing.T) {
	mapping := GetDefaultMapping("ldap")

	if mapping.Username != "uid" {
		t.Errorf("expected Username=uid, got %s", mapping.Username)
	}
	if mapping.Email != "mail" {
		t.Errorf("expected Email=mail, got %s", mapping.Email)
	}
	if mapping.DisplayName != "cn" {
		t.Errorf("expected DisplayName=cn, got %s", mapping.DisplayName)
	}
}

func TestGetDefaultMappingUnknownType(t *testing.T) {
	// Unknown type should default to LDAP mapping
	mapping := GetDefaultMapping("unknown")
	ldapMapping := GetDefaultMapping("ldap")

	if mapping.Username != ldapMapping.Username {
		t.Errorf("expected unknown type to default to LDAP mapping")
	}
}

func TestFillDefaultsEmpty(t *testing.T) {
	mapping := fillDefaults(AttributeMapping{})

	if mapping.Username != "uid" {
		t.Errorf("expected default Username=uid, got %s", mapping.Username)
	}
	if mapping.Email != "mail" {
		t.Errorf("expected default Email=mail, got %s", mapping.Email)
	}
	if mapping.FirstName != "givenName" {
		t.Errorf("expected default FirstName=givenName, got %s", mapping.FirstName)
	}
	if mapping.LastName != "sn" {
		t.Errorf("expected default LastName=sn, got %s", mapping.LastName)
	}
	if mapping.DisplayName != "cn" {
		t.Errorf("expected default DisplayName=cn, got %s", mapping.DisplayName)
	}
}

func TestFillDefaultsPreservesCustom(t *testing.T) {
	custom := AttributeMapping{
		Username:    "customUser",
		Email:       "customEmail",
		FirstName:   "customFirst",
		LastName:    "customLast",
		DisplayName: "customDisplay",
	}
	result := fillDefaults(custom)

	if result.Username != "customUser" {
		t.Errorf("expected custom Username preserved, got %s", result.Username)
	}
	if result.Email != "customEmail" {
		t.Errorf("expected custom Email preserved, got %s", result.Email)
	}
}

func TestFillDefaultsPartial(t *testing.T) {
	partial := AttributeMapping{
		Username: "myUser",
		// Leave others empty
	}
	result := fillDefaults(partial)

	if result.Username != "myUser" {
		t.Errorf("expected Username=myUser, got %s", result.Username)
	}
	if result.Email != "mail" {
		t.Errorf("expected default Email=mail, got %s", result.Email)
	}
}

func TestLDAPConfigDefaults(t *testing.T) {
	cfg := LDAPConfig{
		Host:          "ldap.example.com",
		Port:          389,
		BindDN:        "cn=admin,dc=example,dc=com",
		BindPassword:  "secret",
		BaseDN:        "dc=example,dc=com",
		DirectoryType: "active_directory",
	}

	if cfg.Host != "ldap.example.com" {
		t.Errorf("expected Host=ldap.example.com, got %s", cfg.Host)
	}
	if cfg.Port != 389 {
		t.Errorf("expected Port=389, got %d", cfg.Port)
	}
}

func TestAzureADConfigStruct(t *testing.T) {
	cfg := AzureADConfig{
		TenantID:          "tenant-123",
		ClientID:          "client-456",
		ClientSecret:      "secret-789",
		SyncInterval:      30,
		SyncEnabled:       true,
		DeprovisionAction: "disable",
	}

	if cfg.TenantID != "tenant-123" {
		t.Errorf("expected TenantID=tenant-123, got %s", cfg.TenantID)
	}
	if !cfg.SyncEnabled {
		t.Error("expected SyncEnabled=true")
	}
	if cfg.DeprovisionAction != "disable" {
		t.Errorf("expected DeprovisionAction=disable, got %s", cfg.DeprovisionAction)
	}
}
