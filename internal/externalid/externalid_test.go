package externalid

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRoleAllowed(t *testing.T) {
	for _, tc := range []struct {
		userType, role string
		want           bool
	}{
		{TypeExternal, "user", true},
		{TypeExternal, " User ", true},
		{TypeExternal, "admin", false},
		{TypeExternal, "auditor", false},
		{TypeExternal, "compliance_reader", false},
		{TypeExternal, "developer", false},
		{TypeInternal, "admin", true},
		{TypeService, "operator", true},
	} {
		if got := RoleAllowed(tc.userType, tc.role); got != tc.want {
			t.Errorf("RoleAllowed(%s, %q) = %v, want %v", tc.userType, tc.role, got, tc.want)
		}
	}
}

func TestValidateExpiry(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	day := func(y int, m time.Month, d int) *time.Time { v := time.Date(y, m, d, 0, 0, 0, 0, time.UTC); return &v }
	for _, tc := range []struct {
		name     string
		expires  *time.Time
		contract *time.Time
		want     error
	}{
		{"ninety days", at(90 * 24 * time.Hour), nil, nil},
		{"the last allowed day", at(365 * 24 * time.Hour), nil, nil},
		{"none", nil, nil, ErrExpiryRequired},
		{"now", at(0), nil, ErrExpiryPast},
		{"past", at(-time.Hour), nil, ErrExpiryPast},
		{"beyond a year", at(366 * 24 * time.Hour), nil, ErrExpiryTooLong},
		{"on the contract's last day", day(2026, 12, 31), day(2026, 12, 31), nil},
		{"after the contract", day(2027, 1, 1), day(2026, 12, 31), ErrExpiryContract},
	} {
		if got := ValidateExpiry(now, tc.expires, tc.contract); !errors.Is(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVendorEmailAllowed(t *testing.T) {
	v := Vendor{AllowedEmailDomains: []string{"supplier.example.test"}}
	for email, want := range map[string]bool{
		"a@supplier.example.test":         true,
		"a@SUPPLIER.example.test":         true,
		"a@evil.example.test":             false,
		"a@sub.supplier.example.test":     false,
		"a@supplier.example.test.evil.io": false,
		"not-an-email":                    false,
	} {
		if got := v.EmailAllowed(email); got != want {
			t.Errorf("EmailAllowed(%q) = %v, want %v", email, got, want)
		}
	}
	if !(Vendor{}).EmailAllowed("a@anything.example.test") {
		t.Error("a vendor with no domain list refused an address")
	}
}

func TestFromDBAndCodes(t *testing.T) {
	for constraint, want := range map[string]error{
		"external_role_cap":             ErrRoleCap,
		"external_group_not_allowed":    ErrGroupNotExternal,
		"external_cannot_approve":       ErrExternalApprover,
		"user_type_immutable":           ErrTypeImmutable,
		"external_group_has_members":    ErrGroupHasExternal,
		"users_external_identity_check": ErrIdentityIncomplete,
		"users_external_enabled_check":  ErrAccountNotLive,
	} {
		err := fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23514", ConstraintName: constraint})
		got := Refusal(err)
		if !errors.Is(got, want) {
			t.Errorf("%s: Refusal = %v, want %v", constraint, got, want)
		}
		if Code(got) == "" {
			t.Errorf("%s: no code", constraint)
		}
	}
	if Refusal(&pgconn.PgError{Code: "23514", ConstraintName: "some_other_check"}) != nil {
		t.Error("an unrelated CHECK was read as an external refusal")
	}
	if Refusal(&pgconn.PgError{Code: "23505", ConstraintName: "external_role_cap"}) != nil {
		t.Error("a unique violation was read as an external refusal")
	}
	if Refusal(errors.New("boom")) != nil || Refusal(nil) != nil {
		t.Error("a plain error was read as an external refusal")
	}
	if Code(ErrRoleCap) != "external_role_cap" {
		t.Errorf("Code(ErrRoleCap) = %q", Code(ErrRoleCap))
	}
	// The PAM refusals (I5, I7) are refusals with codes the console switches on.
	for err, want := range map[error]string{
		ErrRevealForbidden:        "external_reveal_forbidden",
		ErrSSHCAForbidden:         "external_ssh_ca_forbidden",
		ErrCloudJITForbidden:      "external_cloud_jit_forbidden",
		ErrRecordingUnavailable:   "external_recording_unavailable",
		ErrBrokerIdentityRequired: "external_broker_identity_required",
	} {
		if !IsRefusal(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("%v is not counted as a refusal", err)
		}
		if got := Code(err); got != want {
			t.Errorf("Code(%v) = %q, want %q", err, got, want)
		}
	}
}
