package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the biometric preferences and policies, migration v158.
//
// A biometric_policies row says which authenticator types are allowed, whether
// a platform authenticator (Face ID / Touch ID) is required, and which groups
// and roles the rule covers. v54 created it with no org_id, and the list is the
// whole query:
//
//	SELECT ... FROM biometric_policies ORDER BY name
//
// GetApplicableBiometricPolicy calls that, walks the result and returns the
// FIRST policy that applies — and a policy naming no groups and no roles
// "applies to all" by the code's own comment. So any administrator on the
// installation could author an untargeted rule that governed every user on it,
// and `ORDER BY name` decided which rule won. A control aimed by sort order is
// aimed by whoever picks the earlier name.
//
// The direction runs both ways: allowed_authenticator_types defaults to both
// types, so a permissive foreign policy sorting first REPLACED a restrictive
// local one.
//
// biometric_preferences is one row per user — including whether the account is
// biometric-only and whether user verification is required — read and written
// by bare user_id.
func TestBiometric_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('bio-b','bio-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	userA := seedUser(orgA, "bio-a")
	userB := seedUser(orgB, "bio-b")

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(ctx, orgctx.Org{ID: orgA})
	ctxB := orgctx.With(ctx, orgctx.Org{ID: orgB})

	// Org A wants security keys only. Org B allows everything, and its policy
	// name sorts first — which is the whole mechanism.
	t.Run("another tenant's policy cannot decide this tenant's authenticators", func(t *testing.T) {
		if _, err := s.CreateBiometricPolicy(ctxA, &BiometricPolicy{
			Name:                         "zz-org-a-keys-only",
			Enabled:                      true,
			RequirePlatformAuthenticator: true,
			AllowedAuthenticatorTypes:    []string{"platform"},
			MinAuthenticatorLevel:        "multi",
		}); err != nil {
			t.Fatalf("org A policy: %v", err)
		}
		if _, err := s.CreateBiometricPolicy(ctxB, &BiometricPolicy{
			Name:                      "aa-org-b-anything",
			Enabled:                   true,
			AllowedAuthenticatorTypes: []string{"platform", "cross-platform"},
			MinAuthenticatorLevel:     "any",
		}); err != nil {
			t.Fatalf("org B policy: %v", err)
		}

		got, err := s.GetApplicableBiometricPolicy(ctxA, userA)
		if err != nil {
			t.Fatalf("applicable policy for org A: %v", err)
		}
		if got == nil {
			t.Fatal("org A's own untargeted policy did not apply to its own user")
		}
		if got.Name != "zz-org-a-keys-only" {
			t.Errorf("org A's user is governed by %q. The policy list had no tenant "+
				"term and ORDER BY name picked the winner, so whoever chose the "+
				"earlier name governed the installation", got.Name)
		}
		// And the enforcement helper that reads it agrees.
		ok, reason, err := s.ValidateAuthenticatorForPolicy(ctxA, userA, "cross-platform")
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if ok {
			t.Error("a cross-platform authenticator was accepted for a user whose " +
				"organization allows platform only, because another tenant's " +
				"permissive rule sorted first")
		}
		if reason == "" {
			t.Error("a refusal with no reason")
		}

		// The list itself must scope, not empty: each side keeps its own.
		listA, err := s.ListBiometricPolicies(ctxA)
		if err != nil {
			t.Fatalf("list as org A: %v", err)
		}
		if len(listA) != 1 || listA[0].Name != "zz-org-a-keys-only" {
			t.Errorf("org A's policy list is %v; want exactly its own", names(listA))
		}
		listB, err := s.ListBiometricPolicies(ctxB)
		if err != nil {
			t.Fatalf("list as org B: %v", err)
		}
		if len(listB) != 1 || listB[0].Name != "aa-org-b-anything" {
			t.Errorf("org B's policy list is %v; want exactly its own", names(listB))
		}
	})

	// Update and delete addressed a policy by bare id.
	t.Run("a policy cannot be re-aimed or deleted from another tenant", func(t *testing.T) {
		listA, err := s.ListBiometricPolicies(ctxA)
		if err != nil || len(listA) == 0 {
			t.Fatalf("org A policy list: %v (%d)", err, len(listA))
		}
		target := listA[0]

		rewritten := target
		rewritten.AllowedAuthenticatorTypes = []string{"platform", "cross-platform"}
		rewritten.RequirePlatformAuthenticator = false
		if err := s.UpdateBiometricPolicy(ctxB, &rewritten); err == nil {
			t.Error("org B rewrote org A's biometric policy. Everything the rule " +
				"says is settable here, so a rule labelled \"platform only\" could " +
				"be widened and handed back to the administrator who owns it")
		}
		if err := s.DeleteBiometricPolicy(ctxB, target.ID); err == nil {
			t.Error("org B deleted org A's biometric policy, with nothing on org A's " +
				"console to say the control had stopped existing")
		}

		// Still there, still strict.
		after, err := s.ListBiometricPolicies(ctxA)
		if err != nil {
			t.Fatalf("re-list as org A: %v", err)
		}
		if len(after) != 1 {
			t.Fatalf("org A now has %d policies, want 1", len(after))
		}
		if !after[0].RequirePlatformAuthenticator ||
			len(after[0].AllowedAuthenticatorTypes) != 1 {
			t.Errorf("org A's policy was weakened: require_platform=%v types=%v",
				after[0].RequirePlatformAuthenticator, after[0].AllowedAuthenticatorTypes)
		}
		// The owner can still edit it: the term must scope, not deny outright.
		if err := s.UpdateBiometricPolicy(ctxA, &after[0]); err != nil {
			t.Errorf("the policy's own organization could not update it: %v", err)
		}
	})

	// The preferences are per user, and one of them switches the account to
	// biometric-only.
	t.Run("preferences are not readable or writable across tenants", func(t *testing.T) {
		if err := s.UpdateBiometricPreferences(ctxA, userA, &BiometricPreferences{
			PlatformAuthenticatorPreferred: true,
			AllowCrossPlatform:             false,
			RequireUserVerification:        true,
			ResidentKeyRequired:            true,
		}); err != nil {
			t.Fatalf("org A save: %v", err)
		}

		// Org B must not be able to read them...
		if _, err := s.GetBiometricPreferences(ctxB, userA); err != nil {
			t.Fatalf("unexpected error reading as org B: %v", err)
		}
		otherView, _ := s.GetBiometricPreferences(ctxB, userA)
		if otherView.ID != "" {
			t.Error("org B read org A's user's stored biometric preferences")
		}
		if !otherView.RequireUserVerification || otherView.ResidentKeyRequired {
			t.Errorf("a cross-tenant read returned something other than the defaults: %+v", otherView)
		}

		// ...nor write them. Turning user verification off is the interesting
		// direction: it weakens what the authenticator must prove.
		if err := s.UpdateBiometricPreferences(ctxB, userA, &BiometricPreferences{
			AllowCrossPlatform:      true,
			RequireUserVerification: false,
			BiometricOnlyEnabled:    true,
		}); err == nil {
			t.Error("org B rewrote org A's user's biometric preferences")
		}

		own, err := s.GetBiometricPreferences(ctxA, userA)
		if err != nil {
			t.Fatalf("org A read back: %v", err)
		}
		if !own.RequireUserVerification || !own.ResidentKeyRequired || own.AllowCrossPlatform {
			t.Errorf("org A's stored preferences changed: %+v", own)
		}
		if own.BiometricOnlyEnabled {
			t.Error("org B switched org A's user to biometric-only login")
		}
	})

	// The direction of a failure: no organization must refuse, not fall back to
	// the permissive defaults.
	t.Run("no organization is a refusal, not the defaults", func(t *testing.T) {
		if _, err := s.GetBiometricPreferences(ctx, userA); err == nil {
			t.Error("reading preferences with no organization returned the built-in " +
				"defaults and a nil error. Every failure used to look like " +
				"\"this user has not set preferences\"")
		}
		if err := s.UpdateBiometricPreferences(ctx, userA, &BiometricPreferences{}); err == nil {
			t.Error("writing preferences with no organization succeeded")
		}
		if _, err := s.ListBiometricPolicies(ctx); err == nil {
			t.Error("listing policies with no organization returned every tenant's")
		}
		if _, err := s.CreateBiometricPolicy(ctx, &BiometricPolicy{Name: "no-org"}); err == nil {
			t.Error("creating a policy with no organization succeeded")
		}
	})

	// A user outside the caller's tenant is refused rather than given a
	// preferences row in the caller's organization.
	t.Run("a foreign user is not a target", func(t *testing.T) {
		if err := s.UpdateBiometricPreferences(ctxA, userB, &BiometricPreferences{
			RequireUserVerification: false,
		}); err == nil {
			t.Error("org A created preferences for a user in org B")
		}
	})
}

func names(policies []BiometricPolicy) []string {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.Name)
	}
	return out
}
