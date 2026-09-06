package access

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/access/edr"
)

// Tenant isolation for the EDR/MDM posture ingestion, migration v165.
//
// v98's registry description says "Org-scoped, encrypted creds." Both tables
// got a nullable org_id with no foreign key, and neither got the belt. The
// needsBelt register has carried a warning against edr_device_mappings since it
// was written: the ingest writes a NULL org_id when the source has none, so a
// belt would HIDE rows rather than scope them.
//
// THE MATCH CROSSED TENANTS, AND THE MATCH IS AN ENFORCEMENT DECISION.
// resolveIdentityForDevice turns an EDR device report into a local Ziti
// identity, and all three of its strategies named no organization:
//
//	SELECT zi.id FROM ziti_identities zi JOIN users u ON u.id = zi.user_id
//	 WHERE lower(u.email) = lower($1) LIMIT 1
//
// The identity it returns goes to RecordPostureResult, and a failing posture
// result is what the proxy and continuous verification read to revoke a session
// and sever the overlay circuit. So one tenant's EDR calling a laptop
// non-compliant could cut another tenant's user off, on a shared email address,
// hostname or serial — with LIMIT 1 and no ORDER BY leaving the choice to the
// planner.
func TestEDRPosture_TenantIsolation(t *testing.T) {
	db, cleanup := setupEDRDB(t)
	defer cleanup()
	ctx := context.Background()
	svc := newEDRTestService(db)

	const orgB = "00000000-0000-0000-0000-0000000000e2"

	// The same email in both organizations — the ordinary case for one person
	// employed by two tenants on one installation.
	seedIdentity := func(org, username, email, zitiID string) string {
		t.Helper()
		var userID, identityID string
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO users (username,email,org_id) VALUES ($1,$2,$3::uuid) RETURNING id`,
			username, email, org).Scan(&userID); err != nil {
			t.Fatalf("seed user %s: %v", username, err)
		}
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO ziti_identities (user_id, ziti_id, org_id) VALUES ($1,$2,$3::uuid) RETURNING id`,
			userID, zitiID, org).Scan(&identityID); err != nil {
			t.Fatalf("seed identity %s: %v", zitiID, err)
		}
		return identityID
	}
	identA := seedIdentity(edrTestOrgID, "shared-a", "shared@corp.com", "zid-a")
	identB := seedIdentity(orgB, "shared-b", "shared@corp.com", "zid-b")
	// An address that exists ONLY in org B. Nothing in org A can match it, so
	// org A's source resolving anything at all is unambiguously a cross-tenant
	// match -- unlike the shared address, where LIMIT 1 with no ORDER BY could
	// return either tenant's row and the planner decides which.
	onlyB := seedIdentity(orgB, "only-b", "only-b@corp.com", "zid-only-b")

	srcA, err := svc.CreateEDRSource(ctx, edrTestOrgID, &EDRSourceInput{
		Name: "org-a-crowdstrike", Provider: "crowdstrike", ClientID: "a", ClientSecret: "a-secret",
		MatchStrategy: "email", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create org A source: %v", err)
	}
	if _, err := svc.CreateEDRSource(ctx, orgB, &EDRSourceInput{
		Name: "org-b-intune", Provider: "intune", ClientID: "b", ClientSecret: "b-secret",
		MatchStrategy: "email", Enabled: true,
	}); err != nil {
		t.Fatalf("create org B source: %v", err)
	}

	t.Run("a device match cannot reach another tenant's identity", func(t *testing.T) {
		got := svc.resolveIdentityForDevice(ctx, srcA, edr.Device{
			ExternalID: "aid-1", Email: "shared@corp.com", Compliant: false,
		})
		if got == identB {
			t.Error("org A's EDR source matched org B's identity. The match named no " +
				"organization, and what it returns is handed to RecordPostureResult -- " +
				"a failing posture result is what revokes the session and severs the " +
				"overlay circuit, so this is a cross-tenant REVOCATION, not a read")
		}
		if got != identA {
			t.Errorf("org A's EDR source resolved %q, want its own identity %q", got, identA)
		}

		// The unambiguous half: an address org A does not have at all.
		if got := svc.resolveIdentityForDevice(ctx, srcA, edr.Device{
			ExternalID: "aid-1b", Email: "only-b@corp.com", Compliant: false,
		}); got != "" {
			t.Errorf("org A's EDR source resolved %q for an address that exists only in "+
				"org B (identity %q). A device org A reports as non-compliant would "+
				"fail the posture check on org B's user and cut their access",
				got, onlyB)
		}
	})

	t.Run("a source with no tenant makes no enforcement decision", func(t *testing.T) {
		orphan := *srcA
		orphan.OrgID = ""
		if got := svc.resolveIdentityForDevice(ctx, &orphan, edr.Device{
			ExternalID: "aid-2", Email: "shared@corp.com",
		}); got != "" {
			t.Errorf("a source with no organization resolved identity %q. The direction "+
				"of this failure matters: the result feeds a posture check, so "+
				"matching nothing is the safe answer and matching anything is not", got)
		}
	})

	t.Run("a source is created with a real tenant, never NULL", func(t *testing.T) {
		var nulls int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM edr_posture_sources WHERE org_id IS NULL`).Scan(&nulls); err != nil {
			t.Fatalf("count: %v", err)
		}
		if nulls != 0 {
			t.Errorf("%d EDR sources were stored with a NULL organization. A NULL-org row "+
				"is invisible to every scoped read once the belt lands: the connection "+
				"keeps polling and stops appearing on the console", nulls)
		}
	})

	t.Run("the source list and the credential are this tenant's", func(t *testing.T) {
		got, err := svc.ListEDRSources(ctx, edrTestOrgID)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].Name != "org-a-crowdstrike" {
			t.Errorf("org A sees %d EDR sources, want exactly its own", len(got))
		}
		wide, err := svc.ListEDRSources(ctx, "")
		if err != nil {
			t.Fatalf("list with no org: %v", err)
		}
		if len(wide) != 0 {
			t.Errorf("an empty organization returned %d EDR sources. The predicate was "+
				"`WHERE (org_id::text=$1 OR $1='')`, so an absent tenant meant every "+
				"tenant", len(wide))
		}

		if _, err := svc.GetEDRSource(ctx, orgB, srcA.ID); err == nil {
			t.Error("org B read org A's EDR connection")
		}
		if err := svc.DeleteEDRSource(ctx, orgB, srcA.ID); err == nil {
			t.Error("org B deleted org A's EDR connection, and its device mappings with it")
		}
		if _, err := svc.GetEDRSource(ctx, edrTestOrgID, srcA.ID); err != nil {
			t.Fatalf("org A lost its own EDR connection: %v", err)
		}
	})

	t.Run("a device mapping carries its source's tenant", func(t *testing.T) {
		svc.upsertEDRMapping(ctx, srcA, edr.Device{
			ExternalID: "aid-3", Email: "shared@corp.com", Compliant: true,
		}, identA)
		var org string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(org_id::text,'<null>') FROM edr_device_mappings WHERE external_device_id = 'aid-3'`).
			Scan(&org); err != nil {
			t.Fatalf("read mapping: %v", err)
		}
		if org != edrTestOrgID {
			t.Errorf("a device mapping carries organization %q; the ingest wrote its "+
				"tenant through edrNullIfEmpty, so a source with no organization "+
				"produced a mapping row no operator could see", org)
		}
	})
}
