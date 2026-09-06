package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// dcrTestOtherOrg is a second tenant on the same installation.
const dcrTestOtherOrg = "66666666-0000-0000-0000-00000000000f"

const dcrTokenSchema = `
CREATE TABLE IF NOT EXISTS oauth_registration_tokens (
    client_id   VARCHAR(255) PRIMARY KEY,
    token_hash  VARCHAR(64) NOT NULL,
    org_id      UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW());`

// TestRegistrationTokenCarriesItsTenant is the assertion v170 exists for.
//
// v97 gave oauth_registration_tokens an org_id and NOTHING EVER WROTE IT: the
// one INSERT named (client_id, token_hash, created_at), so every row on every
// installation carried a NULL tenant. The orgscope register said to belt the
// table — and belting it in that state would have made every row invisible to
// a scoped read, so registrationTokenValid would have found no hash for any
// client and every RFC 7592 management call
//
//	GET / PUT / DELETE /oauth/register/{client_id}
//
// would have answered 401 with a perfectly valid credential in hand. The column
// had to be filled before it could be enforced.
//
// This pins both halves: the write carries the tenant, and the read matches on
// it. Reverting either one fails here rather than in production.
func TestRegistrationTokenCarriesItsTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, dcrTokenSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	s := &Service{db: db, logger: zap.NewNop()}

	const clientID = "dcr-tenant-client"
	token, hash := newRegistrationToken()

	orgACtx := orgctx.With(ctx, orgctx.Org{ID: deviceTestOrg})
	if err := s.storeRegistrationToken(orgACtx, clientID, hash); err != nil {
		t.Fatalf("storeRegistrationToken: %v", err)
	}

	t.Run("the stored row carries the tenant", func(t *testing.T) {
		var org string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(org_id::text,'') FROM oauth_registration_tokens WHERE client_id = $1`,
			clientID).Scan(&org); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if org != deviceTestOrg {
			t.Fatalf("registration token stored with org %q, want %q. A row with no tenant "+
				"is invisible under the belt, so every management call for this client "+
				"would answer 401 with a valid credential", org, deviceTestOrg)
		}
	})

	// asOrg builds a management request carrying the bearer token and a tenant.
	asOrg := func(orgID, bearer string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/oauth/register/"+clientID, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
		c.Request = req
		return c
	}

	t.Run("the owning tenant validates", func(t *testing.T) {
		if !s.registrationTokenValid(asOrg(deviceTestOrg, token), clientID) {
			t.Error("the tenant that registered the client cannot validate its own " +
				"registration access token — RFC 7592 management is broken")
		}
	})

	t.Run("another tenant does not", func(t *testing.T) {
		if s.registrationTokenValid(asOrg(dcrTestOtherOrg, token), clientID) {
			t.Error("another tenant validated this registration access token")
		}
	})

	t.Run("a request with no tenant does not", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/oauth/register/"+clientID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		c.Request = req
		if s.registrationTokenValid(c, clientID) {
			t.Error("a request carrying no organization validated a registration token")
		}
	})

	t.Run("a wrong token does not", func(t *testing.T) {
		other, _ := newRegistrationToken()
		if s.registrationTokenValid(asOrg(deviceTestOrg, other), clientID) {
			t.Error("a token that was never stored validated")
		}
	})
}

// TestDeviceCodeClaimIsTenantScoped covers the redemption update, which took a
// row id and nothing else. The id came off a record loadDeviceCodeByHash had
// already fetched WITH the tenant, so this was bounded rather than open — but a
// claim is what mints the token, and it now names the organization itself so it
// keeps holding under an explicit RLS bypass.
func TestDeviceCodeClaimIsTenantScoped(t *testing.T) {
	s, ctx := deviceTestService(t)
	id := seedDeviceCode(t, s, ctx, "ACDEFGHQ", "approved", 10*time.Minute)
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE oauth_device_codes SET user_id = $2 WHERE id = $1`, id, deviceTestUser); err != nil {
		t.Fatal(err)
	}

	if _, err := s.claimApprovedDeviceCode(ctx, id, dcrTestOtherOrg); err == nil {
		t.Fatal("another tenant redeemed this device authorization: the claim would " +
			"have minted a token for a subject in an organization it does not belong to")
	}

	user, err := s.claimApprovedDeviceCode(ctx, id, deviceTestOrg)
	if err != nil {
		t.Fatalf("the owning tenant could not redeem its own device code: %v", err)
	}
	if user != deviceTestUser {
		t.Errorf("redeemed for %q, want %q", user, deviceTestUser)
	}
}
