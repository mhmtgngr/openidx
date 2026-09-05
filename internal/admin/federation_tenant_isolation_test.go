package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the federation configuration, migration v155.
//
// A federation_rules row maps an email domain to the identity provider that
// authenticates it — the row that decides where someone typing their address
// is sent to sign in. custom_claims_mappings decides what an application is
// told about whoever signed in.
//
// THE LIST WAS THE FINDING. The two reads of federation_rules are the same
// query one word apart. The login path uses an inner join:
//
//	FROM federation_rules fr
//	JOIN identity_providers ip ON fr.provider_id = ip.id AND ip.org_id = $2
//
// and the admin list used a LEFT JOIN of exactly that clause. A left join keeps
// every row of the left table and nulls the right side, so `ip.org_id = $1`
// filtered nothing: the list returned every organization's rules, with
// COALESCE(ip.name,”) rendering the foreign ones' provider as an empty string.
// A join is a tenant predicate only when failing it removes the row.
//
// The harness connects as the container superuser, which bypasses RLS, so what
// these prove is the explicit org predicate in every query. The FORCE RLS belt
// is proven separately in test/integration/cross_org_test.go under a
// NOSUPERUSER NOBYPASSRLS role.
func TestFederationConfig_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
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
		`INSERT INTO organizations (name, slug) VALUES ('fed-b','fed-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	s := &Service{db: db, logger: zap.NewNop()}

	// Both organizations federate to the SAME issuer, deliberately. Until v155
	// the base schema's `issuer_url VARCHAR(255) UNIQUE NOT NULL` made that
	// impossible: identity_providers carries org_id and is ENABLE + FORCE
	// row-level-secured and sits on no register, and two tenants still could
	// not both point at https://accounts.google.com. This seeding is what
	// found it.
	const sharedIssuer = "https://shared-idp.example.test"
	seedProvider := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO identity_providers (org_id, name, provider_type, issuer_url, client_id, client_secret)
			VALUES ($1::uuid, $2, 'oidc', $3, $4, 'x') RETURNING id::text`,
			org, name+"-"+suffix, sharedIssuer, name+"-cid-"+suffix).Scan(&id); err != nil {
			t.Fatalf("seed provider %s: %v. Two organizations must be able to federate "+
				"to one issuer -- both tenants on the same Entra common endpoint, or "+
				"simply both using Google -- and until v155 the second one could not",
				name, err)
		}
		return id
	}
	seedApp := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO applications (org_id, name, client_id, type)
			VALUES ($1::uuid, $2, $3, 'web') RETURNING id::text`,
			org, name+"-"+suffix, name+"-cid-"+suffix).Scan(&id); err != nil {
			t.Fatalf("seed application %s: %v", name, err)
		}
		return id
	}

	providerA := seedProvider(orgA, "fed-a-idp")
	providerB := seedProvider(orgB, "fed-b-idp")
	appA := seedApp(orgA, "fed-a-app")

	domainA := "a-" + suffix + ".example.test"
	var ruleA string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO federation_rules (name, email_domain, provider_id, enabled, org_id)
		VALUES ($1, $2, $3::uuid, true, $4::uuid) RETURNING id::text`,
		"fed-a-rule-"+suffix, domainA, providerA, orgA).Scan(&ruleA); err != nil {
		t.Fatalf("seed org A rule: %v", err)
	}

	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", "00000000-0000-0000-0000-0000000000a1")
		c.Params = params
		handler(c)
		return w
	}

	// THE LEFT JOIN. One word, and the whole list crosses the boundary.
	t.Run("the rule list is scoped by a WHERE clause, not decorated by a join", func(t *testing.T) {
		domainB := "b-" + suffix + ".example.test"
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO federation_rules (name, email_domain, provider_id, enabled, org_id)
			VALUES ($1, $2, $3::uuid, true, $4::uuid)`,
			"fed-b-rule-"+suffix, domainB, providerB, orgB); err != nil {
			t.Fatalf("seed org B rule: %v", err)
		}

		domains := func(org string) map[string]bool {
			t.Helper()
			w := call(s.handleListFederationRules, org, "GET", "/federation-rules", "", nil)
			if w.Code != 200 {
				t.Fatalf("list as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var resp struct {
				Data []FederationRule `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			out := map[string]bool{}
			for _, r := range resp.Data {
				out[r.EmailDomain] = true
			}
			return out
		}
		gotA, gotB := domains(orgA), domains(orgB)

		if gotB[domainA] {
			t.Error("org B's federation-rule list included org A's rule. The tenant " +
				"condition was in a LEFT JOIN's ON clause, where it nulls the " +
				"provider name instead of dropping the row")
		}
		if gotA[domainB] {
			t.Error("org A's federation-rule list included org B's rule")
		}
		if !gotA[domainA] || !gotB[domainB] {
			t.Error("a tenant lost its own federation rule: the predicate must scope " +
				"the read, not empty it")
		}
	})

	// THE DOMAIN SQUAT. Before v155 email_domain was globally UNIQUE, so the
	// first organization to register a domain owned it for the installation.
	t.Run("two organizations can hold the same email domain", func(t *testing.T) {
		w := call(s.handleCreateFederationRule, orgB, "POST", "/federation-rules",
			fmt.Sprintf(`{"name":"fed-b-dup-%s","email_domain":%q,"provider_id":%q,"enabled":true}`,
				suffix, domainA, providerB), nil)
		if w.Code != 201 {
			t.Fatalf("org B could not register a domain org A already holds: status %d, body %s. "+
				"email_domain was UNIQUE across the whole installation, so whoever "+
				"registered a domain first owned it everywhere and the next tenant "+
				"got an unexplained failure", w.Code, w.Body.String())
		}

		// And the second attempt inside ONE organization is still refused, with
		// a message rather than a bare 500.
		dup := call(s.handleCreateFederationRule, orgB, "POST", "/federation-rules",
			fmt.Sprintf(`{"name":"fed-b-dup2-%s","email_domain":%q,"provider_id":%q,"enabled":true}`,
				suffix, domainA, providerB), nil)
		if dup.Code != 400 {
			t.Errorf("a duplicate domain within one organization returned %d, expected 400: %s",
				dup.Code, dup.Body.String())
		}
	})

	// THE FOREIGN PROVIDER. A rule names who authenticates a domain.
	t.Run("a rule cannot name another tenant's identity provider", func(t *testing.T) {
		w := call(s.handleCreateFederationRule, orgB, "POST", "/federation-rules",
			fmt.Sprintf(`{"name":"fed-b-steal-%s","email_domain":"steal-%s.example.test","provider_id":%q,"enabled":true}`,
				suffix, suffix, providerA), nil)
		if w.Code == 201 {
			t.Fatal("org B created a federation rule pointing at org A's identity provider")
		}
	})

	// THE RE-POINT and THE REMOVAL.
	t.Run("another tenant cannot re-point or delete the rule", func(t *testing.T) {
		up := call(s.handleUpdateFederationRule, orgB, "PUT", "/federation-rules/"+ruleA,
			`{"enabled":false}`, gin.Params{{Key: "id", Value: ruleA}})
		if up.Code == 200 {
			t.Error("org B disabled org A's federation rule; the domain would quietly " +
				"stop being federated and its users fall back to a password prompt")
		}

		del := call(s.handleDeleteFederationRule, orgB, "DELETE", "/federation-rules/"+ruleA, "",
			gin.Params{{Key: "id", Value: ruleA}})
		if del.Code == 200 {
			t.Error("org B deleted org A's federation rule")
		}

		var enabled bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT enabled FROM federation_rules WHERE id = $1::uuid`, ruleA).Scan(&enabled); err != nil {
			t.Fatalf("org A's rule is gone: %v", err)
		}
		if !enabled {
			t.Fatal("org A's federation rule was disabled by org B")
		}
	})

	// THE CLAIM MAPPINGS. Currently harmless only because nothing reads them.
	t.Run("another tenant cannot touch the claim mappings on an application", func(t *testing.T) {
		var claimA string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO custom_claims_mappings (application_id, claim_name, source_type, source_value, enabled, org_id)
			VALUES ($1::uuid, 'dept', 'user_attribute', 'department', true, $2::uuid) RETURNING id::text`,
			appA, orgA).Scan(&claimA); err != nil {
			t.Fatalf("seed org A claim: %v", err)
		}

		listB := call(s.handleListCustomClaims, orgB, "GET", "/applications/"+appA+"/claims", "",
			gin.Params{{Key: "id", Value: appA}})
		if listB.Code == 200 {
			var resp struct {
				Data []CustomClaimMapping `json:"data"`
			}
			if err := json.Unmarshal(listB.Body.Bytes(), &resp); err == nil && len(resp.Data) != 0 {
				t.Errorf("org B read %d claim mapping(s) on org A's application", len(resp.Data))
			}
		}

		createB := call(s.handleCreateCustomClaim, orgB, "POST", "/applications/"+appA+"/claims",
			`{"claim_name":"injected","source_type":"literal","source_value":"admin","enabled":true}`,
			gin.Params{{Key: "id", Value: appA}})
		if createB.Code == 201 {
			t.Error("org B attached a claim mapping to org A's application. Nothing reads " +
				"these rows today, which is the only reason this is not an " +
				"identity-forgery primitive")
		}

		delB := call(s.handleDeleteCustomClaim, orgB, "DELETE", "/claims/"+claimA, "",
			gin.Params{{Key: "claimId", Value: claimA}})
		if delB.Code == 200 {
			t.Error("org B deleted a claim mapping on org A's application")
		}

		// The owner still sees its own.
		listA := call(s.handleListCustomClaims, orgA, "GET", "/applications/"+appA+"/claims", "",
			gin.Params{{Key: "id", Value: appA}})
		if listA.Code != 200 {
			t.Fatalf("list claims as org A: status %d, body %s", listA.Code, listA.Body.String())
		}
		var own struct {
			Data []CustomClaimMapping `json:"data"`
		}
		if err := json.Unmarshal(listA.Body.Bytes(), &own); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(own.Data) != 1 {
			t.Fatalf("org A saw %d of its own claim mappings, expected 1", len(own.Data))
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal, not an unfiltered list", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/federation-rules", nil) // bare context
		c.Set("roles", []string{"admin"})
		s.handleListFederationRules(c)
		if w.Code != 403 {
			t.Fatalf("listing federation rules with no organization returned %d: %s",
				w.Code, w.Body.String())
		}
	})
}
