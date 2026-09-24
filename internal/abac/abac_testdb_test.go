package abac

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// abacTestDB returns a database migrated to the latest schema.
//
// OPENIDX_TEST_DATABASE_URL, when set, points the harness at an existing
// server instead of starting a container, the same escape hatch
// internal/admin and internal/access carry. The public schema is DROPPED and
// rebuilt on that path, so point it at a scratch database and run one package
// at a time. CI does not set it and uses a throwaway container.
func abacTestDB(t *testing.T) *database.PostgresDB {
	t.Helper()
	ctx := context.Background()

	var db *database.PostgresDB
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		var err error
		if db, err = database.NewPostgres(url); err != nil {
			t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
			if _, err := db.Pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("reset test schema (%s): %v", stmt, err)
			}
		}
	} else {
		req := testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60 * time.Second),
		}
		container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
			return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: req,
				Started:          true,
			})
		})
		t.Cleanup(func() { _ = container.Terminate(context.Background()) })
		host, err := container.Host(ctx)
		if err != nil {
			t.Skipf("container host: %v", err)
		}
		port, err := container.MappedPort(ctx, "5432")
		if err != nil {
			t.Skipf("container port: %v", err)
		}
		if db, err = database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"); err != nil {
			t.Skipf("connect: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
	}

	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	return db
}

// The ABAC row of docs/evidence/display-equals-enforcement.md, at the
// evaluator, against the real schema.
//
// Every earlier test of this package ran without a database, which is how the
// evaluator's query shipped unable to run at all: it compared a uuid column
// with the empty string, PostgreSQL refused the statement at plan time, and
// every call fell into "policy evaluation error, failing closed" (see the
// comment in Evaluate). This test runs the statement the product runs, over
// the tables SubjectAttributes reads, so both halves are real: a policy
// refuses the subject it names, and leaves everyone else alone.
func TestEvaluateAgainstTheMigratedSchema(t *testing.T) {
	db := abacTestDB(t)
	ctx := context.Background()

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('abac-b', 'abac-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name, department string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, department, enabled)
			VALUES ($1::uuid, $2, $3, $4, true) RETURNING id::text`,
			orgA, name+"-"+suffix, name+"-"+suffix+"@example.test", department).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	engineer := seedUser("abac-engineer", "Engineering")
	contractor := seedUser("abac-contractor", "Contractors")
	suspended := seedUser("abac-suspended", "Engineering")

	var suspendedRole string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		orgA, "suspended-"+suffix).Scan(&suspendedRole); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		suspended, suspendedRole, orgA); err != nil {
		t.Fatalf("seed role membership: %v", err)
	}

	payroll, wiki := uuid.NewString(), uuid.NewString()
	seedPolicy := func(org, name, effect string, resourceID *string, priority int, enabled bool, conditions []Condition) string {
		t.Helper()
		conds, err := json.Marshal(conditions)
		if err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO abac_policies (org_id, name, resource_type, resource_id, conditions, effect, priority, enabled)
			VALUES ($1::uuid, $2, 'application', $3::uuid, $4::jsonb, $5, $6, $7) RETURNING id::text`,
			org, name, resourceID, conds, effect, priority, enabled).Scan(&id); err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
		return id
	}
	contractorsOffPayroll := seedPolicy(orgA, "contractors off payroll", "deny", &payroll, 10, true,
		[]Condition{{Attribute: "department", Operator: "eq", Value: "Contractors"}})
	suspendedEverywhere := seedPolicy(orgA, "suspended nowhere", "deny", nil, 5, true,
		[]Condition{{Attribute: "roles", Operator: "in", Value: []string{"suspended-" + suffix}}})
	engineersOnWiki := seedPolicy(orgA, "engineers on the wiki", "allow", &wiki, 50, true,
		[]Condition{{Attribute: "department", Operator: "eq", Value: "Engineering"}})
	// Two policies that must never decide anything for org A.
	seedPolicy(orgA, "disabled blanket deny", "deny", nil, 100, false, nil)
	seedPolicy(orgB, "another tenant's blanket deny", "deny", nil, 100, true, nil)

	evaluate := func(userID, appID string) Result {
		t.Helper()
		attrs, err := SubjectAttributes(ctx, db, userID, orgA)
		if err != nil {
			t.Fatalf("subject attributes for %s: %v", userID, err)
		}
		return Evaluate(ctx, db, orgA, EvaluationRequest{
			UserAttributes: attrs,
			ResourceType:   ResourceTypeApplication,
			ResourceID:     appID,
		})
	}

	// THE NEGATIVE HALF: the policy refuses the subject it names.
	t.Run("a deny policy refuses the subject its conditions name", func(t *testing.T) {
		res := evaluate(contractor, payroll)
		if res.Allowed || !res.Matched || res.PolicyID != contractorsOffPayroll {
			t.Fatalf("contractor on payroll: %+v, want denied by %s", res, contractorsOffPayroll)
		}
	})
	t.Run("a deny on no particular application applies to every application", func(t *testing.T) {
		for _, app := range []string{payroll, wiki, uuid.NewString()} {
			res := evaluate(suspended, app)
			if res.Allowed || res.PolicyID != suspendedEverywhere {
				t.Fatalf("suspended user on %s: %+v, want denied by %s", app, res, suspendedEverywhere)
			}
		}
	})
	t.Run("deny beats a matching allow of higher priority", func(t *testing.T) {
		// The suspended user is also in Engineering, so the wiki allow matches.
		res := evaluate(suspended, wiki)
		if res.Allowed || res.PolicyID != suspendedEverywhere {
			t.Fatalf("got %+v, want the deny to win", res)
		}
	})

	// THE POSITIVE HALF: everyone the policies do not name is left alone.
	t.Run("a subject no policy names is allowed, and the query ran", func(t *testing.T) {
		// Also proves the disabled blanket deny and the other tenant's blanket
		// deny were not selected: either would refuse the engineer.
		res := evaluate(engineer, payroll)
		if !res.Allowed || res.Matched || res.Reason != "no matching policies" {
			t.Fatalf("engineer on payroll: %+v, want allowed with no match", res)
		}
	})
	t.Run("an application-specific deny leaves other applications alone", func(t *testing.T) {
		res := evaluate(contractor, wiki)
		if !res.Allowed {
			t.Fatalf("contractor on the wiki: %+v, want allowed", res)
		}
	})
	t.Run("a matching allow is reported as the deciding policy", func(t *testing.T) {
		res := evaluate(engineer, wiki)
		if !res.Allowed || !res.Matched || res.PolicyID != engineersOnWiki {
			t.Fatalf("engineer on the wiki: %+v, want allowed by %s", res, engineersOnWiki)
		}
	})

	// The staging contract over the real evaluation.
	t.Run("observe permits and records, enforce refuses and records", func(t *testing.T) {
		attrs, err := SubjectAttributes(ctx, db, contractor, orgA)
		if err != nil {
			t.Fatal(err)
		}
		req := EvaluationRequest{UserAttributes: attrs, ResourceType: ResourceTypeApplication, ResourceID: payroll}
		if allow, wouldDeny, _ := Gate(ctx, db, orgA, ModeObserve, req); !allow || !wouldDeny {
			t.Fatalf("observe: allow=%v wouldDeny=%v, want true/true", allow, wouldDeny)
		}
		if allow, wouldDeny, _ := Gate(ctx, db, orgA, ModeEnforce, req); allow || !wouldDeny {
			t.Fatalf("enforce: allow=%v wouldDeny=%v, want false/true", allow, wouldDeny)
		}
		if allow, wouldDeny, _ := Gate(ctx, db, orgA, ModeOff, req); !allow || wouldDeny {
			t.Fatalf("off: allow=%v wouldDeny=%v, want true/false", allow, wouldDeny)
		}
	})
}
