# Access and Login Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make application assignment the single grant that drives real reach, collapse the two browser login implementations into one, and turn the MFA rule into a policy — each staged behind a flag that defaults to today's behaviour.

**Architecture:** A new `internal/appaccess` package owns one predicate ("may this principal reach this application?"). Three services consume it: access (Ziti attribute sync, dial-policy reconciler, proxy forward-auth), identity (portal catalogue), oauth (authorize gate). Ziti enforcement rides an existing pattern — a per-app identity attribute plus a per-app dial policy, mirroring the `openidx-orgdial-*` path already in the reconciler.

**Tech Stack:** Go 1.26, gin, pgx/v5, PostgreSQL with RLS, OpenZiti edge management API, React 18 + TanStack Query (admin console), testcontainers-go for DB-backed tests.

**Spec:** `docs/access-and-login-convergence-design.md` (commit `3f4757c0`). Read it first; this plan argues from it.

## Global Constraints

- Migration high-water mark is **v136** in both the tree and the box; this plan adds exactly **v137**. Do not renumber.
- Every behaviour change ships behind a flag defaulting to today's behaviour: `ACCESS_ASSIGNMENT_ENFORCE=false`, `OAUTH_LOGIN_UI=server`, and (for MFA) an empty `mfa_policies` table.
- Ziti role attributes are keyed on the application **UUID**, never its name — the attribute set is wholesale-replaced on every sync, so a rename would silently drop reach.
- Migrations must not contain `DO $$` blocks (the splitter cannot handle them); use plain statements.
- SQL that reads org-scoped tables takes `orgID` as an explicit parameter. `internal/appaccess` never reads `orgctx` itself — callers resolve it.
- Go tests that need Postgres use testcontainers and must skip cleanly when Docker is unavailable, following `internal/portal/device_org_scope_test.go:20`.
- Frontend: `flutter`-style info lints do not apply, but `npx eslint` must stay at 0 errors and `npx vitest run` fully green (currently 928/928).

---

## Phase A — assignment drives reach (report-only)

### Task 1: The shared predicate package

**Files:**
- Create: `internal/appaccess/appaccess.go`
- Create: `internal/appaccess/appaccess_test.go`
- Create: `internal/appaccess/testdb_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `appaccess.AppRef{ID, Name, RouteID string}`; `appaccess.Allowed(ctx context.Context, db *database.PostgresDB, userID, orgID, appID string) (bool, error)`; `appaccess.AppsForUser(ctx context.Context, db *database.PostgresDB, userID, orgID string) ([]AppRef, error)`; `appaccess.PrincipalsForApp(ctx context.Context, db *database.PostgresDB, appID, orgID string) (Principals, error)` where `Principals{UserIDs, GroupIDs []string}`.

- [ ] **Step 1: Write the test DB helper**

Create `internal/appaccess/testdb_test.go`:

```go
package appaccess

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// setupTestDB starts a throwaway Postgres and creates only the tables this
// package reads. It returns (nil, nil) when Docker is unavailable so the suite
// stays green on machines without it — the same contract as
// internal/portal/device_org_scope_test.go:20.
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("docker unavailable, skipping DB-backed test: %v", err)
		return nil, nil
	}
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())

	db, err := database.NewPostgresDB(dsn, zap.NewNop())
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("connect: %v", err)
	}

	schema := []string{
		`CREATE TABLE applications (id UUID PRIMARY KEY, name VARCHAR(255), enabled BOOLEAN,
		    route_id UUID, require_assignment BOOLEAN NOT NULL DEFAULT false, org_id UUID)`,
		`CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_application_assignments (group_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	return db, func() {
		db.Close()
		_ = container.Terminate(ctx)
	}
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/appaccess/appaccess_test.go`:

```go
package appaccess

import (
	"context"
	"testing"
)

const (
	orgID    = "00000000-0000-0000-0000-0000000000a0"
	userID   = "11111111-0000-0000-0000-0000000000a1"
	otherOrg = "00000000-0000-0000-0000-0000000000b0"
	groupID  = "22222222-0000-0000-0000-0000000000a1"
	directID = "33333333-0000-0000-0000-0000000000a1"
	groupApp = "33333333-0000-0000-0000-0000000000a2"
	bothApp  = "33333333-0000-0000-0000-0000000000a3"
	otherApp = "33333333-0000-0000-0000-0000000000a4"
	offApp   = "33333333-0000-0000-0000-0000000000a5"
	routeID  = "44444444-0000-0000-0000-0000000000a1"
)

func TestAllowed(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	stmts := []string{
		`INSERT INTO applications (id, name, enabled, route_id, org_id) VALUES
		   ('` + directID + `','Direct',true,'` + routeID + `','` + orgID + `'),
		   ('` + groupApp + `','ViaGroup',true,NULL,'` + orgID + `'),
		   ('` + bothApp + `','Both',true,NULL,'` + orgID + `'),
		   ('` + otherApp + `','Unassigned',true,NULL,'` + orgID + `'),
		   ('` + offApp + `','Disabled',false,NULL,'` + orgID + `')`,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES
		   ('` + userID + `','` + groupID + `','` + orgID + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES
		   ('` + userID + `','` + directID + `','` + orgID + `'),
		   ('` + userID + `','` + bothApp + `','` + orgID + `'),
		   ('` + userID + `','` + offApp + `','` + orgID + `')`,
		`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES
		   ('` + groupID + `','` + groupApp + `','` + orgID + `'),
		   ('` + groupID + `','` + bothApp + `','` + orgID + `')`,
	}
	for _, s := range stmts {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cases := []struct {
		name  string
		appID string
		org   string
		want  bool
	}{
		{"direct assignment", directID, orgID, true},
		{"group-derived assignment", groupApp, orgID, true},
		{"assigned both ways", bothApp, orgID, true},
		{"unassigned denied", otherApp, orgID, false},
		{"disabled application denied even when assigned", offApp, orgID, false},
		{"other org denied", directID, otherOrg, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Allowed(ctx, db, userID, tc.org, tc.appID)
			if err != nil {
				t.Fatalf("Allowed: %v", err)
			}
			if got != tc.want {
				t.Errorf("Allowed(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}

	apps, err := AppsForUser(ctx, db, userID, orgID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	if len(apps) != 3 {
		t.Fatalf("AppsForUser returned %d apps, want 3 (direct + group + both, deduped, excluding disabled and unassigned)", len(apps))
	}
	var withRoute int
	for _, a := range apps {
		if a.RouteID != "" {
			withRoute++
		}
	}
	if withRoute != 1 {
		t.Errorf("expected exactly one route-linked app, got %d", withRoute)
	}

	p, err := PrincipalsForApp(ctx, db, bothApp, orgID)
	if err != nil {
		t.Fatalf("PrincipalsForApp: %v", err)
	}
	if len(p.UserIDs) != 1 || len(p.GroupIDs) != 1 {
		t.Errorf("PrincipalsForApp = %+v, want 1 user and 1 group", p)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/appaccess/ -run TestAllowed -v`
Expected: FAIL — `undefined: Allowed`, `undefined: AppsForUser`, `undefined: PrincipalsForApp`.

- [ ] **Step 4: Write the implementation**

Create `internal/appaccess/appaccess.go`:

```go
// Package appaccess owns the single question "may this principal reach this
// application?".
//
// It exists because that question used to be answered in several places with
// different SQL: the portal catalogue counted only direct assignments, the
// proxy checked route roles, and the Ziti dial policy granted every enrolled
// identity. Those answers disagreed, so an app could be listed and unreachable
// or reachable and unlisted. Every enforcement point now calls this package.
//
// orgID is an explicit parameter rather than read from orgctx: this package is
// consumed by three services with different context plumbing, and an explicit
// scope is also what makes it testable.
package appaccess

import (
	"context"
	"fmt"

	"github.com/openidx/openidx/internal/common/database"
)

// AppRef is an application the caller may reach. RouteID is empty when the
// application has no published route — those are gated at /oauth/authorize
// instead of on the overlay.
type AppRef struct {
	ID      string
	Name    string
	RouteID string
}

// Principals are the grant holders for one application.
type Principals struct {
	UserIDs  []string
	GroupIDs []string
}

// assignedPredicate matches an application assigned to the user directly OR
// through a group they belong to. $1 = user id, $2 = org id.
const assignedPredicate = `(
	EXISTS (SELECT 1 FROM user_application_assignments uaa
	         WHERE uaa.application_id = a.id AND uaa.user_id = $1 AND uaa.org_id = $2)
	OR EXISTS (SELECT 1 FROM group_application_assignments gaa
	            JOIN group_memberships gm ON gm.group_id = gaa.group_id
	           WHERE gaa.application_id = a.id AND gm.user_id = $1 AND gaa.org_id = $2)
)`

// Allowed reports whether the user may reach the application. A disabled
// application is never reachable, however it is assigned.
func Allowed(ctx context.Context, db *database.PostgresDB, userID, orgID, appID string) (bool, error) {
	if userID == "" || orgID == "" || appID == "" {
		return false, nil
	}
	var ok bool
	err := db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM applications a
			 WHERE a.id = $3 AND a.enabled = true AND a.org_id = $2
			   AND `+assignedPredicate+`
		)`, userID, orgID, appID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("appaccess: allowed: %w", err)
	}
	return ok, nil
}

// AppsForUser lists every application the user may reach, deduped.
func AppsForUser(ctx context.Context, db *database.PostgresDB, userID, orgID string) ([]AppRef, error) {
	if userID == "" || orgID == "" {
		return nil, nil
	}
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT a.id, a.name, COALESCE(a.route_id::text, '')
		  FROM applications a
		 WHERE a.enabled = true AND a.org_id = $2
		   AND `+assignedPredicate+`
		 ORDER BY a.name`, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("appaccess: apps for user: %w", err)
	}
	defer rows.Close()

	out := []AppRef{}
	for rows.Next() {
		var a AppRef
		if err := rows.Scan(&a.ID, &a.Name, &a.RouteID); err != nil {
			return nil, fmt.Errorf("appaccess: scan app: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PrincipalsForApp returns the users and groups granted an application. The
// reconciler uses it to decide which identities a per-app dial policy covers.
func PrincipalsForApp(ctx context.Context, db *database.PostgresDB, appID, orgID string) (Principals, error) {
	var p Principals
	if appID == "" || orgID == "" {
		return p, nil
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT user_id FROM user_application_assignments WHERE application_id = $1 AND org_id = $2`,
		appID, orgID)
	if err != nil {
		return p, fmt.Errorf("appaccess: principals (users): %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return p, fmt.Errorf("appaccess: scan user principal: %w", err)
		}
		p.UserIDs = append(p.UserIDs, id)
	}
	rows.Close()

	rows, err = db.Pool.Query(ctx,
		`SELECT group_id FROM group_application_assignments WHERE application_id = $1 AND org_id = $2`,
		appID, orgID)
	if err != nil {
		return p, fmt.Errorf("appaccess: principals (groups): %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return p, fmt.Errorf("appaccess: scan group principal: %w", err)
		}
		p.GroupIDs = append(p.GroupIDs, id)
	}
	return p, rows.Err()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/appaccess/ -v`
Expected: PASS (or SKIP with "docker unavailable").

- [ ] **Step 6: Commit**

```bash
git add internal/appaccess/
git commit -m "feat(appaccess): one predicate for application reach

Direct or group-derived assignment, org-scoped, disabled apps never reachable.
Every enforcement point will consume this instead of re-implementing the SQL."
```

---

### Task 2: Migration v137 — the per-client gate column

**Files:**
- Create: `internal/migrations/sql_v137.go`
- Modify: `internal/migrations/loader.go` (append to the slice that currently ends at version 136, around `:960-967`)
- Test: `internal/migrations/loader_test.go` (existing suite covers ordering; no new test file)

**Interfaces:**
- Consumes: nothing.
- Produces: column `applications.require_assignment boolean not null default false`.

- [ ] **Step 1: Write the migration**

Create `internal/migrations/sql_v137.go`:

```go
package migrations

// Migration v137 — per-client assignment gate.
//
// Turning application assignment into a real grant needs an enforcement point
// for applications that have no published route: those are reached by getting a
// token for the client, so the gate belongs at /oauth/authorize. It is opt-in
// per client and defaults to false, because a blanket gate on deploy day would
// lock every operator out of first-party clients (admin-console, API Service)
// that have no assignments yet.
var applicationRequireAssignmentUp = `-- Migration 137: per-client assignment gate.
ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS require_assignment BOOLEAN NOT NULL DEFAULT false;
`

var applicationRequireAssignmentDown = `-- Rollback migration 137.
ALTER TABLE applications DROP COLUMN IF EXISTS require_assignment;
`
```

- [ ] **Step 2: Register it**

In `internal/migrations/loader.go`, immediately after the `Version: 136` entry, add:

```go
		{
			Version:     137,
			Name:        "application_require_assignment",
			Description: "Add applications.require_assignment (default false): opt-in gate making /oauth/authorize refuse a token for an application the caller is not assigned. Off by default so first-party clients with no assignments keep working; enforcement is staged separately behind ACCESS_ASSIGNMENT_ENFORCE.",
			UpSQL:       applicationRequireAssignmentUp,
			DownSQL:     applicationRequireAssignmentDown,
		},
```

- [ ] **Step 3: Run the migration suite**

Run: `go test ./internal/migrations/ -count=1`
Expected: PASS — versions contiguous, up/down parse.

- [ ] **Step 4: Commit**

```bash
git add internal/migrations/sql_v137.go internal/migrations/loader.go
git commit -m "feat(migrations): v137 applications.require_assignment

Opt-in per-client gate for the /oauth/authorize assignment check. Default false
so no first-party client is locked out on deploy."
```

---

### Task 3: The staging flag

**Files:**
- Modify: `internal/common/config/config.go` (struct field near `ShowAllAppsWhenUnassigned` at `:267-275`; default near `:751`; env mapping near `:987`)
- Test: `internal/common/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `cfg.AccessAssignmentEnforce bool`, env `ACCESS_ASSIGNMENT_ENFORCE`, default `false`.

- [ ] **Step 1: Write the failing test**

Append to `internal/common/config/config_test.go`:

```go
func TestAccessAssignmentEnforceDefaultsOff(t *testing.T) {
	t.Setenv("ACCESS_ASSIGNMENT_ENFORCE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessAssignmentEnforce {
		t.Error("ACCESS_ASSIGNMENT_ENFORCE must default to false: the first deploy reports, it does not remove access")
	}

	t.Setenv("ACCESS_ASSIGNMENT_ENFORCE", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AccessAssignmentEnforce {
		t.Error("ACCESS_ASSIGNMENT_ENFORCE=true must enable enforcement")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/common/config/ -run TestAccessAssignmentEnforce -v`
Expected: FAIL — `cfg.AccessAssignmentEnforce undefined`.

- [ ] **Step 3: Add the field, default and env mapping**

In the struct, after `ShowAllAppsWhenUnassigned`:

```go
	// AccessAssignmentEnforce turns application assignment from a catalogue into
	// a grant. When false (the default) every enforcement point computes the
	// decision and records a would-be denial without acting on it, so the report
	// can be reviewed before anyone loses reach. See
	// docs/access-and-login-convergence-design.md.
	AccessAssignmentEnforce bool `mapstructure:"access_assignment_enforce"`
```

Next to the other defaults:

```go
	v.SetDefault("access_assignment_enforce", false)
```

In the env map:

```go
		"access_assignment_enforce":           "ACCESS_ASSIGNMENT_ENFORCE",
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/common/config/ -run TestAccessAssignmentEnforce -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/common/config/config.go internal/common/config/config_test.go
git commit -m "feat(config): ACCESS_ASSIGNMENT_ENFORCE, default off

Report-only until explicitly flipped."
```

---

### Task 4: Portal catalogue collapses onto the predicate

**Files:**
- Modify: `internal/portal/service.go` (`GetMyApplications` ~`:123-196`, `GetAccessOverview` app count ~`:352-370`)
- Test: `internal/portal/access_overview_apps_test.go` (exists), `internal/portal/my_applications_test.go` (create)

**Interfaces:**
- Consumes: `appaccess.AppsForUser`.
- Produces: no new exported names; `GetMyApplications` and the overview count now return the same set.

- [ ] **Step 1: Write the failing test**

Create `internal/portal/my_applications_test.go`:

```go
package portal

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestMyApplicationsMatchesOverviewCount pins the catalogue and the count to one
// predicate. They drifted before (#874): the count saw only direct assignments
// while the list also saw group-derived ones, so My Access said "0 apps" while
// My Apps listed them.
func TestMyApplicationsMatchesOverviewCount(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		org   = "00000000-0000-0000-0000-0000000000c0"
		user  = "11111111-0000-0000-0000-0000000000c1"
		group = "22222222-0000-0000-0000-0000000000c1"
		appA  = "33333333-0000-0000-0000-0000000000c1"
		appB  = "33333333-0000-0000-0000-0000000000c2"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	schema := []string{
		`CREATE TABLE applications (id UUID PRIMARY KEY, name VARCHAR(255),
		    description TEXT, base_url VARCHAR(500), protocol VARCHAR(50),
		    enabled BOOLEAN, route_id UUID, org_id UUID)`,
		`CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_application_assignments (group_id UUID, application_id UUID, org_id UUID)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID)`,
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE group_join_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, status VARCHAR(32))`,
		`CREATE TABLE vault_access_grants (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, secret_id UUID, principal_type VARCHAR(32), principal_id UUID, expires_at TIMESTAMPTZ)`,
		`CREATE TABLE vault_checkouts (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, principal_id UUID, status VARCHAR(16))`,
		`CREATE TABLE jit_grants (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, expires_at TIMESTAMPTZ, status VARCHAR(16))`,
		`CREATE TABLE guacamole_sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, user_id UUID, status VARCHAR(16))`,
		`CREATE TABLE guacamole_session_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, requester_id UUID, status VARCHAR(16), expires_at TIMESTAMPTZ)`,
		`CREATE TABLE ziti_identities (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    org_id UUID, user_id UUID, enrolled BOOLEAN)`,
		`CREATE TABLE enrolled_agents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID)`,
		`CREATE TABLE known_devices (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id UUID, org_id UUID, trusted BOOLEAN)`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	seeds := []string{
		`INSERT INTO groups (id, name) VALUES ('` + group + `','Engineering')`,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ('` + user + `','` + group + `','` + org + `')`,
		`INSERT INTO applications (id, name, enabled, org_id) VALUES
		   ('` + appA + `','Direct',true,'` + org + `'),
		   ('` + appB + `','ViaGroup',true,'` + org + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ('` + user + `','` + appA + `','` + org + `')`,
		`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES ('` + group + `','` + appB + `','` + org + `')`,
	}
	for _, stmt := range seeds {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	svc := NewService(db, zap.NewNop())
	apps, err := svc.GetMyApplications(ctx, user)
	if err != nil {
		t.Fatalf("GetMyApplications: %v", err)
	}
	ov, err := svc.GetAccessOverview(ctx, user)
	if err != nil {
		t.Fatalf("GetAccessOverview: %v", err)
	}
	if len(apps) != ov.AppsCount {
		t.Errorf("catalogue lists %d apps but the overview counts %d — they must use one predicate", len(apps), ov.AppsCount)
	}
	if len(apps) != 2 {
		t.Errorf("got %d apps, want 2 (one direct, one group-derived)", len(apps))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/portal/ -run TestMyApplicationsMatchesOverviewCount -v`
Expected: FAIL — the count query and the list query are still separate SQL, and the count omits `route_id`-less group apps only if they diverge; if it passes by luck, the following step still removes the duplication.

- [ ] **Step 3: Route both through the predicate**

In `GetMyApplications`, replace the inline `query` with a call that keeps the returned shape:

```go
	refs, err := appaccess.AppsForUser(ctx, s.db, userID, org.ID)
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 && s.showAllAppsWhenUnassigned {
		return s.allEnabledApplications(ctx, org.ID)
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.ID)
	}
	return s.applicationsByID(ctx, org.ID, ids)
```

Add the two helpers below it:

```go
// applicationsByID hydrates the rows the predicate selected. Splitting the
// predicate (appaccess) from the projection (here) is what stops the catalogue
// and the enforcement drifting: only one of them knows who may reach what.
func (s *Service) applicationsByID(ctx context.Context, orgID string, ids []string) ([]Application, error) {
	if len(ids) == 0 {
		return []Application{}, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, COALESCE(a.description, ''), COALESCE(a.base_url, ''), COALESCE(a.protocol, '')
		  FROM applications a
		 WHERE a.org_id = $1 AND a.id = ANY($2)
		 ORDER BY a.name`, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to query applications by id: %w", err)
	}
	defer rows.Close()
	return scanApplications(rows)
}

// allEnabledApplications is the ShowAllAppsWhenUnassigned fallback, unchanged in
// behaviour: an org that has opted into the open catalogue still gets it.
func (s *Service) allEnabledApplications(ctx context.Context, orgID string) ([]Application, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, COALESCE(a.description, ''), COALESCE(a.base_url, ''), COALESCE(a.protocol, '')
		  FROM applications a
		 WHERE a.enabled = true AND a.org_id = $1
		 ORDER BY a.name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query all applications: %w", err)
	}
	defer rows.Close()
	return scanApplications(rows)
}
```

Extract the existing row-scanning loop from `GetMyApplications` into `scanApplications(rows pgx.Rows) ([]Application, error)` so both helpers share it.

In `GetAccessOverview`, replace the app-count query with:

```go
	appRefs, err := appaccess.AppsForUser(ctx, s.db, userID, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to count apps: %w", err)
	}
	overview.AppsCount = len(appRefs)
```

Add the import `"github.com/openidx/openidx/internal/appaccess"`.

- [ ] **Step 4: Run the portal suite**

Run: `go test ./internal/portal/ -count=1`
Expected: PASS, including the existing `TestGetAccessOverview_AppsCountIncludesGroupAssignments`.

- [ ] **Step 5: Commit**

```bash
git add internal/portal/
git commit -m "refactor(portal): catalogue and count share one predicate

GetMyApplications and GetAccessOverview both call appaccess.AppsForUser, so the
list and the count cannot drift again (#874)."
```

---

### Task 5: Per-app Ziti identity attribute

**Files:**
- Modify: `internal/access/ziti_user_sync.go` (`assembleAttributes` `:319`, `buildUserAttributes` `:265-293`)
- Test: `internal/access/ziti_app_attrs_test.go` (create)

**Interfaces:**
- Consumes: `appaccess.AppsForUser`.
- Produces: `appMarkerAttr(appID string) string` returning `"app-"+appID`; `assembleAttributes(groups []string, deviceTrusted, browzer bool, appAttrs []string) []string`.

- [ ] **Step 1: Write the failing test**

Create `internal/access/ziti_app_attrs_test.go`:

```go
package access

import (
	"strings"
	"testing"
)

// TestAssembleAttributesCarriesAppMarkers: a per-app attribute is how an
// assignment reaches the overlay. The dial policy for an app-backed service
// grants #app-<uuid>, so an identity without the marker cannot dial it.
func TestAssembleAttributesCarriesAppMarkers(t *testing.T) {
	got := assembleAttributes([]string{"Engineering"}, true, false,
		[]string{appMarkerAttr("11111111-2222-3333-4444-555555555555")})

	want := map[string]bool{
		"Engineering":                              true,
		"enrolled-users":                           true,
		"device-trusted":                           true,
		"app-11111111-2222-3333-4444-555555555555": true,
	}
	if len(got) != len(want) {
		t.Fatalf("attributes = %v, want exactly %d entries", got, len(want))
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("unexpected attribute %q", a)
		}
	}
}

// TestAppMarkerUsesTheUUID: the attribute set is wholesale-replaced on every
// sync, so keying on a renameable name would silently drop reach on rename.
func TestAppMarkerUsesTheUUID(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	got := appMarkerAttr(id)
	if got != "app-"+id {
		t.Errorf("appMarkerAttr = %q, want %q", got, "app-"+id)
	}
	if strings.ContainsAny(got, " #") {
		t.Errorf("attribute %q must not contain a space or a leading hash (the hash is added by the policy)", got)
	}
}

// TestAssembleAttributesWithoutApps keeps the pre-existing shape intact for a
// user with no assignments.
func TestAssembleAttributesWithoutApps(t *testing.T) {
	got := assembleAttributes([]string{"Sales"}, false, true, nil)
	if len(got) != 3 {
		t.Fatalf("attributes = %v, want [Sales enrolled-users browzer-users]", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/access/ -run 'TestAssembleAttributes|TestAppMarker' -v`
Expected: FAIL — `too many arguments in call to assembleAttributes`, `undefined: appMarkerAttr`.

- [ ] **Step 3: Extend the assembler**

In `internal/access/ziti_user_sync.go`:

```go
// appMarkerAttr is the identity role attribute that carries an application
// assignment onto the overlay. It is keyed on the application UUID, never its
// name: buildUserAttributes replaces the whole attribute set on every sync, so
// a rename would silently drop the user's reach.
func appMarkerAttr(appID string) string { return "app-" + appID }

func assembleAttributes(groups []string, deviceTrusted, browzer bool, appAttrs []string) []string {
	attrs := make([]string, 0, len(groups)+len(appAttrs)+3)
	attrs = append(attrs, groups...)
	// Every enrolled identity carries #enrolled-users so the Tier-1 dial policy
	// (#enrolled-users -> Tier-1 services) applies to any logged-in user.
	attrs = append(attrs, "enrolled-users")
	if deviceTrusted {
		attrs = append(attrs, "device-trusted")
	}
	if browzer {
		attrs = append(attrs, "browzer-users")
	}
	attrs = append(attrs, appAttrs...)
	return attrs
}
```

In `buildUserAttributes`, replace the `assembleAttributes(groups, hasTrusted, browzer)` call with:

```go
	// Per-app markers: one attribute per route-linked application the user is
	// assigned, so the reconciler's openidx-appdial-* policy can grant exactly
	// those identities. Applications with no route are gated at
	// /oauth/authorize instead and get no attribute.
	var appAttrs []string
	if orgID := zm.userOrgID(ctx, userID); orgID != "" {
		refs, aerr := appaccess.AppsForUser(ctx, zm.db, userID, orgID)
		if aerr != nil {
			zm.logger.Warn("failed to load app assignments for ziti attributes",
				zap.String("user_id", userID), zap.Error(aerr))
		}
		for _, r := range refs {
			if r.RouteID != "" {
				appAttrs = append(appAttrs, appMarkerAttr(r.ID))
			}
		}
	}

	attrs := assembleAttributes(groups, hasTrusted, browzer, appAttrs)
```

Add the import `"github.com/openidx/openidx/internal/appaccess"`. `ZitiManager` already holds `db *database.PostgresDB` (`internal/access/ziti.go:40`), so `zm.db` is the right handle.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/access/ -run 'TestAssembleAttributes|TestAppMarker' -v`
Expected: PASS.

- [ ] **Step 5: Run the whole access package**

Run: `go test ./internal/access/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/access/ziti_user_sync.go internal/access/ziti_app_attrs_test.go
git commit -m "feat(ziti): carry app assignments as identity attributes

One #app-<uuid> per route-linked assigned application, keyed on the uuid because
the attribute set is replaced wholesale on every sync."
```

---

### Task 6: Per-app dial policy

**Files:**
- Modify: `internal/access/ziti_reconciler.go` (`ensurePolicies` `:454-503`)
- Test: `internal/access/ziti_app_policy_test.go` (create)

**Interfaces:**
- Consumes: `appMarkerAttr` (Task 5); `DesiredRoute` gains `ApplicationID string`.
- Produces: dial policy named `openidx-appdial-<service>` granting `#app-<uuid>`.

- [ ] **Step 1: Write the failing test**

Create `internal/access/ziti_app_policy_test.go`:

```go
package access

import "testing"

// TestAppDialPolicyName pins the policy naming so the reconciler upserts rather
// than duplicating, exactly like openidx-orgdial-*.
func TestAppDialPolicyName(t *testing.T) {
	if got := appDialPolicyName("es-dev"); got != "openidx-appdial-es-dev" {
		t.Errorf("appDialPolicyName = %q, want openidx-appdial-es-dev", got)
	}
}

// TestDialIdentityRolesForRoute is the heart of enforcement: while the flag is
// off the blanket grant stays and the per-app grant is added beside it; once on,
// an app-backed service is dialable ONLY by identities carrying its marker.
func TestDialIdentityRolesForRoute(t *testing.T) {
	const appID = "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		name      string
		appID     string
		enforce   bool
		blanket   string
		wantRoles []string
	}{
		{"unlinked route keeps the blanket grant", "", false, "#access-proxy-clients", []string{"#access-proxy-clients"}},
		{"unlinked route keeps it under enforcement too", "", true, "#access-proxy-clients", []string{"#access-proxy-clients"}},
		{"app-backed route in report mode keeps both", appID, false, "#browzer-users", []string{"#browzer-users", "#app-" + appID}},
		{"app-backed route under enforcement drops the blanket grant", appID, true, "#browzer-users", []string{"#app-" + appID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dialIdentityRoles(tc.blanket, tc.appID, tc.enforce)
			if len(got) != len(tc.wantRoles) {
				t.Fatalf("roles = %v, want %v", got, tc.wantRoles)
			}
			for i := range got {
				if got[i] != tc.wantRoles[i] {
					t.Fatalf("roles = %v, want %v", got, tc.wantRoles)
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/access/ -run 'TestAppDialPolicyName|TestDialIdentityRoles' -v`
Expected: FAIL — `undefined: appDialPolicyName`, `undefined: dialIdentityRoles`.

- [ ] **Step 3: Implement the helpers and wire them in**

Add to `internal/access/ziti_reconciler.go`:

```go
func appDialPolicyName(service string) string { return "openidx-appdial-" + service }

// dialIdentityRoles decides who may dial a service.
//
// A route with no application behind it is unchanged — the blanket grant is the
// only thing that can express "any enrolled client". For an app-backed route the
// per-app marker is added beside the blanket grant while enforcement is off (so
// the policy exists and can be inspected before it bites), and REPLACES it once
// enforcement is on — which is the whole point: the blanket grant is what makes
// every enrolled identity able to dial an app they were never assigned.
func dialIdentityRoles(blanket, applicationID string, enforce bool) []string {
	if applicationID == "" {
		return []string{blanket}
	}
	marker := "#" + appMarkerAttr(applicationID)
	if enforce {
		return []string{marker}
	}
	return []string{blanket, marker}
}
```

In `ensurePolicies`, replace the dial policy call with:

```go
	dialRoles := dialIdentityRoles(dialIdentity, d.ApplicationID, rec.assignmentEnforce)
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, dialRoles); err != nil {
		rec.logger.Warn("dial policy converge failed", zap.String("svc", d.ServiceName), zap.Error(err))
	}
```

Add `ApplicationID string` to `DesiredRoute` and populate it where desired routes are built, from `applications.route_id` (`SELECT id FROM applications WHERE route_id = <route id> AND enabled = true`). Add `assignmentEnforce bool` to `ZitiReconciler`, set from `cfg.AccessAssignmentEnforce` at construction.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/access/ -run 'TestAppDialPolicyName|TestDialIdentityRoles' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/ziti_reconciler.go internal/access/ziti_app_policy_test.go
git commit -m "feat(ziti): scope an app-backed service's dial policy to its assignees

Report mode adds #app-<uuid> beside the blanket grant; enforcement replaces it,
which is what stops every enrolled identity dialling an unassigned app."
```

---

### Task 7: The reachability report

**Files:**
- Create: `internal/access/assignment_report.go`
- Create: `internal/access/assignment_report_test.go`
- Modify: `internal/access/service.go` (register `api.GET("/assignment-report", svc.requireAdminRole(), svc.handleAssignmentReport)` beside the other admin routes)

**Interfaces:**
- Consumes: `appaccess.AppsForUser`, `collectZitiPillar`.
- Produces: `GET /api/v1/access/assignment-report` returning `{"entries":[{"user_id","username","application_id","application_name","enforcement_point","reason"}],"summary":{"users":N,"applications":N,"would_deny":N}}`.

- [ ] **Step 1: Write the failing test**

Create `internal/access/assignment_report_test.go`:

```go
package access

import "testing"

// TestReportDiffsReachAgainstAssignment: the report answers "who loses what when
// the flag flips". Ziti reach is structural, not per-request, so it is computed
// as a diff rather than logged on a denial.
func TestReportDiffsReachAgainstAssignment(t *testing.T) {
	reachable := map[string][]string{
		"alice": {"app-es", "app-ng"},
		"bob":   {"app-es"},
	}
	assigned := map[string][]string{
		"alice": {"app-es"},
		"bob":   {},
	}

	got := diffReachability(reachable, assigned)

	if len(got) != 2 {
		t.Fatalf("got %d would-deny entries, want 2 (alice loses app-ng, bob loses app-es): %+v", len(got), got)
	}
	for _, e := range got {
		if e.EnforcementPoint != "ziti" {
			t.Errorf("entry %+v: enforcement point should be ziti", e)
		}
		if e.Reason == "" {
			t.Errorf("entry %+v: reason must say why", e)
		}
		if e.UserID == "alice" && e.ApplicationID != "app-ng" {
			t.Errorf("alice should only lose app-ng, got %q", e.ApplicationID)
		}
		if e.UserID == "bob" && e.ApplicationID != "app-es" {
			t.Errorf("bob should lose app-es, got %q", e.ApplicationID)
		}
	}
}

// TestReportEmptyWhenAssignmentsCoverReach: nothing to report once assignment
// already grants everything currently reachable — the signal that it is safe to
// flip ACCESS_ASSIGNMENT_ENFORCE.
func TestReportEmptyWhenAssignmentsCoverReach(t *testing.T) {
	same := map[string][]string{"alice": {"app-es"}}
	if got := diffReachability(same, same); len(got) != 0 {
		t.Errorf("expected no entries, got %+v", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/access/ -run TestReport -v`
Expected: FAIL — `undefined: diffReachability`.

- [ ] **Step 3: Implement**

Create `internal/access/assignment_report.go`:

```go
package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Assignment report.
//
// Ziti reach is structural: the controller decides at circuit time from policies
// we push, so there is no request our code sees to log a would-be denial on. The
// report therefore diffs what each user can dial today against what assignment
// would grant, which answers the question the flag flip actually raises — who
// loses what.

// ReportEntry is one reach that assignment does not cover.
type ReportEntry struct {
	UserID           string `json:"user_id"`
	Username         string `json:"username"`
	ApplicationID    string `json:"application_id"`
	ApplicationName  string `json:"application_name"`
	EnforcementPoint string `json:"enforcement_point"`
	Reason           string `json:"reason"`
}

// diffReachability returns every (user, application) pair the user can reach
// today but would not be granted by assignment. Both maps are keyed by user id
// and hold application ids. Names are filled in by the caller, which has them.
func diffReachability(reachable, assigned map[string][]string) []ReportEntry {
	out := []ReportEntry{}
	for user, apps := range reachable {
		granted := make(map[string]bool, len(assigned[user]))
		for _, a := range assigned[user] {
			granted[a] = true
		}
		for _, a := range apps {
			if !granted[a] {
				out = append(out, ReportEntry{
					UserID:           user,
					ApplicationID:    a,
					EnforcementPoint: "ziti",
					Reason:           "reachable today via the blanket dial policy, but not assigned",
				})
			}
		}
	}
	return out
}

// handleAssignmentReport answers GET /api/v1/access/assignment-report.
func (s *Service) handleAssignmentReport(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Every user with a synced Ziti identity, with their name for display.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT zi.user_id, COALESCE(u.username, '')
		  FROM ziti_identities zi
		  JOIN users u ON u.id = zi.user_id
		 WHERE zi.org_id = $1`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: user query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	names := map[string]string{}
	userIDs := []string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		names[id] = name
		userIDs = append(userIDs, id)
	}
	rows.Close()

	// serviceApp maps a ziti service name to the application behind it, so the
	// services a user can dial today can be expressed as application ids.
	serviceApp := map[string]appaccess.AppRef{}
	appRows, err := s.db.Pool.Query(ctx, `
		SELECT r.ziti_service_name, a.id, a.name
		  FROM applications a
		  JOIN proxy_routes r ON r.id = a.route_id
		 WHERE a.org_id = $1 AND a.enabled = true AND r.ziti_enabled = true
		   AND COALESCE(r.ziti_service_name, '') <> ''`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: service query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	for appRows.Next() {
		var svc string
		var ref appaccess.AppRef
		if err := appRows.Scan(&svc, &ref.ID, &ref.Name); err != nil {
			continue
		}
		serviceApp[svc] = ref
	}
	appRows.Close()

	reachable := map[string][]string{}
	assigned := map[string][]string{}
	appNames := map[string]string{}
	for _, uid := range userIDs {
		pillar, perr := s.collectZitiPillar(ctx, uid)
		if perr != nil {
			s.logger.Warn("assignment report: pillar failed", zap.String("user_id", uid), zap.Error(perr))
			continue
		}
		for _, svc := range pillar.ReachableServices {
			if ref, ok := serviceApp[svc.Name]; ok {
				reachable[uid] = append(reachable[uid], ref.ID)
				appNames[ref.ID] = ref.Name
			}
		}
		refs, aerr := appaccess.AppsForUser(ctx, s.db, uid, org.ID)
		if aerr != nil {
			s.logger.Warn("assignment report: assignments failed", zap.String("user_id", uid), zap.Error(aerr))
			continue
		}
		for _, r := range refs {
			assigned[uid] = append(assigned[uid], r.ID)
			appNames[r.ID] = r.Name
		}
	}

	entries := diffReachability(reachable, assigned)
	affectedUsers := map[string]bool{}
	affectedApps := map[string]bool{}
	for i := range entries {
		entries[i].Username = names[entries[i].UserID]
		entries[i].ApplicationName = appNames[entries[i].ApplicationID]
		affectedUsers[entries[i].UserID] = true
		affectedApps[entries[i].ApplicationID] = true
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"summary": gin.H{
			"users":        len(affectedUsers),
			"applications": len(affectedApps),
			"would_deny":   len(entries),
		},
	})
}
```

If `collectZitiPillar` has a different receiver or signature than `s.collectZitiPillar(ctx, userID)`, adapt the two call sites — it lives in `internal/access/user_access_map.go:451`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/access/ -run TestReport -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/assignment_report.go internal/access/assignment_report_test.go internal/access/service.go
git commit -m "feat(access): report who loses reach when assignment is enforced

Ziti reach is structural, so the report diffs reachable-today against
assignment-derived rather than logging per-request denials."
```

---

### Task 8: Proxy forward-auth

**Files:**
- Modify: `internal/access/service.go` (`handleProxy` around `:2014-2049`)
- Test: `internal/access/proxy_assignment_test.go` (create)

**Interfaces:**
- Consumes: `appaccess.Allowed`, `cfg.AccessAssignmentEnforce`, `logAuditEvent` (`internal/access/service.go:3055`).
- Produces: no new exported names.

- [ ] **Step 1: Write the failing test**

Create `internal/access/proxy_assignment_test.go`:

```go
package access

import "testing"

// TestProxyAssignmentDecision pins the three-way behaviour: routes with no
// application are untouched, report mode never denies, and enforcement denies an
// unassigned caller. Under enforcement the predicate REPLACES the role/group
// check for app-backed routes — checking both would be the intersect model the
// design rejected.
func TestProxyAssignmentDecision(t *testing.T) {
	cases := []struct {
		name       string
		appID      string
		assigned   bool
		enforce    bool
		legacyOK   bool
		wantAllow  bool
		wantReport bool
	}{
		{"no application, legacy allows", "", false, true, true, true, false},
		{"no application, legacy denies", "", false, true, false, false, false},
		{"app-backed, report mode, unassigned", "app-1", false, false, true, true, true},
		{"app-backed, report mode, assigned", "app-1", true, false, true, true, false},
		{"app-backed, enforced, unassigned", "app-1", false, true, true, false, true},
		{"app-backed, enforced, assigned", "app-1", true, true, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, report := proxyAssignmentDecision(tc.appID, tc.assigned, tc.enforce, tc.legacyOK)
			if allow != tc.wantAllow {
				t.Errorf("allow = %v, want %v", allow, tc.wantAllow)
			}
			if report != tc.wantReport {
				t.Errorf("report = %v, want %v", report, tc.wantReport)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/access/ -run TestProxyAssignmentDecision -v`
Expected: FAIL — `undefined: proxyAssignmentDecision`.

- [ ] **Step 3: Implement and wire in**

Add to `internal/access/service.go`:

```go
// proxyAssignmentDecision returns (allow, recordWouldDeny) for one request.
//
// A route with no application behind it keeps the legacy role/group verdict
// untouched. For an app-backed route the assignment predicate replaces that
// verdict under enforcement; in report mode the request is allowed and the gap
// is recorded so the report shows it before anyone loses access.
func proxyAssignmentDecision(applicationID string, assigned, enforce, legacyAllowed bool) (allow, recordWouldDeny bool) {
	if applicationID == "" {
		return legacyAllowed, false
	}
	if assigned {
		return true, false
	}
	if enforce {
		return false, true
	}
	return true, true
}
```

In `handleProxy`, after the existing role and group checks compute `legacyAllowed`, look up the route's application id, call `appaccess.Allowed`, then:

```go
	allow, wouldDeny := proxyAssignmentDecision(appID, assigned, s.cfg().AccessAssignmentEnforce, legacyAllowed)
	if wouldDeny {
		s.logAuditEvent(c, "access.assignment.would_deny", appID, "application",
			map[string]interface{}{"enforcement_point": "proxy", "user_id": userID, "route": route.Name})
	}
	if !allow {
		c.JSON(http.StatusForbidden, gin.H{"error": "not assigned to this application"})
		return
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/access/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access/service.go internal/access/proxy_assignment_test.go
git commit -m "feat(access): proxy consults assignment for app-backed routes

Replaces the role/group verdict under enforcement, records the gap in report
mode, leaves routes with no application untouched."
```

---

### Task 9: The `/oauth/authorize` gate

**Files:**
- Modify: `internal/oauth/service.go` (`issueAuthorizationCode` ~`:2320`, before the consent check)
- Test: `internal/oauth/authorize_assignment_test.go` (create)

**Interfaces:**
- Consumes: `appaccess.Allowed`, `applications.require_assignment` (Task 2), `cfg.AccessAssignmentEnforce`.
- Produces: no new exported names.

- [ ] **Step 1: Write the failing test**

Create `internal/oauth/authorize_assignment_test.go`:

```go
package oauth

import "testing"

// TestAuthorizeAssignmentDecision: the gate is opt-in per client so deploy one
// cannot lock an operator out of a first-party client that has no assignments.
func TestAuthorizeAssignmentDecision(t *testing.T) {
	cases := []struct {
		name       string
		requires   bool
		assigned   bool
		enforce    bool
		wantIssue  bool
		wantReport bool
	}{
		{"client does not require assignment", false, false, true, true, false},
		{"requires, assigned", true, true, true, true, false},
		{"requires, unassigned, report mode", true, false, false, true, true},
		{"requires, unassigned, enforced", true, false, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issue, report := authorizeAssignmentDecision(tc.requires, tc.assigned, tc.enforce)
			if issue != tc.wantIssue {
				t.Errorf("issue = %v, want %v", issue, tc.wantIssue)
			}
			if report != tc.wantReport {
				t.Errorf("report = %v, want %v", report, tc.wantReport)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/oauth/ -run TestAuthorizeAssignmentDecision -v`
Expected: FAIL — `undefined: authorizeAssignmentDecision`.

- [ ] **Step 3: Implement and wire in**

Add to `internal/oauth/service.go`:

```go
// authorizeAssignmentDecision returns (issueCode, recordWouldDeny) for a client
// whose application row may require assignment. The gate is opt-in per client:
// a client that does not require it is never affected, which is what keeps
// first-party clients working on the first deploy.
func authorizeAssignmentDecision(requiresAssignment, assigned, enforce bool) (issue, recordWouldDeny bool) {
	if !requiresAssignment || assigned {
		return true, false
	}
	if enforce {
		return false, true
	}
	return true, true
}
```

In `issueAuthorizationCode`, before the consent check, load the application row for `oauthParams["client_id"]` (`SELECT id, require_assignment FROM applications WHERE client_id = $1 AND org_id = $2`), call `appaccess.Allowed`, then apply the decision. On a refusal respond `403` with `{"error":"access_denied","error_description":"You are not assigned to this application."}`; on a would-deny log the audit event with `enforcement_point: "oidc"`.

- [ ] **Step 4: Run the oauth suite**

Run: `go test ./internal/oauth/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/service.go internal/oauth/authorize_assignment_test.go
git commit -m "feat(oauth): opt-in assignment gate at /oauth/authorize

Covers applications with no published route, which the overlay cannot gate."
```

---

### Task 10: Console — one grant UI and the report

**Files:**
- Modify: `web/admin-console/src/pages/applications.tsx` (Manage Access dialog: label it as the grant)
- Modify: `web/admin-console/src/pages/proxy-routes.tsx` (make `allowed_roles` / `allowed_groups` read-only for app-backed routes)
- Create: `web/admin-console/src/pages/assignment-report.tsx`
- Modify: `web/admin-console/src/config/navigation.ts`, `web/admin-console/src/App.tsx`, `web/admin-console/src/pages/index.ts`
- Test: `web/admin-console/src/pages/assignment-report.test.tsx`

**Interfaces:**
- Consumes: `GET /api/v1/access/assignment-report` (Task 7).
- Produces: route `/assignment-report`, `minRole: 'admin'`.

- [ ] **Step 1: Write the failing test**

Create `web/admin-console/src/pages/assignment-report.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { AssignmentReportPage } from './assignment-report'

const get = vi.fn()
vi.mock('../lib/api', () => ({ api: { get: (...a: unknown[]) => get(...a) } }))

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <AssignmentReportPage />
      </MemoryRouter>
    </QueryClientProvider>
  )

describe('AssignmentReportPage', () => {
  beforeEach(() => get.mockReset())

  it('lists who would lose which application', async () => {
    get.mockResolvedValue({
      entries: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev', enforcement_point: 'ziti', reason: 'no assignment' },
      ],
      summary: { users: 1, applications: 1, would_deny: 1 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText('mehmet.gungor')).toBeInTheDocument())
    expect(screen.getByText('Es-Dev')).toBeInTheDocument()
  })

  it('says so when enforcing would take nothing away', async () => {
    get.mockResolvedValue({ entries: [], summary: { users: 0, applications: 0, would_deny: 0 } })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no one would lose access/i)).toBeInTheDocument()
    )
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd web/admin-console && npx vitest run src/pages/assignment-report.test.tsx`
Expected: FAIL — cannot resolve `./assignment-report`.

- [ ] **Step 3: Build the page**

Create `web/admin-console/src/pages/assignment-report.tsx`:

```tsx
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface ReportEntry {
  user_id: string
  username: string
  application_id: string
  application_name: string
  enforcement_point: string
  reason: string
}

interface Report {
  entries: ReportEntry[]
  summary: { users: number; applications: number; would_deny: number }
}

/**
 * What enforcing application assignment would take away, before it takes it.
 * Reach over the overlay is granted by a policy, not by a request we can deny
 * and log, so this is a diff: what each user can dial today against what their
 * assignments would grant.
 */
export function AssignmentReportPage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['assignment-report'],
    queryFn: () => api.get<Report>('/api/v1/access/assignment-report'),
  })

  if (isError) return <QueryError error={error} onRetry={() => refetch()} />

  const entries = data?.entries ?? []
  const summary = data?.summary

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Assignment report</h1>
        <p className="text-sm text-muted-foreground">
          Who would lose access when ACCESS_ASSIGNMENT_ENFORCE is turned on.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>
            {isLoading
              ? 'Checking…'
              : entries.length === 0
                ? 'No one would lose access — safe to enforce'
                : `${summary?.users ?? 0} user(s) would lose access to ${summary?.applications ?? 0} application(s)`}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {entries.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Application</TableHead>
                  <TableHead>Enforced at</TableHead>
                  <TableHead>Why</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e) => (
                  <TableRow key={`${e.user_id}-${e.application_id}`}>
                    <TableCell>{e.username || e.user_id}</TableCell>
                    <TableCell>{e.application_name || e.application_id}</TableCell>
                    <TableCell>{e.enforcement_point}</TableCell>
                    <TableCell className="text-muted-foreground">{e.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
```

Then register it: export from `web/admin-console/src/pages/index.ts` as a lazy import matching the file's siblings, add `<Route path="assignment-report" element={<AssignmentReport />} />` in `App.tsx`, and add
`{ name: 'Assignment Report', href: '/assignment-report', icon: ClipboardList, minRole: 'admin', keywords: ['assignment', 'enforcement', 'who loses access'] }`
to the Access group in `config/navigation.ts`.

- [ ] **Step 4: Run the frontend suite and lint**

Run: `cd web/admin-console && npx vitest run && npx eslint src/pages/assignment-report.tsx`
Expected: all tests pass, 0 eslint errors.

- [ ] **Step 5: Commit**

```bash
git add web/admin-console/src
git commit -m "feat(console): assignment report and one grant surface

Manage Access is the grant; app-backed routes show their derived restrictions
read-only; the report shows who loses what before the flag is flipped."
```

---

## Phase C — MFA policy (no behaviour change)

### Task 11: Tests for the dead evaluator

**Files:**
- Test: `internal/identity/mfa_policy_test.go` (create)
- Modify: `internal/identity/service.go` only if a test exposes a defect

**Interfaces:**
- Consumes: `IsMFARequired(ctx, userID, clientIP) (bool, *MFAPolicy, error)` (`internal/identity/service.go:2529`).
- Produces: no new names — this task establishes the safety net before the function gates a login.

- [ ] **Step 1: Write the tests**

Create `internal/identity/mfa_policy_test.go` (the package already has
`setupTestDB` at `internal/identity/testdb_test.go:17`):

```go
package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestIsMFARequired covers the evaluator BEFORE it gates a login. It has never
// executed in production: the admin console has full CRUD over mfa_policies
// while nothing read the result, so every behaviour below is unverified until
// this test says otherwise.
func TestIsMFARequired(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		org  = "00000000-0000-0000-0000-0000000000d0"
		user = "11111111-0000-0000-0000-0000000000d1"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			description TEXT,
			enabled BOOLEAN DEFAULT true,
			priority INTEGER DEFAULT 0,
			conditions JSONB,
			required_methods JSONB,
			grace_period_hours INTEGER DEFAULT 24,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL)`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	// IsMFARequired logs on entry, so a bare &Service{db: db} nil-panics on the
	// logger. Build it the way the package's own tests do
	// (internal/identity/orgscope_test.go:21).
	svc := NewService(db, nil, nil, zap.NewNop())

	t.Run("no policies means not required", func(t *testing.T) {
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required || policy != nil {
			t.Errorf("got (%v, %+v), want (false, nil) — an empty table must not challenge anyone", required, policy)
		}
	})

	t.Run("a disabled policy is ignored", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('off', false, 10, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		required, _, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Error("a disabled policy must not require MFA")
		}
	})

	t.Run("an enabled matching policy requires MFA and is returned", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, grace_period_hours, org_id)
			VALUES ('always', true, 5, '{"factor_enrolled":true}', 12, $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if !required || policy == nil {
			t.Fatalf("got (%v, %+v), want required with the matching policy", required, policy)
		}
		if policy.GracePeriodHours != 12 {
			t.Errorf("grace_period_hours = %d, want 12 — the caller needs it to honour the grace window", policy.GracePeriodHours)
		}
	})

	t.Run("the highest priority policy wins", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('stronger', true, 99, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if policy == nil || policy.Name != "stronger" {
			t.Errorf("got %+v, want the priority-99 policy", policy)
		}
	})

	t.Run("another org's policy does not apply", func(t *testing.T) {
		otherCtx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-0000000000d9"})
		required, _, err := svc.IsMFARequired(otherCtx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Error("policies must not leak across orgs")
		}
	})
}
```

- [ ] **Step 2: Run them**

Run: `go test ./internal/identity/ -run TestIsMFARequired -v`
Expected: some FAIL — this function has never executed. Fix `IsMFARequired` until they pass; record any behaviour change in the commit message.

- [ ] **Step 3: Commit**

```bash
git add internal/identity/mfa_policy_test.go internal/identity/service.go
git commit -m "test(identity): cover IsMFARequired before it gates a login

The evaluator behind mfa_policies has never executed in production; wiring dead
code into an auth path without tests is how you learn its semantics the hard way."
```

---

### Task 12: Condition allowlist

**Files:**
- Modify: `internal/admin/mfa_management.go` (create `:207`, update `:317`)
- Create: `internal/admin/mfa_policy_conditions.go`
- Test: `internal/admin/mfa_policy_conditions_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `validateMFAConditions(raw json.RawMessage) error`, allowing `factor_enrolled` (bool), `min_risk_score` (number), `client_ids` (array of string).

- [ ] **Step 1: Write the failing test**

```go
package admin

import "testing"

func TestValidateMFAConditions(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"factor_enrolled", `{"factor_enrolled":true}`, false},
		{"min_risk_score", `{"min_risk_score":70}`, false},
		{"client_ids", `{"client_ids":["admin-console"]}`, false},
		{"combined", `{"factor_enrolled":true,"client_ids":["a"]}`, false},
		{"empty", `{}`, false},
		// Silently ignoring unknown keys is how this table became decorative:
		// an admin authors a policy, nothing reads the key, nothing happens.
		{"unknown key rejected", `{"require_hardware_token":true}`, true},
		{"wrong type rejected", `{"factor_enrolled":"yes"}`, true},
		{"not an object", `[1,2,3]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMFAConditions([]byte(tc.in))
			if (err != nil) != tc.wantErr {
				t.Errorf("validateMFAConditions(%s) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/admin/ -run TestValidateMFAConditions -v`
Expected: FAIL — `undefined: validateMFAConditions`.

- [ ] **Step 3: Implement and call it from create/update**

```go
package admin

import (
	"encoding/json"
	"fmt"
)

// validateMFAConditions rejects a policy whose conditions this server does not
// evaluate. Accepting unknown keys silently is exactly how mfa_policies became a
// knob that did nothing: the admin authors a condition, no code reads it, and the
// policy appears to be in force while it is not.
func validateMFAConditions(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var conds map[string]any
	if err := json.Unmarshal(raw, &conds); err != nil {
		return fmt.Errorf("conditions must be a JSON object: %w", err)
	}
	for key, val := range conds {
		switch key {
		case "factor_enrolled":
			if _, ok := val.(bool); !ok {
				return fmt.Errorf("condition %q must be a boolean", key)
			}
		case "min_risk_score":
			if _, ok := val.(float64); !ok {
				return fmt.Errorf("condition %q must be a number", key)
			}
		case "client_ids":
			items, ok := val.([]any)
			if !ok {
				return fmt.Errorf("condition %q must be an array of client ids", key)
			}
			for _, it := range items {
				if _, ok := it.(string); !ok {
					return fmt.Errorf("condition %q must contain only strings", key)
				}
			}
		default:
			return fmt.Errorf("unsupported condition %q (supported: factor_enrolled, min_risk_score, client_ids)", key)
		}
	}
	return nil
}
```

Call it in the create and update handlers, returning `400` with the error text.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/admin/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/admin/mfa_policy_conditions.go internal/admin/mfa_policy_conditions_test.go internal/admin/mfa_management.go
git commit -m "feat(admin): reject MFA policy conditions the server cannot evaluate

An unknown condition key is now a 400 instead of a silently-ignored field."
```

---

### Task 13: Wire the policy into the MFA decision

**Files:**
- Modify: `internal/oauth/mfa_policy.go` (`evaluateMFA`)
- Test: `internal/oauth/mfa_policy_test.go` (create)

**Interfaces:**
- Consumes: `identityService.IsMFARequired`.
- Produces: `mfaEvaluation.PolicyRequired bool`; `Challenge` becomes `Enabled && !SkipMFA && (RequireMFA || totpEnabled || PolicyRequired)`.

- [ ] **Step 1: Write the failing test**

```go
package oauth

import "testing"

// TestPolicyOnlyRaisesTheRequirement: a policy may add a challenge, never remove
// one, and with no policy rows the pre-existing rule is untouched — that is what
// makes shipping this a no-op until an admin creates a policy.
func TestPolicyOnlyRaisesTheRequirement(t *testing.T) {
	cases := []struct {
		name          string
		enabled       bool
		skip          bool
		riskRequires  bool
		totpEnabled   bool
		policyRequires bool
		want          bool
	}{
		{"no factors, policy requires", false, false, false, false, true, false},
		{"push only, no policy", true, false, false, false, false, false},
		{"push only, policy requires", true, false, false, false, true, true},
		{"totp always challenged", true, false, false, true, false, true},
		{"trusted browser still skips", true, true, false, true, true, false},
		{"risk requires", true, false, true, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := challengeRequired(tc.enabled, tc.skip, tc.riskRequires, tc.totpEnabled, tc.policyRequires)
			if got != tc.want {
				t.Errorf("challengeRequired = %v, want %v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/oauth/ -run TestPolicyOnlyRaises -v`
Expected: FAIL — `undefined: challengeRequired`.

- [ ] **Step 3: Implement**

In `internal/oauth/mfa_policy.go`:

```go
// challengeRequired is the single rule deciding whether a password login must be
// completed with a second factor.
//
// A policy can only RAISE the requirement: it is ORed in, never consulted to
// skip. A user with no enrolled factor is never challenged whatever the policy
// says — requiring a factor from someone who has none is a lockout with extra
// steps; they belong in the enrollment-gap report instead.
func challengeRequired(enabled, skipMFA, riskRequires, totpEnabled, policyRequires bool) bool {
	if !enabled || skipMFA {
		return false
	}
	return riskRequires || totpEnabled || policyRequires
}
```

In `evaluateMFA`, after the risk assessment, set `ev.PolicyRequired` from `IsMFARequired` (log and treat an error as false), then `ev.Challenge = challengeRequired(ev.Enabled, ev.SkipMFA, ev.RequireMFA, totpEnabled, ev.PolicyRequired)`.

- [ ] **Step 4: Run the oauth suite**

Run: `go test ./internal/oauth/ -count=1`
Expected: PASS — with no policy rows the existing tests are unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/mfa_policy.go internal/oauth/mfa_policy_test.go
git commit -m "feat(oauth): let an MFA policy raise the challenge requirement

Wires the previously-dead IsMFARequired into the shared decision. No policy rows
means byte-for-byte today's behaviour."
```

---

## Phase B — one login front end

### Task 14: Redirect every client to the SPA login

**Files:**
- Modify: `internal/oauth/service.go` (`handleAuthorize` around `:1613-1637`)
- Modify: `internal/common/config/config.go` (add `OAuthLoginUI string`, default `"server"`, env `OAUTH_LOGIN_UI`)
- Test: `internal/oauth/authorize_login_ui_test.go` (create)

**Interfaces:**
- Consumes: `cfg.OAuthLoginUI`, `s.issuer`.
- Produces: `loginRedirectURL(issuer, clientRedirectURI, loginSession, ui string) string`.

- [ ] **Step 1: Write the failing test**

```go
package oauth

import (
	"net/url"
	"testing"
)

// TestLoginRedirectURL: in spa mode every client — public, confidential, native
// — goes to the IdP's own login page. That is what lets the server-rendered page
// be deleted: a native client whose redirect_uri is openidx://oauth-callback
// cannot host a login page, which is why the hosted page existed.
func TestLoginRedirectURL(t *testing.T) {
	const issuer = "https://openidx.tdv.org"

	got := loginRedirectURL(issuer, "openidx://oauth-callback", "sess-1", "spa")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	if u.Host != "openidx.tdv.org" || u.Path != "/login" {
		t.Errorf("spa mode must target the issuer's login page, got %q", got)
	}
	if u.Query().Get("login_session") != "sess-1" {
		t.Errorf("login_session missing from %q", got)
	}

	// server mode keeps today's behaviour: back to the client's own page.
	got = loginRedirectURL(issuer, "https://openidx.tdv.org/login", "sess-1", "server")
	if u, _ = url.Parse(got); u.Query().Get("login_session") != "sess-1" || u.Path != "/login" {
		t.Errorf("server mode must preserve the client redirect, got %q", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/oauth/ -run TestLoginRedirectURL -v`
Expected: FAIL — `undefined: loginRedirectURL`.

- [ ] **Step 3: Implement and wire in**

```go
// loginRedirectURL decides where the browser goes to authenticate.
//
// In "spa" mode every client is sent to the IdP's own login page, which is the
// ordinary hosted-IdP pattern and the thing that makes a single login UI
// possible: a native client (redirect_uri openidx://oauth-callback) cannot host
// one, which is why a second, server-rendered login existed at all.
func loginRedirectURL(issuer, clientRedirectURI, loginSession, ui string) string {
	target := clientRedirectURI
	if ui == "spa" {
		target = strings.TrimRight(issuer, "/") + "/login"
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("login_session", loginSession)
	u.RawQuery = q.Encode()
	return u.String()
}
```

In `handleAuthorize`, replace both the `renderLoginPage` branch and the SPA-redirect branch with a single `c.Redirect(302, loginRedirectURL(s.issuer, oauthParams["redirect_uri"], loginSession, s.cfg.OAuthLoginUI))`, keeping `renderLoginPage` reachable only while `OAuthLoginUI == "server"`.

- [ ] **Step 4: Run the oauth suite**

Run: `go test ./internal/oauth/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/service.go internal/common/config/config.go internal/oauth/authorize_login_ui_test.go
git commit -m "feat(oauth): OAUTH_LOGIN_UI=spa sends every client to the IdP login

Default stays server; the flip is one env var and reverts the same way."
```

---

### Task 15: Delete the server-rendered login

**Do not start this task until `OAUTH_LOGIN_UI=spa` has held on the box through a console, mobile and BrowZer sign-in** (see Task 16 step 3). Deleting first removes the fallback.

**Files:**
- Delete: `internal/oauth/hosted_mfa.go`, `internal/oauth/hosted_mfa_test.go`
- Modify: `internal/oauth/service.go` (remove `renderLoginPage`, `renderBrandedPage`, `handleAuthorizeCallback`, the `/oauth/authorize/callback` and `/oauth/authorize/mfa*` routes, and the `OAuthLoginUI` branch)
- Modify: `internal/common/middleware/ratelimit.go` (remove `/oauth/authorize/mfa` from `authPaths` and `/oauth/authorize/mfa/wait` from `pollPaths`)
- Modify: `internal/common/config/config.go` (remove `OAuthLoginUI`)

**Interfaces:**
- Consumes: nothing.
- Produces: removal only. `evaluateMFA`, `createMFASession` and `verifyStepUpFactor` survive with a single consumer.

- [ ] **Step 1: Delete and build**

```bash
git rm internal/oauth/hosted_mfa.go internal/oauth/hosted_mfa_test.go
go build ./...
```

Fix every compile error by removing the dead references; do not reintroduce a caller.

- [ ] **Step 2: Verify nothing references the removed routes**

Run: `grep -rn "authorize/callback\|authorize/mfa\|renderLoginPage\|renderBrandedPage" --include=*.go --include=*.ts --include=*.tsx . | grep -v _test`
Expected: no output.

- [ ] **Step 3: Run the full suite**

Run: `go test ./internal/oauth/ ./internal/common/middleware/ -count=1`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add -A internal/oauth internal/common
git commit -m "refactor(oauth): delete the server-rendered login

One login UI. evaluateMFA, createMFASession and verifyStepUpFactor survive with
a single consumer; the divergence that produced #873 is gone."
```

---

### Task 16: Rollout

**Files:** none — this task is the staged flip, in this order.

- [ ] **Step 1: Deploy phases A and C (no behaviour change).** Build and install `oidx-{access,identity,oauth}-service` from main with rollback copies, apply migration v137, restart. Verify: all seven `/health` endpoints `up`, `GET /api/v1/access/my/ziti/services` unchanged for `mehmet.gungor`, `openidx-appdial-*` policies present beside the blanket ones in the Ziti controller, and no `mfa_policies` rows.

- [ ] **Step 2: Review the report.** Open `/assignment-report`, create the assignments you actually want, and re-check until the entries you care about are gone. The report is only a go/no-go signal when its `reachability_source` is `controller` and `incomplete_users` is 0 — the page says so in place of the headline otherwise. An "unavailable" report means the Ziti controller could not be read, NOT that nobody would lose access; do not proceed to step 5 on one.

- [ ] **Step 3: Flip the login UI.** Set `OAUTH_LOGIN_UI=spa`, restart oauth, then sign in through the console, the mobile client and BrowZer. BrowZer is the one to watch: it bootstraps its own OIDC dance from `browzer.tdv.org`, so verify the cross-origin bounce to `openidx.tdv.org/login` and back lands on `browzer.tdv.org/auth/callback` with a working code. Revert the env var if any flow fails.

- [ ] **Step 4: Execute Task 15** once step 3 has held.

- [ ] **Step 5: Enforce assignment.** Set `ACCESS_ASSIGNMENT_ENFORCE=true`, restart access and oauth. Verify a user with no assignment to `Es-Dev` can no longer dial it and the audit trail records the denial.

- [ ] **Step 6: Create the MFA policy.** Confirm a push challenge can actually be approved on your device first, then create a policy with `{"factor_enrolled": true}` and verify a push-only account is challenged and can complete. Users with no enrolled factor are unaffected by the policy (see Task 13) — find them on the MFA Management page, which already reports enrollment (`handleMFAEnrollmentStats`, `internal/admin/mfa_management.go:70`), and chase enrollment there rather than by tightening the rule.
