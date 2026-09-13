package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// keysetIndexDDL returns v190's own UpSQL, looked up in the registry rather
// than copied here: a copy would keep passing after the shipped index changed.
func keysetIndexDDL(t *testing.T) string {
	t.Helper()
	for _, m := range migrations.All() {
		if m.Version == 190 {
			return m.UpSQL
		}
	}
	t.Fatal("migration 190 (the audit keyset index) is not in the registry")
	return ""
}

// setupKeysetTestDB gives the keyset tests a database. An env DSN first so a
// developer (and a CI job that already has a Postgres service) can run these
// without a container runtime; a throwaway container otherwise.
func setupKeysetTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	if dsn := os.Getenv("TEST_POSTGRES_DSN"); dsn != "" {
		db, err := database.NewPostgres(dsn)
		if err != nil {
			t.Skipf("TEST_POSTGRES_DSN set but unreachable: %v", err)
		}
		return db, func() { db.Close() }
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req, Started: true,
		})
	})
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container port: %v", err)
	}
	db, err := database.NewPostgres(fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port()))
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
	}
	return db, func() { db.Close(); container.Terminate(context.Background()) }
}

const keysetOrgA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

// seedKeysetEvents creates the table (the shape sql.go ships plus the v190
// index) and fills it with n events for orgA -- deliberately including a run of
// rows that share ONE timestamp, because that tie is the case the ordering has
// to survive.
func seedKeysetEvents(t *testing.T, db *database.PostgresDB, n, tied int) *Service {
	t.Helper()
	ctx := context.Background()
	tbl := "audit_events"

	_, err := db.Pool.Exec(ctx, `
		DROP TABLE IF EXISTS `+tbl+`;
		CREATE TABLE `+tbl+` (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			event_type VARCHAR(100) NOT NULL,
			category VARCHAR(50) NOT NULL,
			action VARCHAR(255) NOT NULL,
			outcome VARCHAR(50) NOT NULL,
			actor_id VARCHAR(255), actor_type VARCHAR(50), actor_ip VARCHAR(45),
			target_id VARCHAR(255), target_type VARCHAR(100), resource_id VARCHAR(255),
			details JSONB, session_id VARCHAR(255), request_id VARCHAR(255)
		);`)
	require.NoError(t, err)
	// v190's index, from the registry so it cannot drift from what ships.
	_, err = db.Pool.Exec(ctx, keysetIndexDDL(t))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+tbl) })

	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if i < tied {
			// The burst: identical timestamp, to the nanosecond.
			ts = base
		}
		_, err := db.Pool.Exec(ctx, `
			INSERT INTO `+tbl+` (org_id, timestamp, event_type, category, action, outcome)
			VALUES ($1, $2, 'authentication', 'auth', $3, 'success')`,
			keysetOrgA, ts, fmt.Sprintf("action-%04d", i))
		require.NoError(t, err)
	}
	// A second tenant's rows, so "every row exactly once" also means "and
	// nobody else's".
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO `+tbl+` (org_id, timestamp, event_type, category, action, outcome)
		VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', $1, 'authentication', 'auth', 'other-tenant', 'success')`, base)
	require.NoError(t, err)

	return &Service{db: db, logger: zap.NewNop()}
}

func keysetCtx() context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: keysetOrgA})
}

// The property the whole change rests on: paging by cursor visits every row
// exactly once, in order, with no duplicate and no gap -- INCLUDING across a
// run of rows that share one timestamp, which is where `ORDER BY timestamp`
// alone stops being a total order.
func TestKeysetPagingVisitsEveryRowExactlyOnce(t *testing.T) {
	db, cleanup := setupKeysetTestDB(t)
	defer cleanup()

	const total, tied, page = 97, 11, 10
	svc := seedKeysetEvents(t, db, total, tied)
	ctx := keysetCtx()

	seen := map[string]int{}
	var order []time.Time
	var cursor *EventCursor
	for pages := 0; ; pages++ {
		require.Less(t, pages, 50, "paging did not terminate; the cursor is not advancing")

		q := &AuditQuery{Limit: page, Cursor: cursor}
		events, count, err := svc.QueryEvents(ctx, q)
		require.NoError(t, err)

		if cursor != nil {
			// The cost half: no COUNT(*) is run on the cursor path.
			assert.Zero(t, count, "the cursor path computed a total; that is the expensive statement this change exists to avoid")
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			seen[e.ID]++
			order = append(order, e.Timestamp)
		}
		if len(events) < page {
			break
		}
		last := events[len(events)-1]
		cursor = &EventCursor{Timestamp: last.Timestamp, ID: last.ID}
	}

	assert.Len(t, seen, total, "paging did not see every row exactly once")
	for id, n := range seen {
		assert.Equal(t, 1, n, "row %s came back %d times", id, n)
	}
	for i := 1; i < len(order); i++ {
		assert.False(t, order[i].After(order[i-1]),
			"page order is not descending at %d: %s after %s", i, order[i], order[i-1])
	}
}

// The other tenant's row must never appear, cursor or not. The cursor adds a
// WHERE clause, and a WHERE clause is exactly the kind of change that can
// quietly displace a tenant predicate.
func TestKeysetPagingStaysInsideTheTenant(t *testing.T) {
	db, cleanup := setupKeysetTestDB(t)
	defer cleanup()

	svc := seedKeysetEvents(t, db, 20, 5)
	ctx := keysetCtx()

	var cursor *EventCursor
	for pages := 0; pages < 10; pages++ {
		events, _, err := svc.QueryEvents(ctx, &AuditQuery{Limit: 5, Cursor: cursor})
		require.NoError(t, err)
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			assert.NotEqual(t, "other-tenant", e.Action, "another tenant's event came back")
		}
		if len(events) < 5 {
			break
		}
		last := events[len(events)-1]
		cursor = &EventCursor{Timestamp: last.Timestamp, ID: last.ID}
	}
}

// The offset path keeps its total: X-Total-Count is published and the console
// reads it, so the old shape has to keep answering the old way.
func TestOffsetPathStillReturnsATotal(t *testing.T) {
	db, cleanup := setupKeysetTestDB(t)
	defer cleanup()

	svc := seedKeysetEvents(t, db, 30, 0)
	events, total, err := svc.QueryEvents(keysetCtx(), &AuditQuery{Limit: 10, Offset: 0})
	require.NoError(t, err)
	assert.Len(t, events, 10)
	assert.Equal(t, 30, total, "the offset path stopped reporting a total")
}

// The claim behind "p99 < 100ms at page 1000" is that the database SEEKS to the
// cursor rather than reading up to it. That is a property of the plan, so the
// plan is what the test reads -- a timing assertion here would measure this
// machine, not the change.
func TestKeysetQueryUsesTheIndexRatherThanScanning(t *testing.T) {
	db, cleanup := setupKeysetTestDB(t)
	defer cleanup()

	seedKeysetEvents(t, db, 500, 0)
	ctx := context.Background()

	// Small tables are faster to scan than to seek, and the planner is right
	// about that -- so ask it to plan as though the table were large.
	_, err := db.Pool.Exec(ctx, "SET enable_seqscan = off")
	require.NoError(t, err)

	cur := EventCursor{Timestamp: time.Date(2026, 9, 13, 12, 5, 0, 0, time.UTC), ID: "0f8fad5b-d9cb-469f-a165-70867728950e"}
	rows, err := db.Pool.Query(ctx, `
		EXPLAIN SELECT id, timestamp FROM audit_events
		 WHERE org_id = $1 AND (timestamp, id) < ($2, $3::uuid)
		 ORDER BY timestamp DESC, id DESC LIMIT 50`,
		keysetOrgA, cur.Timestamp, cur.ID)
	require.NoError(t, err)
	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line + "\n")
	}
	rows.Close()
	require.NoError(t, rows.Err())

	assert.Contains(t, plan.String(), "idx_audit_events_org_ts_id",
		"the keyset query does not use v190's index; paging deep would read up to the cursor instead of seeking to it:\n%s", plan.String())
	assert.NotContains(t, plan.String(), "Sort ",
		"the plan sorts; the index is supposed to supply the ordering:\n%s", plan.String())
}
