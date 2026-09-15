package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TWO STORES, AND ONLY ONE OF THEM IS THE RECORD.
//
// audit_events in PostgreSQL is the tamper-evident store: v181 gave it
// chain_seq, prev_hash and event_hash, and the sealer chains every row into a
// per-org sequence that the verification endpoint walks. Elasticsearch holds a
// copy for search, and the console reads THAT one.
//
// The relationship between them is a one-way lag, and it has to be: an event
// can be in PostgreSQL and not yet in Elasticsearch -- the index write is
// fire-and-forget and the reconciler backfills it. The reverse is not a lag,
// it is a DIVERGENCE: a document in the searchable index that the tamper-
// evident store never accepted has no sequence number, no hash and no seal,
// and chain verification will keep reporting the chain intact while the
// console shows an event the chain says nothing about.
//
// This is measured against a real PostgreSQL and a real HTTP Elasticsearch
// (the product's own client, over the wire) because the question is about
// ordering between two round trips, which is not a thing a mock can have.

// fakeES speaks enough of the Elasticsearch HTTP API for the product's client.
// It is not a search engine: it records what was indexed, which is the only
// thing these tests ask about.
type fakeES struct {
	mu      sync.Mutex
	docs    map[string][]byte
	arrived chan string
	fail    bool
	srv     *httptest.Server
}

func newFakeES(t *testing.T) *fakeES {
	t.Helper()
	f := &fakeES{docs: map[string][]byte{}, arrived: make(chan string, 64)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Without this header the client refuses every response as "not
		// Elasticsearch", so the round trip is the real one.
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")

		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.URL.Path == "/" || r.URL.Path == "":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":{"number":"8.11.0"}}`))
		case len(parts) == 3 && parts[1] == "_doc": // PUT /audit_events/_doc/{id}
			f.mu.Lock()
			failing := f.fail
			f.mu.Unlock()
			if failing {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"unavailable"}`))
				return
			}
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			f.mu.Lock()
			f.docs[parts[2]] = body
			f.mu.Unlock()
			select {
			case f.arrived <- parts[2]:
			default:
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"result":"created"}`))
		default: // index exists / create
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeES) client(t *testing.T) *database.ElasticsearchClient {
	t.Helper()
	c, err := database.NewElasticsearch(f.srv.URL)
	require.NoError(t, err)
	return c
}

func (f *fakeES) doc(id string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.docs[id]
	return b, ok
}

func (f *fakeES) setFailing(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

// waitForDoc blocks until the given document id reaches the index, or fails.
// The index write is a detached goroutine, so this is how a test observes it
// without sleeping for a guessed duration.
func (f *fakeES) waitForDoc(t *testing.T, id string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if _, ok := f.doc(id); ok {
			return
		}
		select {
		case <-f.arrived:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("document %s never reached Elasticsearch", id)
		}
	}
}

// openAuditESPool hands back a pool whose search_path points at a schema of
// this test's own, so the audit_events it creates and drops is never the one a
// sibling step in the same database is using. The statements under test name
// the table unqualified, which is what makes the redirect work.
func openAuditESPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the audit index ordering tests (they need a real Postgres)")
	}
	schema := "audit_es_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	bootstrap, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	_, err = bootstrap.Exec(context.Background(), `CREATE SCHEMA `+schema)
	bootstrap.Close()
	require.NoError(t, err, "the test DSN must be allowed to create a schema")

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		pool.Close()
		drop, derr := pgxpool.New(context.Background(), dsn)
		if derr == nil {
			_, _ = drop.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			drop.Close()
		}
	})
	return pool
}

// seedAuditEvents builds audit_events with the columns LogEvent writes plus the
// two the reconciler and the chain depend on.
func seedAuditEvents(t *testing.T, pool *pgxpool.Pool, es *database.ElasticsearchClient) *Service {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE audit_events (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			timestamp timestamptz DEFAULT NOW(),
			event_type varchar(100) NOT NULL,
			category varchar(50) NOT NULL,
			action varchar(255) NOT NULL,
			outcome varchar(50) NOT NULL,
			actor_id varchar(255), actor_type varchar(50), actor_ip varchar(45),
			target_id varchar(255), target_type varchar(100), resource_id varchar(255),
			details jsonb, session_id varchar(255), request_id varchar(255),
			org_id uuid,
			indexed_at timestamptz,
			created_at timestamptz DEFAULT NOW());`)
	require.NoError(t, err)
	return &Service{
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
		es:     es,
		logger: zap.NewNop(),
	}
}

func auditEventCtx(orgID string) context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: orgID})
}

func anEvent(id, action string) *ServiceAuditEvent {
	return &ServiceAuditEvent{
		ID:        id,
		EventType: "user.created",
		Category:  "identity",
		Action:    action,
		Outcome:   "success",
	}
}

// THE PROPERTY. PostgreSQL may lead Elasticsearch; Elasticsearch may never
// lead PostgreSQL.
func TestElasticsearchNeverHoldsAnEventPostgresRefused(t *testing.T) {
	pool := openAuditESPool(t)
	es := newFakeES(t)
	svc := seedAuditEvents(t, pool, es.client(t))

	orgA := uuid.NewString()
	orgB := uuid.NewString()

	// Org B writes an event, and it lands in both stores.
	taken := uuid.NewString()
	require.NoError(t, svc.LogEvent(auditEventCtx(orgB), anEvent(taken, "org B's event")))
	es.waitForDoc(t, taken)
	before, ok := es.doc(taken)
	require.True(t, ok)
	require.Contains(t, string(before), "org B's event")

	// Org A posts an event carrying org B's id. audit_events.id is the PRIMARY
	// KEY, so PostgreSQL refuses it -- and that refusal is the ONLY thing in
	// the system making the Elasticsearch document id unique, because the id
	// is also the document id.
	err := svc.LogEvent(auditEventCtx(orgA), anEvent(taken, "org A's event"))
	require.Error(t, err, "PostgreSQL must refuse a duplicate audit event id")

	// Fence the negative with a positive through the same path rather than
	// sleeping for a guessed duration: if the refused event were going to be
	// indexed, its write started before this one did.
	fence := uuid.NewString()
	require.NoError(t, svc.LogEvent(auditEventCtx(orgA), anEvent(fence, "the fence")))
	es.waitForDoc(t, fence)
	time.Sleep(250 * time.Millisecond)

	after, ok := es.doc(taken)
	require.True(t, ok, "org B's document disappeared entirely")
	require.NotContains(t, string(after), "org A's event",
		"Elasticsearch holds an audit document PostgreSQL refused, written over another tenant's. "+
			"The searchable index and the tamper-evident store now disagree, and chain verification "+
			"walks only the rows that exist -- so it will keep reporting the chain intact.")
	require.Contains(t, string(after), "org B's event")

	// And PostgreSQL is untouched, which is the half that makes the divergence
	// invisible: nothing in the record says the overwrite happened.
	var storedOrg string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT org_id::text FROM audit_events WHERE id = $1`, taken).Scan(&storedOrg))
	require.Equal(t, orgB, storedOrg)
}

// The same defect without an adversary, and the one that actually happened:
// LogEvent's own comment records an era when EVERY audit event access-service
// emitted was refused by PostgreSQL, because the id was empty and the column is
// a uuid. Seen from this side, that era shipped every one of those events to
// Elasticsearch and none to the chain. A statement timeout -- which task 2.4
// set per plane, and which arrives under load -- is the same shape today.
func TestARefusedInsertIndexesNothing(t *testing.T) {
	pool := openAuditESPool(t)
	es := newFakeES(t)
	svc := seedAuditEvents(t, pool, es.client(t))
	org := uuid.NewString()

	// Refused for a reason that has nothing to do with the id: category is
	// NOT NULL and varchar(50).
	tooLong := anEvent(uuid.NewString(), "over the column width")
	tooLong.Category = EventCategory(strings.Repeat("x", 80))
	require.Error(t, svc.LogEvent(auditEventCtx(org), tooLong))

	fence := uuid.NewString()
	require.NoError(t, svc.LogEvent(auditEventCtx(org), anEvent(fence, "the fence")))
	es.waitForDoc(t, fence)
	time.Sleep(250 * time.Millisecond)

	_, indexed := es.doc(tooLong.ID)
	require.False(t, indexed,
		"an event PostgreSQL refused reached the search index; the two stores diverge and only the index is what the console shows")

	var rows int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE id = $1`, tooLong.ID).Scan(&rows))
	require.Zero(t, rows)
}

// VACUITY. Every assertion above is satisfied by a LogEvent that indexes
// nothing at all, which would be a far worse bug than the one they describe.
func TestAnAcceptedEventStillReachesElasticsearchAndIsStamped(t *testing.T) {
	pool := openAuditESPool(t)
	es := newFakeES(t)
	svc := seedAuditEvents(t, pool, es.client(t))
	org := uuid.NewString()

	ev := anEvent(uuid.NewString(), "an ordinary event")
	require.NoError(t, svc.LogEvent(auditEventCtx(org), ev))
	es.waitForDoc(t, ev.ID)

	body, _ := es.doc(ev.ID)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))
	require.Equal(t, org, doc["org_id"], "the indexed document must carry the org or ES search cannot be tenant-scoped")

	// indexed_at is what keeps the reconciler from backfilling a row already
	// in the index, so the stamp is part of the delivery, not decoration.
	require.Eventually(t, func() bool {
		var stamped bool
		if err := pool.QueryRow(context.Background(),
			`SELECT indexed_at IS NOT NULL FROM audit_events WHERE id = $1`, ev.ID).Scan(&stamped); err != nil {
			return false
		}
		return stamped
	}, 5*time.Second, 25*time.Millisecond, "indexed_at was never stamped; the reconciler will index this row again")
}

// THE LAG THAT IS ALLOWED, and the reason the ordering above is a one-way
// constraint rather than a symmetric one. PostgreSQL ahead of Elasticsearch is
// the designed state; the reconciler closes it.
func TestAnEventPostgresAcceptedReachesTheIndexEvenWhenTheFirstWriteFails(t *testing.T) {
	pool := openAuditESPool(t)
	es := newFakeES(t)
	svc := seedAuditEvents(t, pool, es.client(t))
	org := uuid.NewString()

	es.setFailing(true)
	ev := anEvent(uuid.NewString(), "written while the index was down")
	require.NoError(t, svc.LogEvent(auditEventCtx(org), ev), "an Elasticsearch outage must not fail the audit write")

	// The row is in the record, unstamped, waiting.
	require.Eventually(t, func() bool {
		var n int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE id = $1 AND indexed_at IS NULL`, ev.ID).Scan(&n)
		return n == 1
	}, 5*time.Second, 25*time.Millisecond)

	// The reconciler only picks up rows past its grace window.
	_, err := pool.Exec(context.Background(),
		`UPDATE audit_events SET timestamp = NOW() - INTERVAL '5 minutes' WHERE id = $1`, ev.ID)
	require.NoError(t, err)

	es.setFailing(false)
	svc.reconcileUnindexedToES(orgctx.WithBypassRLS(context.Background()))

	_, indexed := es.doc(ev.ID)
	require.True(t, indexed, "the reconciler did not backfill a row PostgreSQL holds and the index does not")

	var stamped bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT indexed_at IS NOT NULL FROM audit_events WHERE id = $1`, ev.ID).Scan(&stamped))
	require.True(t, stamped)
}
