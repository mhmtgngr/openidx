package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// THE SEAM, MEASURED END TO END against a live PostgreSQL: a severing path
// writes a row with ssfsignal.Enqueue under its tenant; the drainer, under
// bypass-RLS, turns it into a signed SET on every stream of THAT tenant that
// asked for account-disabled, and on no other.
//
// The table is created from the migration the loader ships (v196), not a copy,
// so an edit to the DDL that breaks the drainer's SQL fails here rather than in
// production. ssf_streams and ssf_stream_delivery are hand-built to the shape
// v99 gives them, because migrating the whole chain is the migrations package's
// job and would make this test about it.

type ssfDrainFixture struct {
	pool *pgxpool.Pool
	svc  *Service
	orgA string
	orgB string
}

func openSSFDrainFixture(t *testing.T) *ssfDrainFixture {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the SSF signal drain test")
	}
	ctx := context.Background()
	// database.NewPostgres, not a bare pgxpool: the tenant scope the producer
	// writes under and the bypass the drainer reads under are stamped on the
	// connection at checkout by the pool hook the product installs. A bare
	// pool would make every INSERT an RLS violation and every read empty.
	db, err := database.NewPostgres(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	pool := db.Pool.Raw()

	drop := `DROP TABLE IF EXISTS ssf_stream_delivery; DROP TABLE IF EXISTS ssf_streams; DROP TABLE IF EXISTS ssf_pending_events;`
	_, err = pool.Exec(ctx, drop)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), drop) })

	_, err = pool.Exec(ctx, `
		CREATE TABLE ssf_streams (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID,
			audience TEXT NOT NULL,
			delivery_endpoint TEXT NOT NULL,
			events_requested JSONB NOT NULL DEFAULT '[]'::jsonb,
			status VARCHAR(16) NOT NULL DEFAULT 'enabled');
		CREATE TABLE ssf_stream_delivery (
			id BIGSERIAL PRIMARY KEY,
			org_id UUID,
			stream_id UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
			event_type TEXT NOT NULL,
			subject TEXT,
			set_jwt TEXT NOT NULL,
			state VARCHAR(16) NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`)
	require.NoError(t, err)

	var v196 string
	for _, m := range migrations.All() {
		if m.Version == 196 {
			v196 = m.UpSQL
		}
	}
	require.NotEmpty(t, v196, "migration v196 is not registered")
	_, err = pool.Exec(ctx, v196)
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	svc := &Service{
		db:     db,
		logger: zap.NewNop(),
		issuer: "https://idp.example.test",
	}
	svc.privateKey = priv
	svc.publicKey = &priv.PublicKey

	return &ssfDrainFixture{pool: pool, svc: svc, orgA: uuid.NewString(), orgB: uuid.NewString()}
}

func (f *ssfDrainFixture) bypass() context.Context { return orgctx.WithBypassRLS(context.Background()) }

func (f *ssfDrainFixture) tenant(orgID string) context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: orgID, Slug: "t-" + orgID[:8]})
}

func (f *ssfDrainFixture) stream(t *testing.T, orgID, audience string, events ...string) string {
	t.Helper()
	ev, _ := json.Marshal(events)
	var id string
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO ssf_streams (org_id, audience, delivery_endpoint, events_requested)
		VALUES ($1, $2, 'https://receiver.example.test/events', $3) RETURNING id::text`,
		orgID, audience, string(ev)).Scan(&id))
	return id
}

type ssfDelivered struct {
	streamID, orgID, eventType, subject, setJWT string
}

func (f *ssfDrainFixture) delivered(t *testing.T) []ssfDelivered {
	t.Helper()
	rows, err := f.svc.db.Pool.Query(f.bypass(),
		`SELECT stream_id::text, COALESCE(org_id::text,''), event_type, COALESCE(subject,''), set_jwt FROM ssf_stream_delivery ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []ssfDelivered
	for rows.Next() {
		var d ssfDelivered
		require.NoError(t, rows.Scan(&d.streamID, &d.orgID, &d.eventType, &d.subject, &d.setJWT))
		out = append(out, d)
	}
	return out
}

type ssfPendingRow struct {
	publishedAt     *string
	attempts        int
	streamsEnqueued *int
}

func (f *ssfDrainFixture) pending(t *testing.T, id int64) ssfPendingRow {
	t.Helper()
	var r ssfPendingRow
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(),
		`SELECT published_at::text, attempts, streams_enqueued FROM ssf_pending_events WHERE id = $1`, id).
		Scan(&r.publishedAt, &r.attempts, &r.streamsEnqueued))
	return r
}

func (f *ssfDrainFixture) onlyPendingID(t *testing.T) int64 {
	t.Helper()
	var id int64
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(), `SELECT id FROM ssf_pending_events`).Scan(&id))
	return id
}

// setEvents decodes the SET's payload without verifying it: the test holds
// the key that signed it, and what is being measured is the claim set.
func setEvents(t *testing.T, setJWT string) (iss string, events map[string]interface{}) {
	t.Helper()
	parts := strings.Split(setJWT, ".")
	require.Len(t, parts, 3, "a compact JWS has three parts")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Iss    string                 `json:"iss"`
		Events map[string]interface{} `json:"events"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Iss, claims.Events
}

// THE POSITIVE PATH, and the two negatives beside it in one picture: the
// tenant's subscribing stream gets one signed SET; the tenant's stream that
// asked only for session-revoked gets nothing; the OTHER tenant's stream that
// asked for everything gets nothing.
func TestAPendingAccountDisabledSignalBecomesOneSignedSETPerSubscribedStreamOfItsTenant(t *testing.T) {
	f := openSSFDrainFixture(t)
	wants := f.stream(t, f.orgA, "https://a-wants.example.test", EventAccountDisabled)
	f.stream(t, f.orgA, "https://a-declines.example.test", EventSessionRevoked)
	f.stream(t, f.orgB, "https://b-everything.example.test")

	userID := uuid.NewString()
	require.NoError(t, ssfsignal.Enqueue(f.tenant(f.orgA), f.svc.db.Pool, ssfsignal.Signal{
		OrgID: f.orgA, SubjectID: userID, SubjectEmail: "leaver@example.test",
		Claims: map[string]interface{}{"reason": "offboarded"},
	}))

	n, err := f.svc.drainSSFSignals(f.bypass())
	require.NoError(t, err)
	require.Equal(t, 1, n, "one row was pending")

	got := f.delivered(t)
	require.Len(t, got, 1, "exactly one stream subscribed to account-disabled in the tenant: %+v", got)
	require.Equal(t, wants, got[0].streamID)
	require.Equal(t, f.orgA, got[0].orgID)
	require.Equal(t, EventAccountDisabled, got[0].eventType)
	require.Equal(t, "leaver@example.test", got[0].subject)

	iss, events := setEvents(t, got[0].setJWT)
	require.Equal(t, "https://idp.example.test", iss)
	ev, ok := events[ssfsignal.AccountDisabled].(map[string]interface{})
	require.True(t, ok, "the SET carries the account-disabled event under its RISC URI: %v", events)
	require.Equal(t, "offboarded", ev["reason"], "the producer's claims ride into the SET")
	subj, _ := ev["subject"].(map[string]interface{})
	require.Equal(t, "leaver@example.test", subj["email"], "subject: %v", ev["subject"])

	row := f.pending(t, f.onlyPendingID(t))
	require.NotNil(t, row.publishedAt, "the row is marked published after the emit")
	require.NotNil(t, row.streamsEnqueued)
	require.Equal(t, 1, *row.streamsEnqueued)
	require.Equal(t, 1, row.attempts)

	n, err = f.svc.drainSSFSignals(f.bypass())
	require.NoError(t, err)
	require.Equal(t, 0, n, "a published row is not drained again")
	require.Len(t, f.delivered(t), 1, "and no second SET appears")
}

// A row whose event type the drainer does not know is retired, not signed:
// published_at set, streams_enqueued zero, nothing on any stream. Without the
// allow-list a producer (or a poisoned row) could make the issuer sign a SET
// for an event URI nobody advertised.
func TestAnUnknownEventTypeIsRetiredWithZeroStreamsAndNeverSigned(t *testing.T) {
	f := openSSFDrainFixture(t)
	f.stream(t, f.orgA, "https://a-everything.example.test")

	_, err := f.svc.db.Pool.Exec(f.bypass(), `
		INSERT INTO ssf_pending_events (org_id, event_type, subject_id)
		VALUES ($1, 'https://schemas.openid.net/secevent/nobody/event-type/made-up', $2)`, f.orgA, uuid.NewString())
	require.NoError(t, err)

	n, err := f.svc.drainSSFSignals(f.bypass())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Empty(t, f.delivered(t), "nothing was signed")
	row := f.pending(t, f.onlyPendingID(t))
	require.NotNil(t, row.publishedAt, "the row does not stay in the backlog forever")
	require.NotNil(t, row.streamsEnqueued)
	require.Equal(t, 0, *row.streamsEnqueued, "an operator can read 'drained into zero streams' off the row")
}

// A drainer that died mid-batch left rows claimed and unpublished; after the
// grace they are anybody's again. A row that has been tried ten times is
// poison and is left alone. Both branches are driven, because a stale-requeue
// that never fires and a cap that never bites look identical to a working one.
func TestAStalledClaimIsHandedBackAndAPoisonedRowIsLeftAlone(t *testing.T) {
	f := openSSFDrainFixture(t)
	f.stream(t, f.orgA, "https://a.example.test", EventAccountDisabled)

	var stalled, poisoned, fresh int64
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO ssf_pending_events (org_id, event_type, subject_id, claimed_at, attempts)
		VALUES ($1, $2, $3, NOW() - INTERVAL '10 minutes', 1) RETURNING id`,
		f.orgA, ssfsignal.AccountDisabled, uuid.NewString()).Scan(&stalled))
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO ssf_pending_events (org_id, event_type, subject_id, attempts)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		f.orgA, ssfsignal.AccountDisabled, uuid.NewString(), ssfSignalMaxAttempt).Scan(&poisoned))
	require.NoError(t, f.svc.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO ssf_pending_events (org_id, event_type, subject_id, claimed_at)
		VALUES ($1, $2, $3, NOW()) RETURNING id`,
		f.orgA, ssfsignal.AccountDisabled, uuid.NewString()).Scan(&fresh))

	n, err := f.svc.drainSSFSignals(f.bypass())
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the stalled row is claimable: the poisoned one is over the cap, the fresh claim belongs to another drainer")

	require.NotNil(t, f.pending(t, stalled).publishedAt, "the stalled row was handed back and drained")
	require.Equal(t, 2, f.pending(t, stalled).attempts, "the earlier try still counts")
	require.Nil(t, f.pending(t, poisoned).publishedAt, "the poisoned row was not touched")
	require.Equal(t, ssfSignalMaxAttempt, f.pending(t, poisoned).attempts)
	require.Nil(t, f.pending(t, fresh).publishedAt, "a claim inside the grace is still the other drainer's")
	require.Len(t, f.delivered(t), 1)
}

// THE BELT: a producer under tenant A cannot read tenant B's pending signals.
// Needs a non-superuser role, since a superuser bypasses RLS by definition;
// the CI job runs this file as openidx_app.
func TestAPendingSignalIsInvisibleToAnotherTenant(t *testing.T) {
	f := openSSFDrainFixture(t)
	var super bool
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super))
	if super {
		t.Skip("TEST_POSTGRES_DSN is a superuser; RLS does not apply, so this test says nothing here")
	}
	require.NoError(t, ssfsignal.Enqueue(f.tenant(f.orgA), f.svc.db.Pool, ssfsignal.Signal{OrgID: f.orgA, SubjectID: uuid.NewString()}))
	require.NoError(t, ssfsignal.Enqueue(f.tenant(f.orgB), f.svc.db.Pool, ssfsignal.Signal{OrgID: f.orgB, SubjectID: uuid.NewString()}))

	count := func(ctx context.Context) int {
		var n int
		require.NoError(t, f.svc.db.Pool.QueryRow(ctx, `SELECT count(*) FROM ssf_pending_events`).Scan(&n))
		return n
	}
	require.Equal(t, 1, count(f.tenant(f.orgA)), "tenant A sees its own row and not B's")
	require.Equal(t, 1, count(f.tenant(f.orgB)))
	require.Equal(t, 2, count(f.bypass()), "the drainer sees both")

	// And a producer cannot write a row INTO another tenant either.
	err := ssfsignal.Enqueue(f.tenant(f.orgA), f.svc.db.Pool, ssfsignal.Signal{OrgID: f.orgB, SubjectID: uuid.NewString()})
	require.Error(t, err, "WITH CHECK refuses a row whose org_id is not the session's tenant")
}
