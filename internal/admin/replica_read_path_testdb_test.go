package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// WHAT A READ REPLICA REFUSES, MEASURED INSTEAD OF ASSUMED.
//
// Every offload in replica_offload_test.go rests on one unmeasured assumption:
// that the queries still WORK when Reader() really is a replica. In this
// repository that is not the obvious tautology it looks like, because a read
// through ScopedPool is not a bare SELECT. In RLS_MODE=local it is
//
//	BEGIN; select set_config('app.org_id', $1, true), ...; SELECT ...
//
// -- a transaction, and a set_config call, on a server that answers SQLSTATE
// 25006 to anything it considers a write. A standby also refuses a transaction
// that is not read-only. So the question "does the admin plane survive being
// pointed at a replica" is really "does BEGIN + set_config + SELECT survive
// being pointed at a replica", and nothing in the tree had asked a real server.
//
// If the answer were no, it would not be these two handlers that break: it
// would be all six files already offloaded, at once, on the day
// values-prod.yaml sets readReplica: true. That is the wrong day to find out.
//
// A read-only SESSION is not a byte-for-byte standby, but it is the same
// refusal from the same server: default_transaction_read_only makes every
// transaction read-only, and 25006 is the error a standby raises. Which is
// exactly what this test needs -- a replica that this container does not have.
func TestTheOffloadedHandlersAnswerOverAReadOnlyReplica(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the read-replica path test")
	}
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	const schema = "replica_offload_probe"

	// The scope is applied through set_config in a transaction, which is the
	// half of this that a read-only server could refuse. Measure local mode,
	// because that is the mode the plan is moving to, and restore whatever the
	// rest of the package expects.
	previous := database.CurrentRLSMode()
	database.SetRLSMode(database.RLSModeLocal)
	t.Cleanup(func() { database.SetRLSMode(previous) })

	primaryDSN := dsnWithOptions(t, dsn, "-c search_path="+schema+",public")
	// The whole point: this pool cannot write, exactly as a standby cannot.
	replicaDSN := dsnWithOptions(t, dsn,
		"-c search_path="+schema+",public",
		"-c default_transaction_read_only=on")

	t.Setenv("DATABASE_READ_URL", replicaDSN)
	db, err := database.NewPostgres(primaryDSN)
	require.NoError(t, err, "open the primary and the read pool")
	t.Cleanup(func() { _ = db.Close() })

	// Vacuity, and the failure this test exists to make loud: with no read pool
	// Reader() hands back the primary and every assertion below would pass
	// while measuring nothing.
	require.True(t, db.HasReadReplica(),
		"DATABASE_READ_URL did not open a second pool; this test would otherwise be reading the primary and calling it a replica")

	_, err = db.Pool.Raw().Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS `+schema+`;
		CREATE TABLE IF NOT EXISTS `+schema+`.ispm_scores (
			org_id uuid NOT NULL, overall_score int NOT NULL, category_scores jsonb NOT NULL DEFAULT '{}'::jsonb,
			total_findings int NOT NULL DEFAULT 0, critical_findings int NOT NULL DEFAULT 0,
			high_findings int NOT NULL DEFAULT 0, medium_findings int NOT NULL DEFAULT 0,
			low_findings int NOT NULL DEFAULT 0, snapshot_date date NOT NULL,
			PRIMARY KEY (org_id, snapshot_date));
		CREATE TABLE IF NOT EXISTS `+schema+`.users (
			id uuid PRIMARY KEY, org_id uuid NOT NULL, username text NOT NULL DEFAULT '', email text);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_totp (user_id uuid, org_id uuid, enabled bool);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_sms (user_id uuid, org_id uuid, enabled bool, verified bool);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_email_otp (user_id uuid, org_id uuid, enabled bool);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_push_devices (user_id uuid, org_id uuid, enabled bool);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_webauthn (user_id uuid, org_id uuid);
		CREATE TABLE IF NOT EXISTS `+schema+`.mfa_backup_codes (user_id uuid, org_id uuid, used bool NOT NULL DEFAULT false);
		CREATE TABLE IF NOT EXISTS `+schema+`.notifications (org_id uuid NOT NULL, read bool NOT NULL DEFAULT false, channel text NOT NULL DEFAULT 'email');
		CREATE TABLE IF NOT EXISTS `+schema+`.notification_routing_rules (org_id uuid NOT NULL, enabled bool NOT NULL DEFAULT true);
		CREATE TABLE IF NOT EXISTS `+schema+`.broadcast_messages (
			id uuid PRIMARY KEY, org_id uuid NOT NULL, title text NOT NULL, body text NOT NULL,
			channel text NOT NULL DEFAULT 'email', target_type text NOT NULL DEFAULT 'all',
			target_ids jsonb NOT NULL DEFAULT '[]'::jsonb, priority text NOT NULL DEFAULT 'normal',
			scheduled_at timestamptz, sent_at timestamptz, status text NOT NULL DEFAULT 'sent',
			total_recipients int NOT NULL DEFAULT 0, delivered_count int NOT NULL DEFAULT 0,
			read_count int NOT NULL DEFAULT 0, created_by text,
			created_at timestamptz NOT NULL DEFAULT NOW(), updated_at timestamptz NOT NULL DEFAULT NOW());`)
	require.NoError(t, err, "create the probe schema")
	t.Cleanup(func() {
		_, _ = db.Pool.Raw().Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE;`)
	})

	const (
		orgA = "00000000-0000-0000-0000-0000000000a1"
		orgB = "00000000-0000-0000-0000-0000000000b1"
		u1   = "00000000-0000-0000-0000-0000000000f1"
		u2   = "00000000-0000-0000-0000-0000000000f2"
		u3   = "00000000-0000-0000-0000-0000000000f3" // org B: must never be counted for org A
	)
	seed := func(q string, args ...any) {
		t.Helper()
		_, serr := db.Pool.Raw().Exec(ctx, q, args...)
		require.NoError(t, serr, q)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	seed(`INSERT INTO ispm_scores (org_id, overall_score, total_findings, critical_findings, snapshot_date)
	      VALUES ($1, 71, 9, 2, $2), ($1, 64, 14, 3, $3), ($4, 12, 99, 40, $2)`,
		orgA, today, today.AddDate(0, 0, -1), orgB)
	seed(`INSERT INTO users (id, org_id, username, email) VALUES ($1, $3, 'ada', 'ada@example.test'),
	      ($2, $3, 'grace', 'grace@example.test'), ($4, $5, 'intruder', 'intruder@example.test')`,
		u1, u2, orgA, u3, orgB)
	seed(`INSERT INTO mfa_totp (user_id, org_id, enabled) VALUES ($1, $2, true)`, u1, orgA)
	seed(`INSERT INTO mfa_webauthn (user_id, org_id) VALUES ($1, $2)`, u3, orgB)
	seed(`INSERT INTO mfa_backup_codes (user_id, org_id, used) VALUES ($1, $2, false), ($1, $2, false), ($1, $2, true)`, u1, orgA)
	seed(`INSERT INTO mfa_backup_codes (user_id, org_id, used) VALUES ($1, $2, false)`, u3, orgB)
	seed(`INSERT INTO notifications (org_id, read, channel) VALUES ($1, true, 'email'), ($1, false, 'email'), ($1, false, 'sms'), ($2, false, 'email')`, orgA, orgB)
	seed(`INSERT INTO notification_routing_rules (org_id, enabled) VALUES ($1, true), ($1, false), ($2, true)`, orgA, orgB)
	seed(`INSERT INTO broadcast_messages (id, org_id, title, body) VALUES ($1, $2, 'maintenance window', 'at 02:00'), ($3, $4, 'other tenant', 'not yours')`,
		"00000000-0000-0000-0000-0000000000c1", orgA, "00000000-0000-0000-0000-0000000000c2", orgB)

	s := &Service{db: db, logger: zap.NewNop()}
	call := func(orgID string, h gin.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
		c.Set("roles", []string{"admin"})
		h(c)
		return w
	}

	t.Run("posture trends come back from the replica, tenant-scoped", func(t *testing.T) {
		w := call(orgA, s.handleGetPostureTrends)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got struct {
			Data []struct {
				OverallScore  int    `json:"overall_score"`
				TotalFindings int    `json:"total_findings"`
				Date          string `json:"date"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		require.Len(t, got.Data, 2, "org A has two snapshots and org B's must not appear")
		assert.Equal(t, 71, got.Data[0].OverallScore, "newest snapshot first")
		assert.Equal(t, 64, got.Data[1].OverallScore)
		for _, row := range got.Data {
			assert.NotEqual(t, 99, row.TotalFindings, "org B's snapshot leaked through the replica read")
		}
	})

	t.Run("enrolment stats come back from the replica, tenant-scoped", func(t *testing.T) {
		w := call(orgA, s.handleMFAEnrollmentStats)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got MFAEnrollmentStats
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, 2, got.TotalUsers, "org B's user must not be counted")
		assert.Equal(t, 1, got.AnyMFA)
		assert.Equal(t, 1, got.TOTPCount)
		assert.Equal(t, 0, got.WebAuthnCount, "org B's webauthn credential must not be counted")
	})

	t.Run("the user MFA table comes back from the replica, tenant-scoped", func(t *testing.T) {
		w := call(orgA, s.handleListUserMFAStatus)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got struct {
			Data  []UserMFAStatus `json:"data"`
			Total int             `json:"total"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, 2, got.Total, "org B's user must not be counted")
		require.Len(t, got.Data, 2)
		for _, u := range got.Data {
			assert.NotEqual(t, "intruder", u.Username, "org B's user leaked through the replica read")
		}
		// The correlated subquery is the interesting half, and it has to be read
		// on BOTH rows. It carries its own org_id AND its own correlation to the
		// user, and a mutation that drops the correlation leaves ada's count
		// unchanged at 2 -- it is the row that holds all of this tenant's unused
		// codes. Only grace can tell the two apart: she holds none, and a
		// subquery that has stopped correlating hands her ada's two. Asserting
		// on ada alone let that mutation through, which is a fact about the
		// assertion rather than about the query.
		byName := map[string]UserMFAStatus{}
		for _, u := range got.Data {
			byName[u.Username] = u
		}
		require.Contains(t, byName, "ada")
		require.Contains(t, byName, "grace")
		assert.Equal(t, 2, byName["ada"].BackupCodesRemaining, "ada holds two unused codes and one used one")
		assert.Equal(t, 0, byName["grace"].BackupCodesRemaining, "grace holds none; a count of 2 here is ada's, reached through a subquery that no longer correlates")
		assert.True(t, byName["ada"].TOTPEnabled)
		assert.False(t, byName["grace"].TOTPEnabled)
	})

	t.Run("notification stats come back from the replica, tenant-scoped", func(t *testing.T) {
		w := call(orgA, s.handleNotificationStats)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got struct {
			TotalSent         int                `json:"total_sent"`
			TotalRead         int                `json:"total_read"`
			TotalUnread       int                `json:"total_unread"`
			ChannelBreakdown  map[string]int     `json:"channel_breakdown"`
			RecentBroadcasts  []BroadcastMessage `json:"recent_broadcasts"`
			RoutingRulesCount int                `json:"routing_rules_count"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, 3, got.TotalSent, "org B's notification must not be counted")
		assert.Equal(t, 1, got.TotalRead)
		assert.Equal(t, 2, got.TotalUnread)
		assert.Equal(t, map[string]int{"email": 2, "sms": 1}, got.ChannelBreakdown)
		assert.Equal(t, 1, got.RoutingRulesCount, "only the enabled rule, and only this tenant's")
		require.Len(t, got.RecentBroadcasts, 1, "org B's broadcast must not appear in this tenant's preview")
		assert.Equal(t, "maintenance window", got.RecentBroadcasts[0].Title)
	})

	// And the control: the pool those FOUR handlers just read from really does
	// refuse a write. Without this the tests above would pass just as well
	// against a second writable pool, and would be measuring nothing about
	// replicas at all.
	t.Run("the pool they read from refuses a write", func(t *testing.T) {
		_, werr := db.Reader().Raw().Exec(ctx,
			`INSERT INTO ispm_scores (org_id, overall_score, snapshot_date) VALUES ($1, 1, $2)`,
			orgA, today.AddDate(0, 0, -5))
		require.Error(t, werr, "the read pool accepted a write, so it is not standing in for a replica")

		var pgErr *pgconn.PgError
		require.ErrorAs(t, werr, &pgErr)
		assert.Equal(t, "25006", pgErr.Code,
			"expected read_only_sql_transaction, the error a standby raises; got %s (%s)", pgErr.Code, pgErr.Message)
	})
}

// dsnWithOptions returns dsn with libpq `options` set, so a pool can be opened
// against a schema and a transaction mode without a second database.
func dsnWithOptions(t *testing.T, dsn string, opts ...string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	require.NoError(t, err, "parse TEST_POSTGRES_DSN")
	q := u.Query()
	q.Set("options", strings.Join(opts, " "))
	u.RawQuery = q.Encode()
	return u.String()
}
