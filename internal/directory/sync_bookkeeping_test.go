package directory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// A directory sync that happened and left no trace.
//
// RunSync creates a log row with status 'running', runs the sync, and then
// writes four things down: the run's outcome, when the directory was last
// synced, the integration's status, and (for Azure AD) the delta cursor. Every
// one of those Execs discarded its error.
//
// The worst of them is not a display. Scheduler.checkAndRunSyncs reads
// directory_sync_state.last_sync_at to decide whether a sync is due, and a NULL
// there means "never synced", which schedules a FULL sync. So a lost write
// there does not leave the console stale -- it makes the scheduler run a full
// directory sync against the customer's LDAP or Graph tenant on every
// 60-second tick, indefinitely, while the console reports the directory has
// never been synchronised.
//
// The log row is the same shape as the queues elsewhere on this branch: it is
// created 'running' and this is the only statement that ever takes it out of
// that state, so losing it strands a finished run as in-progress and throws
// away error_message, the one place a failed sync's reason is kept.

const syncBookkeepingSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255),
    first_name VARCHAR(255), last_name VARCHAR(255), password_hash VARCHAR(255),
    enabled BOOLEAN DEFAULT true, email_verified BOOLEAN DEFAULT false,
    source VARCHAR(50), directory_id UUID, external_id VARCHAR(255),
    external_hr_id VARCHAR(128), employee_number VARCHAR(64),
    job_title VARCHAR(255), department VARCHAR(255), employment_status VARCHAR(32),
    hire_date DATE, termination_date DATE, manager_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);

CREATE TABLE IF NOT EXISTS directory_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL, type VARCHAR(50) NOT NULL,
    config JSONB, enabled BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMPTZ, sync_status VARCHAR(50) DEFAULT 'never',
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id UUID NOT NULL);

CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL, sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL, started_at TIMESTAMPTZ NOT NULL, completed_at TIMESTAMPTZ,
    users_added INTEGER DEFAULT 0, users_updated INTEGER DEFAULT 0, users_disabled INTEGER DEFAULT 0,
    groups_added INTEGER DEFAULT 0, groups_updated INTEGER DEFAULT 0, groups_deleted INTEGER DEFAULT 0,
    error_message TEXT, details JSONB, org_id UUID NOT NULL);

CREATE TABLE IF NOT EXISTS directory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL, last_sync_at TIMESTAMPTZ,
    last_delta_link TEXT, last_usn_changed BIGINT, last_modify_timestamp VARCHAR(255),
    users_synced INTEGER DEFAULT 0, groups_synced INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0, sync_duration_ms INTEGER,
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID NOT NULL,
    UNIQUE (directory_id));`

const (
	bkOrg = "00000000-0000-0000-0000-0000000000b1"
	bkDir = "00000000-0000-0000-0000-0000000000b2"
)

// bookkeepingFixture gets a real PostgreSQL with the four tables RunSync
// writes, and one HRIS integration. Real, because every property here is about
// what happens when the database refuses a statement.
func bookkeepingFixture(t *testing.T, baseURL string) (*SyncEngine, context.Context, func()) {
	t.Helper()
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return nil, nil, func() {}
	}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		cleanup()
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, syncBookkeepingSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}

	cfg, err := json.Marshal(HRISConfig{Provider: "bamboohr", APIKey: "k", BaseURL: baseURL, DeprovisionAction: "disable"})
	if err != nil {
		cleanup()
		t.Fatalf("marshal config: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO directory_integrations (id, name, type, config, sync_status, org_id)
		VALUES ($1::uuid, 'hr', 'hris', $2::jsonb, 'never', $3::uuid)`, bkDir, string(cfg), bkOrg); err != nil {
		cleanup()
		t.Fatalf("seed integration: %v", err)
	}

	return NewSyncEngine(db, zap.NewNop()), ctx, cleanup
}

// refuse installs a trigger that makes every write of the named kind on a table
// fail, the way a constraint or a policy would.
func refuse(t *testing.T, db *database.PostgresDB, table, event string) {
	t.Helper()
	ctx := context.Background()
	fn := "refuse_" + table + "_" + strings.ToLower(event)
	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER `+fn+`_trg BEFORE `+event+` ON `+table+`
		FOR EACH ROW EXECUTE FUNCTION `+fn+`();`); err != nil {
		t.Fatalf("install refusal trigger on %s %s: %v", table, event, err)
	}
}

func runHRISFullSync(t *testing.T, e *SyncEngine, ctx context.Context) error {
	t.Helper()
	cfg, err := json.Marshal(HRISConfig{Provider: "bamboohr", APIKey: "k",
		BaseURL: hrisBaseURL(t, e, ctx), DeprovisionAction: "disable"})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	_, syncErr := e.RunSync(ctx, bkDir, "hris", cfg, true)
	return syncErr
}

// hrisBaseURL reads back the base URL the fixture stored, so the run uses the
// same mock server the fixture was built with.
func hrisBaseURL(t *testing.T, e *SyncEngine, ctx context.Context) string {
	t.Helper()
	var raw []byte
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT config FROM directory_integrations WHERE id = $1::uuid`, bkDir).Scan(&raw); err != nil {
		t.Fatalf("read the integration config: %v", err)
	}
	var cfg HRISConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode the integration config: %v", err)
	}
	return cfg.BaseURL
}

// The positive control. Without this, a test that watches a refused write could
// pass because the sync never got that far.
func TestASyncRecordsEveryPartOfItsOutcome(t *testing.T) {
	srv := bambooServer(`{"employees":[{"id":"1","employeeNumber":"E1","firstName":"Ann","lastName":"A",` +
		`"workEmail":"ann@corp.com","status":"Active","hireDate":"2024-01-01"}]}`)
	defer srv.Close()

	e, ctx, cleanup := bookkeepingFixture(t, srv.URL)
	if e == nil {
		return
	}
	defer cleanup()

	if err := runHRISFullSync(t, e, ctx); err != nil {
		t.Fatalf("a sync against a healthy source reported an error: %v", err)
	}

	var logStatus string
	var completed, lastSync *string
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT status, completed_at::text FROM directory_sync_logs WHERE directory_id = $1::uuid`,
		bkDir).Scan(&logStatus, &completed); err != nil {
		t.Fatalf("read the sync log back: %v", err)
	}
	if logStatus != "success" || completed == nil {
		t.Errorf("the run's log row is status=%q completed_at=%v; a finished run must not read as running",
			logStatus, completed)
	}

	if err := e.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at::text FROM directory_sync_state WHERE directory_id = $1::uuid`,
		bkDir).Scan(&lastSync); err != nil {
		t.Fatalf("read the sync state back: %v", err)
	}
	if lastSync == nil {
		t.Error("last_sync_at is NULL after a completed sync — the scheduler reads that as 'never synced' " +
			"and will run a full sync on every 60-second tick")
	}

	var dirStatus string
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT sync_status FROM directory_integrations WHERE id = $1::uuid`, bkDir).Scan(&dirStatus); err != nil {
		t.Fatalf("read the integration back: %v", err)
	}
	if dirStatus != "synced" {
		t.Errorf("the integration is %q after a successful sync, want synced", dirStatus)
	}
}

func TestASyncThatCannotRecordItsOutcomeSaysSo(t *testing.T) {
	srv := bambooServer(`{"employees":[]}`)
	defer srv.Close()

	e, ctx, cleanup := bookkeepingFixture(t, srv.URL)
	if e == nil {
		return
	}
	defer cleanup()

	refuse(t, e.db, "directory_sync_logs", "UPDATE")

	err := runHRISFullSync(t, e, ctx)
	if err == nil {
		t.Fatal("the sync log's completion write was refused and RunSync reported success. " +
			"The log row stays 'running' for ever and error_message — the only record of why a " +
			"sync failed — is never written, and nothing anywhere says so.")
	}
	if !strings.Contains(err.Error(), "the outcome of the run") {
		t.Errorf("the error does not name what was not recorded: %v", err)
	}
	if !strings.Contains(err.Error(), "sync itself completed") {
		t.Errorf("the error must distinguish a failed sync from a sync that could not be written down; got: %v", err)
	}
}

func TestASyncWhoseScheduleStateIsLostSaysSo(t *testing.T) {
	srv := bambooServer(`{"employees":[]}`)
	defer srv.Close()

	e, ctx, cleanup := bookkeepingFixture(t, srv.URL)
	if e == nil {
		return
	}
	defer cleanup()

	refuse(t, e.db, "directory_sync_state", "INSERT")

	err := runHRISFullSync(t, e, ctx)
	if err == nil {
		t.Fatal("last_sync_at could not be written and RunSync reported success. The scheduler reads " +
			"that column to decide when a sync is due; a NULL means 'never synced', which schedules " +
			"a FULL sync — so this directory is now fully re-synced every 60 seconds, for ever, silently.")
	}
	if !strings.Contains(err.Error(), "last synced") {
		t.Errorf("the error does not name what was not recorded: %v", err)
	}
}

// A failed sync must be reported as a failed sync, not as a bookkeeping
// problem: it is the more serious of the two and it is the one an operator
// must act on.
func TestTheSyncsOwnFailureIsReportedOverItsBookkeeping(t *testing.T) {
	srv := bambooServer(`{"employees":[]}`)
	srv.Close() // nothing is listening, so the HR fetch fails

	e, ctx, cleanup := bookkeepingFixture(t, srv.URL)
	if e == nil {
		return
	}
	defer cleanup()

	refuse(t, e.db, "directory_sync_logs", "UPDATE")

	err := runHRISFullSync(t, e, ctx)
	if err == nil {
		t.Fatal("a sync whose source was unreachable reported success")
	}
	if strings.Contains(err.Error(), "sync itself completed") {
		t.Errorf("a failed sync was reported as a bookkeeping failure, which hides it: %v", err)
	}
}

// The delta cursor.
//
// Graph's delta query returns only what has changed since the token was issued,
// so storing the new token means never being offered those records again. It
// used to be stored the moment Graph handed it over -- before a single record
// had been applied -- so a user whose write the database refused was stepped
// over permanently, and the sync reported itself partial without ever saying
// the change had been lost rather than deferred.
func TestTheDeltaCursorIsHeldWhenRecordsWereNotApplied(t *testing.T) {
	e, ctx, cleanup := bookkeepingFixture(t, "http://127.0.0.1:1")
	if e == nil {
		return
	}
	defer cleanup()

	result := &SyncResult{Errors: []string{"failed to update user ann: refused"}}
	e.storeDeltaLink(ctx, bkDir, bkOrg, "https://graph.example/delta?token=second", 1, result)

	var stored *string
	err := e.db.Pool.QueryRow(ctx,
		`SELECT last_delta_link FROM directory_sync_state WHERE directory_id = $1::uuid`, bkDir).Scan(&stored)
	if err == nil && stored != nil {
		t.Errorf("the cursor advanced to %q even though a record in that page was not applied. "+
			"Graph will never offer that record again: the change is lost, permanently, and the "+
			"sync reports itself merely partial.", *stored)
	}
}

func TestTheDeltaCursorAdvancesWhenEveryRecordLanded(t *testing.T) {
	e, ctx, cleanup := bookkeepingFixture(t, "http://127.0.0.1:1")
	if e == nil {
		return
	}
	defer cleanup()

	result := &SyncResult{}
	// No state row exists yet: this is a directory's first incremental sync,
	// which the old UPDATE could not write at all.
	e.storeDeltaLink(ctx, bkDir, bkOrg, "https://graph.example/delta?token=second", 0, result)
	if len(result.Errors) != 0 {
		t.Fatalf("storing the cursor reported errors: %v", result.Errors)
	}

	var stored string
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT last_delta_link FROM directory_sync_state WHERE directory_id = $1::uuid`,
		bkDir).Scan(&stored); err != nil {
		t.Fatalf("no cursor was stored on a directory's first incremental sync: %v. "+
			"Every such run then threw its delta token away and re-enumerated the tenant.", err)
	}
	if stored != "https://graph.example/delta?token=second" {
		t.Errorf("stored cursor is %q", stored)
	}

	// And a later page replaces it rather than inserting a second row.
	e.storeDeltaLink(ctx, bkDir, bkOrg, "https://graph.example/delta?token=third", 0, result)
	var rows int
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM directory_sync_state WHERE directory_id = $1::uuid`, bkDir).Scan(&rows); err != nil {
		t.Fatalf("count state rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("the directory has %d sync-state rows", rows)
	}
}
