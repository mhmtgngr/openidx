package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
)

// edrSchema is the subset of migration v98 + the posture/identity tables the
// EDR ingestion tests need.
const edrSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), username VARCHAR(255) UNIQUE,
    email VARCHAR(255), enabled BOOLEAN DEFAULT true, org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, ziti_id VARCHAR(255),
    org_id UUID);
CREATE TABLE IF NOT EXISTS enrolled_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), agent_id VARCHAR(64),
    enrolled_by_user_id UUID, metadata JSONB DEFAULT '{}');
CREATE TABLE IF NOT EXISTS posture_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), ziti_id VARCHAR(255), name VARCHAR(255),
    check_type VARCHAR(100), parameters JSONB DEFAULT '{}', enabled BOOLEAN DEFAULT true,
    severity VARCHAR(50) DEFAULT 'critical', created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS device_posture_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), identity_id UUID, check_id UUID,
    passed BOOLEAN NOT NULL, details JSONB DEFAULT '{}', checked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ, org_id UUID);
CREATE TABLE IF NOT EXISTS edr_posture_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, name VARCHAR(255) NOT NULL,
    provider VARCHAR(32) NOT NULL, base_url TEXT, client_id TEXT, client_secret_enc TEXT,
    tenant_id TEXT, api_user TEXT, api_token_enc TEXT, posture_check_id UUID,
    match_strategy VARCHAR(16) NOT NULL DEFAULT 'serial', result_ttl_minutes INTEGER NOT NULL DEFAULT 60,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 15, enabled BOOLEAN NOT NULL DEFAULT true,
    last_sync_at TIMESTAMPTZ, last_sync_status VARCHAR(32), last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS edr_device_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
    source_id UUID NOT NULL REFERENCES edr_posture_sources(id) ON DELETE CASCADE,
    external_device_id VARCHAR(255) NOT NULL, match_value VARCHAR(255), user_id UUID,
    identity_id UUID, last_compliant BOOLEAN, last_risk VARCHAR(32), last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_id, external_device_id));`

func newEDRTestService(db *database.PostgresDB) *Service {
	s := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	// Wire a minimal ZitiManager so RecordPostureResult writes to the DB.
	s.SetZitiManager(&ZitiManager{db: db, logger: zap.NewNop()})
	return s
}

func setupEDRDB(t *testing.T) (*database.PostgresDB, func()) {
	db, cleanup := setupTestDB(t)
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, edrSchema); err != nil {
		cleanup()
		t.Fatalf("edr schema: %v", err)
	}
	return db, cleanup
}

func TestEDRSourceCRUDSecretNoLeak(t *testing.T) {
	db, cleanup := setupEDRDB(t)
	defer cleanup()
	ctx := context.Background()
	svc := newEDRTestService(db)

	src, err := svc.CreateEDRSource(ctx, "", &EDRSourceInput{
		Name: "cs", Provider: "crowdstrike", ClientID: "id", ClientSecret: "topsecret",
		MatchStrategy: "email", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateEDRSource: %v", err)
	}
	if src.ID == "" {
		t.Fatal("expected source id")
	}
	// Secret never surfaced in the struct.
	got, _ := svc.GetEDRSource(ctx, "", src.ID)
	if got.MatchStrategy != "email" || got.Provider != "crowdstrike" {
		t.Errorf("unexpected source: %+v", got)
	}
	// Verify the stored secret is encrypted-at-rest markerless here (noop cipher
	// in tests stores plaintext, but the API struct must not carry it).
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "topsecret") {
		t.Error("secret leaked in source JSON")
	}

	list, _ := svc.ListEDRSources(ctx, "")
	if len(list) != 1 {
		t.Fatalf("expected 1 source, got %d", len(list))
	}
	if err := svc.DeleteEDRSource(ctx, "", src.ID); err != nil {
		t.Fatalf("DeleteEDRSource: %v", err)
	}
	if _, err := svc.GetEDRSource(ctx, "", src.ID); err == nil {
		t.Error("expected source gone after delete")
	}
}

func TestEDRSourceValidation(t *testing.T) {
	db, cleanup := setupEDRDB(t)
	defer cleanup()
	ctx := context.Background()
	svc := newEDRTestService(db)

	if _, err := svc.CreateEDRSource(ctx, "", &EDRSourceInput{Name: "x", Provider: "sentinelone"}); err == nil {
		t.Error("expected unsupported provider rejected")
	}
	if _, err := svc.CreateEDRSource(ctx, "", &EDRSourceInput{Name: "x", Provider: "jamf", MatchStrategy: "fingerprint"}); err == nil {
		t.Error("expected unsupported match_strategy rejected")
	}
}

// TestEDRSyncWritesPostureResult is the core enforcement-chain test: a
// non-compliant device from a mock EDR must land a FAILING posture result keyed
// on the matched Ziti identity (which the existing enforcement reads).
func TestEDRSyncWritesPostureResult(t *testing.T) {
	db, cleanup := setupEDRDB(t)
	defer cleanup()
	ctx := context.Background()
	svc := newEDRTestService(db)

	// Seed a user + ziti identity so an email match resolves.
	var userID, identityID string
	db.Pool.QueryRow(ctx, `INSERT INTO users (username,email) VALUES ('alice','alice@corp.com') RETURNING id`).Scan(&userID)
	db.Pool.QueryRow(ctx, `INSERT INTO ziti_identities (user_id, ziti_id) VALUES ($1,'zid-1') RETURNING id`, userID).Scan(&identityID)
	// A posture check the EDR signal fails.
	var checkID string
	db.Pool.QueryRow(ctx, `INSERT INTO posture_checks (name, check_type, severity) VALUES ('EDR Compliance','EDR','critical') RETURNING id`).Scan(&checkID)

	// Mock CrowdStrike returning one compliant + one non-compliant device; the
	// compliant one belongs to alice.
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"access_token":"t"}`)) })
	mux.HandleFunc("/devices/queries/devices/v1", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"resources":["aid-1"]}`)) })
	mux.HandleFunc("/devices/entities/devices/v2", func(w http.ResponseWriter, r *http.Request) {
		// alice's device is CONTAINED (non-compliant) -> should fail posture.
		w.Write([]byte(`{"resources":[{"device_id":"aid-1","hostname":"h1","serial_number":"S1","email":"alice@corp.com","status":"contained","reduced_functionality_mode":"no"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	src, err := svc.CreateEDRSource(ctx, "", &EDRSourceInput{
		Name: "cs", Provider: "crowdstrike", BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec",
		PostureCheckID: checkID, MatchStrategy: "email", Enabled: true, ResultTTLMinutes: 30,
	})
	if err != nil {
		t.Fatalf("CreateEDRSource: %v", err)
	}

	status, err := svc.syncEDRSource(ctx, src.ID)
	if err != nil {
		t.Fatalf("syncEDRSource: %v", err)
	}
	if status.DevicesSeen != 1 || status.DevicesMatched != 1 || status.PostureFailed != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}

	// A failing posture result was written for alice's identity.
	var passed bool
	var expires *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT passed, expires_at FROM device_posture_results WHERE identity_id=$1 AND check_id=$2`,
		identityID, checkID).Scan(&passed, &expires); err != nil {
		t.Fatalf("expected a posture result row: %v", err)
	}
	if passed {
		t.Error("expected FAILING posture result for a contained device")
	}
	if expires == nil {
		t.Error("expected an expiry (TTL) on the posture result")
	}

	// The device mapping was recorded and resolved to the identity.
	var mapIdentity *string
	var lastCompliant bool
	db.Pool.QueryRow(ctx,
		`SELECT identity_id::text, last_compliant FROM edr_device_mappings WHERE source_id=$1 AND external_device_id='aid-1'`,
		src.ID).Scan(&mapIdentity, &lastCompliant)
	if mapIdentity == nil || *mapIdentity != identityID {
		t.Errorf("expected mapping resolved to identity %s, got %v", identityID, mapIdentity)
	}
	if lastCompliant {
		t.Error("expected mapping last_compliant=false")
	}
}

func TestEDRSyncCompliantDevicePasses(t *testing.T) {
	db, cleanup := setupEDRDB(t)
	defer cleanup()
	ctx := context.Background()
	svc := newEDRTestService(db)

	var userID, identityID, checkID string
	db.Pool.QueryRow(ctx, `INSERT INTO users (username,email) VALUES ('bob','bob@corp.com') RETURNING id`).Scan(&userID)
	db.Pool.QueryRow(ctx, `INSERT INTO ziti_identities (user_id, ziti_id) VALUES ($1,'zid-2') RETURNING id`, userID).Scan(&identityID)
	db.Pool.QueryRow(ctx, `INSERT INTO posture_checks (name, check_type, severity) VALUES ('EDR','EDR','high') RETURNING id`).Scan(&checkID)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"access_token":"t"}`)) })
	mux.HandleFunc("/devices/queries/devices/v1", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"resources":["aid-9"]}`)) })
	mux.HandleFunc("/devices/entities/devices/v2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"resources":[{"device_id":"aid-9","email":"bob@corp.com","status":"normal","reduced_functionality_mode":"no"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	src, _ := svc.CreateEDRSource(ctx, "", &EDRSourceInput{
		Name: "cs", Provider: "crowdstrike", BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec",
		PostureCheckID: checkID, MatchStrategy: "email", Enabled: true,
	})
	status, err := svc.syncEDRSource(ctx, src.ID)
	if err != nil {
		t.Fatalf("syncEDRSource: %v", err)
	}
	if status.PosturePassed != 1 || status.PostureFailed != 0 {
		t.Fatalf("expected 1 pass 0 fail, got %+v", status)
	}
	var passed bool
	db.Pool.QueryRow(ctx, `SELECT passed FROM device_posture_results WHERE identity_id=$1`, identityID).Scan(&passed)
	if !passed {
		t.Error("expected PASSING posture result for a normal device")
	}
}
