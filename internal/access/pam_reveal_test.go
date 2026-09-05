package access

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/vault"
)

// The PAM reveal path: the most sensitive read in the product.
//
// handlePamRevealEntry hands back a privileged account's password in plaintext.
// Six checks stand in front of that, and what they decide is not only WHETHER
// the caller gets the secret but WHICH refusal they get — a 403 that says
// "reveal is disabled for this entry" and a 404 that says "no such entry" tell
// an attacker enumerating ids very different things. No test named the handler.
//
// The harness migrates a real database rather than hand-rolling the tables:
// pam_entries, the v105 checkout controls and the vault's own schema are spread
// across migrations and carry FORCE RLS, and a test that approximates them can
// pass against a shape production does not have.

const (
	pamOrg    = "00000000-0000-0000-0000-000000000010"
	pamAdmin  = "00000000-0000-0000-0000-000000000091"
	pamViewer = "00000000-0000-0000-0000-000000000092"
)

func pamRevealTestDB(t *testing.T) *database.PostgresDB {
	t.Helper()
	ctx := context.Background()

	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		db, cleanup := setupTestDB(t)
		if db == nil {
			t.SkipNow()
		}
		t.Cleanup(cleanup)
		if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return db
	}

	db, err := database.NewPostgres(url)
	if err != nil {
		t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
	}
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			db.Close()
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type pamFixture struct {
	svc *Service
	ctx context.Context
	t   *testing.T
}

func newPamRevealFixture(t *testing.T) *pamFixture {
	t.Helper()
	db := pamRevealTestDB(t)

	cfg := &config.Config{AccessSessionSecret: "pam-reveal-test-session-secret-00"}
	svc := NewService(db, nil, cfg, zap.NewNop())

	// The same construction cmd/access-service uses, so the reveal path under
	// test is the production one rather than a stand-in.
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: base64.StdEncoding.EncodeToString([]byte("pam-reveal-test-kek-0123456789ab")),
	})
	if err != nil {
		t.Fatalf("vault keyring: %v", err)
	}
	vaultSvc, err := vault.NewService(db, ring, nil, time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}
	svc.SetVaultService(vaultSvc)

	f := &pamFixture{svc: svc, ctx: orgctx.With(context.Background(), orgctx.Org{ID: pamOrg}), t: t}
	// vault_secrets.owner_id and pam_entries.created_by are real foreign keys.
	for id, name := range map[string]string{pamAdmin: "pam-admin", pamViewer: "pam-viewer"} {
		f.exec(`INSERT INTO users (id, username, email, password_hash, org_id)
		        VALUES ($1,$2,$3,'x',$4) ON CONFLICT (id) DO NOTHING`, id, name, name+"@example.test", pamOrg)
	}
	return f
}

func (f *pamFixture) exec(sql string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.svc.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// secret stores a vault secret and returns its id.
func (f *pamFixture) secret(name, value string) string {
	f.t.Helper()
	s, err := f.svc.vaultSvc.Store(f.ctx, vault.StoreInput{
		Name: name, Type: "password", Value: []byte(value), CreatedBy: pamAdmin, OwnerID: pamAdmin,
	})
	if err != nil {
		f.t.Fatalf("create secret: %v", err)
	}
	return s.ID
}

// entry inserts a pam_entries row. secretID or credentialEntryID may be empty.
func (f *pamFixture) entry(name, secretID, credentialEntryID string, allowReveal bool) string {
	f.t.Helper()
	var id string
	var sec, cred interface{}
	if secretID != "" {
		sec = secretID
	}
	if credentialEntryID != "" {
		cred = credentialEntryID
	}
	if err := f.svc.db.Pool.QueryRow(f.ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, vault_secret_id, credential_entry_id, allow_reveal, created_by)
		VALUES ($1,$2,'password',$3,$4,$5,$6) RETURNING id`,
		pamOrg, name, sec, cred, allowReveal, pamAdmin).Scan(&id); err != nil {
		f.t.Fatalf("create entry: %v", err)
	}
	return id
}

// revealAs runs the handler and returns the recorder.
func (f *pamFixture) revealAs(entryID, caller string, roles []string, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/access/pam/entries/"+entryID+"/reveal",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(f.ctx)
	c.Params = gin.Params{{Key: "id", Value: entryID}}
	c.Set("user_id", caller)
	c.Set("roles", roles)

	f.svc.handlePamRevealEntry(c)
	return w
}

func pamBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

var admin = []string{"admin"}

// --------------------------------------------------------------------------

// The happy path, and the two things it must leave behind: the plaintext, and
// a ledger row saying who read it and why. A reveal with no trail is a reveal
// nobody can investigate.
func TestPamRevealReturnsThePlaintextAndRecordsTheCheckout(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root", "hunter2"), "", true)

	w := f.revealAs(id, pamAdmin, admin, `{"reason":"incident 4711"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if got := pamBody(t, w)["value"]; got != "hunter2" {
		t.Errorf("value = %v, want the stored plaintext", got)
	}

	var n int
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM pam_active_checkouts WHERE entry_id = $1 AND principal_id = $2 AND reason = $3`,
		id, pamAdmin, "incident 4711").Scan(&n); err != nil {
		t.Fatalf("count checkouts: %v", err)
	}
	if n != 1 {
		t.Errorf("%d checkout rows for a reveal, want 1 carrying the caller's reason", n)
	}
}

// A reason is not paperwork: it is the only field in the ledger that says WHY,
// and it cannot be reconstructed afterwards.
func TestPamRevealRequiresAReason(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-2", "hunter2"), "", true)

	for _, body := range []string{`{}`, `{"reason":""}`, `not json`} {
		w := f.revealAs(id, pamAdmin, admin, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, w.Code)
		}
		if bytes.Contains(w.Body.Bytes(), []byte("hunter2")) {
			t.Errorf("body %q: the refusal leaked the secret", body)
		}
	}
}

// allow_reveal false means injection-only: the credential may be pushed into a
// session but never shown to a human. The refusal has to say that rather than
// pretend the entry is missing, because an operator needs to know the control
// is what stopped them.
func TestPamRevealRefusesAnInjectionOnlyEntry(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-3", "hunter2"), "", false)

	w := f.revealAs(id, pamAdmin, admin, `{"reason":"curiosity"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("hunter2")) {
		t.Fatal("the refusal leaked the secret")
	}

	var n int
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM pam_active_checkouts WHERE entry_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count checkouts: %v", err)
	}
	if n != 0 {
		t.Errorf("%d checkout rows for a refused reveal, want 0", n)
	}
}

// An entry with no stored secret and an entry pointing at a linked credential
// are different situations, and the caller can act on the second one.
func TestPamRevealDistinguishesNoSecretFromALinkedCredential(t *testing.T) {
	f := newPamRevealFixture(t)

	empty := f.entry("no-secret", "", "", true)
	if w := f.revealAs(empty, pamAdmin, admin, `{"reason":"x"}`); w.Code != http.StatusNotFound {
		t.Errorf("entry with no secret: status = %d, want 404", w.Code)
	}

	// A real entry to point at: credential_entry_id is a foreign key.
	target := f.entry("shared-credential", f.secret("shared-credential", "hunter2"), "", true)
	linked := f.entry("linked", "", target, true)
	w := f.revealAs(linked, pamAdmin, admin, `{"reason":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("linked entry: status = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if got, _ := pamBody(t, w)["error"].(string); got == "" || !bytes.Contains([]byte(got), []byte("credential")) {
		t.Errorf("error = %q; it should point the caller at the credential entry", got)
	}
}

// An unknown id and another tenant's id must be indistinguishable: anything
// else confirms that an entry exists to someone with no business knowing it.
func TestPamRevealHidesAnotherTenantsEntry(t *testing.T) {
	f := newPamRevealFixture(t)
	const otherOrg = "00000000-0000-0000-0000-0000000000b0"
	f.exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,'other','other') ON CONFLICT DO NOTHING`, otherOrg)

	// Written with the belt bypassed, the way a migration or another tenant's
	// own request would have written it.
	var foreign string
	if _, err := f.svc.db.Pool.Exec(f.ctx, `SET app.bypass_rls = 'on'`); err != nil {
		t.Fatalf("bypass: %v", err)
	}
	if err := f.svc.db.Pool.QueryRow(f.ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, allow_reveal, created_by)
		VALUES ($1,'foreign','password',true,$2) RETURNING id`, otherOrg, pamAdmin).Scan(&foreign); err != nil {
		t.Fatalf("create foreign entry: %v", err)
	}

	unknown := f.revealAs("00000000-0000-0000-0000-0000000000ff", pamAdmin, admin, `{"reason":"x"}`)
	other := f.revealAs(foreign, pamAdmin, admin, `{"reason":"x"}`)

	if other.Code != unknown.Code || other.Body.String() != unknown.Body.String() {
		t.Errorf("another tenant's entry answers %d %s; an unknown id answers %d %s — they must be identical",
			other.Code, other.Body.String(), unknown.Code, unknown.Body.String())
	}
}

// The entry-level ACL. A caller who is not an administrator needs a grant for
// THIS entry and THIS action; without one the answer is a refusal, not a
// secret.
func TestPamRevealRefusesANonAdminWithoutAGrant(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-4", "hunter2"), "", true)

	w := f.revealAs(id, pamViewer, []string{"viewer"}, `{"reason":"looking"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("hunter2")) {
		t.Fatal("the refusal leaked the secret")
	}
}

// Exclusivity: while one principal holds the entry, a second gets 409 rather
// than a copy of the credential. That is the whole point of the control — two
// people on the same privileged account at once is what it exists to prevent.
func TestPamRevealHonoursExclusiveCheckout(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-5", "hunter2"), "", true)
	f.exec(`UPDATE pam_entries SET exclusive_checkout = true WHERE id = $1`, id)

	if w := f.revealAs(id, pamAdmin, admin, `{"reason":"first"}`); w.Code != http.StatusOK {
		t.Fatalf("first reveal: status = %d (body=%s)", w.Code, w.Body.String())
	}

	w := f.revealAs(id, pamViewer, admin, `{"reason":"second"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("second reveal while held: status = %d, want 409 (body=%s)", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("hunter2")) {
		t.Fatal("the exclusivity refusal leaked the secret")
	}
}

// Dual control: a two-person entry answers 202 and hands back nothing until a
// second administrator authorizes the checkout.
func TestPamRevealHonoursDualControl(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-6", "hunter2"), "", true)
	f.exec(`UPDATE pam_entries SET dual_control_required = true WHERE id = $1`, id)

	w := f.revealAs(id, pamAdmin, admin, `{"reason":"needs a second pair of eyes"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("hunter2")) {
		t.Fatal("a pending dual-control reveal returned the secret")
	}

	// Once a second person authorizes it, the same call succeeds.
	f.exec(`UPDATE pam_checkout_authorizations SET status='approved', decided_at=NOW()
	        WHERE org_id=$1 AND entry_id=$2 AND requester_id=$3`, pamOrg, id, pamAdmin)
	w = f.revealAs(id, pamAdmin, admin, `{"reason":"authorized"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("after authorization: status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
}

// No organization context: refuse before the entry is looked up at all,
// because the lookup below it would otherwise be unscoped.
func TestPamRevealRequiresAnOrganization(t *testing.T) {
	f := newPamRevealFixture(t)
	id := f.entry("db-root", f.secret("db-root-7", "hunter2"), "", true)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(context.Background()) // no org
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("user_id", pamAdmin)
	c.Set("roles", admin)

	f.svc.handlePamRevealEntry(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
}
