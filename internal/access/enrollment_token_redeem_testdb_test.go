package access

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// A ONE-TIME TOKEN THAT ADMITS TWO DEVICES IS NOT A ONE-TIME TOKEN.
//
// These tests drive the real agent_enrollment_tokens table -- built from the
// registered v43 and v86 DDL, not a copy -- through both public redemption
// routes: the agent's HandleEnroll and the dark-mode Service.handleEnroll.
// Before the shared redeemer the two routes disagreed about expiry (one never
// checked it), about a spend that fails (one accepted the token anyway), and
// neither made the spend a claim, so a concurrent double redemption enrolled
// two devices on one token. Each of those is a test here, and the positive
// control -- a valid token redeemed and spent, its subject handed back -- is
// what says the refusals are refusals and not a broken fixture.

type enrollTokenFixture struct {
	db  *database.PostgresDB
	ctx context.Context
}

func newEnrollTokenFixture(t *testing.T) *enrollTokenFixture {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the enrollment token redemption tests")
	}
	db, err := database.NewPostgres(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	_, err = db.Pool.Exec(ctx, `DROP TABLE IF EXISTS agent_enrollment_tokens, enrolled_agents, enrollment_sessions`)
	require.NoError(t, err)
	// The token table is the one under test, so it is built from the migrations
	// that shipped it: v43 creates it, v86 adds reusable, v197 adds the tenant.
	_, err = db.Pool.Exec(ctx, registeredEnrollmentTokenDDL(t))
	require.NoError(t, err)
	// The rows HandleEnroll writes after a redemption. Minimal shapes: they are
	// not what is measured, they only have to accept the writes -- except
	// org_id on the agent, which IS measured: the device lands in the token's
	// tenant.
	_, err = db.Pool.Exec(ctx, `
		CREATE TABLE enrolled_agents (
			agent_id text primary key, device_id text, status text, auth_token_hash text,
			enrolled_at timestamptz, compliance_status text, metadata jsonb,
			platform text, form_factor text, enrollment_method text, enrolled_by_user_id text,
			management_mode text, is_device_owner boolean, device_fingerprint text,
			ziti_identity_id text, last_seen_at timestamptz, org_id uuid not null);
		CREATE TABLE enrollment_sessions (
			id uuid primary key, token_hash text, created_by_user_id text, org_id uuid,
			mfa_verified boolean, status text, expires_at timestamptz);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DROP TABLE IF EXISTS agent_enrollment_tokens, enrolled_agents, enrollment_sessions`)
	})
	return &enrollTokenFixture{db: db, ctx: ctx}
}

// registeredEnrollmentTokenDDL returns the agent_enrollment_tokens statements
// from the migrations register: the CREATE TABLE (with its index) from v43,
// the whole of v86, and v197's tenant column. A fixture built from anything
// else would measure the fixture. (v197's backfill, NOT NULL, foreign keys and
// belt need organizations and users and are measured by the fleet tenant
// isolation test against the full chain; here the column is enough, because
// what this file measures is redemption.)
func registeredEnrollmentTokenDDL(t *testing.T) string {
	t.Helper()
	var v43, v86, v197 string
	for _, m := range migrations.All() {
		switch m.Version {
		case 43:
			v43 = m.UpSQL
		case 86:
			v86 = m.UpSQL
		case 197:
			v197 = m.UpSQL
		}
	}
	require.NotEmpty(t, v43, "migration v43 (agent_enrollment_tokens) is not registered")
	require.NotEmpty(t, v86, "migration v86 (reusable) is not registered")
	require.NotEmpty(t, v197, "migration v197 (fleet per tenant) is not registered")
	create := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS agent_enrollment_tokens \(.*?\);\s*CREATE INDEX[^;]*agent_enrollment_tokens[^;]*;`)
	stmt := create.FindString(v43)
	require.NotEmpty(t, stmt, "v43 no longer carries CREATE TABLE agent_enrollment_tokens")
	addOrg := regexp.MustCompile(`ALTER TABLE agent_enrollment_tokens\s+ADD COLUMN IF NOT EXISTS org_id UUID;`).FindString(v197)
	require.NotEmpty(t, addOrg, "v197 no longer adds agent_enrollment_tokens.org_id")
	return stmt + "\n" + v86 + "\n" + addOrg
}

// redeemOrg is the tenant every token in these tests is minted in.
const redeemOrg = "00000000-0000-0000-0000-00000000dd01"

type seededToken struct {
	plaintext string
	id        string
}

func (f *enrollTokenFixture) seed(t *testing.T, createdBy string, expiresIn time.Duration, reusable, revoked bool) seededToken {
	t.Helper()
	plaintext := uuid.New().String()
	var id string
	err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, created_by, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'test', $2, NOW() + $3::interval, $4, $5, $6) RETURNING id`,
		sha256Hex(plaintext), createdBy, expiresIn.String(), reusable, revoked, redeemOrg).Scan(&id)
	require.NoError(t, err)
	return seededToken{plaintext: plaintext, id: id}
}

func (f *enrollTokenFixture) usedAt(t *testing.T, id string) *time.Time {
	t.Helper()
	var usedAt *time.Time
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT used_at FROM agent_enrollment_tokens WHERE id = $1`, id).Scan(&usedAt))
	return usedAt
}

func (f *enrollTokenFixture) agentHandler() *AgentAPIHandler {
	return &AgentAPIHandler{logger: zap.NewNop(), db: f.db, conf: &config.Config{Environment: "production"}}
}

func (f *enrollTokenFixture) service() *Service {
	return &Service{logger: zap.NewNop(), db: f.db}
}

// agentEnroll drives POST /agent/enroll with the token as the bearer.
func agentEnroll(h *AgentAPIHandler, token string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	h.HandleEnroll(c)
	return w
}

// darkEnroll drives POST /api/v1/access/enroll with the token in the body.
func darkEnroll(s *Service, token string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := []byte(`{"enrollment_token":"` + token + `"}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	s.handleEnroll(c)
	return w
}

func TestAValidSingleUseEnrollmentTokenIsRedeemedOnceAndSpentOnBothRoutes(t *testing.T) {
	f := newEnrollTokenFixture(t)

	// Positive control, redeemer: the subject comes back and the token is spent.
	tok := f.seed(t, "user-42", time.Hour, false, false)
	got, err := redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
	require.NoError(t, err)
	assert.Equal(t, "user-42", got.CreatedBy)
	assert.False(t, got.Reusable)
	assert.Equal(t, redeemOrg, got.OrgID, "the redeemer did not hand back the token's tenant")
	require.NotNil(t, f.usedAt(t, tok.id), "a redeemed single-use token was not spent")

	// Positive control, agent route: a fresh token enrolls, and is spent, and
	// the device lands in the token's tenant (v197).
	tok = f.seed(t, "user-42", time.Hour, false, false)
	w := agentEnroll(f.agentHandler(), tok.plaintext)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "auth_token")
	require.NotNil(t, f.usedAt(t, tok.id), "the agent route enrolled without spending the token")
	var usedBy *string
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT used_by_agent FROM agent_enrollment_tokens WHERE id = $1`, tok.id).Scan(&usedBy))
	require.NotNil(t, usedBy, "the enrolling agent was not recorded on the token")
	var agentOrg string
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT org_id::text FROM enrolled_agents WHERE agent_id = $1`, *usedBy).Scan(&agentOrg))
	assert.Equal(t, redeemOrg, agentOrg, "the enrolled device is not in the token's tenant")

	// The same token a second time is refused -- on either route.
	w = agentEnroll(f.agentHandler(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "already been used")
	w = darkEnroll(f.service(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Positive control, dark route: the token is accepted (the request then
	// fails on the Ziti mint, which is not under test and is not 401) and spent.
	tok = f.seed(t, "user-42", time.Hour, false, false)
	subject, err := f.service().validateEnrollmentToken(f.ctx, tok.plaintext)
	require.NoError(t, err)
	assert.Equal(t, "user-42", subject)
	require.NotNil(t, f.usedAt(t, tok.id), "the dark route accepted without spending the token")
	tok = f.seed(t, "", time.Hour, false, false)
	w = darkEnroll(f.service(), tok.plaintext)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code, "a valid token was refused on the dark route: %s", w.Body.String())
	require.NotNil(t, f.usedAt(t, tok.id))
}

func TestAnExpiredEnrollmentTokenIsRefusedOnBothRoutes(t *testing.T) {
	f := newEnrollTokenFixture(t)

	// Expired a minute ago: the redeemer refuses it and does not spend it.
	tok := f.seed(t, "user-42", -time.Minute, false, false)
	_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
	assert.ErrorIs(t, err, errEnrollmentTokenExpired)
	assert.Nil(t, f.usedAt(t, tok.id), "a refused token was spent")

	// Agent route.
	w := agentEnroll(f.agentHandler(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "expired")
	assert.NotContains(t, w.Body.String(), "auth_token")

	// Dark route -- the one that never compared expires_at. Before the shared
	// redeemer this returned the mint's error, not 401: the token was accepted.
	w = darkEnroll(f.service(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "an expired token was accepted on the dark route: %s", w.Body.String())
	_, err = f.service().validateEnrollmentToken(f.ctx, tok.plaintext)
	assert.ErrorIs(t, err, errEnrollmentTokenExpired)

	// Expiry is not waived for a reusable token.
	fleet := f.seed(t, "mdm", -time.Minute, true, false)
	_, err = redeemEnrollmentToken(f.ctx, f.db.Pool, fleet.plaintext)
	assert.ErrorIs(t, err, errEnrollmentTokenExpired)
}

func TestARevokedOrUnknownEnrollmentTokenIsRefusedOnBothRoutes(t *testing.T) {
	f := newEnrollTokenFixture(t)

	revoked := f.seed(t, "user-42", time.Hour, false, true)
	_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, revoked.plaintext)
	assert.ErrorIs(t, err, errEnrollmentTokenRevoked)
	assert.Nil(t, f.usedAt(t, revoked.id))
	assert.Equal(t, http.StatusUnauthorized, agentEnroll(f.agentHandler(), revoked.plaintext).Code)
	assert.Equal(t, http.StatusUnauthorized, darkEnroll(f.service(), revoked.plaintext).Code)

	_, err = redeemEnrollmentToken(f.ctx, f.db.Pool, "never-issued")
	assert.ErrorIs(t, err, errEnrollmentTokenUnknown)
	assert.Equal(t, http.StatusUnauthorized, agentEnroll(f.agentHandler(), "never-issued").Code)
	assert.Equal(t, http.StatusUnauthorized, darkEnroll(f.service(), "never-issued").Code)
}

func TestAReusableEnrollmentTokenEnrollsManyAndIsNeverSpent(t *testing.T) {
	f := newEnrollTokenFixture(t)
	fleet := f.seed(t, "mdm", time.Hour, true, false)
	for i := 0; i < 3; i++ {
		got, err := redeemEnrollmentToken(f.ctx, f.db.Pool, fleet.plaintext)
		require.NoError(t, err, "redemption %d of a reusable token", i+1)
		assert.True(t, got.Reusable)
		require.Equal(t, http.StatusOK, agentEnroll(f.agentHandler(), fleet.plaintext).Code)
	}
	assert.Nil(t, f.usedAt(t, fleet.id), "a reusable token was spent")
}

// Two devices present the same one-time token in the same instant. The spend
// is an UPDATE ... WHERE used_at IS NULL, so the database admits exactly one;
// the others see zero rows and are refused. Twenty goroutines on one pool is
// twenty connections racing to the same row.
func TestAConcurrentDoubleRedemptionOfAOneTimeTokenAdmitsExactlyOne(t *testing.T) {
	f := newEnrollTokenFixture(t)
	const racers = 20
	for round := 0; round < 5; round++ {
		tok := f.seed(t, "user-42", time.Hour, false, false)
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			admitted int
			refused  int
			other    []error
		)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					admitted++
				case err == errEnrollmentTokenUsed:
					refused++
				default:
					other = append(other, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		require.Empty(t, other, "round %d: redemption failed for a reason other than the claim", round)
		assert.Equal(t, 1, admitted, "round %d: a one-time token admitted %d devices", round, admitted)
		assert.Equal(t, racers-1, refused, "round %d", round)
	}

	// The same race through the agent route: exactly one 200.
	tok := f.seed(t, "user-42", time.Hour, false, false)
	h := f.agentHandler()
	var wg sync.WaitGroup
	codes := make(chan int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- agentEnroll(h, tok.plaintext).Code
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for code := range codes {
		if code == http.StatusOK {
			ok++
		} else {
			assert.Equal(t, http.StatusUnauthorized, code)
		}
	}
	assert.Equal(t, 1, ok, "the agent route enrolled %d devices on one one-time token", ok)
}

// A token that cannot be spent is not a token that may be used. The spend is
// made to fail by a trigger; the redeemer must return the failure -- not a
// refusal, not success -- and the agent route must mint nothing. Before the
// shared redeemer HandleEnroll logged a Warn here and enrolled the device.
func TestAOneTimeTokenWhoseSpendFailsIsNotRedeemed(t *testing.T) {
	f := newEnrollTokenFixture(t)
	_, err := f.db.Pool.Exec(f.ctx, `
		CREATE OR REPLACE FUNCTION refuse_spend() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'spend refused by test'; END $$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_spend BEFORE UPDATE OF used_at ON agent_enrollment_tokens
		FOR EACH ROW EXECUTE FUNCTION refuse_spend();`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = f.db.Pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS refuse_spend() CASCADE`) })

	tok := f.seed(t, "user-42", time.Hour, false, false)
	_, err = redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
	require.Error(t, err)
	var refusal enrollError
	assert.NotErrorAs(t, err, &refusal, "a failed spend was reported as a client refusal")
	assert.True(t, strings.Contains(err.Error(), "spend enrollment token"), err.Error())

	w := agentEnroll(f.agentHandler(), tok.plaintext)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "auth_token", "a credential was minted on a token that could not be spent")
	var agents int
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM enrolled_agents`).Scan(&agents))
	assert.Equal(t, 0, agents, "an agent was enrolled on a token that could not be spent")

	w = darkEnroll(f.service(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// A reusable token is never spent, so the trigger does not touch it: the
	// control that says the trigger is the only thing failing above.
	fleet := f.seed(t, "mdm", time.Hour, true, false)
	_, err = redeemEnrollmentToken(f.ctx, f.db.Pool, fleet.plaintext)
	require.NoError(t, err)
}
