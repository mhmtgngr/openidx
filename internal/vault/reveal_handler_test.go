package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// handleReveal returns the only plaintext this service ever emits. What it
// decides is not whether the secret exists but which REFUSAL the caller gets,
// and the difference matters: a 403 carrying X-Step-Up-Required tells the
// console to run a second-factor challenge and retry, while a plain 403 means
// the caller is not permitted at all. Answer the first where the second is
// true and the console offers step-up as a route past an authorization denial.
// Nothing named this handler in a test.

func storeSecret(t *testing.T, s *Service, ctx context.Context, name, value string, requireStepUp bool) *SecretMeta {
	t.Helper()
	meta, err := s.Store(ctx, StoreInput{
		Name:          name,
		Type:          "generic",
		Value:         []byte(value),
		RequireStepUp: requireStepUp,
	})
	if err != nil {
		t.Fatalf("store %q: %v", name, err)
	}
	return meta
}

func doReveal(t *testing.T, s *Service, ctx context.Context, secretID, userID string, roles []string, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/vault/secrets/"+secretID+"/reveal", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(ctx)
	c.Params = gin.Params{{Key: "id", Value: secretID}}
	c.Set("user_id", userID)
	c.Set("roles", roles)
	s.handleReveal(c)
	return w
}

func TestHandleRevealRefusesWithoutAReason(t *testing.T) {
	s, ctx := newVaultService(t)
	meta := storeSecret(t, s, ctx, "db-root", "s3cr3t", false)

	w := doReveal(t, s, ctx, meta.ID, "u1", []string{"admin"}, `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (reveal without a stated reason)", w.Code)
	}
	if strings.Contains(w.Body.String(), "s3cr3t") {
		t.Fatal("the refusal leaked the secret")
	}
}

func TestHandleRevealDistinguishesForbiddenFromStepUp(t *testing.T) {
	s, ctx := newVaultService(t)

	plain := storeSecret(t, s, ctx, "ordinary", "value-1", false)
	gated := storeSecret(t, s, ctx, "high-value", "value-2", true)

	t.Run("no grant is a plain 403", func(t *testing.T) {
		w := doReveal(t, s, ctx, plain.ID, uuid.New().String(), []string{"user"}, `{"reason":"support call"}`)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if got := w.Header().Get("X-Step-Up-Required"); got != "" {
			t.Fatalf("X-Step-Up-Required = %q on an authorization denial; the console would offer step-up as a way past it", got)
		}
	})

	t.Run("step-up required is a 403 that says so", func(t *testing.T) {
		// Admin: past the grant check, and deliberately NOT exempt from the
		// step-up gate — the point is a fresh second factor on the action.
		w := doReveal(t, s, ctx, gated.ID, uuid.New().String(), []string{"admin"}, `{"reason":"incident 42"}`)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if w.Header().Get("X-Step-Up-Required") != "true" {
			t.Fatal("a step-up denial did not carry X-Step-Up-Required")
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body: %v", err)
		}
		if body["step_up_required"] != true {
			t.Fatalf("body = %v, want step_up_required:true", body)
		}
		if strings.Contains(w.Body.String(), "value-2") {
			t.Fatal("the refusal leaked the secret")
		}
	})

	t.Run("an unknown secret is 404, not 403", func(t *testing.T) {
		w := doReveal(t, s, ctx, uuid.New().String(), "u1", []string{"admin"}, `{"reason":"typo"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
	})
}

func TestHandleRevealReturnsThePlaintextAndRecordsTheCheckout(t *testing.T) {
	s, ctx := newVaultService(t)
	meta := storeSecret(t, s, ctx, "api-key", "correct-horse", false)
	principal := uuid.New().String()

	w := doReveal(t, s, ctx, meta.ID, principal, []string{"super_admin"}, `{"reason":"rotating the key"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s, want 200", w.Code, w.Body.String())
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Value != "correct-horse" {
		t.Fatalf("value = %q, want the stored plaintext", body.Value)
	}

	// A reveal is an event, not just a read: the checkout ledger is what makes
	// "who saw this secret, when, and why" answerable afterwards.
	var n int
	var reason string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(max(reason), '') FROM vault_checkouts
		 WHERE secret_id = $1 AND principal_id::text = $2 AND mode = 'reveal'`,
		meta.ID, principal).Scan(&n, &reason); err != nil {
		t.Fatalf("checkouts: %v", err)
	}
	if n != 1 {
		t.Fatalf("checkout rows = %d, want 1", n)
	}
	if reason != "rotating the key" {
		t.Fatalf("recorded reason = %q", reason)
	}
}

func TestHandleCheckoutsListsTheLedgerForASecret(t *testing.T) {
	s, ctx := newVaultService(t)
	meta := storeSecret(t, s, ctx, "shared", "v", false)
	principal := uuid.New().String()

	if w := doReveal(t, s, ctx, meta.ID, principal, []string{"admin"}, `{"reason":"first look"}`); w.Code != http.StatusOK {
		t.Fatalf("seed reveal: %d %s", w.Code, w.Body.String())
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/vault/secrets/"+meta.ID+"/checkouts", nil).WithContext(ctx)
	c.Params = gin.Params{{Key: "id", Value: meta.ID}}
	s.handleCheckouts(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "first look") {
		t.Fatalf("ledger did not carry the reason: %s", w.Body.String())
	}
	// The ledger is metadata about a reveal, never the value itself.
	if strings.Contains(w.Body.String(), `"value"`) || strings.Contains(w.Body.String(), "ciphertext") {
		t.Fatalf("the checkout ledger exposed a value/ciphertext field: %s", w.Body.String())
	}
}
