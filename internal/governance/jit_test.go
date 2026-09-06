// Package governance provides unit tests for JIT access functionality.
package governance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Ten of the cases in this file used to be one unconditional t.Skip each --
// five of them saying "validation test - but still needs service init,
// skipping for now". That was not true when it was written and is not true
// now: RequestElevation validates the duration and the required fields BEFORE
// it resolves an organization or touches the database, so the validation cases
// need a JITService with a nil pool and nothing else.
//
// The five DB-backed ones were skipped as "DB mock not available - requires
// integration test", while this package has carried setupTestDB (container,
// with the OPENIDX_TEST_DATABASE_URL escape hatch) the whole time.
//
// JIT elevation hands a user a privileged role for a window. The bounds are
// the control -- a 30-second minimum makes the audit trail useless and a
// 30-day maximum is not elevation, it is a grant -- and nothing was checking
// that either bound held.

const (
	jitOrg  = "aaaa1111-0000-0000-0000-00000000000a"
	jitUser = "bbbb2222-0000-0000-0000-000000000001"
	jitRole = "cccc3333-0000-0000-0000-000000000001"
)

const jitSchema = `
CREATE TABLE roles (
    id     UUID PRIMARY KEY,
    name   TEXT NOT NULL,
    org_id UUID NOT NULL
);

CREATE TABLE jit_grants (
    id            UUID PRIMARY KEY,
    user_id       UUID NOT NULL,
    role_id       UUID NOT NULL,
    role_name     TEXT NOT NULL,
    granted_by    TEXT,
    justification TEXT,
    duration      TEXT,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT,
    status        TEXT NOT NULL,
    org_id        UUID NOT NULL
);`

// validationOnlyJIT has no database on purpose: every case that uses it must
// be refused before RequestElevation reaches one. If a check is ever moved
// after the org lookup, these panic rather than quietly passing.
func validationOnlyJIT() *JITService {
	return NewJITService(nil, zap.NewNop())
}

func TestJITRequestElevationValidation(t *testing.T) {
	svc := validationOnlyJIT()
	ctx := context.Background()
	valid := JITRequest{
		UserID:        jitUser,
		RoleID:        jitRole,
		Duration:      time.Hour,
		Justification: "incident 4471",
		RequestedBy:   "manager-1",
	}

	t.Run("shorter than the minimum is refused", func(t *testing.T) {
		req := valid
		req.Duration = MinimumJITDuration - time.Second
		_, err := svc.RequestElevation(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least")
	})

	t.Run("longer than the maximum is refused", func(t *testing.T) {
		req := valid
		req.Duration = MaximumJITDuration + time.Second
		_, err := svc.RequestElevation(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not exceed")
	})

	// The bounds are inclusive. Exactly-at-the-limit is the value an operator
	// picks when they read the documentation, so an off-by-one here refuses
	// the most common request there is.
	for name, d := range map[string]time.Duration{
		"exactly the minimum": MinimumJITDuration,
		"exactly the maximum": MaximumJITDuration,
	} {
		t.Run(name+" is accepted by the bounds check", func(t *testing.T) {
			req := valid
			req.Duration = d
			_, err := svc.RequestElevation(ctx, req)
			// It still fails -- there is no org on this context -- but it must
			// not fail for the duration.
			require.Error(t, err)
			if strings.Contains(err.Error(), "at least") || strings.Contains(err.Error(), "not exceed") {
				t.Fatalf("%v was refused by the bounds check: %v", d, err)
			}
		})
	}

	for field, mutate := range map[string]func(*JITRequest){
		"user_id":       func(r *JITRequest) { r.UserID = "" },
		"role_id":       func(r *JITRequest) { r.RoleID = "" },
		"justification": func(r *JITRequest) { r.Justification = "" },
	} {
		t.Run("a missing "+field+" is refused", func(t *testing.T) {
			req := valid
			mutate(&req)
			_, err := svc.RequestElevation(ctx, req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
		})
	}

	// Justification is not paperwork. It is the only field that says WHY a
	// standing privilege was handed out, and it is what an auditor reads back.
	t.Run("a blank justification is not a justification", func(t *testing.T) {
		req := valid
		req.Justification = ""
		_, err := svc.RequestElevation(ctx, req)
		require.Error(t, err)
	})
}

func TestJITRequestElevationAgainstADatabase(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: jitOrg})
	if _, err := db.Pool.Exec(ctx, jitSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1, 'dba', $2)`, jitRole, jitOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	svc := NewJITService(db, zap.NewNop())
	base := JITRequest{
		UserID:        jitUser,
		RoleID:        jitRole,
		Duration:      2 * time.Hour,
		Justification: "incident 4471",
		RequestedBy:   "manager-1",
	}

	t.Run("a grant expires at the requested duration", func(t *testing.T) {
		before := time.Now()
		grant, err := svc.RequestElevation(ctx, base)
		require.NoError(t, err)
		after := time.Now()

		require.NotNil(t, grant)
		assert.Equal(t, "active", grant.Status)
		assert.Equal(t, "dba", grant.RoleName, "the grant records the role NAME, which is what an audit row shows")

		// Bracket the mint rather than comparing against a single Now(): the
		// expiry is computed inside the call.
		if grant.ExpiresAt.Before(before.Add(base.Duration)) || grant.ExpiresAt.After(after.Add(base.Duration)) {
			t.Errorf("expires_at %s is outside [%s, %s]",
				grant.ExpiresAt, before.Add(base.Duration), after.Add(base.Duration))
		}

		// And it is persisted, not just returned.
		var status string
		var expires time.Time
		require.NoError(t, db.Pool.QueryRow(ctx,
			`SELECT status, expires_at FROM jit_grants WHERE id = $1 AND org_id = $2`,
			grant.ID, jitOrg).Scan(&status, &expires))
		assert.Equal(t, "active", status)
		assert.WithinDuration(t, grant.ExpiresAt, expires, time.Second)
	})

	t.Run("a second live grant for the same role is refused", func(t *testing.T) {
		// The first grant from the case above is still active. Stacking a
		// second one would make revocation ambiguous: revoking the elevation
		// would leave the other row live and the privilege in place.
		_, err := svc.RequestElevation(ctx, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already has an active JIT grant")

		var n int
		require.NoError(t, db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM jit_grants WHERE user_id = $1 AND role_id = $2 AND org_id = $3`,
			jitUser, jitRole, jitOrg).Scan(&n))
		assert.Equal(t, 1, n, "the refused request still wrote a grant row")
	})

	t.Run("an unknown role is refused", func(t *testing.T) {
		req := base
		req.UserID = "bbbb2222-0000-0000-0000-000000000002"
		req.RoleID = "cccc3333-0000-0000-0000-0000000000ff"
		_, err := svc.RequestElevation(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role not found")
	})

	// The duplicate check and the role lookup are both org-scoped. Another
	// tenant's role must not be electable, and another tenant's live grant must
	// not block this one.
	t.Run("the role must belong to the caller's organization", func(t *testing.T) {
		const otherOrg = "aaaa1111-0000-0000-0000-00000000000b"
		otherCtx := orgctx.With(context.Background(), orgctx.Org{ID: otherOrg})
		req := base
		req.UserID = "bbbb2222-0000-0000-0000-000000000003"
		_, err := svc.RequestElevation(otherCtx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role not found",
			"a role from another tenant was electable for JIT elevation")
	})
}

func TestJITConstants(t *testing.T) {
	// These bounds are quoted in docs/docs/guide/pam.md and shown in the
	// console's JIT dialog. Changing one is a product decision, not a tidy-up.
	assert.Equal(t, 30*time.Second, JITExpiryCheckInterval)
	assert.Equal(t, 15*time.Minute, MinimumJITDuration)
	assert.Equal(t, 8*time.Hour, MaximumJITDuration)
}
