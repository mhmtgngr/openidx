// Package governance provides unit tests for JIT access functionality
package governance

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// mockDB is a minimal mock for testing
type mockJITDB struct {
	database.PostgresDB
	grants      []JITGrant
	roles       map[string]string // roleID -> roleName
	activeError bool
	queryError  bool
}

func (m *mockJITDB) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return &mockRow{m: m, ctx: ctx, query: query, args: args}
}

func (m *mockJITDB) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	if m.queryError {
		return nil, assert.AnError
	}
	return &mockRows{m: m, grants: m.grants}, nil
}

func (m *mockJITDB) Exec(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return &mockResult{rowsAffected: 1}, nil
}

type mockRow struct {
	m       *mockJITDB
	ctx     context.Context
	query   string
	args    []interface{}
	scanned bool
}

func (r *mockRow) Scan(dest ...interface{}) error {
	r.scanned = true
	query := r.query

	// Check for active grant query
	if containsJIT(query, "SELECT COUNT(*)") && containsJIT(query, "jit_grants") {
		count := 0
		for _, g := range r.m.grants {
			if g.Status == "active" && g.ExpiresAt.After(time.Now()) {
				if len(r.args) >= 2 {
					userID := asString(r.args[0])
					roleID := asString(r.args[1])
					if g.UserID == userID && g.RoleID == roleID {
						count = 1
					}
				}
			}
		}
		if len(dest) > 0 {
			if p, ok := dest[0].(*int); ok {
				*p = count
			}
		}
		return nil
	}

	// Check for existing active grant
	if containsJIT(query, "SELECT id") && containsJIT(query, "jit_grants") && containsJIT(query, "status = 'active'") {
		for _, g := range r.m.grants {
			if g.Status == "active" && g.ExpiresAt.After(time.Now()) {
				if len(r.args) >= 2 {
					userID := asString(r.args[0])
					roleID := asString(r.args[1])
					if g.UserID == userID && g.RoleID == roleID {
						if len(dest) > 0 {
							if p, ok := dest[0].(*string); ok {
								*p = g.ID
							}
						}
						return nil
					}
				}
			}
		}
		return assert.AnError
	}

	// Check for role lookup
	if containsJIT(query, "SELECT name FROM roles") {
		roleID := asString(r.args[0])
		if name, ok := r.m.roles[roleID]; ok {
			if len(dest) > 0 {
				if p, ok := dest[0].(*string); ok {
					*p = name
				}
			}
			return nil
		}
		return assert.AnError
	}

	return nil
}

type mockRows struct {
	m      *mockJITDB
	grants []JITGrant
	index  int
}

func (r *mockRows) Close() {}

func (r *mockRows) Next() bool {
	r.index++
	return r.index <= len(r.grants)
}

func (r *mockRows) Scan(dest ...interface{}) error {
	if r.index > len(r.grants) {
		return assert.AnError
	}
	g := r.grants[r.index-1]
	// Scan fields in order: id, user_id, role_id, role_name
	if len(dest) >= 4 {
		if p, ok := dest[0].(*string); ok {
			*p = g.ID
		}
		if p, ok := dest[1].(*string); ok {
			*p = g.UserID
		}
		if p, ok := dest[2].(*string); ok {
			*p = g.RoleID
		}
		if p, ok := dest[3].(*string); ok {
			*p = g.RoleName
		}
	}
	return nil
}

type mockResult struct {
	rowsAffected int64
}

func (m *mockResult) RowsAffected() int64 {
	return m.rowsAffected
}

func containsJIT(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findInStringJIT(s, substr))
}

func findInStringJIT(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestJITRequestElevation(t *testing.T) {
	t.Run("valid duration within bounds", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles: map[string]string{
				"role-1": "Admin",
			},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      1 * time.Hour,
			Justification: "Need access for emergency deployment",
			RequestedBy:   "user-1",
		}

		// Patch the service to use our mock
		grant, err := svc.RequestElevation(context.Background(), req)

		require.NoError(t, err)
		assert.NotNil(t, grant)
		assert.Equal(t, "user-1", grant.UserID)
		assert.Equal(t, "role-1", grant.RoleID)
		assert.Equal(t, "active", grant.Status)
		assert.Equal(t, 1*time.Hour, grant.Duration)
	})

	t.Run("duration too short - less than 15 minutes", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles:  map[string]string{},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      10 * time.Minute,
			Justification: "Too short",
			RequestedBy:   "user-1",
		}

		_, err := svc.RequestElevation(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least")
	})

	t.Run("duration too long - more than 8 hours", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles:  map[string]string{},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      9 * time.Hour,
			Justification: "Too long",
			RequestedBy:   "user-1",
		}

		_, err := svc.RequestElevation(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not exceed")
	})

	t.Run("missing required fields", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles:  map[string]string{},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		t.Run("missing user_id", func(t *testing.T) {
			req := JITRequest{
				RoleID:        "role-1",
				Duration:      1 * time.Hour,
				Justification: "test",
				RequestedBy:   "user-1",
			}
			_, err := svc.RequestElevation(context.Background(), req)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "user_id")
		})

		t.Run("missing role_id", func(t *testing.T) {
			req := JITRequest{
				UserID:        "user-1",
				Duration:      1 * time.Hour,
				Justification: "test",
				RequestedBy:   "user-1",
			}
			_, err := svc.RequestElevation(context.Background(), req)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "role_id")
		})

		t.Run("missing justification", func(t *testing.T) {
			req := JITRequest{
				UserID:      "user-1",
				RoleID:      "role-1",
				Duration:    1 * time.Hour,
				RequestedBy: "user-1",
			}
			_, err := svc.RequestElevation(context.Background(), req)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "justification")
		})
	})

	t.Run("duplicate active grant for same user and role", func(t *testing.T) {
		existingGrant := JITGrant{
			ID:        "grant-1",
			UserID:    "user-1",
			RoleID:    "role-1",
			RoleName:  "Admin",
			Status:    "active",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		db := &mockJITDB{
			grants: []JITGrant{existingGrant},
			roles: map[string]string{
				"role-1": "Admin",
			},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      1 * time.Hour,
			Justification: "Duplicate request",
			RequestedBy:   "user-1",
		}

		_, err := svc.RequestElevation(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already has an active")
	})
}

func TestJITGrantTiming(t *testing.T) {
	t.Run("grant expires at correct time", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles: map[string]string{
				"role-1": "Admin",
			},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		duration := 2 * time.Hour
		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      duration,
			Justification: "Test",
			RequestedBy:   "user-1",
		}

		grant, err := svc.RequestElevation(context.Background(), req)
		require.NoError(t, err)

		// Check that expiration time is approximately duration from now
		expectedExpiry := time.Now().Add(duration)
		diff := grant.ExpiresAt.Sub(expectedExpiry)
		assert.Less(t, diff.Abs(), 5*time.Second, "Expiration time should be within ~5 seconds of expected")
	})

	t.Run("minimum duration boundary", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles: map[string]string{
				"role-1": "Admin",
			},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      MinimumJITDuration,
			Justification: "Test",
			RequestedBy:   "user-1",
		}

		grant, err := svc.RequestElevation(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, MinimumJITDuration, grant.Duration)
	})

	t.Run("maximum duration boundary", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles: map[string]string{
				"role-1": "Admin",
			},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		req := JITRequest{
			UserID:        "user-1",
			RoleID:        "role-1",
			Duration:      MaximumJITDuration,
			Justification: "Test",
			RequestedBy:   "user-1",
		}

		grant, err := svc.RequestElevation(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, MaximumJITDuration, grant.Duration)
	})
}

func TestJITValidateGrant(t *testing.T) {
	t.Run("valid active grant", func(t *testing.T) {
		activeGrant := JITGrant{
			ID:        "grant-1",
			UserID:    "user-1",
			RoleID:    "role-1",
			RoleName:  "Admin",
			Status:    "active",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		db := &mockJITDB{
			grants: []JITGrant{activeGrant},
			roles:  map[string]string{},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		valid, err := svc.ValidateGrant(context.Background(), "user-1", "role-1")
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("no grant exists", func(t *testing.T) {
		db := &mockJITDB{
			grants: []JITGrant{},
			roles:  map[string]string{},
		}
		logger := zap.NewNop()
		svc := NewJITService(&database.PostgresDB{}, logger)
		svc.db = db

		valid, err := svc.ValidateGrant(context.Background(), "user-1", "role-1")
		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestJITExpiryCheckInterval(t *testing.T) {
	t.Run("interval is 30 seconds", func(t *testing.T) {
		assert.Equal(t, 30*time.Second, JITExpiryCheckInterval)
	})
}

func TestMinimumJITDuration(t *testing.T) {
	t.Run("minimum is 15 minutes", func(t *testing.T) {
		assert.Equal(t, 15*time.Minute, MinimumJITDuration)
	})
}

func TestMaximumJITDuration(t *testing.T) {
	t.Run("maximum is 8 hours", func(t *testing.T) {
		assert.Equal(t, 8*time.Hour, MaximumJITDuration)
	})
}
