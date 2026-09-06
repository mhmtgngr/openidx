package identity

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
)

// The v10 seed migration creates admin@openidx.local (fixed id below) with a
// published default password so a fresh install has a way in.
// config.ValidateProduction() cannot see database state, so this gate runs at
// service startup after migrations: production refuses to serve while that
// password still authenticates. The check verifies the stored hash against
// the known plaintext with the same verifier the login path uses, rather than
// pinning the seed's hash bytes — a re-hash of the same password must not
// slip through.
const (
	seededAdminID    = "00000000-0000-0000-0000-000000000001"
	seededAdminEmail = "admin@openidx.local"
	// seededAdminPassword is the published default this gate exists to
	// retire. It appears in source only to prove it no longer works.
	seededAdminPassword = "Admin@123"
)

type seededAdminRow struct {
	ID           string
	Email        string
	Enabled      bool
	PasswordHash string
}

// EnsureDefaultAdminRotated returns an error when an enabled account still
// accepts the seeded default admin password. A disabled account that still
// carries it only warns: the operator has already cut off the login path, and
// refusing to boot over it would punish a legitimate remediation.
func EnsureDefaultAdminRotated(ctx context.Context, db *database.PostgresDB, logger *zap.Logger) error {
	rows, err := db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide startup gate: the seeded admin must be found whichever org it landed in
		`SELECT id, email, COALESCE(enabled, false), COALESCE(password_hash, '')
		   FROM users
		  WHERE id = $1 OR email = $2`,
		seededAdminID, seededAdminEmail)
	if err != nil {
		// Fail closed: a gate that cannot look is a gate that cannot vouch.
		return fmt.Errorf("default-admin check: query users: %w", err)
	}
	defer rows.Close()

	var admins []seededAdminRow
	for rows.Next() {
		var a seededAdminRow
		if err := rows.Scan(&a.ID, &a.Email, &a.Enabled, &a.PasswordHash); err != nil {
			return fmt.Errorf("default-admin check: scan: %w", err)
		}
		admins = append(admins, a)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("default-admin check: read users: %w", err)
	}
	return defaultAdminVerdict(admins, logger)
}

// defaultAdminVerdict is the pure decision over the fetched rows, split out
// so it can be tested without a database.
func defaultAdminVerdict(admins []seededAdminRow, logger *zap.Logger) error {
	for _, a := range admins {
		if a.PasswordHash == "" {
			continue
		}
		ok, _, err := pwhash.Verify(a.PasswordHash, seededAdminPassword)
		if err != nil || !ok {
			continue
		}
		if !a.Enabled {
			logger.Warn("seeded admin account is disabled but still carries the default password; set a real one before ever re-enabling it",
				zap.String("user_id", a.ID), zap.String("email", a.Email))
			continue
		}
		return fmt.Errorf(
			"account %s (%s) still accepts the seeded default password; rotate it (console: Users → Set password, or POST /api/v1/identity/users/%s/set-password) before serving production traffic",
			a.Email, a.ID, a.ID)
	}
	return nil
}
