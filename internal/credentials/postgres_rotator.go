package credentials

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// pgConf holds the parsed, validated fields from a postgres connector_config map.
type pgConf struct {
	host          string
	port          int
	dbname        string
	sslmode       string
	adminSecretID string
	adminUsername string
	targetRole    string
}

// pgConfigFromMap parses and validates a PostgreSQL connector_config map.
// Defaults: port=5432, sslmode="require".
// Required: host, dbname, admin_secret_id, admin_username, target_role.
func pgConfigFromMap(cfg map[string]any) (pgConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}

	host := str("host")
	dbname := str("dbname")
	adminSecretID := str("admin_secret_id")
	adminUsername := str("admin_username")
	targetRole := str("target_role")

	switch {
	case host == "":
		return pgConf{}, fmt.Errorf("postgres connector: missing required field %q", "host")
	case dbname == "":
		return pgConf{}, fmt.Errorf("postgres connector: missing required field %q", "dbname")
	case adminSecretID == "":
		return pgConf{}, fmt.Errorf("postgres connector: missing required field %q", "admin_secret_id")
	case adminUsername == "":
		return pgConf{}, fmt.Errorf("postgres connector: missing required field %q", "admin_username")
	case targetRole == "":
		return pgConf{}, fmt.Errorf("postgres connector: missing required field %q", "target_role")
	}

	// port: accept int, float64 (JSON), or string representations.
	port := 5432
	if raw, ok := cfg["port"]; ok {
		switch v := raw.(type) {
		case int:
			port = v
		case float64:
			port = int(v)
		case string:
			n, err := strconv.Atoi(v)
			if err != nil {
				return pgConf{}, fmt.Errorf("postgres connector: invalid port %q: %w", v, err)
			}
			port = n
		}
	}

	sslmode := str("sslmode")
	if sslmode == "" {
		sslmode = "require"
	}

	return pgConf{
		host:          host,
		port:          port,
		dbname:        dbname,
		sslmode:       sslmode,
		adminSecretID: adminSecretID,
		adminUsername: adminUsername,
		targetRole:    targetRole,
	}, nil
}

// pgQuoteConnValue wraps a conninfo value in single quotes and backslash-escapes
// any single quotes or backslashes within, per the libpq conninfo quoting rules.
// This ensures passwords with special characters are transmitted safely over the
// key=value conninfo string without breaking the parser.
func pgQuoteConnValue(s string) string {
	// Escape backslashes first (must come before quote-escaping).
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// buildAdminDSN returns a libpq key=value conninfo string for the admin connection.
// The password is quoted via pgQuoteConnValue so special characters are safe.
// This DSN must NEVER be logged.
func buildAdminDSN(conf pgConf, adminPassword string) string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		conf.host,
		conf.port,
		conf.dbname,
		conf.adminUsername,
		pgQuoteConnValue(adminPassword),
		conf.sslmode,
	)
}

// buildTargetDSN returns a libpq key=value conninfo string to authenticate as
// the target role with the new password. Used by Verify to confirm rotation.
// This DSN must NEVER be logged.
func buildTargetDSN(conf pgConf, targetPassword string) string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		conf.host,
		conf.port,
		conf.dbname,
		conf.targetRole,
		pgQuoteConnValue(targetPassword),
		conf.sslmode,
	)
}

// postgresRotator applies a PostgreSQL role password rotation via ALTER ROLE.
type postgresRotator struct{ vault vaultUser }

// NewPostgresRotator returns a Rotator that rotates a PostgreSQL role's password,
// authenticating with a bootstrap admin credential resolved from the vault.
// vaultUser is satisfied by *vault.Service.
func NewPostgresRotator(v vaultUser) Rotator { return &postgresRotator{vault: v} }

func (r *postgresRotator) Type() string { return "postgres" }

// Apply resolves the admin credential from the vault, connects as the admin,
// and issues ALTER ROLE … WITH PASSWORD using server-side format(%I/%L) quoting
// so the new password is never string-concatenated into DDL.
func (r *postgresRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := pgConfigFromMap(cfg)
	if err != nil {
		return err
	}

	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return fmt.Errorf("postgres: resolve admin secret: %w", err)
	}
	defer zero(admin)

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// DSN is built from validated config + secret; never logged.
	conn, err := pgx.Connect(cctx, buildAdminDSN(conf, string(admin)))
	if err != nil {
		return fmt.Errorf("postgres: admin connect: %w", err)
	}
	defer conn.Close(context.Background())

	// Build the ALTER ROLE DDL server-side using PostgreSQL's format() with
	// %I (identifier quoting) for the role name and %L (literal quoting) for
	// the password. The new password is passed as a bound parameter ($2), so
	// it is never concatenated into a string on the client side.
	var ddl string
	if err := conn.QueryRow(cctx,
		`SELECT format('ALTER ROLE %I WITH PASSWORD %L', $1::text, $2::text)`,
		conf.targetRole, string(newValue),
	).Scan(&ddl); err != nil {
		return fmt.Errorf("postgres: build ddl: %w", err)
	}

	if _, err := conn.Exec(cctx, ddl); err != nil {
		return fmt.Errorf("postgres: alter role: %w", err)
	}
	return nil
}

// Verify connects to the database AS the target role using the new password.
// A successful connection + ping proves the rotation was applied.
func (r *postgresRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := pgConfigFromMap(cfg)
	if err != nil {
		return err
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// DSN never logged.
	conn, err := pgx.Connect(cctx, buildTargetDSN(conf, string(newValue)))
	if err != nil {
		return fmt.Errorf("postgres: verify connect failed: %w", err)
	}
	defer conn.Close(context.Background())

	return conn.Ping(cctx)
}

// ValidateConfig satisfies ConfigValidator: the config is valid if it parses.
func (r *postgresRotator) ValidateConfig(cfg map[string]any) error {
	_, err := pgConfigFromMap(cfg)
	return err
}
