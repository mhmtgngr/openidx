package credentials

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// mysqlIdentRE constrains MySQL identifiers (target_user / target_host) to a safe
// character set, because those values are interpolated directly into ALTER USER
// DDL (MySQL cannot bind identifiers as ? parameters).
var mysqlIdentRE = regexp.MustCompile(`^[A-Za-z0-9_.%-]+$`)

// mysqlConf holds the parsed, validated fields from a mysql connector_config map.
type mysqlConf struct {
	host          string
	port          int
	dbname        string
	tls           bool
	adminSecretID string
	adminUsername string
	targetUser    string
	targetHost    string
}

// mysqlConfigFromMap parses and validates a MySQL connector_config map.
// Defaults: port=3306, target_host="%".
// Required: host, admin_secret_id, admin_username, target_user.
// target_user and target_host are validated against a safe identifier charset
// because they are interpolated into ALTER USER DDL.
func mysqlConfigFromMap(cfg map[string]any) (mysqlConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}

	host := str("host")
	adminSecretID := str("admin_secret_id")
	adminUsername := str("admin_username")
	targetUser := str("target_user")

	switch {
	case host == "":
		return mysqlConf{}, fmt.Errorf("mysql connector: missing required field %q", "host")
	case adminSecretID == "":
		return mysqlConf{}, fmt.Errorf("mysql connector: missing required field %q", "admin_secret_id")
	case adminUsername == "":
		return mysqlConf{}, fmt.Errorf("mysql connector: missing required field %q", "admin_username")
	case targetUser == "":
		return mysqlConf{}, fmt.Errorf("mysql connector: missing required field %q", "target_user")
	}

	// port: accept int, float64 (JSON), or string representations.
	port := 3306
	if raw, ok := cfg["port"]; ok {
		switch v := raw.(type) {
		case int:
			port = v
		case float64:
			port = int(v)
		case string:
			n, err := strconv.Atoi(v)
			if err != nil {
				return mysqlConf{}, fmt.Errorf("mysql connector: invalid port %q: %w", v, err)
			}
			port = n
		}
	}

	targetHost := str("target_host")
	if targetHost == "" {
		targetHost = "%"
	}

	if !mysqlIdentRE.MatchString(targetUser) {
		return mysqlConf{}, fmt.Errorf("mysql connector: invalid target_user %q: must match %s", targetUser, mysqlIdentRE.String())
	}
	if !mysqlIdentRE.MatchString(targetHost) {
		return mysqlConf{}, fmt.Errorf("mysql connector: invalid target_host %q: must match %s", targetHost, mysqlIdentRE.String())
	}

	tls, _ := cfg["tls"].(bool)

	return mysqlConf{
		host:          host,
		port:          port,
		dbname:        str("dbname"),
		tls:           tls,
		adminSecretID: adminSecretID,
		adminUsername: adminUsername,
		targetUser:    targetUser,
		targetHost:    targetHost,
	}, nil
}

// mysqlQuoteLiteral escapes s for a MySQL single-quoted string literal. Safe when
// NO_BACKSLASH_ESCAPES is OFF (Apply enforces that on the session). Rejects NUL.
func mysqlQuoteLiteral(s string) (string, error) {
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("mysql: password contains NUL byte")
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'", nil
}

// buildMySQLDSN constructs a DSN for the given user/password against conf's target.
// The password is set via mysql.Config (not string-concatenated); the resulting DSN
// must NEVER be logged.
func buildMySQLDSN(conf mysqlConf, user, password string) string {
	c := gomysql.NewConfig()
	c.User = user
	c.Passwd = password
	c.Net = "tcp"
	c.Addr = fmt.Sprintf("%s:%d", conf.host, conf.port)
	if conf.dbname != "" {
		c.DBName = conf.dbname
	}
	if conf.tls {
		c.TLSConfig = "true"
	} else {
		c.TLSConfig = "preferred"
	}
	return c.FormatDSN()
}

// mysqlRotator applies a MySQL user password rotation via ALTER USER.
type mysqlRotator struct{ vault vaultUser }

// NewMySQLRotator returns a Rotator that rotates a MySQL user's password,
// authenticating with a bootstrap admin credential resolved from the vault.
// vaultUser is satisfied by *vault.Service.
func NewMySQLRotator(v vaultUser) Rotator { return &mysqlRotator{vault: v} }

func (r *mysqlRotator) Type() string { return "mysql" }

// Apply resolves the admin credential from the vault, connects as the admin, and
// issues ALTER USER … IDENTIFIED BY '<escaped>'. MySQL cannot bind the password
// or identifiers as ? parameters, so: the identifiers are validated to a safe
// charset in mysqlConfigFromMap, and the password is escaped for a single-quoted
// literal (with NO_BACKSLASH_ESCAPES stripped from the session sql_mode so the
// backslash escaping in the literal is honoured). The DSN and DDL are never logged.
func (r *mysqlRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := mysqlConfigFromMap(cfg)
	if err != nil {
		return err
	}

	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return fmt.Errorf("mysql: resolve admin secret: %w", err)
	}
	defer zero(admin)

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// DSN is built from validated config + secret; never logged.
	db, err := sql.Open("mysql", buildMySQLDSN(conf, conf.adminUsername, string(admin)))
	if err != nil {
		return fmt.Errorf("mysql: admin open: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(cctx); err != nil {
		return fmt.Errorf("mysql: admin connect: %w", err)
	}

	// Pin a single physical connection: the SET SESSION sql_mode below only affects
	// the connection it runs on, so the ALTER must run on that SAME connection —
	// otherwise the *sql.DB pool could route them to different connections and the
	// NO_BACKSLASH_ESCAPES strip would not apply to the ALTER.
	conn, err := db.Conn(cctx)
	if err != nil {
		return fmt.Errorf("mysql: acquire conn: %w", err)
	}
	defer conn.Close()

	// Strip NO_BACKSLASH_ESCAPES so the backslash-escaping in the quoted literal
	// is interpreted as an escape (not a literal backslash).
	if _, err := conn.ExecContext(cctx,
		"SET SESSION sql_mode = REPLACE(@@SESSION.sql_mode, 'NO_BACKSLASH_ESCAPES', '')",
	); err != nil {
		return fmt.Errorf("mysql: set sql_mode: %w", err)
	}

	quoted, err := mysqlQuoteLiteral(string(newValue))
	if err != nil {
		return fmt.Errorf("mysql: quote password: %w", err)
	}

	// Identifiers validated to the safe charset; password is escaped-and-quoted.
	// Never log this DDL (it contains the new secret).
	ddl := fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY %s", conf.targetUser, conf.targetHost, quoted)
	if _, err := conn.ExecContext(cctx, ddl); err != nil {
		return fmt.Errorf("mysql: alter user: %w", err)
	}
	return nil
}

// Verify opens a new connection AS the target user using the new password.
// A successful connection + ping proves the rotation was applied.
func (r *mysqlRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := mysqlConfigFromMap(cfg)
	if err != nil {
		return err
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// DSN never logged.
	db, err := sql.Open("mysql", buildMySQLDSN(conf, conf.targetUser, string(newValue)))
	if err != nil {
		return fmt.Errorf("mysql: verify connect failed: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(cctx); err != nil {
		return fmt.Errorf("mysql: verify connect failed: %w", err)
	}
	return nil
}

// ValidateConfig satisfies ConfigValidator: the config is valid if it parses.
func (r *mysqlRotator) ValidateConfig(cfg map[string]any) error {
	_, err := mysqlConfigFromMap(cfg)
	return err
}
