package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// SIGN-IN ADDRESSES AN ADMINISTRATOR GIVES AN ACCOUNT (migration 266).
//
// The sign-in lookup (resolveLoginUser) reads these in the same layer as
// users.email and users.mail. They exist because the directory sync owns
// users.mail (it rewrites it every run) and a local account has no directory.
//
// Only an administrator writes them, and never the account holder: the address
// decides which account a person is signing in to, so letting a user add one to
// their own account, or worse to someone else's, would be the first step of an
// account takeover. The routes are therefore NOT in isIdentitySelfService.

// maxLoginAddressesPerUser bounds the list: one person has a handful of
// addresses, and a long list is a mistake or an attempt to squat addresses.
const maxLoginAddressesPerUser = 5

var (
	errLoginAddressFormat = errors.New("not a usable sign-in address")
	errLoginAddressInUse  = errors.New("the address already belongs to another account")
	errLoginAddressLimit  = errors.New("the account already has the most sign-in addresses allowed")
	errLoginAddressUser   = errors.New("no such account")
)

// normalizeLoginAddress is the stored form of what an administrator typed:
// trimmed and lower-cased (the table's CHECK demands exactly that), one "@" with
// something on both sides, nothing that is whitespace, a control character or
// punctuation an address list would split on.
func normalizeLoginAddress(raw string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(raw))
	if a == "" || len(a) > 255 {
		return "", errLoginAddressFormat
	}
	for _, r := range a {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`<>,;:"'\()[]`, r) {
			return "", errLoginAddressFormat
		}
	}
	local, domain, ok := strings.Cut(a, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", errLoginAddressFormat
	}
	return a, nil
}

// loginAddress is one administrator-given address as the API shows it.
type loginAddress struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy *string   `json:"created_by,omitempty"`
}

// addLoginAddress gives the account an address. created is false when the
// account already had it (the call is idempotent). An address that is another
// account's username, email, mail or administrator-given address is refused;
// the account's OWN email or mail is allowed, so the address keeps working if a
// later directory sync changes them.
//
// The check and the insert run in one transaction with the account row locked,
// which also makes the per-account limit exact. The unique index is the backstop
// against two administrators adding the same address to two accounts at once.
func (s *Service) addLoginAddress(ctx context.Context, userID, raw, actorID string) (addr loginAddress, created bool, err error) {
	address, err := normalizeLoginAddress(raw)
	if err != nil {
		return addr, false, err
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return addr, false, err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return addr, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var one int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM users WHERE id = $1 AND org_id = $2 FOR UPDATE`, userID, org.ID).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return addr, false, errLoginAddressUser
		}
		return addr, false, err
	}

	err = tx.QueryRow(ctx, `
		SELECT id::text, address, created_at FROM user_login_addresses
		WHERE org_id = $1 AND user_id = $2 AND address = $3`, org.ID, userID, address).
		Scan(&addr.ID, &addr.Address, &addr.CreatedAt)
	if err == nil {
		return addr, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return addr, false, err
	}

	var taken bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE org_id = $1 AND id <> $2
			  AND (lower(username) = $3 OR lower(email) = $3 OR lower(mail) = $3)
		) OR EXISTS (
			SELECT 1 FROM user_login_addresses WHERE org_id = $1 AND user_id <> $2 AND address = $3
		)`, org.ID, userID, address).Scan(&taken); err != nil {
		return addr, false, err
	}
	if taken {
		return addr, false, errLoginAddressInUse
	}

	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM user_login_addresses WHERE org_id = $1 AND user_id = $2`, org.ID, userID).Scan(&n); err != nil {
		return addr, false, err
	}
	if n >= maxLoginAddressesPerUser {
		return addr, false, errLoginAddressLimit
	}

	var createdBy any
	if actorID != "" && actorID != "system" {
		createdBy = actorID
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO user_login_addresses (org_id, user_id, address, created_by)
		VALUES ($1, $2, $3, $4) RETURNING id::text, address, created_at`,
		org.ID, userID, address, createdBy).Scan(&addr.ID, &addr.Address, &addr.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return addr, false, errLoginAddressInUse
		}
		return addr, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return addr, false, err
	}
	return addr, true, nil
}

// removeLoginAddress deletes one address of one account. It reports whether a
// row was removed and the address it held (for the audit record).
func (s *Service) removeLoginAddress(ctx context.Context, userID, addrID string) (address string, removed bool, err error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", false, err
	}
	err = s.db.Pool.QueryRow(ctx, `
		DELETE FROM user_login_addresses
		WHERE id = $1 AND user_id = $2 AND org_id = $3 RETURNING address`,
		addrID, userID, org.ID).Scan(&address)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return address, true, nil
}

// listLoginAddresses is what the console shows for an account: the address the
// account already signs in with by itself (email, the directory's mail) and the
// administrator-given list.
func (s *Service) listLoginAddresses(ctx context.Context, userID string) (email, mail string, list []loginAddress, err error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", "", nil, err
	}
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(email, ''), COALESCE(mail, '') FROM users WHERE id = $1 AND org_id = $2`,
		userID, org.ID).Scan(&email, &mail); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil, errLoginAddressUser
		}
		return "", "", nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, address, created_at, created_by::text FROM user_login_addresses
		WHERE org_id = $1 AND user_id = $2 ORDER BY created_at, address`, org.ID, userID)
	if err != nil {
		return "", "", nil, err
	}
	defer rows.Close()
	list = []loginAddress{}
	for rows.Next() {
		var a loginAddress
		if err := rows.Scan(&a.ID, &a.Address, &a.CreatedAt, &a.CreatedBy); err != nil {
			return "", "", nil, err
		}
		list = append(list, a)
	}
	return email, mail, list, rows.Err()
}

func (s *Service) handleListLoginAddresses(c *gin.Context) {
	userID := c.Param("id")
	email, mail, list, err := s.listLoginAddresses(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, errLoginAddressUser) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		s.logger.Error("failed to list sign-in addresses", logsafe.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": email, "mail": mail, "addresses": list})
}

func (s *Service) handleAddLoginAddress(c *gin.Context) {
	userID := c.Param("id")
	var req struct {
		Address string `json:"address"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_address"})
		return
	}
	actor := getActorID(c)
	addr, created, err := s.addLoginAddress(c.Request.Context(), userID, req.Address, actor)
	switch {
	case errors.Is(err, errLoginAddressFormat):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_address"})
		return
	case errors.Is(err, errLoginAddressUser):
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	case errors.Is(err, errLoginAddressInUse):
		// No account is named: the address is somebody's, and who is not the
		// administrator's to learn from a refusal.
		c.JSON(http.StatusConflict, gin.H{"error": "address_in_use"})
		return
	case errors.Is(err, errLoginAddressLimit):
		c.JSON(http.StatusConflict, gin.H{"error": "too_many"})
		return
	case err != nil:
		s.logger.Error("failed to add sign-in address", logsafe.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !created {
		c.JSON(http.StatusOK, addr)
		return
	}
	s.logAuditEvent(auditCtx(c), "identity", "user_management", "user.login_address_added", "success",
		actor, userID, "user", map[string]interface{}{"address": addr.Address})
	c.JSON(http.StatusCreated, addr)
}

func (s *Service) handleRemoveLoginAddress(c *gin.Context) {
	userID, addrID := c.Param("id"), c.Param("addrId")
	address, removed, err := s.removeLoginAddress(c.Request.Context(), userID, addrID)
	if err != nil {
		s.logger.Error("failed to remove sign-in address", logsafe.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !removed {
		c.JSON(http.StatusNotFound, gin.H{"error": "address not found"})
		return
	}
	s.logAuditEvent(auditCtx(c), "identity", "user_management", "user.login_address_removed", "success",
		getActorID(c), userID, "user", map[string]interface{}{"address": address})
	c.Status(http.StatusNoContent)
}
