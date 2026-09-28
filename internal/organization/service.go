// Package organization provides multi-tenant organization management functionality
package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Organization represents a tenant organization in the system
type Organization struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Domain          *string                `json:"domain,omitempty"`
	Plan            string                 `json:"plan"`
	Status          string                 `json:"status"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
	MaxUsers        int                    `json:"max_users"`
	MaxApplications int                    `json:"max_applications"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	MemberCount     int                    `json:"member_count,omitempty"`
}

// OrganizationMember represents a user's membership in an organization
type OrganizationMember struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           string    `json:"role"`
	JoinedAt       time.Time `json:"joined_at"`
	InvitedBy      *string   `json:"invited_by,omitempty"`
	UserEmail      string    `json:"user_email"`
	UserName       string    `json:"user_name"`
}

// Service provides organization management operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new organization service instance
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "organization")),
	}
}

// CreateOrganization creates a new organization and adds the creator as the owner
func (s *Service) CreateOrganization(ctx context.Context, org *Organization, creatorUserID string) error {
	org.ID = uuid.New().String()
	now := time.Now().UTC()
	org.CreatedAt = now
	org.UpdatedAt = now

	if org.Status == "" {
		org.Status = "active"
	}
	if org.Plan == "" {
		org.Plan = "free"
	}

	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO organizations (id, name, slug, domain, plan, status, settings, max_users, max_applications, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		org.ID, org.Name, org.Slug, org.Domain, org.Plan, org.Status, settingsJSON,
		org.MaxUsers, org.MaxApplications, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert organization: %w", err)
	}

	memberID := uuid.New().String()
	_, err = tx.Exec(ctx,
		`INSERT INTO organization_members (id, organization_id, user_id, role, joined_at, invited_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		memberID, org.ID, creatorUserID, "owner", now, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to add creator as owner: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Info("organization created",
		zap.String("org_id", org.ID),
		zap.String("creator_id", creatorUserID),
	)

	return nil
}

// GetOrganization retrieves an organization by ID with its member count
func (s *Service) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	var org Organization
	var settingsBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at,
		        COUNT(m.id) AS member_count
		 FROM organizations o
		 LEFT JOIN organization_members m ON o.id = m.organization_id
		 WHERE o.id = $1
		 GROUP BY o.id`, orgID,
	).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
		&settingsBytes, &org.MaxUsers, &org.MaxApplications,
		&org.CreatedAt, &org.UpdatedAt, &org.MemberCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if settingsBytes != nil {
		if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &org, nil
}

// GetOrganizationBySlug retrieves an organization by its slug.
//
// The slug is the URL-safe handle used by the tenant-resolver middleware
// to translate an X-Org-Slug header (set by the gateway from the
// subdomain) into an org row. This method intentionally does not join
// organization_members for a member count — the tenant resolver does
// not need it, and avoiding the join makes this the cheap hot-path
// query that runs on every browser-facing request.
//
// Returns the underlying pgx error wrapped with %w on failure; the
// caller can `errors.Is(err, pgx.ErrNoRows)` to distinguish
// not-found from a transport error. (The OrgLookup adapter does
// exactly that.)
func (s *Service) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	var org Organization
	var settingsBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, slug, domain, plan, status, settings,
		        max_users, max_applications, created_at, updated_at
		 FROM organizations
		 WHERE slug = $1`, slug,
	).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
		&settingsBytes, &org.MaxUsers, &org.MaxApplications,
		&org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization by slug: %w", err)
	}

	if settingsBytes != nil {
		if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &org, nil
}

// ListOrganizations returns a paginated list of organizations with a total count
func (s *Service) ListOrganizations(ctx context.Context, limit, offset int) ([]Organization, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at,
		        COUNT(m.id) AS member_count
		 FROM organizations o
		 LEFT JOIN organization_members m ON o.id = m.organization_id
		 GROUP BY o.id
		 ORDER BY o.created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var org Organization
		var settingsBytes []byte
		if err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
			&settingsBytes, &org.MaxUsers, &org.MaxApplications,
			&org.CreatedAt, &org.UpdatedAt, &org.MemberCount,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}
		if settingsBytes != nil {
			if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
			}
		}
		orgs = append(orgs, org)
	}

	return orgs, total, nil
}

// OrganizationUpdate is a change to an organization's record: each field that
// is set is written, and a nil field keeps its value.
type OrganizationUpdate struct {
	Name            *string `json:"name"`
	Plan            *string `json:"plan"`
	Status          *string `json:"status"`
	MaxUsers        *int    `json:"max_users"`
	MaxApplications *int    `json:"max_applications"`
}

// installFieldChanges names the fields of u that would change the plan, the
// status or a limit of org. Those are the install's decisions about a tenant --
// what it is sold, whether it is suspended, how much it may hold -- and so the
// platform admin's, not the organization's own owners'. A field restated with
// the value it has changes nothing and is not named.
func (u OrganizationUpdate) installFieldChanges(org *Organization) []string {
	var changed []string
	if u.Plan != nil && *u.Plan != org.Plan {
		changed = append(changed, "plan")
	}
	if u.Status != nil && *u.Status != org.Status {
		changed = append(changed, "status")
	}
	if u.MaxUsers != nil && *u.MaxUsers != org.MaxUsers {
		changed = append(changed, "max_users")
	}
	if u.MaxApplications != nil && *u.MaxApplications != org.MaxApplications {
		changed = append(changed, "max_applications")
	}
	return changed
}

// UpdateOrganization writes the fields of u that are set.
func (s *Service) UpdateOrganization(ctx context.Context, orgID string, u OrganizationUpdate) error {
	now := time.Now().UTC()

	result, err := s.db.Pool.Exec(ctx,
		`UPDATE organizations SET name = COALESCE($1, name), plan = COALESCE($2, plan), status = COALESCE($3, status),
		        max_users = COALESCE($4, max_users), max_applications = COALESCE($5, max_applications), updated_at = $6
		 WHERE id = $7`,
		u.Name, u.Plan, u.Status, u.MaxUsers, u.MaxApplications, now, orgID,
	)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}

	s.logger.Info("organization updated",
		zap.String("org_id", orgID),
	)

	return nil
}

// GetUserOrganizations returns all organizations where the user is a member
func (s *Service) GetUserOrganizations(ctx context.Context, userID string) ([]Organization, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.domain, o.plan, o.status, o.settings,
		        o.max_users, o.max_applications, o.created_at, o.updated_at
		 FROM organizations o
		 INNER JOIN organization_members m ON o.id = m.organization_id
		 WHERE m.user_id = $1
		 ORDER BY o.name ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var org Organization
		var settingsBytes []byte
		if err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.Domain, &org.Plan, &org.Status,
			&settingsBytes, &org.MaxUsers, &org.MaxApplications,
			&org.CreatedAt, &org.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		if settingsBytes != nil {
			if err := json.Unmarshal(settingsBytes, &org.Settings); err != nil {
				return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
			}
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// orgRoles are the roles an organization grants its members: an owner or an
// admin administers it through this API, and a member reads it. They are the
// roles the console offers, and nothing else is stored.
var orgRoles = map[string]bool{"owner": true, "admin": true, "member": true}

// The ways a membership change is refused.
var (
	errOrganizationNotFound = errors.New("organization not found")
	errMemberNotFound       = errors.New("member not found")
	errNotOrgAdmin          = errors.New("must be an owner or admin of this organization")
	errOwnerOnly            = errors.New("only an owner can grant the owner role or change an owner's membership")
	errLastOwner            = errors.New("an organization must keep at least one owner")
)

// membershipChange is one write to an organization's membership: userID is
// given role, or leaves the organization when role is empty. actorID is the
// caller, whose own membership authorizes the change unless platform is set.
type membershipChange struct {
	orgID, userID, role string
	actorID             string
	platform            bool
	invitedBy           string
}

// changeMembership applies ch and reports whether it added a member.
//
// Each membership write to an organization runs in a transaction that first
// locks the organization's row, so what the checks read cannot change under
// them: two owners removing each other at the same time cannot each see the
// other remain and leave the organization with none.
//
//   - The caller must be an owner or admin of the organization, read again
//     under the lock, or the platform admin.
//   - Granting the owner role, or changing or removing an owner's membership,
//     needs an owner or the platform admin. Otherwise an admin could demote
//     the owners one at a time, make themselves one and take the organization.
//   - The last owner can be neither demoted nor removed, by anyone: an
//     organization with no owner is one only the platform admin can manage.
func (s *Service) changeMembership(ctx context.Context, ch membershipChange) (bool, error) {
	if _, err := uuid.Parse(ch.orgID); err != nil {
		return false, errOrganizationNotFound
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin membership change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM organizations WHERE id = $1 FOR UPDATE`, ch.orgID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, errOrganizationNotFound
		}
		return false, fmt.Errorf("lock organization: %w", err)
	}
	roleOf := func(userID string) (string, error) {
		var role string
		err := tx.QueryRow(ctx,
			`SELECT COALESCE((SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2), '')`,
			ch.orgID, userID).Scan(&role)
		return role, err
	}

	current, err := roleOf(ch.userID)
	if err != nil {
		return false, fmt.Errorf("read membership: %w", err)
	}
	if ch.role == "" && current == "" {
		return false, errMemberNotFound
	}
	if !ch.platform {
		actorRole := ""
		if _, perr := uuid.Parse(ch.actorID); perr == nil {
			if actorRole, err = roleOf(ch.actorID); err != nil {
				return false, fmt.Errorf("read the caller's membership: %w", err)
			}
		}
		if actorRole != "owner" && actorRole != "admin" {
			return false, errNotOrgAdmin
		}
		if (ch.role == "owner" || current == "owner") && actorRole != "owner" {
			return false, errOwnerOnly
		}
	}
	if current == "owner" && ch.role != "owner" {
		var owners int
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM organization_members WHERE organization_id = $1 AND role = 'owner'`,
			ch.orgID).Scan(&owners); err != nil {
			return false, fmt.Errorf("count owners: %w", err)
		}
		if owners <= 1 {
			return false, errLastOwner
		}
	}

	if ch.role == "" {
		if _, err := tx.Exec(ctx,
			`DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
			ch.orgID, ch.userID); err != nil {
			return false, fmt.Errorf("remove member: %w", err)
		}
	} else {
		// invited_by is a nullable UUID; store NULL rather than a value the
		// UUID cast would refuse when the inviter is unknown.
		var inviter interface{}
		if _, err := uuid.Parse(ch.invitedBy); err == nil {
			inviter = ch.invitedBy
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO organization_members (id, organization_id, user_id, role, joined_at, invited_by)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (organization_id, user_id)
			 DO UPDATE SET role = EXCLUDED.role`,
			uuid.New().String(), ch.orgID, ch.userID, ch.role, time.Now().UTC(), inviter); err != nil {
			return false, fmt.Errorf("add member: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit membership change: %w", err)
	}

	s.logger.Info("organization membership changed",
		zap.String("org_id", ch.orgID),
		zap.String("user_id", ch.userID),
		zap.String("from_role", current),
		zap.String("to_role", ch.role),
	)
	return current == "" && ch.role != "", nil
}

// userOrganization returns the organization a user belongs to (users.org_id),
// and false when no user has the id.
//
// users is under the RLS belt and this one read is not. A platform admin may
// add a user of any organization, and an owner's request is scoped to the
// organization of their token, which need not be the one they administer; left
// to the belt, the lookup would answer "no such user" for the wrong reason in
// both cases. The rule is applied by the caller to the org_id returned, and
// nothing else of the row leaves this function.
func (s *Service) userOrganization(ctx context.Context, userID string) (string, bool, error) {
	var orgID string
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore one user's organization by id, to decide whether the caller may make them a member; the caller applies its rule to the org_id returned and nothing else of the row is read
		`SELECT org_id::text FROM users WHERE id = $1`, userID).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return orgID, true, nil
}

// GetMemberRole returns the caller's role within an organization, or "" if they
// are not a member. Used to authorize per-org write operations. The scalar
// subquery is wrapped in COALESCE so the query always returns exactly one row
// (empty string for a non-member) rather than a no-rows error.
func (s *Service) GetMemberRole(ctx context.Context, orgID, userID string) (string, error) {
	var role string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2), '')`,
		orgID, userID).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

// ListMembers returns a paginated list of organization members with user info
func (s *Service) ListMembers(ctx context.Context, orgID string, limit, offset int) ([]OrganizationMember, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM organization_members WHERE organization_id = $1`, orgID,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count members: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT m.id, m.organization_id, m.user_id, m.role, m.joined_at, m.invited_by,
		        COALESCE(u.email, '') AS user_email, COALESCE(u.username, '') AS user_name
		 FROM organization_members m
		 LEFT JOIN users u ON m.user_id = u.id AND u.org_id = $1
		 WHERE m.organization_id = $1
		 ORDER BY m.joined_at ASC
		 LIMIT $2 OFFSET $3`, orgID, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []OrganizationMember
	for rows.Next() {
		var member OrganizationMember
		if err := rows.Scan(
			&member.ID, &member.OrganizationID, &member.UserID, &member.Role,
			&member.JoinedAt, &member.InvitedBy, &member.UserEmail, &member.UserName,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, member)
	}

	return members, total, nil
}

// HTTP Handlers

func (s *Service) handleListOrganizations(c *gin.Context) {
	// Enumerating every tenant (name/slug/plan/member count) is a platform-admin
	// operation. A non-admin caller is scoped to the organizations they belong
	// to — otherwise any authenticated user could list all tenants. The
	// organizations table is deliberately outside the RLS belt, so this gate is
	// enforced here rather than by row-level security.
	if !orgctx.IsPlatformAdmin(c.Request.Context()) {
		userID, _ := c.Get("user_id")
		uid, _ := userID.(string)
		if uid == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "authentication required to list organizations"})
			return
		}
		orgs, err := s.GetUserOrganizations(c.Request.Context(), uid)
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to get user organizations", err), s.logger)
			return
		}
		c.Header("X-Total-Count", strconv.Itoa(len(orgs)))
		c.JSON(http.StatusOK, orgs)
		return
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	orgs, total, err := s.ListOrganizations(c.Request.Context(), limit, offset)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list organizations", err), s.logger)
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(http.StatusOK, orgs)
}

func (s *Service) handleCreateOrganization(c *gin.Context) {
	// A new organization is a new tenant of the install, and whoever creates
	// it becomes its owner. That is the install's decision, so it belongs to
	// the platform admin -- super_admin held in the default organization, the
	// marker the tenant resolver attaches -- and not to the admin role, which
	// each organization grants inside itself. Nothing creates an organization
	// for its own users either: there is no self-service sign-up, and the
	// console's Organizations page is the only caller.
	if !orgctx.IsPlatformAdmin(c.Request.Context()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "only a platform admin can create an organization"})
		return
	}

	var req struct {
		Name            string `json:"name" binding:"required"`
		Slug            string `json:"slug" binding:"required"`
		Plan            string `json:"plan"`
		MaxUsers        int    `json:"max_users"`
		MaxApplications int    `json:"max_applications"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Creating an organization records the caller as its owner. Fall back to no
	// seed identity: an unauthenticated caller must not be able to mint a tenant
	// as the seed admin (reachable under SoftAuth in dev). Require a real
	// authenticated user.
	userID, _ := c.Get("user_id")
	creatorUserID, _ := userID.(string)
	if creatorUserID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "authentication required to create an organization"})
		return
	}

	org := &Organization{
		Name:            req.Name,
		Slug:            req.Slug,
		Plan:            req.Plan,
		MaxUsers:        req.MaxUsers,
		MaxApplications: req.MaxApplications,
	}

	if err := s.CreateOrganization(c.Request.Context(), org, creatorUserID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to create organization", err), s.logger)
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (s *Service) handleGetOrganization(c *gin.Context) {
	orgID := c.Param("id")
	if !s.requireOrgMember(c, orgID) {
		return
	}

	org, err := s.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		s.logger.Error("failed to get organization", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	c.JSON(http.StatusOK, org)
}

// handleUpdateOrganization changes an organization's record. A field the
// request leaves out keeps its value.
//
// An owner or admin of the organization changes its name. The plan, the status
// and the limits are the platform admin's: an owner used to be able to upgrade
// their own plan, raise their limits or lift their own suspension here. An owner
// or admin may still send them as they are -- the console restates them with
// every rename, and every client did while plan and status were required -- but
// a request that would change one is refused whole with 403 naming the fields,
// rather than applied without them.
func (s *Service) handleUpdateOrganization(c *gin.Context) {
	orgID := c.Param("id")
	if !s.requireOrgAdmin(c, orgID) {
		return
	}

	var req OrganizationUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == nil && req.Plan == nil && req.Status == nil && req.MaxUsers == nil && req.MaxApplications == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nothing to update"})
		return
	}
	for _, f := range []struct {
		name  string
		value *string
	}{{"name", req.Name}, {"plan", req.Plan}, {"status", req.Status}} {
		if f.value != nil && strings.TrimSpace(*f.value) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": f.name + " must not be empty"})
			return
		}
	}
	for _, f := range []struct {
		name  string
		value *int
	}{{"max_users", req.MaxUsers}, {"max_applications", req.MaxApplications}} {
		if f.value != nil && *f.value < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": f.name + " must not be negative"})
			return
		}
	}

	ctx := c.Request.Context()
	current, ok := s.loadOrganization(c, orgID)
	if !ok {
		return
	}
	if !orgctx.IsPlatformAdmin(ctx) {
		if changed := req.installFieldChanges(current); len(changed) > 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": "only a platform admin can change an organization's plan, status or limits",
				"fields":            changed,
			})
			return
		}
		// Restated as they are, so nothing of them is written: a concurrent
		// change by the platform admin is not undone by an owner's rename.
		req.Plan, req.Status, req.MaxUsers, req.MaxApplications = nil, nil, nil, nil
	}

	if err := s.UpdateOrganization(ctx, orgID, req); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to update organization", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "organization updated"})
}

// loadOrganization reads the organization a write names. An id that names none
// -- reachable by a platform admin, whom requireOrgAdmin does not look up -- is
// answered 404, as is an id that is not a UUID, rather than a database error.
func (s *Service) loadOrganization(c *gin.Context, orgID string) (*Organization, bool) {
	if _, err := uuid.Parse(orgID); err == nil {
		org, err := s.GetOrganization(c.Request.Context(), orgID)
		if err == nil {
			return org, true
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to load organization", err), s.logger)
			return nil, false
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
	return nil, false
}

func (s *Service) handleListMembers(c *gin.Context) {
	orgID := c.Param("id")
	if !s.requireOrgMember(c, orgID) {
		return
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	members, total, err := s.ListMembers(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list members", err), s.logger)
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(http.StatusOK, members)
}

// handleAddMember makes a user a member of the organization in a role, or
// changes the role of one who is.
//
// It used to accept any user id -- another organization's user, or no user at
// all -- and any role string. The role must be one the organization grants and
// the user must exist. An owner or admin may add only the organization's own
// users (users.org_id); a platform admin may add any user. A user of another
// organization is answered exactly as an id that names no user, so the answer
// does not tell an owner which ids exist elsewhere. changeMembership decides
// who may touch an owner and keeps the last one.
func (s *Service) handleAddMember(c *gin.Context) {
	orgID := c.Param("id")
	if !s.requireOrgAdmin(c, orgID) {
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Role   string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !orgRoles[req.Role] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be one of owner, admin, member"})
		return
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be a user's id"})
		return
	}

	ctx := c.Request.Context()
	platform := orgctx.IsPlatformAdmin(ctx)
	userOrg, found, err := s.userOrganization(ctx, req.UserID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to look up user", err), s.logger)
		return
	}
	if !found || (!platform && userOrg != orgID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// The inviter is the authenticated caller, or NULL when there is none,
	// never the seed admin identity.
	caller := c.GetString("user_id")
	added, err := s.changeMembership(ctx, membershipChange{
		orgID: orgID, userID: req.UserID, role: req.Role,
		actorID: caller, platform: platform, invitedBy: caller,
	})
	if err != nil {
		s.respondMembershipError(c, err)
		return
	}
	if added {
		c.JSON(http.StatusCreated, gin.H{"message": "member added"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "member role updated"})
}

// handleRemoveMember removes a member from the organization. changeMembership
// keeps an owner's membership to owners and the last owner in place.
func (s *Service) handleRemoveMember(c *gin.Context) {
	orgID := c.Param("id")
	userID := c.Param("userId")
	if !s.requireOrgAdmin(c, orgID) {
		return
	}
	if _, err := uuid.Parse(userID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}

	ctx := c.Request.Context()
	if _, err := s.changeMembership(ctx, membershipChange{
		orgID: orgID, userID: userID,
		actorID: c.GetString("user_id"), platform: orgctx.IsPlatformAdmin(ctx),
	}); err != nil {
		s.respondMembershipError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "member removed"})
}

// respondMembershipError answers a refused or failed membership change.
func (s *Service) respondMembershipError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errOrganizationNotFound), errors.Is(err, errMemberNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, errNotOrgAdmin), errors.Is(err, errOwnerOnly):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": err.Error()})
	case errors.Is(err, errLastOwner):
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "error_description": err.Error()})
	default:
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to change membership", err), s.logger)
	}
}

func (s *Service) handleGetMyOrganizations(c *gin.Context) {
	// The caller's own memberships, so the caller has to be a user. With no
	// user bound -- a service account's API key, a client-credentials token,
	// an unauthenticated request under SoftAuth -- this used to answer with
	// the seed admin's memberships instead: the default organization and
	// every organization created from that account, whichever tenant asked.
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "authentication required to list your organizations"})
		return
	}

	orgs, err := s.GetUserOrganizations(c.Request.Context(), uid)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to get user organizations", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, orgs)
}

// requireOrgAdmin authorizes a per-org write operation. The caller must be a
// platform admin, or an owner/admin member of orgID. It fails closed: an
// unauthenticated caller (no user_id) or any lookup error is denied. On failure
// it writes the HTTP response and returns false, so handlers can `if
// !s.requireOrgAdmin(c, orgID) { return }`. The platform-admin bypass mirrors
// the list handler and the tenant resolver's cross-org model (crossing orgs as
// platform admin is expected and separately audited).
func (s *Service) requireOrgAdmin(c *gin.Context, orgID string) bool {
	ctx := c.Request.Context()
	if orgctx.IsPlatformAdmin(ctx) {
		return true
	}
	uid, _ := c.Get("user_id")
	callerID, _ := uid.(string)
	if callerID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "authentication required"})
		return false
	}
	// An id that is not a UUID names no membership; asking the database would
	// only turn the refusal into a 500.
	role := ""
	if _, err := uuid.Parse(orgID); err == nil {
		if _, err := uuid.Parse(callerID); err == nil {
			if role, err = s.GetMemberRole(ctx, orgID, callerID); err != nil {
				s.logger.Error("failed to check organization membership", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return false
			}
		}
	}
	if role != "owner" && role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "must be an owner or admin of this organization"})
		return false
	}
	return true
}

// requireOrgMember authorizes a read of one organization's record or member
// list: the caller must be a platform admin, or a member of orgID in any role.
// organizations and organization_members span the install, outside the RLS
// belt, so without this check any authenticated caller of any organization
// could read another's name, plan, limits and settings, and who its members
// are and in which role.
//
// Anyone else is answered 404, exactly as an id that names no organization is,
// so the answer does not tell a caller which organizations exist -- the answer
// a cross-organization read of a tenant table gets from the belt. An id or a
// subject that is not a UUID cannot name a membership and is answered the same
// way rather than handed to the database. The write checks in requireOrgAdmin
// answer 403 as before; they too answer it whether or not the organization
// exists.
func (s *Service) requireOrgMember(c *gin.Context, orgID string) bool {
	ctx := c.Request.Context()
	if orgctx.IsPlatformAdmin(ctx) {
		return true
	}
	uid, _ := c.Get("user_id")
	callerID, _ := uid.(string)
	if _, err := uuid.Parse(orgID); err == nil {
		if _, err := uuid.Parse(callerID); err == nil {
			role, err := s.GetMemberRole(ctx, orgID, callerID)
			if err != nil {
				s.logger.Error("failed to check organization membership", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return false
			}
			if role != "" {
				return true
			}
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
	return false
}

// RegisterRoutes registers organization HTTP routes on the given router group
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/organizations", svc.handleListOrganizations)
	router.POST("/organizations", svc.handleCreateOrganization)
	router.GET("/organizations/:id", svc.handleGetOrganization)
	router.PUT("/organizations/:id", svc.handleUpdateOrganization)
	router.GET("/organizations/:id/members", svc.handleListMembers)
	router.POST("/organizations/:id/members", svc.handleAddMember)
	router.DELETE("/organizations/:id/members/:userId", svc.handleRemoveMember)
	router.GET("/me/organizations", svc.handleGetMyOrganizations)
}
