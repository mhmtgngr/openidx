package access

// GET /api/v1/access/my/vendor: what an external (vendor) user needs to know
// about their own access, for the vendor portal. Their vendor organization,
// their sponsor, when their account ends, and their engagements that are
// running or scheduled, each with what it covers and when it ends. An
// internal user gets {"external": false} and nothing else, which is how the
// console tells the two apart (the token does not carry the user type).
// Deliberately not adminOnly: it answers about the caller only.

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// MyVendorEngagement is one engagement as its member sees it.
type MyVendorEngagement struct {
	ID          string                `json:"id"`
	Title       string                `json:"title"`
	Purpose     string                `json:"purpose"`
	TicketRef   string                `json:"ticket_ref"`
	SponsorName string                `json:"sponsor_name"`
	StartsAt    time.Time             `json:"starts_at"`
	EndsAt      time.Time             `json:"ends_at"`
	State       string                `json:"state"`
	Targets     []MyVendorEngagedItem `json:"targets"`
}

// MyVendorEngagedItem is one target of an engagement.
type MyVendorEngagedItem struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Name       string `json:"name"`
}

func (s *Service) handleMyVendor(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	var (
		vendorID, vendorName, status, sponsorName, sponsorEmail string
		requireEngagement, closedList                           bool
		expiresAt                                               *time.Time
	)
	err = s.db.Pool.QueryRow(ctx, `
		SELECT v.id::text, v.name, COALESCE(u.account_status, ''), v.require_engagement, v.closed_list, u.account_expires_at,
		       COALESCE(NULLIF(TRIM(COALESCE(sp.first_name, '') || ' ' || COALESCE(sp.last_name, '')), ''), sp.username, ''),
		       COALESCE(sp.email, '')
		  FROM users u
		  JOIN vendor_organizations v ON v.id = u.vendor_org_id AND v.org_id = u.org_id
		  LEFT JOIN users sp ON sp.id = u.sponsor_user_id
		 WHERE u.id::text = $1 AND u.org_id = $2 AND u.user_type = 'external'`, userID, org.ID).
		Scan(&vendorID, &vendorName, &status, &requireEngagement, &closedList, &expiresAt, &sponsorName, &sponsorEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusOK, gin.H{"external": false})
		return
	}
	if err != nil {
		s.logger.Error("my vendor: read failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read your vendor organization"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT e.id::text, e.title, e.purpose, e.ticket_ref,
		       COALESCE(NULLIF(TRIM(COALESCE(sp.first_name, '') || ' ' || COALESCE(sp.last_name, '')), ''), sp.username, ''),
		       e.starts_at, e.ends_at,
		       CASE WHEN e.starts_at > NOW() THEN 'scheduled' ELSE 'running' END,
		       t.target_type, t.target_id,
		       COALESCE(a.name, pe.name, NULLIF(ag.metadata->>'hostname', ''), t.target_id)
		  FROM vendor_engagements e
		  LEFT JOIN users sp ON sp.id = e.sponsor_user_id
		  JOIN vendor_engagement_targets t ON t.engagement_id = e.id AND t.org_id = e.org_id
		  LEFT JOIN applications a ON t.target_type = 'application' AND a.id::text = t.target_id AND a.org_id = t.org_id
		  LEFT JOIN pam_entries pe ON t.target_type = 'pam_entry' AND pe.id::text = t.target_id AND pe.org_id = t.org_id
		  LEFT JOIN enrolled_agents ag ON t.target_type = 'device' AND ag.agent_id = t.target_id AND ag.org_id = t.org_id
		 WHERE e.org_id = $1 AND e.vendor_org_id = $2::uuid AND e.status = 'open' AND e.ends_at > NOW()
		   AND (cardinality(e.member_user_ids) = 0 OR $3::uuid = ANY (e.member_user_ids))
		 ORDER BY e.starts_at, e.id, t.target_type, 11`, org.ID, vendorID, userID)
	if err != nil {
		s.logger.Error("my vendor: engagements failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read your engagements"})
		return
	}
	defer rows.Close()
	engagements := []*MyVendorEngagement{}
	byID := map[string]*MyVendorEngagement{}
	for rows.Next() {
		var e MyVendorEngagement
		var it MyVendorEngagedItem
		if err := rows.Scan(&e.ID, &e.Title, &e.Purpose, &e.TicketRef, &e.SponsorName, &e.StartsAt, &e.EndsAt, &e.State,
			&it.TargetType, &it.TargetID, &it.Name); err != nil {
			s.logger.Error("my vendor: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read your engagements"})
			return
		}
		cur := byID[e.ID]
		if cur == nil {
			e.Targets = []MyVendorEngagedItem{}
			cur = &e
			byID[e.ID] = cur
			engagements = append(engagements, cur)
		}
		cur.Targets = append(cur.Targets, it)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("my vendor: engagements failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read your engagements"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"external":           true,
		"vendor":             gin.H{"id": vendorID, "name": vendorName, "require_engagement": requireEngagement, "closed_list": closedList},
		"account_status":     status,
		"account_expires_at": expiresAt,
		"sponsor":            gin.H{"name": sponsorName, "email": sponsorEmail},
		"engagements":        engagements,
	})
}
