package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Assignment report.
//
// Ziti reach is structural: the controller decides at circuit time from policies
// we push, so there is no request our code sees to log a would-be denial on. The
// report therefore diffs what each user can dial today against what assignment
// would grant, which answers the question the flag flip actually raises — who
// loses what.

// ReportEntry is one reach that assignment does not cover.
type ReportEntry struct {
	UserID           string `json:"user_id"`
	Username         string `json:"username"`
	ApplicationID    string `json:"application_id"`
	ApplicationName  string `json:"application_name"`
	EnforcementPoint string `json:"enforcement_point"`
	Reason           string `json:"reason"`
}

// diffReachability returns every (user, application) pair the user can reach
// today but would not be granted by assignment. Both maps are keyed by user id
// and hold application ids. Names are filled in by the caller, which has them.
func diffReachability(reachable, assigned map[string][]string) []ReportEntry {
	out := []ReportEntry{}
	for user, apps := range reachable {
		granted := make(map[string]bool, len(assigned[user]))
		for _, a := range assigned[user] {
			granted[a] = true
		}
		for _, a := range apps {
			if !granted[a] {
				out = append(out, ReportEntry{
					UserID:           user,
					ApplicationID:    a,
					EnforcementPoint: "ziti",
					Reason:           "reachable today via the blanket dial policy, but not assigned",
				})
			}
		}
	}
	return out
}

// handleAssignmentReport answers GET /api/v1/access/assignment-report.
func (s *Service) handleAssignmentReport(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Every user with a synced Ziti identity, with their name for display.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT zi.user_id, COALESCE(u.username, '')
		  FROM ziti_identities zi
		  JOIN users u ON u.id = zi.user_id
		 WHERE zi.org_id = $1`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: user query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	names := map[string]string{}
	userIDs := []string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		names[id] = name
		userIDs = append(userIDs, id)
	}
	rows.Close()

	// serviceApp maps a ziti service name to the application behind it, so the
	// services a user can dial today can be expressed as application ids.
	serviceApp := map[string]appaccess.AppRef{}
	appRows, err := s.db.Pool.Query(ctx, `
		SELECT r.ziti_service_name, a.id, a.name
		  FROM applications a
		  JOIN proxy_routes r ON r.id = a.route_id
		 WHERE a.org_id = $1 AND a.enabled = true AND r.ziti_enabled = true
		   AND COALESCE(r.ziti_service_name, '') <> ''`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: service query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	for appRows.Next() {
		var svc string
		var ref appaccess.AppRef
		if err := appRows.Scan(&svc, &ref.ID, &ref.Name); err != nil {
			continue
		}
		serviceApp[svc] = ref
	}
	appRows.Close()

	reachable := map[string][]string{}
	assigned := map[string][]string{}
	appNames := map[string]string{}
	for _, uid := range userIDs {
		var pillar AccessMapZiti
		if perr := s.collectZitiPillar(ctx, org.ID, uid, &pillar); perr != nil {
			s.logger.Warn("assignment report: pillar failed", zap.String("user_id", uid), zap.Error(perr))
			continue
		}
		for _, svcName := range pillar.ReachableServices {
			if ref, ok := serviceApp[svcName]; ok {
				reachable[uid] = append(reachable[uid], ref.ID)
				appNames[ref.ID] = ref.Name
			}
		}
		refs, aerr := appaccess.AppsForUser(ctx, s.db, uid, org.ID)
		if aerr != nil {
			s.logger.Warn("assignment report: assignments failed", zap.String("user_id", uid), zap.Error(aerr))
			continue
		}
		for _, r := range refs {
			assigned[uid] = append(assigned[uid], r.ID)
			appNames[r.ID] = r.Name
		}
	}

	entries := diffReachability(reachable, assigned)
	affectedUsers := map[string]bool{}
	affectedApps := map[string]bool{}
	for i := range entries {
		entries[i].Username = names[entries[i].UserID]
		entries[i].ApplicationName = appNames[entries[i].ApplicationID]
		affectedUsers[entries[i].UserID] = true
		affectedApps[entries[i].ApplicationID] = true
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"summary": gin.H{
			"users":        len(affectedUsers),
			"applications": len(affectedApps),
			"would_deny":   len(entries),
		},
	})
}
