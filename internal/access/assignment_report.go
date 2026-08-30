package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

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
//
// Reach is read from the LIVE CONTROLLER, never from the local
// ziti_service_policies / ziti_services mirror. The mirror is written only by
// App Publish (with ON CONFLICT DO NOTHING) and by manual admin creates — the
// reconciler, which is what actually converges the policies that govern reach,
// never writes it. A mirror-backed report therefore renders "safe to enforce"
// more or less regardless of the truth. When the controller cannot be read the
// report says so (reachability_source = "unavailable") instead of falling back
// to the mirror: this endpoint is the operator's go/no-go for the one
// irreversible step of the rollout, and a signal that fails silently toward
// "go" is the worst possible failure direction.

// Reachability sources reported to the caller.
const (
	// ReachabilityFromController means the reach half was computed from live
	// controller data and can be trusted.
	ReachabilityFromController = "controller"
	// ReachabilityUnavailable means reach could not be determined at all. The
	// assignment half is still populated (it is DB-only), the reach half is
	// empty, and every user counts as incomplete.
	ReachabilityUnavailable = "unavailable"
)

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

// AssignmentEntry is one (user, application) pair that assignment grants today.
// It is the DB-only half of the report and is populated even when reach cannot
// be read, so an operator still learns what assignment WOULD cover.
type AssignmentEntry struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	ApplicationID   string `json:"application_id"`
	ApplicationName string `json:"application_name"`
}

// reportUser is one org user with a synced Ziti identity: the display name for
// the report and the identity attributes reach is matched against.
//
// ziti_identities IS maintained by the sync poller (unlike the policy/service
// mirrors), so reading identity attributes from it is sound.
type reportUser struct {
	ID       string
	Username string
	ZitiID   string
	Attrs    []string
}

// reachabilityInputs pulls the Dial policies and the service index from the
// live controller, once per report request. Returns an error — never a partial
// or empty-but-plausible result — when anything is off, because the caller
// turns any error into reachability_source: "unavailable".
// Both listings go through the PAGINATING helpers (ListAllServicePolicies /
// ListAllServices), which follow meta.pagination and refuse to return a
// listing they cannot show to be complete. The old `len(...) >= limit`
// truncation heuristic is gone: it only fires when the controller honours the
// limit we asked for, and a controller that caps `limit` server-side would
// truncate below the threshold and never trip it.
func reachabilityInputs(ctx context.Context, zm *ZitiManager) ([]zitiDialPolicy, zitiServiceIndex, error) {
	var idx zitiServiceIndex
	policies, err := zm.ListAllServicePolicies(ctx)
	if err != nil {
		return nil, idx, fmt.Errorf("could not list service policies: %w", err)
	}
	services, err := zm.ListAllServices(ctx)
	if err != nil {
		return nil, idx, fmt.Errorf("could not list services: %w", err)
	}

	idx.byZitiID = make(map[string]string, len(services))
	idx.byAttr = map[string][]string{}
	idx.byName = make(map[string]bool, len(services))
	for _, svc := range services {
		idx.byZitiID[svc.ID] = svc.Name
		idx.all = append(idx.all, svc.Name)
		if svc.Name != "" {
			// A `#tag` that names a service must resolve to that service even
			// when the service does not carry its own name as a role
			// attribute; otherwise the role degrades to the literal "#name",
			// matches no application, and the application drops out of reach.
			idx.byName[svc.Name] = true
		}
		attrs := append(append([]string{}, svc.Attributes...), svc.RoleAttributes...)
		for _, attr := range attrs {
			attr = strings.TrimPrefix(attr, "#")
			if attr == "" {
				continue
			}
			idx.byAttr[attr] = append(idx.byAttr[attr], svc.Name)
		}
	}

	dial := make([]zitiDialPolicy, 0, len(policies))
	for _, p := range policies {
		if !strings.EqualFold(p.Type, "Dial") {
			continue
		}
		dial = append(dial, zitiDialPolicy{
			Name:          p.Name,
			IdentityRoles: p.IdentityRoles,
			ServiceRoles:  p.ServiceRoles,
		})
	}
	// The controller has policies but the Dial filter kept none. On a live
	// overlay that is not a credible "nobody may dial anything" — every
	// published route gets a Dial policy — it is far more likely that the
	// `type` field was absent or renamed, in which case every user reaches
	// nothing and the report reads "safe to enforce". Fail loud instead.
	if len(policies) > 0 && len(dial) == 0 {
		return nil, idx, fmt.Errorf(
			"controller returned %d service policies but none is of type Dial: "+
				"reach cannot be derived (has the policy type field changed?)", len(policies))
	}
	return dial, idx, nil
}

// reportRows is the slice of pgx.Rows the report's scan loops use. Naming it
// lets those loops — and above all their failure paths, which are the whole
// point of this endpoint's fidelity — be exercised directly.
type reportRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// scanReportUsers reads the org's users that have a synced Ziti identity.
//
// It returns the users, their display names, the number of rows it could not
// read (each of which must show up as an incomplete user rather than silently
// vanish), and a FATAL error when the iteration itself failed. An iteration
// failure is not a per-user problem: it means the user list is partial, so the
// report's inputs are untrustworthy and the caller must report the reach half
// as unavailable rather than diff over whatever arrived first.
func scanReportUsers(rows reportRows) ([]reportUser, map[string]string, int, error) {
	names := map[string]string{}
	users := []reportUser{}
	incomplete := 0
	for rows.Next() {
		var u reportUser
		var attrsJSON []byte
		if err := rows.Scan(&u.ID, &u.Username, &u.ZitiID, &attrsJSON); err != nil {
			// The row cannot even be identified, so it cannot be named — but
			// it must still be counted, or the report claims to have covered
			// a user it never looked at.
			incomplete++
			continue
		}
		if len(attrsJSON) > 0 {
			if err := json.Unmarshal(attrsJSON, &u.Attrs); err != nil {
				// Malformed attributes would leave the identity matching
				// fewer policies than it really does, i.e. under-report reach.
				// Skip the user and count them instead of guessing "no
				// attributes".
				incomplete++
				continue
			}
		}
		names[u.ID] = u.Username
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, incomplete,
			fmt.Errorf("could not read this organization's Ziti identities: %w", err)
	}
	return users, names, incomplete, nil
}

// scanServiceApps reads the ziti-service-name → application index.
//
// Unlike a user row, a dropped row here removes an application from the reach
// side for EVERY user — the exact under-report direction this endpoint exists
// to remove — so a scan failure is fatal to the report's inputs rather than a
// single incomplete user.
func scanServiceApps(rows reportRows) (map[string]appaccess.AppRef, error) {
	serviceApp := map[string]appaccess.AppRef{}
	for rows.Next() {
		var svc string
		var ref appaccess.AppRef
		if err := rows.Scan(&svc, &ref.ID, &ref.Name); err != nil {
			return nil, fmt.Errorf(
				"could not read this organization's Ziti-backed applications: %w", err)
		}
		serviceApp[svc] = ref
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"could not read this organization's Ziti-backed applications: %w", err)
	}
	return serviceApp, nil
}

// handleAssignmentReport answers GET /api/v1/access/assignment-report.
func (s *Service) handleAssignmentReport(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Every user with a synced Ziti identity, with their name for display and
	// the identity attributes their reach is matched against.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT zi.user_id, COALESCE(u.username, ''), COALESCE(zi.ziti_id, ''),
		       COALESCE(zi.attributes, '[]'::jsonb)
		  FROM ziti_identities zi
		  JOIN users u ON u.id = zi.user_id
		 WHERE zi.org_id = $1`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: user query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	users, names, incompleteUsers, inputErr := scanReportUsers(rows)
	rows.Close()

	// usersTotal is the denominator the report is answerable for. The user set
	// above comes from ziti_identities, so an org whose sync poller has never
	// run — or that has gained users since the last poll — would otherwise
	// evaluate NOBODY and still render "safe to enforce". Org-scoped like every
	// other query here.
	// It is read even when the identity read already failed, so a partial
	// listing still reports a denominator the shortfall can be measured
	// against.
	usersTotal := 0
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE org_id = $1`, org.ID).Scan(&usersTotal); err != nil {
		if inputErr == nil {
			inputErr = fmt.Errorf("could not count this organization's users: %w", err)
		}
	}

	// serviceApp maps a ziti service name to the application behind it, so the
	// services a user can dial today can be expressed as application ids. It is
	// also what keeps the report org-scoped on the reach side: the controller is
	// install-wide, so a reachable service belonging to another org has no entry
	// here and drops out.
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
	scanned, scanErr := scanServiceApps(appRows)
	appRows.Close()
	if scanErr != nil {
		if inputErr == nil {
			inputErr = scanErr
		}
	} else {
		serviceApp = scanned
	}

	// Reach comes from the live controller, fetched ONCE for the whole report
	// rather than per user. s.ziti() is nil whenever the overlay is not
	// connected, which is the same "we cannot tell you" answer as a failed call.
	//
	// A failure while READING the report's own DB inputs is treated exactly
	// the same way: the inputs are partial, so the report must not present a
	// diff over them.
	source := ReachabilityFromController
	reachErr := ""
	var policies []zitiDialPolicy
	var svcIdx zitiServiceIndex
	zm := s.ziti()
	switch {
	case inputErr != nil:
		s.logger.Warn("assignment report: input read failed", zap.Error(inputErr))
		source = ReachabilityUnavailable
		reachErr = inputErr.Error()
	case zm == nil:
		source = ReachabilityUnavailable
		reachErr = "the Ziti controller is not connected"
	default:
		if policies, svcIdx, err = reachabilityInputs(ctx, zm); err != nil {
			s.logger.Warn("assignment report: controller read failed", zap.Error(err))
			source = ReachabilityUnavailable
			reachErr = err.Error()
		}
	}

	reachable := map[string][]string{}
	assigned := map[string][]string{}
	appNames := map[string]string{}
	usersEvaluated := 0
	for _, u := range users {
		refs, aerr := appaccess.AppsForUser(ctx, s.db, u.ID, org.ID)
		if aerr != nil {
			s.logger.Warn("assignment report: assignments failed",
				zap.String("user_id", u.ID), zap.Error(aerr))
			incompleteUsers++
			continue
		}
		if source != ReachabilityFromController {
			// Reach is unknown for everyone. The user counts as incomplete and
			// is entered into NEITHER side of the diff: no fallback to the
			// mirror, and no empty diff that would read as "loses nothing".
			// The assignment half is still recorded — it is DB-only and
			// correct — so the page can still show what assignment covers.
			incompleteUsers++
			for _, r := range refs {
				assigned[u.ID] = append(assigned[u.ID], r.ID)
				appNames[r.ID] = r.Name
			}
			continue
		}
		// Both halves are known: only now is the user entered into either side
		// of the diff. A user whose reach or assignment could not be computed
		// must contribute zero entries in either direction — never a false
		// "loses nothing" (reach missing) nor a false "loses everything"
		// (assignment missing).
		_, svcNames := reachabilityForIdentity(policies, u.ZitiID, u.Attrs, svcIdx)
		for _, svcName := range svcNames {
			if ref, ok := serviceApp[svcName]; ok {
				reachable[u.ID] = append(reachable[u.ID], ref.ID)
				appNames[ref.ID] = ref.Name
			}
		}
		for _, r := range refs {
			assigned[u.ID] = append(assigned[u.ID], r.ID)
			appNames[r.ID] = r.Name
		}
		usersEvaluated++
	}

	// Anyone in the org the loop never even saw — no ziti_identities row, so
	// absent from `users` entirely — is not evaluated and must not read as
	// evaluated-and-clean. incompleteUsers already accounts for the users the
	// loop saw and could not finish, so only the remainder is added.
	if missing := usersTotal - usersEvaluated - incompleteUsers; missing > 0 {
		incompleteUsers += missing
	}

	// buildReport only ever diffs users present in `reachable`; the
	// unavailable path leaves that map empty, so entries stay empty while
	// incomplete_users equals the user count.
	entries, summary := buildReport(reachable, assigned, names, appNames,
		incompleteUsers, usersEvaluated, usersTotal)

	body := gin.H{
		"entries":             entries,
		"summary":             summary,
		"assignments":         buildAssignments(assigned, names, appNames),
		"reachability_source": source,
	}
	if reachErr != "" {
		body["reachability_error"] = reachErr
	}
	c.JSON(http.StatusOK, body)
}

// buildAssignments flattens the assignment half of the report — what each user
// would keep once enforcement is on. Sorted so the response is stable.
func buildAssignments(assigned map[string][]string, names, appNames map[string]string) []AssignmentEntry {
	out := []AssignmentEntry{}
	for uid, apps := range assigned {
		for _, appID := range apps {
			out = append(out, AssignmentEntry{
				UserID:          uid,
				Username:        names[uid],
				ApplicationID:   appID,
				ApplicationName: appNames[appID],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID != out[j].UserID {
			return out[i].UserID < out[j].UserID
		}
		return out[i].ApplicationID < out[j].ApplicationID
	})
	return out
}

// buildReport diffs reachability against assignment and packages the result
// for the API response. incompleteUsers is the count of users excluded from
// both reachable and assigned because their lookup failed; it is surfaced in
// the summary so an operator can tell a low would_deny count is genuine and
// not a symptom of silently-skipped users.
//
// usersEvaluated / usersTotal are the report's denominator: without them an
// org that evaluated nobody (no synced Ziti identities at all) is textually
// indistinguishable from one that evaluated everybody and found nothing to
// take away.
func buildReport(reachable, assigned map[string][]string, names, appNames map[string]string,
	incompleteUsers, usersEvaluated, usersTotal int) ([]ReportEntry, gin.H) {
	entries := diffReachability(reachable, assigned)
	affectedUsers := map[string]bool{}
	affectedApps := map[string]bool{}
	for i := range entries {
		entries[i].Username = names[entries[i].UserID]
		entries[i].ApplicationName = appNames[entries[i].ApplicationID]
		affectedUsers[entries[i].UserID] = true
		affectedApps[entries[i].ApplicationID] = true
	}

	summary := gin.H{
		"users":            len(affectedUsers),
		"applications":     len(affectedApps),
		"would_deny":       len(entries),
		"incomplete_users": incompleteUsers,
		"users_evaluated":  usersEvaluated,
		"users_total":      usersTotal,
	}
	return entries, summary
}
