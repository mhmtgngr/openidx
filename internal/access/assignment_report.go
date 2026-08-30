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
//
// A user's reach is the UNION over all their Ziti identities — one per enrolled
// device is the normal shape — so the same application can arrive several times
// for the same user. Emitting it once per arrival would inflate
// `summary.would_deny` N× while `summary.users` stayed at one, i.e. the two
// halves of the same summary would contradict each other. De-duplicate per
// user.
func diffReachability(reachable, assigned map[string][]string) []ReportEntry {
	out := []ReportEntry{}
	for user, apps := range reachable {
		granted := make(map[string]bool, len(assigned[user]))
		for _, a := range assigned[user] {
			granted[a] = true
		}
		seen := make(map[string]bool, len(apps))
		for _, a := range apps {
			if granted[a] || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, ReportEntry{
				UserID:           user,
				ApplicationID:    a,
				EnforcementPoint: "ziti",
				Reason:           "reachable today via the blanket dial policy, but not assigned",
			})
		}
	}
	return out
}

// addPair records a (user, application) pair once, however many identity rows
// the user has. The reach of a user's several identities must be unioned — each
// identity carries its own attributes and therefore matches its own policies —
// but the union must not repeat an application.
func addPair(m map[string]map[string]bool, user, app string) {
	if m[user] == nil {
		m[user] = map[string]bool{}
	}
	m[user][app] = true
}

// flattenPairs turns the union sets back into the sorted slices the diff and
// the assignment view consume. Sorting also makes the response stable.
func flattenPairs(m map[string]map[string]bool) map[string][]string {
	out := make(map[string][]string, len(m))
	for user, apps := range m {
		list := make([]string, 0, len(apps))
		for a := range apps {
			list = append(list, a)
		}
		sort.Strings(list)
		out[user] = list
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

// scanReportUsers reads the org's users that have a synced Ziti identity. One
// row is one IDENTITY, not one user: a user with two enrolled devices has two
// rows, and both must be read because each carries its own attributes.
//
// It returns the identity rows, their display names, the set of USER IDS whose
// row could not be used (returned as a set so that a user with several rows is
// counted once), the number of rows so broken that not even the user id could
// be read, and a FATAL error when the iteration itself failed. An iteration
// failure is not a per-user problem: it means the user list is partial, so the
// report's inputs are untrustworthy and the caller must report the reach half
// as unavailable rather than diff over whatever arrived first.
func scanReportUsers(rows reportRows) ([]reportUser, map[string]string, map[string]bool, int, error) {
	names := map[string]string{}
	users := []reportUser{}
	incomplete := map[string]bool{}
	unidentified := 0
	for rows.Next() {
		var u reportUser
		var attrsJSON []byte
		if err := rows.Scan(&u.ID, &u.Username, &u.ZitiID, &attrsJSON); err != nil {
			// The row cannot even be identified, so it cannot be named or
			// attributed to a user — but it must still be counted, or the
			// report claims to have covered a user it never looked at.
			unidentified++
			continue
		}
		if len(attrsJSON) > 0 {
			if err := json.Unmarshal(attrsJSON, &u.Attrs); err != nil {
				// Malformed attributes would leave the identity matching
				// fewer policies than it really does, i.e. under-report reach.
				// Skip the identity and mark its user incomplete instead of
				// guessing "no attributes" — even if another of that user's
				// identities reads cleanly, their reach is now partial.
				incomplete[u.ID] = true
				continue
			}
		}
		names[u.ID] = u.Username
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, incomplete, unidentified,
			fmt.Errorf("could not read this organization's Ziti identities: %w", err)
	}
	return users, names, incomplete, unidentified, nil
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

	// Every identity of every user in this org, with the user's name for
	// display and the identity attributes their reach is matched against. One
	// row per IDENTITY: a user with several enrolled devices has several rows,
	// and all of them are read because each carries its own attributes and its
	// own reach.
	//
	// Both sides of the join are org-scoped. Filtering only zi.org_id would let
	// a cross-org ziti_identities row put a user into the numerator who is not
	// in the denominator below — the same masking mechanism as counting rows
	// instead of users, with a narrower trigger.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT zi.user_id, COALESCE(u.username, ''), COALESCE(zi.ziti_id, ''),
		       COALESCE(zi.attributes, '[]'::jsonb)
		  FROM ziti_identities zi
		  JOIN users u ON u.id = zi.user_id
		 WHERE zi.org_id = $1 AND u.org_id = $1`, org.ID)
	if err != nil {
		s.logger.Error("assignment report: user query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}
	users, names, incompleteIDs, unidentifiedRows, inputErr := scanReportUsers(rows)
	rows.Close()

	// usersTotal is the denominator the report is answerable for; the identity
	// rows above come from ziti_identities, so an org whose sync poller has
	// never run would otherwise evaluate NOBODY and still render "safe to
	// enforce".
	//
	// usersWithoutIdentity is the honest explanation for the gap between the
	// two. A user with no Ziti identity has no Ziti reach, and therefore has no
	// Ziti reach to LOSE, so they are not "incomplete" — but an operator must
	// still be able to see the number and decide whether such a user SHOULD
	// have had an identity. We surface it; we fold it into neither "safe" nor
	// "incomplete".
	//
	// Read even when the identity read already failed, so a partial listing
	// still reports a denominator against which it can be judged.
	usersTotal, usersWithoutIdentity := 0, 0
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*)::int,
		       COUNT(*) FILTER (
		         WHERE NOT EXISTS (
		           SELECT 1 FROM ziti_identities zi
		            WHERE zi.user_id = u.id AND zi.org_id = $1))::int
		  FROM users u
		 WHERE u.org_id = $1`, org.ID).Scan(&usersTotal, &usersWithoutIdentity); err != nil {
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

	// The loop below walks IDENTITY rows, but the report counts USERS. Both
	// tallies are therefore sets of user ids, not counters: a user with two
	// enrolled devices contributes two rows, and counting rows lets that user
	// silently cancel out a user who was never evaluated at all —
	// evaluated == total, shortfall zero, "safe to enforce" over someone nobody
	// looked at. That is the exact hole this denominator exists to close.
	reachSet := map[string]map[string]bool{}
	assignedSet := map[string]map[string]bool{}
	appNames := map[string]string{}
	evaluated := map[string]bool{}
	incomplete := map[string]bool{}
	for id := range incompleteIDs {
		incomplete[id] = true
	}
	assignmentsRead := map[string]bool{}
	for _, u := range users {
		// Assignment is per user, not per identity: read it once however many
		// devices the user has enrolled.
		if !assignmentsRead[u.ID] {
			refs, aerr := appaccess.AppsForUser(ctx, s.db, u.ID, org.ID)
			if aerr != nil {
				s.logger.Warn("assignment report: assignments failed",
					zap.String("user_id", u.ID), zap.Error(aerr))
				incomplete[u.ID] = true
				continue
			}
			assignmentsRead[u.ID] = true
			for _, r := range refs {
				addPair(assignedSet, u.ID, r.ID)
				appNames[r.ID] = r.Name
			}
		}
		if source != ReachabilityFromController {
			// Reach is unknown for everyone. The user counts as incomplete and
			// is entered into NEITHER side of the diff: no fallback to the
			// mirror, and no empty diff that would read as "loses nothing".
			// The assignment half is still recorded above — it is DB-only and
			// correct — so the page can still show what assignment covers.
			incomplete[u.ID] = true
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
				addPair(reachSet, u.ID, ref.ID)
				appNames[ref.ID] = ref.Name
			}
		}
		evaluated[u.ID] = true
	}
	// A user with several identities can be evaluated through one and fail
	// through another. Partial reach is not an evaluation, so incompleteness
	// wins — the direction that withholds reassurance rather than granting it.
	for id := range incomplete {
		delete(evaluated, id)
	}
	usersEvaluated := len(evaluated)
	// Rows too broken to attribute to a user cannot join a set, so they are
	// added as a count. They still have to be counted: an unevaluated user
	// scored as zero is indistinguishable from an evaluated one who loses
	// nothing.
	incompleteUsers := len(incomplete) + unidentifiedRows

	reachable := flattenPairs(reachSet)
	assigned := flattenPairs(assignedSet)

	// buildReport only ever diffs users present in `reachable`; the
	// unavailable path leaves that map empty, so entries stay empty while
	// incomplete_users equals the user count.
	entries, summary := buildReport(reachable, assigned, names, appNames, reportCounts{
		IncompleteUsers:      incompleteUsers,
		UsersEvaluated:       usersEvaluated,
		UsersTotal:           usersTotal,
		UsersWithoutIdentity: usersWithoutIdentity,
		EvaluationComplete:   evaluationComplete(source, incompleteUsers, usersEvaluated),
	})

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

// reportCounts is the denominator half of the summary — everything an operator
// needs to judge how much of the org the report actually covered.
type reportCounts struct {
	// IncompleteUsers is the number of users excluded from both reachable and
	// assigned because their lookup failed. Surfaced so an operator can tell a
	// low would_deny count is genuine and not a symptom of skipped users.
	IncompleteUsers int
	// UsersEvaluated / UsersTotal are the denominator: without them an org
	// that evaluated nobody is textually indistinguishable from one that
	// evaluated everybody and found nothing to take away.
	UsersEvaluated int
	UsersTotal     int
	// UsersWithoutIdentity is how much of the gap between the two is explained
	// by users who have no Ziti identity at all.
	UsersWithoutIdentity int
	// EvaluationComplete is the go/no-go, computed once server-side so that
	// every consumer reads the same rule instead of re-deriving it from four
	// fields — a non-console client that re-derived it wrongly would read a
	// zero-user org as clean.
	EvaluationComplete bool
}

// evaluationComplete is the single definition of "this report earned the
// reassuring headline".
//
// It deliberately does NOT require UsersEvaluated == UsersTotal. Every org on
// this deployment has users with no Ziti identity — disabled accounts, service
// accounts, admins who never onboarded ZTNA — and such a user has no Ziti reach
// and therefore no Ziti reach to LOSE. Requiring equality would keep the signal
// permanently amber, and a go/no-go that is always amber teaches operators to
// ignore it, which is its own failure.
//
// usersEvaluated > 0 still catches the case the strict rule was written for: an
// org whose sync has never run evaluates nobody and cannot read as clean.
func evaluationComplete(source string, incompleteUsers, usersEvaluated int) bool {
	return source == ReachabilityFromController && incompleteUsers == 0 && usersEvaluated > 0
}

// buildReport diffs reachability against assignment and packages the result
// for the API response.
func buildReport(reachable, assigned map[string][]string, names, appNames map[string]string,
	counts reportCounts) ([]ReportEntry, gin.H) {
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
		"users":                  len(affectedUsers),
		"applications":           len(affectedApps),
		"would_deny":             len(entries),
		"incomplete_users":       counts.IncompleteUsers,
		"users_evaluated":        counts.UsersEvaluated,
		"users_total":            counts.UsersTotal,
		"users_without_identity": counts.UsersWithoutIdentity,
		"evaluation_complete":    counts.EvaluationComplete,
	}
	return entries, summary
}
