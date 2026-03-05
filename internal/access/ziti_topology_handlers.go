package access

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Network Topology API – provides a graph of all Ziti entities and edges
// for frontend visualization
// ---------------------------------------------------------------------------

// TopologyNode represents a single node in the network topology graph
type TopologyNode struct {
	ID       string                 `json:"id"`
	Label    string                 `json:"label"`
	Type     string                 `json:"type"` // controller, router, service, identity, gateway
	Status   string                 `json:"status"` // online, offline, pending, healthy, degraded
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TopologyEdge represents a connection between two nodes
type TopologyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"` // fabric, policy, binding, enrollment
	Label  string `json:"label,omitempty"`
}

// TopologyGraph is the full network topology
type TopologyGraph struct {
	Nodes       []TopologyNode        `json:"nodes"`
	Edges       []TopologyEdge        `json:"edges"`
	Summary     TopologySummary       `json:"summary"`
	GeneratedAt time.Time             `json:"generated_at"`
}

// TopologySummary gives quick counts
type TopologySummary struct {
	Controllers      int `json:"controllers"`
	Routers          int `json:"routers"`
	RoutersOnline    int `json:"routers_online"`
	RoutersOffline   int `json:"routers_offline"`
	Services         int `json:"services"`
	ServicesEnabled  int `json:"services_enabled"`
	Identities       int `json:"identities"`
	IdentitiesEnrolled int `json:"identities_enrolled"`
	ServicePolicies  int `json:"service_policies"`
	EdgeRouterPolicies int `json:"edge_router_policies"`
}

// ---------------------------------------------------------------------------
// Recommendations API – generates actionable management advice
// ---------------------------------------------------------------------------

// Recommendation is a single actionable suggestion
type Recommendation struct {
	ID          string `json:"id"`
	Category    string `json:"category"`    // security, performance, reliability, cleanup
	Severity    string `json:"severity"`    // critical, high, medium, low, info
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`      // suggested remediation
	AutoFixable bool   `json:"auto_fixable"`
}

// RecommendationsResponse wraps the list with summary scores
type RecommendationsResponse struct {
	Recommendations []Recommendation `json:"recommendations"`
	Scores          ScoreSummary     `json:"scores"`
	GeneratedAt     time.Time        `json:"generated_at"`
}

// ScoreSummary provides overall health scores
type ScoreSummary struct {
	Overall     int `json:"overall"`     // 0-100
	Security    int `json:"security"`
	Performance int `json:"performance"`
	Reliability int `json:"reliability"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Service) handleGetNetworkTopology(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	graph := TopologyGraph{
		Nodes:       []TopologyNode{},
		Edges:       []TopologyEdge{},
		GeneratedAt: time.Now(),
	}

	var summary TopologySummary

	// 1. Controller node
	controllerStatus := "offline"
	if s.zitiManager != nil {
		if _, err := s.zitiManager.GetControllerVersion(c.Request.Context()); err == nil {
			controllerStatus = "online"
		}
	}
	graph.Nodes = append(graph.Nodes, TopologyNode{
		ID:     "controller",
		Label:  "Ziti Controller",
		Type:   "controller",
		Status: controllerStatus,
		Metadata: map[string]interface{}{
			"role": "control-plane",
		},
	})
	summary.Controllers = 1

	// 2. Edge Routers
	routers, err := s.zitiManager.ListEdgeRouters(c.Request.Context())
	if err != nil {
		s.logger.Warn("topology: failed to list routers", zap.Error(err))
	}
	for _, r := range routers {
		status := "offline"
		if r.IsOnline {
			status = "online"
			summary.RoutersOnline++
		} else {
			summary.RoutersOffline++
		}
		graph.Nodes = append(graph.Nodes, TopologyNode{
			ID:     "router-" + r.ID,
			Label:  r.Name,
			Type:   "router",
			Status: status,
			Metadata: map[string]interface{}{
				"hostname":  r.Hostname,
				"verified":  r.IsVerified,
				"roles":     r.RoleAttributes,
			},
		})
		// Router connects to controller
		graph.Edges = append(graph.Edges, TopologyEdge{
			Source: "controller",
			Target: "router-" + r.ID,
			Type:   "fabric",
			Label:  "fabric link",
		})
	}
	summary.Routers = len(routers)

	// 3. Services from DB
	svcRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, protocol, host, port, enabled, ziti_id FROM ziti_services ORDER BY name`)
	if err != nil {
		s.logger.Warn("topology: failed to list services", zap.Error(err))
	} else {
		defer svcRows.Close()
		for svcRows.Next() {
			var id, name, protocol, host, zitiID string
			var port int
			var enabled bool
			if err := svcRows.Scan(&id, &name, &protocol, &host, &port, &enabled, &zitiID); err != nil {
				continue
			}
			status := "offline"
			if enabled {
				status = "online"
				summary.ServicesEnabled++
			}
			graph.Nodes = append(graph.Nodes, TopologyNode{
				ID:     "service-" + id,
				Label:  name,
				Type:   "service",
				Status: status,
				Metadata: map[string]interface{}{
					"protocol": protocol,
					"host":     host,
					"port":     port,
					"ziti_id":  zitiID,
				},
			})
			summary.Services++
		}
	}

	// 4. Identities from DB
	identRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, identity_type, enrolled, user_id, ziti_id, attributes FROM ziti_identities ORDER BY name`)
	if err != nil {
		s.logger.Warn("topology: failed to list identities", zap.Error(err))
	} else {
		defer identRows.Close()
		for identRows.Next() {
			var id, name, identType, zitiID string
			var enrolled bool
			var userID, attrsRaw *string
			if err := identRows.Scan(&id, &name, &identType, &enrolled, &userID, &zitiID, &attrsRaw); err != nil {
				continue
			}
			status := "pending"
			if enrolled {
				status = "online"
				summary.IdentitiesEnrolled++
			}
			nodeType := "identity"
			if identType == "Router" || identType == "Edge Router" {
				nodeType = "gateway"
			}
			meta := map[string]interface{}{
				"identity_type": identType,
				"ziti_id":       zitiID,
			}
			if userID != nil {
				meta["user_id"] = *userID
			}
			graph.Nodes = append(graph.Nodes, TopologyNode{
				ID:     "identity-" + id,
				Label:  name,
				Type:   nodeType,
				Status: status,
				Metadata: meta,
			})
			summary.Identities++
		}
	}

	// 5. Service Policies → create edges between identities and services
	policies, err := s.zitiManager.ListServicePolicies(c.Request.Context())
	if err != nil {
		s.logger.Warn("topology: failed to list service policies", zap.Error(err))
	} else {
		summary.ServicePolicies = len(policies)
		for _, p := range policies {
			policyNodeID := "policy-" + p.ID
			graph.Nodes = append(graph.Nodes, TopologyNode{
				ID:     policyNodeID,
				Label:  p.Name,
				Type:   "policy",
				Status: "active",
				Metadata: map[string]interface{}{
					"policy_type":    p.Type,
					"service_roles":  p.ServiceRoles,
					"identity_roles": p.IdentityRoles,
				},
			})
		}
	}

	// 6. Edge Router Policies
	erPolicies, err := s.zitiManager.ListEdgeRouterPolicies(c.Request.Context())
	if err != nil {
		s.logger.Warn("topology: failed to list edge router policies", zap.Error(err))
	} else {
		summary.EdgeRouterPolicies = len(erPolicies)
	}

	graph.Summary = summary
	c.JSON(http.StatusOK, graph)
}

func (s *Service) handleGetRecommendations(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var recs []Recommendation
	secScore, perfScore, relScore := 100, 100, 100

	// ----- Security checks -----

	// Check for unenrolled identities
	var unenrolledCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_identities WHERE enrolled = false`).Scan(&unenrolledCount)
	if unenrolledCount > 0 {
		recs = append(recs, Recommendation{
			ID:          "sec-unenrolled-identities",
			Category:    "security",
			Severity:    "high",
			Title:       "Unenrolled identities detected",
			Description: fmtCount(unenrolledCount, "identity", "identities") + " pending enrollment. These identities have outstanding enrollment tokens that could be intercepted.",
			Action:      "Complete enrollment for pending identities or delete unused ones from the Identities tab.",
			AutoFixable: false,
		})
		secScore -= minInt(20, unenrolledCount*5)
	}

	// Check for services without policies
	var svcCount, policiedSvcCount int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_services WHERE enabled = true`).Scan(&svcCount)
	policies, _ := s.zitiManager.ListServicePolicies(c.Request.Context())
	policiedServices := map[string]bool{}
	for _, p := range policies {
		for _, r := range p.ServiceRoles {
			policiedServices[r] = true
		}
	}
	policiedSvcCount = len(policiedServices)
	if svcCount > 0 && policiedSvcCount == 0 {
		recs = append(recs, Recommendation{
			ID:          "sec-no-service-policies",
			Category:    "security",
			Severity:    "critical",
			Title:       "No service policies configured",
			Description: "Services exist but no service policies grant access. No identity can reach any service through the overlay.",
			Action:      "Create Dial and Bind service policies in the Security tab to grant identities access to services.",
			AutoFixable: false,
		})
		secScore -= 30
	}

	// Check for expiring certificates
	var expiringCerts int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_certificates WHERE not_after < NOW() + INTERVAL '30 days' AND not_after > NOW()`).Scan(&expiringCerts)
	if expiringCerts > 0 {
		recs = append(recs, Recommendation{
			ID:          "sec-expiring-certs",
			Category:    "security",
			Severity:    "high",
			Title:       "Certificates expiring soon",
			Description: fmtCount(expiringCerts, "certificate", "certificates") + " will expire within 30 days.",
			Action:      "Rotate expiring certificates from the Security > Certificates section to avoid service disruption.",
			AutoFixable: true,
		})
		secScore -= minInt(25, expiringCerts*10)
	}

	// Check for disabled posture checks
	var disabledPosture int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_posture_checks WHERE enabled = false`).Scan(&disabledPosture)
	if disabledPosture > 0 {
		recs = append(recs, Recommendation{
			ID:          "sec-disabled-posture",
			Category:    "security",
			Severity:    "medium",
			Title:       "Disabled posture checks",
			Description: fmtCount(disabledPosture, "posture check is", "posture checks are") + " disabled, reducing zero-trust enforcement.",
			Action:      "Review and re-enable posture checks in the Security tab to strengthen device trust verification.",
			AutoFixable: false,
		})
		secScore -= minInt(15, disabledPosture*5)
	}

	// ----- Reliability checks -----

	// Check for offline routers
	routers, _ := s.zitiManager.ListEdgeRouters(c.Request.Context())
	offlineRouters := 0
	for _, r := range routers {
		if !r.IsOnline {
			offlineRouters++
		}
	}
	if offlineRouters > 0 {
		recs = append(recs, Recommendation{
			ID:          "rel-offline-routers",
			Category:    "reliability",
			Severity:    "critical",
			Title:       "Offline edge routers",
			Description: fmtCount(offlineRouters, "edge router is", "edge routers are") + " offline. Traffic cannot route through offline routers.",
			Action:      "Check the status of offline routers from the Overview tab. Run Health Check and Reconnect if needed.",
			AutoFixable: false,
		})
		relScore -= minInt(40, offlineRouters*20)
	}

	if len(routers) == 0 {
		recs = append(recs, Recommendation{
			ID:          "rel-no-routers",
			Category:    "reliability",
			Severity:    "critical",
			Title:       "No edge routers registered",
			Description: "No edge routers are registered. The overlay network cannot route any traffic without at least one edge router.",
			Action:      "Deploy and enroll at least one edge router to enable overlay traffic routing.",
			AutoFixable: false,
		})
		relScore -= 50
	} else if len(routers) == 1 {
		recs = append(recs, Recommendation{
			ID:          "rel-single-router",
			Category:    "reliability",
			Severity:    "medium",
			Title:       "Single point of failure: only one router",
			Description: "Only one edge router is deployed. If it goes down, all overlay traffic will be disrupted.",
			Action:      "Deploy a second edge router in a different availability zone for high availability.",
			AutoFixable: false,
		})
		relScore -= 15
	}

	// Check for unsynced users
	var unsyncedUsers int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM users u LEFT JOIN ziti_identities z ON z.user_id = u.id WHERE z.id IS NULL AND u.status = 'active'`).Scan(&unsyncedUsers)
	if unsyncedUsers > 0 {
		recs = append(recs, Recommendation{
			ID:          "rel-unsynced-users",
			Category:    "reliability",
			Severity:    "low",
			Title:       "Users without Ziti identities",
			Description: fmtCount(unsyncedUsers, "active user does", "active users do") + " not have Ziti identities. These users cannot access zero-trust overlay services.",
			Action:      "Sync users from the Identities tab using the Sync All Users button.",
			AutoFixable: true,
		})
		relScore -= minInt(10, unsyncedUsers)
	}

	// ----- Performance checks -----

	// Check for services with no terminators
	var svcNoTerminators int
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM ziti_services WHERE enabled = true`).Scan(&svcNoTerminators)
	// If many services exist but we haven't verified terminators, suggest a check
	if svcCount > 5 {
		recs = append(recs, Recommendation{
			ID:          "perf-review-terminators",
			Category:    "performance",
			Severity:    "info",
			Title:       "Review service terminators",
			Description: "With " + fmtCount(svcCount, "service", "services") + ", consider reviewing terminators to ensure optimal traffic routing.",
			Action:      "Check the Security > Terminators section to verify each service has healthy terminators.",
			AutoFixable: false,
		})
		perfScore -= 5
	}

	// Check controller connectivity
	if _, err := s.zitiManager.GetControllerVersion(c.Request.Context()); err != nil {
		recs = append(recs, Recommendation{
			ID:          "rel-controller-unreachable",
			Category:    "reliability",
			Severity:    "critical",
			Title:       "Controller unreachable",
			Description: "Cannot reach the Ziti controller. All management operations and new connections will fail.",
			Action:      "Verify the controller is running and the ZITI_CTRL_ADDRESS is correct. Use Reconnect from the Overview tab.",
			AutoFixable: false,
		})
		relScore -= 50
	}

	// Add a positive recommendation if everything looks good
	if len(recs) == 0 {
		recs = append(recs, Recommendation{
			ID:          "info-all-healthy",
			Category:    "info",
			Severity:    "info",
			Title:       "Network is healthy",
			Description: "All checks passed. Your OpenZiti network is well-configured.",
			Action:      "No action needed. Continue monitoring from the Overview tab.",
			AutoFixable: false,
		})
	}

	// Clamp scores
	secScore = maxInt(0, secScore)
	perfScore = maxInt(0, perfScore)
	relScore = maxInt(0, relScore)
	overall := (secScore + perfScore + relScore) / 3

	c.JSON(http.StatusOK, RecommendationsResponse{
		Recommendations: recs,
		Scores: ScoreSummary{
			Overall:     overall,
			Security:    secScore,
			Performance: perfScore,
			Reliability: relScore,
		},
		GeneratedAt: time.Now(),
	})
}

// Helpers
func fmtCount(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
