// Package access - guided OpenZiti network-setup status.
//
// One endpoint (GET /ziti/setup/status) aggregates everything the admin
// console needs to render the "Network Setup" page: an ordered setup
// checklist with remediation, the install advisor (which pieces — controller,
// edge router, tunneler, BrowZer, hop — must exist for THIS deployment), and
// per-route next-hop advice derived from the same effectiveHostingMode logic
// the reconciler applies, so what the UI explains is what actually happens.
package access

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Setup step / component status values.
const (
	setupComplete = "complete"      // done / healthy
	setupWarning  = "warning"       // works, but not recommended for production
	setupAction   = "action_needed" // operator must do something
	setupError    = "error"         // configured but broken
	setupBlocked  = "blocked"       // cannot evaluate until an earlier step completes
	setupOptional = "optional"      // not required for a minimal working network
)

// ZitiSetupStep is one entry of the ordered setup checklist.
type ZitiSetupStep struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	ActionLabel string `json:"action_label,omitempty"`
	ActionHref  string `json:"action_href,omitempty"` // admin-console path
}

// ZitiSetupComponent describes one installable piece of the network and
// whether this deployment needs it ("required" / "conditional" / "optional").
type ZitiSetupComponent struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Required string   `json:"required"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Install  []string `json:"install,omitempty"`
}

// ZitiSetupRouteAdvice explains, for one ziti-enabled route, the effective
// hosting mode, the concrete next-hop chain, what the client side needs, and
// any requirements/warnings — plus the reconciler's live converge state.
type ZitiSetupRouteAdvice struct {
	RouteName      string   `json:"route_name"`
	ServiceName    string   `json:"service_name"`
	ToURL          string   `json:"to_url"`
	StoredMode     string   `json:"stored_mode"`
	EffectiveMode  string   `json:"effective_mode"`
	BrowZerEnabled bool     `json:"browzer_enabled"`
	RouteEnabled   bool     `json:"route_enabled"`
	HopPort        int      `json:"hop_port,omitempty"`
	NextHop        string   `json:"next_hop"`
	ClientSide     string   `json:"client_side"`
	ReconcileState string   `json:"reconcile_state"`
	Requirements   []string `json:"requirements,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// ZitiSetupStatusResponse is the full payload for the Network Setup page.
type ZitiSetupStatusResponse struct {
	Ready      bool                   `json:"ready"`
	Summary    string                 `json:"summary"`
	Steps      []ZitiSetupStep        `json:"steps"`
	Components []ZitiSetupComponent   `json:"components"`
	Routes     []ZitiSetupRouteAdvice `json:"routes"`
	Routers    []ZitiEdgeRouterInfo   `json:"routers"`
	SyncStatus *SyncStatus            `json:"sync_status,omitempty"`
}

// routeNextHop renders the data-path chain for a route as one line the UI can
// show verbatim. hopHost/hopPort are only meaningful for hop mode.
func routeNextHop(effMode, toURL, hopHost string, hopPort int) string {
	switch effMode {
	case HostingModeIdentity:
		return "edge router → OpenIDX access-proxy (SDK terminator, injects identity headers) → " + toURL
	case HostingModeDirect:
		return "edge router (host.v1) → " + toURL
	case HostingModeHop:
		return fmt.Sprintf("edge router (host.v1) → hop nginx %s:%d (SNI demux + Host rewrite) → %s", hopHost, hopPort, toURL)
	default:
		return toURL
	}
}

// routeClientSide states what must run on the end-user side to reach the route.
func routeClientSide(effMode string, browzer bool) string {
	if browzer {
		return "Nothing to install — browser via BrowZer (dials as #browzer-users)"
	}
	if effMode == HostingModeIdentity {
		return "Ziti tunneler (Desktop/Mobile Edge or ziti-edge-tunnel) or OpenIDX Agent, enrolled as #access-proxy-clients"
	}
	return "Ziti tunneler with an identity granted by the route's dial policy"
}

// routeRequirements lists the infrastructure a route's effective mode depends on.
func routeRequirements(effMode string, browzer bool) []string {
	var reqs []string
	if isRouterHosted(effMode) {
		reqs = append(reqs,
			"≥1 online edge router tagged #ziti-routers (tunneler-enabled — created with --tunneler-enabled / -t)")
		if effMode == HostingModeHop {
			reqs = append(reqs, "hop nginx running and listening on the route's hop port (BROWZER_HOP_ADDR)")
		} else {
			reqs = append(reqs, "the edge router must be able to reach the upstream URL on its own network")
		}
	} else {
		reqs = append(reqs,
			"OpenIDX access-proxy identity enrolled (auto-managed)",
			"≥1 online edge router for the fabric path")
	}
	if browzer {
		reqs = append(reqs, "BrowZer bootstrapper configured (users dial from the browser, no client install)")
	}
	return reqs
}

// routeWarnings surfaces stored-vs-effective divergences the reconciler only logs.
func routeWarnings(storedMode, effMode string, browzer bool, toURL string) []string {
	var w []string
	if browzer && storedMode == HostingModeIdentity {
		w = append(w, "stored mode 'identity' is invalid for BrowZer — auto-corrected to '"+effMode+
			"'; set hosting_mode=hop explicitly for external HTTPS upstreams")
	}
	if effMode == HostingModeHop && !needsHopUpstream(toURL) {
		w = append(w, "hop mode requires an https upstream — this route will be skipped by the hop config generator")
	}
	return w
}

// handleZitiReconcilerStatus exposes the reconciler's per-service converge
// state (previously only visible in logs). GET /ziti/reconciler/status
func (s *Service) handleZitiReconcilerStatus(c *gin.Context) {
	if s.zitiReconciler == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false, "services": map[string]string{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": true, "services": s.zitiReconciler.StatusSnapshot()})
}

// setupRouteRow is one org-scoped ziti-enabled proxy_route.
type setupRouteRow struct {
	Name        string
	ServiceName string
	ToURL       string
	StoredMode  string
	BrowZer     bool
	Enabled     bool
}

// loadSetupRoutes returns the caller org's ziti-enabled routes.
func (s *Service) loadSetupRoutes(ctx context.Context, orgID string) ([]setupRouteRow, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT name, COALESCE(ziti_service_name,''), to_url,
		        COALESCE(hosting_mode,'identity'), COALESCE(browzer_enabled,false), enabled
		 FROM proxy_routes
		 WHERE ziti_enabled = true AND org_id = $1
		 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []setupRouteRow
	for rows.Next() {
		var r setupRouteRow
		if err := rows.Scan(&r.Name, &r.ServiceName, &r.ToURL, &r.StoredMode, &r.BrowZer, &r.Enabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadInstallWideHopPorts computes the hop-port map over ALL hop-effective
// routes install-wide — the same input set assignHopPorts gets from the
// reconciler and the hop nginx generator, so displayed ports always match.
func (s *Service) loadInstallWideHopPorts(ctx context.Context, basePort int) map[string]int {
	bctx := orgctx.WithBypassRLS(ctx)
	rows, err := s.db.Pool.Query(bctx,
		//orgscope:ignore hop ports are assigned install-wide over globally-unique ziti_service_name, same as the reconciler
		`SELECT ziti_service_name, to_url, COALESCE(hosting_mode,'identity'), COALESCE(browzer_enabled,false)
		 FROM proxy_routes
		 WHERE ziti_enabled = true AND enabled = true
		   AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		s.logger.Warn("setup: load hop routes failed", zap.Error(err))
		return map[string]int{}
	}
	defer rows.Close()
	var hopNames []string
	for rows.Next() {
		var name, toURL, mode string
		var browzer bool
		if err := rows.Scan(&name, &toURL, &mode, &browzer); err != nil {
			continue
		}
		if effectiveHostingMode(mode, browzer, toURL) == HostingModeHop {
			hopNames = append(hopNames, name)
		}
	}
	return assignHopPorts(hopNames, basePort)
}

// handleZitiSetupStatus builds the guided-setup payload. GET /ziti/setup/status
func (s *Service) handleZitiSetupStatus(c *gin.Context) {
	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	resp := ZitiSetupStatusResponse{}

	// ---- Resolve the effective connection config (DB row wins, else env) ----
	st, hasRow, _ := loadZitiConnSettings(ctx, s.db)
	identityDir := s.config.ZitiIdentityDir
	insecure := s.config.ZitiInsecureSkipVerify
	ctrlURL := s.config.ZitiCtrlURL
	configured := hasRow || s.config.ZitiEnabled
	if hasRow {
		if st.IdentityDir != "" {
			identityDir = st.IdentityDir
		}
		if st.ControllerURL != "" {
			ctrlURL = st.ControllerURL
		}
		insecure = st.InsecureSkipVerify
	}

	zm := s.ziti()
	sdkReady := zm != nil && zm.IsInitialized()
	reachable := false
	ctrlErr := ""
	if zm != nil {
		ok, err := zm.CheckControllerHealth(ctx)
		reachable = ok
		if err != nil {
			ctrlErr = err.Error()
		}
	}

	// ---- Step 1: controller connection ----
	stepCtrl := ZitiSetupStep{
		ID:          "controller",
		Title:       "Connect the Ziti controller",
		Description: "OpenIDX drives one OpenZiti controller — the control plane every router, identity and policy registers with.",
		ActionLabel: "Open connection settings",
		ActionHref:  "/ziti-network?tab=connection",
	}
	switch {
	case reachable:
		stepCtrl.Status = setupComplete
		stepCtrl.Detail = "Controller reachable at " + ctrlURL
	case zm != nil:
		stepCtrl.Status = setupError
		stepCtrl.Detail = "Connected manager cannot reach the controller: " + ctrlErr
		stepCtrl.Remediation = "Check the controller is running and the URL/credentials are current, then press Reconnect."
	case configured:
		stepCtrl.Status = setupAction
		stepCtrl.Detail = "Connection settings exist but OpenIDX is not connected."
		stepCtrl.Remediation = "Open the Connection tab and press Connect (or Save & Connect after fixing settings)."
	default:
		stepCtrl.Status = setupAction
		stepCtrl.Detail = "No controller configured."
		stepCtrl.Remediation = "Install an OpenZiti controller (the bundled docker-compose ships one; standalone: `ziti edge quickstart`), then enter its URL and admin credentials and press Save & Connect."
	}
	resp.Steps = append(resp.Steps, stepCtrl)

	// ---- Step 2: PKI trust (ca.pem) ----
	caPath := filepath.Join(identityDir, "ca.pem")
	stepPKI := ZitiSetupStep{
		ID:          "pki",
		Title:       "Trust the controller's CA",
		Description: "OpenIDX verifies the controller's TLS certificate against ca.pem in the identity directory.",
	}
	if _, err := os.Stat(caPath); err == nil {
		stepPKI.Status = setupComplete
		stepPKI.Detail = "CA bundle present at " + caPath
	} else if insecure {
		stepPKI.Status = setupWarning
		stepPKI.Detail = "TLS verification is DISABLED (insecure_skip_verify). Fine for a lab, never for production."
		stepPKI.Remediation = "Copy the controller CA to " + caPath + " (e.g. `ziti pki` output or the controller's pki/cas.pem) and turn verification back on."
	} else {
		stepPKI.Status = setupAction
		stepPKI.Detail = "No CA bundle at " + caPath + " and TLS verification is on — connecting will fail."
		stepPKI.Remediation = "Copy the controller's CA chain to " + caPath + ", or (lab only) enable insecure_skip_verify in the Connection tab."
	}
	resp.Steps = append(resp.Steps, stepPKI)

	// ---- Step 3: access-proxy identity (auto-managed) ----
	idPath := filepath.Join(identityDir, "access-proxy.json")
	stepID := ZitiSetupStep{
		ID:          "access_proxy",
		Title:       "OpenIDX access-proxy identity",
		Description: "OpenIDX enrolls its own 'access-proxy' identity to host identity-mode services and inject identity headers. Created automatically on first connect.",
	}
	if _, err := os.Stat(idPath); err == nil && sdkReady {
		stepID.Status = setupComplete
		stepID.Detail = "Enrolled at " + idPath + "; SDK ready."
	} else if !reachable {
		stepID.Status = setupBlocked
		stepID.Detail = "Waiting for a controller connection."
	} else {
		stepID.Status = setupAction
		stepID.Detail = "Identity not enrolled yet (missing " + idPath + " or SDK not initialized)."
		stepID.Remediation = "Press Reconnect on the Overview tab — bootstrap re-runs and enrolls the identity automatically."
	}
	resp.Steps = append(resp.Steps, stepID)

	// ---- Step 4: edge routers ----
	stepRouters := ZitiSetupStep{
		ID:          "routers",
		Title:       "Run at least one edge router",
		Description: "Edge routers are the data plane — every connection transits one, and in direct/hop modes the router itself hosts the app. OpenIDX registers and tags them, but the router process must be installed where it can reach your apps.",
		ActionLabel: "View routers",
		ActionHref:  "/ziti-network?tab=overview",
	}
	routersOnline := 0
	if !reachable {
		stepRouters.Status = setupBlocked
		stepRouters.Detail = "Waiting for a controller connection."
	} else if routers, err := zm.ListEdgeRouters(ctx); err != nil {
		stepRouters.Status = setupError
		stepRouters.Detail = "Failed to list routers: " + err.Error()
	} else {
		resp.Routers = routers
		for _, r := range routers {
			if r.IsOnline {
				routersOnline++
			}
		}
		switch {
		case len(routers) == 0:
			stepRouters.Status = setupAction
			stepRouters.Detail = "No edge routers registered."
			stepRouters.Remediation = "On the controller: `ziti edge create edge-router edge1 --jwt-output-file edge1.jwt --tunneler-enabled`, then run the router (`ziti router run` or the openziti/ziti-router container) with that enrollment JWT. --tunneler-enabled is required for direct/hop hosting."
		case routersOnline == 0:
			stepRouters.Status = setupError
			stepRouters.Detail = fmt.Sprintf("%d router(s) registered but none online.", len(routers))
			stepRouters.Remediation = "Check the router process/container is running and can reach the controller's fabric port."
		default:
			stepRouters.Status = setupComplete
			stepRouters.Detail = fmt.Sprintf("%d/%d router(s) online.", routersOnline, len(routers))
		}
	}
	resp.Steps = append(resp.Steps, stepRouters)

	// ---- Per-route advice (org-scoped) + Step 5 ----
	hopHost, hopBase := ParseHopAddr(s.config.ZitiBrowZerHopAddr)
	hopPorts := s.loadInstallWideHopPorts(ctx, hopBase)
	var recState map[string]string
	if s.zitiReconciler != nil {
		recState = s.zitiReconciler.StatusSnapshot()
	}
	routes, rerr := s.loadSetupRoutes(ctx, org.ID)
	if rerr != nil {
		s.logger.Warn("setup: load routes failed", zap.Error(rerr))
	}
	errCount := 0
	browzerRoutes := 0
	identityRoutes := 0
	for _, r := range routes {
		eff := effectiveHostingMode(r.StoredMode, r.BrowZer, r.ToURL)
		adv := ZitiSetupRouteAdvice{
			RouteName:      r.Name,
			ServiceName:    r.ServiceName,
			ToURL:          r.ToURL,
			StoredMode:     r.StoredMode,
			EffectiveMode:  eff,
			BrowZerEnabled: r.BrowZer,
			RouteEnabled:   r.Enabled,
			HopPort:        hopPorts[r.ServiceName],
			NextHop:        routeNextHop(eff, r.ToURL, hopHost, hopPorts[r.ServiceName]),
			ClientSide:     routeClientSide(eff, r.BrowZer),
			Requirements:   routeRequirements(eff, r.BrowZer),
			Warnings:       routeWarnings(r.StoredMode, eff, r.BrowZer, r.ToURL),
		}
		switch {
		case s.zitiReconciler == nil:
			adv.ReconcileState = "reconciler_disabled"
		case !r.Enabled:
			adv.ReconcileState = "route_disabled"
		default:
			if st, ok := recState[r.ServiceName]; ok {
				adv.ReconcileState = st
			} else {
				adv.ReconcileState = "pending"
			}
		}
		if len(adv.ReconcileState) >= 6 && adv.ReconcileState[:6] == "error:" {
			errCount++
		}
		if r.BrowZer {
			browzerRoutes++
		}
		if eff == HostingModeIdentity {
			identityRoutes++
		}
		resp.Routes = append(resp.Routes, adv)
	}

	stepRoutes := ZitiSetupStep{
		ID:          "services",
		Title:       "Expose your applications",
		Description: "Each app is a proxy route with Ziti enabled; the reconciler creates the Ziti service, policies and hosting for you.",
		ActionLabel: "Manage routes",
		ActionHref:  "/proxy-routes",
	}
	switch {
	case len(routes) == 0:
		stepRoutes.Status = setupAction
		stepRoutes.Detail = "No Ziti-enabled routes yet."
		stepRoutes.Remediation = "Use Quick Create on Proxy Routes (web apps) or App Publish, then enable Ziti on the route."
	case errCount > 0:
		stepRoutes.Status = setupError
		stepRoutes.Detail = fmt.Sprintf("%d of %d route(s) failed to converge — see the route list below.", errCount, len(routes))
	case s.zitiReconciler == nil:
		stepRoutes.Status = setupWarning
		stepRoutes.Detail = fmt.Sprintf("%d route(s) configured, but the reconciler is disabled — provisioning is imperative-only.", len(routes))
		stepRoutes.Remediation = "Set ZITI_RECONCILER=true so routes continuously self-heal."
	default:
		stepRoutes.Status = setupComplete
		stepRoutes.Detail = fmt.Sprintf("%d route(s) exposed via Ziti.", len(routes))
	}
	resp.Steps = append(resp.Steps, stepRoutes)

	// ---- Step 6: user identities ----
	stepUsers := ZitiSetupStep{
		ID:          "identities",
		Title:       "Sync users to Ziti identities",
		Description: "Users dial services with their own Ziti identity; group memberships become role attributes that policies match on.",
		ActionLabel: "Open identity sync",
		ActionHref:  "/ziti-network?tab=security",
	}
	if zm == nil {
		stepUsers.Status = setupBlocked
		stepUsers.Detail = "Waiting for a controller connection."
	} else if sync, err := zm.GetSyncStatus(ctx); err == nil {
		resp.SyncStatus = sync
		if sync.UnsyncedUsers > 0 {
			stepUsers.Status = setupAction
			stepUsers.Detail = fmt.Sprintf("%d of %d enabled user(s) have no Ziti identity.", sync.UnsyncedUsers, sync.TotalUsers)
			stepUsers.Remediation = "Run Sync All Users (Security tab → Policy Sync) or enable the background sync poller."
		} else {
			stepUsers.Status = setupComplete
			stepUsers.Detail = fmt.Sprintf("%d identities cover all %d enabled user(s).", sync.TotalIdentities, sync.TotalUsers)
		}
	} else {
		stepUsers.Status = setupWarning
		stepUsers.Detail = "Sync status unavailable: " + err.Error()
	}
	resp.Steps = append(resp.Steps, stepUsers)

	// ---- Step 7: client access ----
	stepClient := ZitiSetupStep{
		ID:          "client_access",
		Title:       "Choose how users connect",
		Description: "Web apps: BrowZer needs nothing installed on the device. TCP/identity-mode apps: each device runs a Ziti tunneler or the OpenIDX Agent.",
	}
	browzerEnabled := false
	if zm != nil {
		if bz, err := zm.GetBrowZerConfig(ctx); err == nil && bz != nil {
			browzerEnabled = bz.Enabled
		}
	}
	switch {
	case browzerRoutes > 0 && !browzerEnabled:
		stepClient.Status = setupAction
		stepClient.Detail = fmt.Sprintf("%d route(s) are BrowZer-enabled but BrowZer itself is not bootstrapped.", browzerRoutes)
		stepClient.Remediation = "Enable BrowZer under BrowZer Management (creates the JWT signer, auth policy and dial policy)."
		stepClient.ActionLabel = "Open BrowZer management"
		stepClient.ActionHref = "/browzer-management"
	case browzerRoutes > 0:
		stepClient.Status = setupComplete
		stepClient.Detail = fmt.Sprintf("BrowZer active for %d route(s) — clientless browser access.", browzerRoutes)
	case identityRoutes > 0:
		stepClient.Status = setupOptional
		stepClient.Detail = fmt.Sprintf("%d identity-mode route(s) — users need a tunneler (Ziti Desktop/Mobile Edge, ziti-edge-tunnel) or the OpenIDX Agent.", identityRoutes)
		stepClient.ActionLabel = "Agent fleet"
		stepClient.ActionHref = "/agent-fleet"
	default:
		stepClient.Status = setupOptional
		stepClient.Detail = "Decide per app: BrowZer for web apps (no install), tunneler/Agent for everything else."
	}
	resp.Steps = append(resp.Steps, stepClient)

	// ---- Install advisor components ----
	hopRoutes := 0
	for _, r := range resp.Routes {
		if r.EffectiveMode == HostingModeHop {
			hopRoutes++
		}
	}
	resp.Components = buildSetupComponents(reachable, sdkReady, len(resp.Routers), routersOnline,
		browzerRoutes, browzerEnabled, identityRoutes, hopRoutes, hopHost, hopBase)

	// ---- Summary ----
	done := 0
	countable := 0
	resp.Ready = true
	for _, st := range resp.Steps {
		switch st.Status {
		case setupComplete:
			done++
			countable++
		case setupOptional:
			// not counted
		default:
			countable++
			if st.Status != setupWarning {
				resp.Ready = false
			}
		}
	}
	resp.Summary = fmt.Sprintf("%d of %d required steps complete", done, countable)

	c.JSON(http.StatusOK, resp)
}

// buildSetupComponents renders the install advisor: every piece a Ziti network
// can involve, whether THIS deployment needs it, and how to install it.
func buildSetupComponents(reachable, sdkReady bool, routersTotal, routersOnline,
	browzerRoutes int, browzerEnabled bool, identityRoutes, hopRoutes int, hopHost string, hopBase int) []ZitiSetupComponent {

	statusOf := func(needed, ok bool) string {
		switch {
		case ok:
			return setupComplete
		case needed:
			return setupAction
		default:
			return setupOptional
		}
	}

	comps := []ZitiSetupComponent{
		{
			ID: "controller", Name: "OpenZiti Controller", Required: "required",
			Role:   "Control plane: identities, services, policies. One per deployment.",
			Status: statusOf(true, reachable),
			Install: []string{
				"Bundled: the OpenIDX docker-compose stack ships a controller.",
				"Standalone: `ziti edge quickstart` (lab) or the openziti/ziti controller deployment (production).",
			},
		},
		{
			ID: "edge-router", Name: "Ziti Edge Router", Required: "required",
			Role:   "Data plane. Every connection transits a router; in direct/hop modes the router also hosts the app, so run it on a network that can reach your upstreams.",
			Status: statusOf(true, routersOnline > 0),
			Detail: fmt.Sprintf("%d/%d online", routersOnline, routersTotal),
			Install: []string{
				"Create on the controller: `ziti edge create edge-router edge1 --jwt-output-file edge1.jwt --tunneler-enabled`",
				"Run it: `ziti router run router.yml` or the openziti/ziti-router container, feeding it edge1.jwt to enroll.",
				"--tunneler-enabled matters: without it the router cannot host direct/hop services.",
			},
		},
		{
			ID: "access-proxy", Name: "OpenIDX access-proxy identity", Required: "required",
			Role:   "OpenIDX's own service-hosting identity for identity-mode routes (adds identity headers). Auto-created and auto-enrolled on connect — nothing to install.",
			Status: statusOf(true, sdkReady),
		},
		{
			ID: "browzer", Name: "BrowZer Bootstrapper", Required: requiredIf(browzerRoutes > 0),
			Role:   "Clientless access for web apps: users open a URL in any browser, auth via OpenIDX SSO, traffic runs Ziti-in-WASM. Nothing installed on devices.",
			Status: statusOf(browzerRoutes > 0, browzerEnabled),
			Detail: fmt.Sprintf("%d BrowZer route(s)", browzerRoutes),
			Install: []string{
				"Enable under BrowZer Management — OpenIDX creates the external JWT signer, auth policy and dial policy on the controller.",
				"The bootstrapper container is part of the compose stack; give it a resolvable *.domain (wildcard DNS + TLS).",
			},
		},
		{
			ID: "tunneler", Name: "Ziti tunneler / OpenIDX Agent (client devices)", Required: requiredIf(identityRoutes > 0 && browzerRoutes == 0),
			Role:   "Per-device client for non-browser (TCP/identity-mode) apps. The OpenIDX Agent embeds a tunneler and self-enrolls via the Agent Fleet QR flow.",
			Status: setupOptional,
			Detail: fmt.Sprintf("%d identity-mode route(s)", identityRoutes),
			Install: []string{
				"Windows/macOS: Ziti Desktop Edge; iOS/Android: Ziti Mobile Edge; Linux: ziti-edge-tunnel.",
				"Or deploy the OpenIDX Agent (Agent Fleet page → enrollment QR) for managed devices.",
			},
		},
		{
			ID: "hop", Name: "Hop nginx (shared TLS hop)", Required: requiredIf(hopRoutes > 0),
			Role:   "Only for hop-mode routes: SNI-demuxes per-app ports and rewrites the Host header for external HTTPS upstreams BrowZer can't address directly.",
			Status: statusOf(hopRoutes > 0, hopRoutes == 0 || hopHost != ""),
			Detail: fmt.Sprintf("%d hop route(s); base %s:%d (BROWZER_HOP_ADDR)", hopRoutes, hopHost, hopBase),
			Install: []string{
				"Part of the compose stack — OpenIDX generates its nginx config from the same port map shown per route below.",
			},
		},
	}
	return comps
}

// requiredIf maps a condition to the component "required" label.
func requiredIf(needed bool) string {
	if needed {
		return "conditional"
	}
	return "optional"
}
