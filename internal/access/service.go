// Package access provides the identity-aware reverse proxy (Zero Trust Access) for OpenIDX
package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/abac"
	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/vault"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// ProxyRoute represents a configured proxy route
type ProxyRoute struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	FromURL               string            `json:"from_url"`
	ToURL                 string            `json:"to_url"`
	PreserveHost          bool              `json:"preserve_host"`
	RequireAuth           bool              `json:"require_auth"`
	AllowedRoles          []string          `json:"allowed_roles,omitempty"`
	AllowedGroups         []string          `json:"allowed_groups,omitempty"`
	PolicyIDs             []string          `json:"policy_ids,omitempty"`
	IdleTimeout           int               `json:"idle_timeout"`
	AbsoluteTimeout       int               `json:"absolute_timeout"`
	CORSAllowedOrigins    []string          `json:"cors_allowed_origins,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	Enabled               bool              `json:"enabled"`
	Priority              int               `json:"priority"`
	ZitiEnabled           bool              `json:"ziti_enabled"`
	ZitiServiceName       string            `json:"ziti_service_name,omitempty"`
	IDPId                 string            `json:"idp_id,omitempty"`
	RouteType             string            `json:"route_type"`
	RemoteHost            string            `json:"remote_host,omitempty"`
	RemotePort            int               `json:"remote_port,omitempty"`
	ReverifyInterval      int               `json:"reverify_interval"`
	PostureCheckIDs       []string          `json:"posture_check_ids,omitempty"`
	InlinePolicy          string            `json:"inline_policy,omitempty"`
	RequireDeviceTrust    bool              `json:"require_device_trust"`
	AllowedCountries      []string          `json:"allowed_countries,omitempty"`
	MaxRiskScore          int               `json:"max_risk_score"`
	GuacamoleConnectionID string            `json:"guacamole_connection_id,omitempty"`
	LandingPath           string            `json:"landing_path,omitempty"`
	HostingMode           string            `json:"hosting_mode,omitempty"`
	// UpstreamPoolID points the route at an upstream pool instead of the single
	// address in ToURL. Empty means "use to_url", which is what every route did
	// before pools existed and what one still does when the pool it names has no
	// usable member.
	UpstreamPoolID string    `json:"upstream_pool_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	// OrgID is the organization that owns the route. findRouteByHost fills it
	// for the data plane, which resolves a request's organization from the
	// route its host matched; the route API does not return it.
	OrgID string `json:"-"`
	// ApplicationID/ApplicationName identify the application (if any) whose
	// applications.route_id points at this route — the same link appForRoute
	// (proxy_assignment_cache.go) resolves to decide real access under
	// ACCESS_ASSIGNMENT_ENFORCE. Populated read-only by handleListRoutes so the
	// console can point admins at "Manage Access" on that application instead
	// of editing AllowedRoles/AllowedGroups, which enforcement ignores once a
	// route is app-backed. Empty when no application links to this route.
	ApplicationID   string `json:"application_id,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
}

// normalizeHostingMode validates a hosting_mode value from the API. An empty
// value defaults to identity (the reconciler then auto-selects hop/direct for
// BrowZer routes — see ZitiReconciler EffectiveMode). Returns ok=false for any
// other value so the handler can reject it with a 400.
func normalizeHostingMode(mode string) (string, bool) {
	switch mode {
	case "":
		return HostingModeIdentity, true
	case HostingModeIdentity, HostingModeDirect, HostingModeHop:
		return mode, true
	default:
		return "", false
	}
}

// ProxySession represents an active proxy session
type ProxySession struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	RouteID           string    `json:"route_id,omitempty"`
	SessionToken      string    `json:"-"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
	StartedAt         time.Time `json:"started_at"`
	LastActiveAt      time.Time `json:"last_active_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Revoked           bool      `json:"revoked"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	RiskScore         int       `json:"risk_score,omitempty"`
	AuthMethods       []string  `json:"auth_methods,omitempty"`
	Location          string    `json:"location,omitempty"`
	DeviceTrusted     bool      `json:"device_trusted,omitempty"`
	// IDPName is the external identity provider that authenticated this
	// session, empty for a session created by OpenIDX's own login. An operator
	// answering "an IdP is compromised, whose sessions came through it?" has
	// nothing else to go on: proxy_sessions.idp_id was written by the multi-IdP
	// callback and read by nothing until this field existed.
	IDPName string `json:"idp_name,omitempty"`
	// bearer is the Authorization header value the proxy authenticated this
	// request with, when it came from getSessionFromBearer. The proxy removes
	// exactly that value before the request goes upstream.
	bearer string
	// orgID is the organization of the route the session was signed in on,
	// which is where its roles hold: a proxy session is accepted only on that
	// organization's routes (sessionOnRoute).
	orgID string
}

// Service provides access proxy operations
type Service struct {
	db                   *database.PostgresDB
	redis                *database.RedisClient
	config               *config.Config
	logger               *zap.Logger
	governanceURL        string
	auditURL             string
	sessionSecret        []byte
	oauthIssuer          string
	oauthInternalURL     string // Docker-internal URL for server-to-server calls
	oauthJWKSURL         string
	idpCipher            *secretcrypt.Cipher // decrypts identity_providers.client_secret at rest
	zitiProvider         *ZitiProvider
	zitiReconciler       *ZitiReconciler
	guacamoleClient      *GuacamoleClient // "direct" PAM broker (guacd dials targets directly)
	guacamoleZitiClient  *GuacamoleClient // dedicated OpenZiti PAM broker (guacd + ziti-tunnel)
	featureManager       *FeatureManager
	auditService         *UnifiedAuditService
	browzerTargetManager *BrowZerTargetManager
	healthEngine         *HealthEngine
	apisixConfigPath     string
	agentHandler         *AgentAPIHandler
	remoteSupportHandler *RemoteSupportHandler
	vaultSvc             *vault.Service
	// guacRecordingRing seals guacd recordings at rest (PAM A1). Nil when
	// encryption is unconfigured — the recording download handler then streams
	// plaintext unchanged. Same keyring the sealer worker uses.
	guacRecordingRing *recordingKeyring
	// groupCache memoizes per-user group membership for route authorization
	// (allowed_groups), keyed by user id with a short TTL.
	groupCache sync.Map
	// routeAppCache memoizes the route→application resolution used by the
	// assignment overlay in handleProxy, keyed by route id with a short TTL —
	// see proxy_assignment_cache.go.
	routeAppCache sync.Map
	// assignCache memoizes the assignment predicate used by the same overlay,
	// keyed by "userID|applicationID" with a short TTL.
	assignCache sync.Map
}

// handleAgentDownload serves the per-OS agent installers + manifest + APK
// without auth. Delegates to AgentAPIHandler where the download logic lives.
func (s *Service) handleAgentDownload(c *gin.Context) {
	if s.agentHandler == nil {
		c.JSON(503, gin.H{"error": "agent handler not initialized"})
		return
	}
	s.agentHandler.HandleAgentDownload(c)
}

// SetGuacamoleClient sets the "direct" PAM broker (guacd dials targets directly).
func (s *Service) SetGuacamoleClient(gc *GuacamoleClient) {
	s.guacamoleClient = gc
	if s.featureManager != nil {
		s.featureManager.SetGuacamoleClient(gc)
	}
	if s.auditService != nil {
		s.auditService.SetGuacamoleClient(gc)
	}
}

// SetGuacamoleZitiClient wires the dedicated OpenZiti PAM broker. Entries with
// reach_mode='ziti' launch through this broker (its guacd is colocated with a
// ziti-tunnel that carries the target hop over the overlay).
func (s *Service) SetGuacamoleZitiClient(gc *GuacamoleClient) { s.guacamoleZitiClient = gc }

// brokerFor returns the Guacamole broker client a launch should use for the
// given reach mode: the dedicated Ziti broker for 'ziti', otherwise the direct
// broker. Returns nil when the required broker is not configured — the caller
// fails closed rather than dialing a target the wrong way.
func (s *Service) brokerFor(reachMode string) *GuacamoleClient {
	if reachMode == "ziti" {
		return s.guacamoleZitiClient
	}
	return s.guacamoleClient
}

// ziti returns the live OpenZiti manager (nil when disconnected, or when no
// provider was wired — e.g. bare Service construction in tests). All call
// sites read through this accessor so the manager can be swapped at runtime.
func (s *Service) ziti() *ZitiManager {
	if s.zitiProvider == nil {
		return nil
	}
	return s.zitiProvider.Get()
}

// ZitiProvider exposes the shared provider (for the connect/disconnect handlers).
func (s *Service) ZitiProvider() *ZitiProvider { return s.zitiProvider }

// SetZitiProvider wires the shared provider and fans it to the child services so
// a runtime Swap is visible everywhere.
func (s *Service) SetZitiProvider(p *ZitiProvider) {
	s.zitiProvider = p
	if s.featureManager != nil {
		s.featureManager.SetZitiProvider(p)
	}
	if s.auditService != nil {
		s.auditService.SetZitiProvider(p)
	}
}

// SetZitiManager installs a manager into the shared provider (compat shim for
// boot/tests). Creates+fans a provider if one isn't wired yet.
func (s *Service) SetZitiManager(zm *ZitiManager) {
	if s.zitiProvider == nil {
		s.SetZitiProvider(NewZitiProvider())
	}
	s.zitiProvider.Store(zm)
}

// SetFeatureManager sets the feature manager for the service. The manager
// seals the secrets it stores with this service's ENCRYPTION_KEY cipher.
func (s *Service) SetFeatureManager(fm *FeatureManager) {
	s.featureManager = fm
	if s.idpCipher != nil {
		fm.SetSecretCipher(s.idpCipher)
	}
	if s.zitiProvider != nil {
		fm.SetZitiProvider(s.zitiProvider)
	}
	if s.guacamoleClient != nil {
		fm.SetGuacamoleClient(s.guacamoleClient)
	}
}

// SetZitiReconciler wires the Ziti reconciler so mutation handlers can request
// a converge after changing desired state. No-op safe when nil.
func (s *Service) SetZitiReconciler(r *ZitiReconciler) { s.zitiReconciler = r }

// enqueueReconcile asks the reconciler to converge, if one is running.
func (s *Service) enqueueReconcile() {
	if s.zitiReconciler != nil {
		s.zitiReconciler.Enqueue()
	}
}

// appTileClientID is the deterministic client_id of the Applications launcher
// tile that mirrors a proxy route, so the route appears on the admin console's
// Applications page (which reads `applications`, not `proxy_routes`). Matches
// the one-click publish flow's convention (app_publish.go).
func appTileClientID(routeID string) string { return "proxy-app-" + routeID }

// upsertAppTile keeps a proxy route's Applications launcher tile in sync, so a
// route created or edited directly under Proxy Routes shows on the Applications
// page with working row actions — instead of needing a tile backfilled by hand.
// Same upsert shape the one-click publish flow produces. Best-effort: a tile
// failure must not fail the route mutation.
func (s *Service) upsertAppTile(ctx context.Context, routeID, name, description, fromURL, landingPath string, orgID string) {
	baseURL := strings.TrimRight(fromURL, "/")
	if landingPath == "" {
		landingPath = "/"
	}
	baseURL += landingPath
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled, org_id)
		VALUES ($1, $2, $3, $4, 'proxy', 'proxy', $5, '{}', true, $6)
		ON CONFLICT (client_id) DO UPDATE SET
			name = EXCLUDED.name, description = EXCLUDED.description,
			base_url = EXCLUDED.base_url, enabled = true, updated_at = NOW()`,
		uuid.New().String(), appTileClientID(routeID), name, description, baseURL, orgID)
	if err != nil {
		s.logger.Warn("upsert app tile failed", zap.String("route_id", routeID), zap.Error(err))
	}
}

// deleteAppTile removes the Applications launcher tile for a deleted proxy route.
func (s *Service) deleteAppTile(ctx context.Context, routeID string) {
	if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore tile cleanup deletes the route's launcher tile by its globally-unique synthetic client_id
		`DELETE FROM applications WHERE client_id = $1`, appTileClientID(routeID)); err != nil {
		s.logger.Warn("delete app tile failed", zap.String("route_id", routeID), zap.Error(err))
	}
}

// refreshBrowZerEdge reconverges the clientless edge to the current DB state:
// it regenerates the bootstrapper/hop/vhost configs (which also reconciles the
// APISIX BrowZer routes, pruning any keyed to a now-absent or renamed host) and
// triggers a Ziti reconcile. Call after a route mutation (create/update/delete)
// so a deleted route's edge wiring is removed and a renamed route's wiring is
// re-keyed under the new host instead of stranded under the old one.
func (s *Service) refreshBrowZerEdge(ctx context.Context) {
	if s.browzerTargetManager != nil {
		if err := s.browzerTargetManager.RegenerateConfigs(ctx); err != nil {
			s.logger.Warn("refreshBrowZerEdge: regenerate configs failed", zap.Error(err))
		}
	}
	s.enqueueReconcile()
}

// SetHealthEngine wires the relations/integrity doctor engine.
func (s *Service) SetHealthEngine(e *HealthEngine) { s.healthEngine = e }

// SetBrowZerTargetManager sets the BrowZer target manager
func (s *Service) SetBrowZerTargetManager(btm *BrowZerTargetManager) {
	s.browzerTargetManager = btm
}

// SetAPISIXConfigPath sets the path to the APISIX standalone config file
func (s *Service) SetAPISIXConfigPath(path string) {
	s.apisixConfigPath = path
}

// SetAuditService sets the unified audit service
func (s *Service) SetAuditService(as *UnifiedAuditService) {
	s.auditService = as
	if s.zitiProvider != nil {
		as.SetZitiProvider(s.zitiProvider)
	}
	if s.guacamoleClient != nil {
		as.SetGuacamoleClient(s.guacamoleClient)
	}
}

// SetVaultService wires the in-process PAM credential vault.
func (s *Service) SetVaultService(v *vault.Service) { s.vaultSvc = v }

// NewService creates a new access proxy service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	secret := cfg.AccessSessionSecret
	if len(secret) < 32 {
		secret = secret + strings.Repeat("0", 32-len(secret))
	}

	// Derive internal OAuth URL from JWKS URL for server-to-server calls
	// JWKS URL is like http://oauth-service:8006/.well-known/jwks.json
	oauthInternal := cfg.OAuthIssuer
	if cfg.OAuthJWKSURL != "" {
		if parsed, err := url.Parse(cfg.OAuthJWKSURL); err == nil {
			oauthInternal = parsed.Scheme + "://" + parsed.Host
		}
	}

	alog := logger.With(zap.String("service", "access"))
	encKey := ""
	if cfg != nil {
		encKey = cfg.EncryptionKey
	}
	idpCipher, err := secretcrypt.New(encKey)
	if err != nil {
		alog.Warn("IdP client secrets will NOT be decrypted (plaintext at rest); set a 32-byte ENCRYPTION_KEY", zap.Error(err))
		idpCipher = secretcrypt.NewNoop()
	}

	return &Service{
		db:               db,
		redis:            redis,
		config:           cfg,
		logger:           alog,
		governanceURL:    cfg.GovernanceURL,
		auditURL:         cfg.AuditURL,
		sessionSecret:    []byte(secret[:32]),
		oauthIssuer:      cfg.OAuthIssuer,
		oauthInternalURL: oauthInternal,
		oauthJWKSURL:     cfg.OAuthJWKSURL,
		idpCipher:        idpCipher,
	}
}

// RegisterRoutes registers all access proxy routes
func RegisterRoutes(router *gin.Engine, svc *Service, authMiddleware ...gin.HandlerFunc) {
	// Auth flow endpoints (no auth required)
	auth := router.Group("/access/.auth")
	{
		auth.GET("/login", svc.handleLogin)
		auth.GET("/callback", svc.handleCallback)
		auth.GET("/logout", svc.handleLogout)
		auth.GET("/session", svc.handleSessionInfo)
		auth.GET("/idps", svc.handleIDPDiscovery)
	}

	// Admin API for route management (requires auth)
	api := router.Group("/api/v1/access")
	// WebSocket auth promotion MUST run before the bearer auth middleware:
	// browsers cannot set an Authorization header on a WebSocket, so the token
	// rides as a `bearer.<jwt>` subprotocol. This copies it into the header so the
	// standard auth middleware validates it exactly like any other request (and
	// makes WS auth independent of edge/APISIX behavior).
	api.Use(promoteWebSocketBearer)
	if len(authMiddleware) > 0 {
		api.Use(authMiddleware...)
	}
	{
		// `adminOnly` is the shared admin gate; see the comment on the Ziti
		// routes below for what stays open and why.
		adminOnly := svc.requireAdminRole()
		// `operatorTier` and `auditTier` hold a route to the tier the console
		// shows its page at, for the pages it gives to operators and auditors
		// (role_tiers.go). They check roles only.
		operatorTier := svc.requireOperatorTier()
		auditTier := svc.requireAuditTier()

		// The proxy route table and the proxy sessions are administration,
		// reads included. A route decides who may reach which upstream, with
		// which headers, and whether signing in is needed at all, and its
		// definition names the internal address behind it. The session list
		// names every user of every route, and revoking a session ends somebody
		// else's access. No end-user page reads either: a user's own reachable
		// apps come from /my/resources and /my/ziti/services.
		api.GET("/routes", adminOnly, svc.handleListRoutes)
		api.POST("/routes", adminOnly, svc.handleCreateRoute)
		// Bulk / subnet resource onboarding (admin-only): create many routes at
		// once (explicit list and/or a CIDR expansion) and converge the overlay.
		api.POST("/routes/bulk", svc.requireAdminRole(), svc.handleBulkRoutes)
		api.GET("/routes/:id", adminOnly, svc.handleGetRoute)
		api.PUT("/routes/:id", adminOnly, svc.handleUpdateRoute)
		api.DELETE("/routes/:id", adminOnly, svc.handleDeleteRoute)
		api.GET("/sessions", adminOnly, svc.handleListSessions)
		api.DELETE("/sessions/:id", adminOnly, svc.handleRevokeSession)

		// Unified Zero Trust Access overview (resource spine + coverage gaps):
		// every route's upstream and which of its controls are missing, so it
		// is gated like the route list it summarises.
		api.GET("/overview", adminOnly, svc.handleAccessOverview)

		// OpenZiti management endpoints.
		//
		// One controller serves every organization, and its objects carry no
		// tenant (ziti_scope.go). So each route here that reads it is one of
		// three kinds:
		//
		//   - a status probe any signed-in user may call, answering whether
		//     the overlay is up with the organization's own counts and nothing
		//     that names an address;
		//   - a read of the organization's own part of the fabric, which needs
		//     `operatorTier` and shows an install administrator the whole
		//     controller and anyone else only what their organization owns;
		//   - a read of something no organization owns -- the routers, the
		//     metrics, the edge-router and authentication policies, the JWT
		//     signers, the AI ledger -- which needs `adminOnly, platformOnly`.
		//
		// Writes follow the same line. One that changes something the
		// organization owns -- its services, identities, policies, posture
		// checks, certificates, sessions and terminators, BrowZer on one of
		// its services -- needs `adminOnly` and reaches only the
		// organization's own objects, as the mirror records them; an install
		// administrator reaches any. One that changes something no
		// organization owns -- a router, an edge-router, authentication or
		// JWT-signer policy, a raw config, the AI ledger, a governance-policy
		// sync, an import of an unowned service -- needs `adminOnly,
		// platformOnly`. The self-service routes (/my/ziti/services,
		// /ziti/sync/my-identity and the device posture self-report) answer
		// for the caller only.
		//
		// `platformOnly` follows adminOnly on the routes whose object or
		// setting exists once for the whole install -- the OpenZiti controller
		// connection, the BrowZer domain and certificate, the platform TLS
		// certificate, and the controller's install-wide objects -- which an
		// organization's admin role cannot authorize on its own. See
		// middleware.RequirePlatformAdmin.
		platformOnly := svc.requirePlatformAdmin()
		api.GET("/ziti/status", svc.handleZitiStatus)
		// Guided network setup: checklist + install advisor + per-route advice.
		// It reports the controller's address, the identity directory and every
		// edge router, and carries the install's user sync counts: the setup of
		// the install's network, not of one organization's part of it.
		api.GET("/ziti/setup/status", adminOnly, platformOnly, svc.handleZitiSetupStatus)
		// The reconciler converges every organization's services and reports
		// each by name.
		api.GET("/ziti/reconciler/status", adminOnly, platformOnly, svc.handleZitiReconcilerStatus)

		// Upstream pools: the operator's declaration of a route's backend set.
		// Admin-only like the route list, reads included: a pool's members are
		// the internal addresses behind a route, and adding a member or
		// draining one moves production traffic between backends.
		api.GET("/upstream-pools", adminOnly, svc.handleListUpstreamPools)
		api.POST("/upstream-pools", adminOnly, svc.handleCreateUpstreamPool)
		api.GET("/upstream-pools/:id", adminOnly, svc.handleGetUpstreamPool)
		api.PUT("/upstream-pools/:id", adminOnly, svc.handleUpdateUpstreamPool)
		api.DELETE("/upstream-pools/:id", adminOnly, svc.handleDeleteUpstreamPool)
		api.POST("/upstream-pools/:id/members", adminOnly, svc.handleAddUpstreamPoolMember)
		api.PUT("/upstream-pools/:id/members/:memberId", adminOnly, svc.handleUpdateUpstreamPoolMember)
		api.DELETE("/upstream-pools/:id/members/:memberId", adminOnly, svc.handleDeleteUpstreamPoolMember)

		// Runtime connection control: configure + connect/disconnect the
		// OpenZiti controller from the admin panel with no restart. One
		// controller serves every organization, so this is for platform
		// administrators only. The read returns the controller's admin account,
		// and the test dials a caller-chosen controller with the stored
		// password, so both are gated like the writes.
		api.GET("/ziti/settings", adminOnly, platformOnly, svc.handleGetZitiSettings)
		api.PUT("/ziti/settings", adminOnly, platformOnly, svc.handlePutZitiSettings)
		api.POST("/ziti/settings/test", adminOnly, platformOnly, svc.handleTestZitiSettings)
		api.POST("/ziti/connect", adminOnly, platformOnly, svc.handleZitiConnect)
		api.POST("/ziti/disconnect", adminOnly, platformOnly, svc.handleZitiDisconnect)
		// The organization's services, with the internal host and port each
		// one forwards to.
		api.GET("/ziti/services", operatorTier, svc.handleListZitiServices)
		api.POST("/ziti/services", adminOnly, svc.handleCreateZitiService)
		api.DELETE("/ziti/services/:id", adminOnly, svc.handleDeleteZitiService)
		// The identity list names every user who has one.
		api.GET("/ziti/identities", operatorTier, svc.handleListZitiIdentities)
		api.POST("/ziti/identities", adminOnly, svc.handleCreateZitiIdentity)
		api.DELETE("/ziti/identities/:id", adminOnly, svc.handleDeleteZitiIdentity)
		// Enrollment JWT is a bearer network-join credential — admin-only read.
		api.GET("/ziti/identities/:id/enrollment-jwt", adminOnly, svc.handleGetEnrollmentJWT)
		api.POST("/ziti/routes/:id/enable", adminOnly, svc.handleEnableZitiOnRoute)
		api.POST("/ziti/routes/:id/disable", adminOnly, svc.handleDisableZitiOnRoute)

		// Phase 2: Fabric & Router management. The overview and the health
		// are the organization's view of the fabric (orgFabricHealth); the
		// routers, which name the hosts they run on, and the metrics, which
		// count every organization's objects, are the install's.
		api.GET("/ziti/fabric/overview", operatorTier, svc.handleGetFabricOverview)
		api.GET("/ziti/fabric/routers", adminOnly, platformOnly, svc.handleListEdgeRouters)
		// One-command router/gateway onboarding: mint an edge-router enrollment
		// JWT + a copy-paste command; the router joins via the #all bootstrap
		// and carries every organization's traffic.
		api.POST("/ziti/fabric/routers/enroll-token", adminOnly, platformOnly, svc.handleRouterEnrollToken)
		api.GET("/ziti/fabric/routers/:id", adminOnly, platformOnly, svc.handleGetEdgeRouter)
		api.GET("/ziti/fabric/health", operatorTier, svc.handleGetHealth)
		api.POST("/ziti/fabric/reconnect", adminOnly, platformOnly, svc.handleReconnect)
		api.GET("/ziti/fabric/metrics", adminOnly, platformOnly, svc.handleGetMetrics)
		api.GET("/ziti/fabric/service-policies", operatorTier, svc.handleListServicePolicies)

		// Ziti service connectivity test: the server dials the service's
		// upstream and returns the dial errors, which name its address, so it
		// is gated like the route connection test.
		api.POST("/ziti/services/:id/test", adminOnly, svc.handleTestZitiService)
		// Admin "behind the scenes": explain how a resource is wired end to end
		// and which link is broken, so diagnosis needs no CLI.
		api.GET("/ziti/services/by-name/:name/explain", adminOnly, svc.handleExplainZitiService)

		// Edge router policy CRUD. The policies decide which identities of any
		// organization may use which routers.
		api.GET("/ziti/edge-router-policies", adminOnly, platformOnly, svc.handleListEdgeRouterPolicies)
		api.POST("/ziti/edge-router-policies", adminOnly, platformOnly, svc.handleCreateEdgeRouterPolicy)
		api.PUT("/ziti/edge-router-policies/:id", adminOnly, platformOnly, svc.handleUpdateEdgeRouterPolicy)
		api.DELETE("/ziti/edge-router-policies/:id", adminOnly, platformOnly, svc.handleDeleteEdgeRouterPolicy)

		// Service policy CRUD
		api.POST("/ziti/service-policies", adminOnly, svc.handleCreateServicePolicy)
		api.PUT("/ziti/service-policies/:id", adminOnly, svc.handleUpdateServicePolicy)
		api.DELETE("/ziti/service-policies/:id", adminOnly, svc.handleDeleteServicePolicy)

		// Identity attribute management
		api.PATCH("/ziti/identities/:id/attributes", adminOnly, svc.handlePatchIdentityAttributes)

		// User-to-Ziti identity sync. The status counts the organization's
		// users (an install administrator's, the install's), the unsynced list
		// names users, and the map pairs each user with their identity; the
		// console reads them on operator pages (the dashboard for staff, Users).
		api.GET("/ziti/sync/status", operatorTier, svc.handleGetSyncStatus)
		api.GET("/ziti/sync/unsynced", operatorTier, svc.handleGetUnsyncedUsers)
		api.GET("/ziti/sync/user-map", operatorTier, svc.handleGetUserZitiMap)
		api.GET("/ziti/sync/my-identity", svc.handleGetMyZitiIdentity)
		api.POST("/ziti/sync/users", adminOnly, svc.handleSyncAllUsers)
		api.POST("/ziti/sync/users/:userId", adminOnly, svc.handleSyncSingleUser)
		api.POST("/ziti/sync/groups", adminOnly, svc.handleSyncAllGroups)
		api.POST("/ziti/sync/device-trust/:userId", adminOnly, svc.handleSyncDeviceTrust)

		// Enriched device management (unified view): every user's devices, with
		// their addresses and fingerprints, shown on the operator Devices page.
		api.GET("/devices/enriched", operatorTier, svc.handleGetEnrichedDevices)

		// Cross-pillar user correlation (IAM ⇄ PAM ⇄ Ziti): one map of
		// everything a user can reach, and one switch that severs it all.
		api.GET("/users/:id/access-map", adminOnly, svc.handleUserAccessMap)
		api.POST("/users/:id/kill-switch", adminOnly, svc.handleUserKillSwitch)

		// Assignment report: who loses reach if ACCESS_ASSIGNMENT_ENFORCE is
		// flipped on — diffs today's Ziti reach against assignment-derived reach.
		api.GET("/assignment-report", adminOnly, svc.handleAssignmentReport)

		// Cross-pillar device correlation: a user's devices with IAM trust +
		// Ziti compliance/posture side by side, and a device-scoped revoke.
		api.GET("/users/:id/devices", adminOnly, svc.handleUserDevices)
		api.POST("/users/:id/devices/:agentId/revoke", adminOnly, svc.handleRevokeUserDevice)
		// Self-service: the caller's own correlated devices (compliance visibility).
		api.GET("/my-devices", svc.handleMyDevices)

		// Self-service: "My Network" — what the caller can reach, in plain
		// language (no overlay vocabulary). Deliberately not adminOnly.
		api.GET("/my/resources", svc.handleMyResources)

		// Self-service: the OpenZiti (zero-trust) apps the caller can reach,
		// enriched with connection details. Deliberately not adminOnly.
		api.GET("/my/ziti/services", svc.handleMyZitiServices)

		// Phase 3: Posture checks. Definitions are admin-managed; they, the
		// summary of the organization's results and one identity's posture and
		// its evaluation carry the operator tier. The device self-report is
		// data-plane and stays open.
		api.GET("/ziti/posture/checks", operatorTier, svc.handleListPostureChecks)
		api.POST("/ziti/posture/checks", adminOnly, svc.handleCreatePostureCheck)
		api.PUT("/ziti/posture/checks/:id", adminOnly, svc.handleUpdatePostureCheck)
		api.DELETE("/ziti/posture/checks/:id", adminOnly, svc.handleDeletePostureCheck)
		api.GET("/ziti/posture/identities/:id", operatorTier, svc.handleGetIdentityPosture)
		api.POST("/ziti/posture/identities/:id/evaluate", operatorTier, svc.handleEvaluateIdentityPosture)
		api.GET("/ziti/posture/summary", operatorTier, svc.handleGetPostureSummary)
		api.POST("/ziti/posture/device", svc.handleSubmitDevicePosture)

		// EDR/MDM posture sources (CrowdStrike/Intune/Jamf) — ingest external
		// device compliance into the Ziti-bound posture pipeline.
		api.GET("/ziti/posture/edr", adminOnly, svc.handleListEDRSources)
		api.POST("/ziti/posture/edr", adminOnly, svc.handleCreateEDRSource)
		api.GET("/ziti/posture/edr/:id", adminOnly, svc.handleGetEDRSource)
		api.GET("/ziti/posture/edr/:id/devices", adminOnly, svc.handleListEDRDevices)
		api.DELETE("/ziti/posture/edr/:id", adminOnly, svc.handleDeleteEDRSource)
		api.POST("/ziti/posture/edr/:id/test", adminOnly, svc.handleTestEDRSource)
		api.POST("/ziti/posture/edr/:id/sync", adminOnly, svc.handleSyncEDRSource)

		// MCP / AI-agent gateway (Wave D1). Admin manages servers + per-tool
		// allowlists; the invoke endpoint authenticates the AGENT's own token
		// (not the admin session), so it lives outside adminOnly.
		api.GET("/mcp/servers", adminOnly, svc.handleListMCPServers)
		api.POST("/mcp/servers", adminOnly, svc.handleCreateMCPServer)
		api.DELETE("/mcp/servers/:id", adminOnly, svc.handleDeleteMCPServer)
		api.POST("/mcp/servers/:id/policies", adminOnly, svc.handleAddMCPToolPolicy)
		// PAM C5: HITL approval queue for sensitive AI-agent tool calls. Static
		// path segment 'approvals' is registered before the ':server' wildcard.
		api.GET("/mcp/approvals/pending", adminOnly, svc.handleListPendingToolApprovals)
		api.POST("/mcp/approvals/:id/:decision", adminOnly, svc.handleDecideToolApproval)
		// Agent-facing gateway: POST /api/v1/access/mcp/:server/tools/:tool.
		api.POST("/mcp/:server/tools/:tool", svc.handleMCPInvoke)

		// Phase 3: Policy sync. policy_sync_state has no organization.
		api.GET("/ziti/policy-sync", adminOnly, platformOnly, svc.handleListPolicySyncStates)
		api.POST("/ziti/policy-sync", adminOnly, platformOnly, svc.handleSyncGovernancePolicy)
		api.POST("/ziti/policy-sync/:id/trigger", adminOnly, platformOnly, svc.handleTriggerPolicySync)
		api.DELETE("/ziti/policy-sync/:id", adminOnly, platformOnly, svc.handleDeletePolicySyncState)

		// Config types & configs management. A host.v1 config names the
		// internal address its service forwards to. The writes take any
		// config by its controller id, and a changed host.v1 moves where a
		// service's traffic goes, so they are the install's; an organization's
		// own configs follow its routes and services.
		api.GET("/ziti/config-types", adminOnly, platformOnly, svc.handleListConfigTypes)
		api.GET("/ziti/configs", operatorTier, svc.handleListConfigs)
		api.POST("/ziti/configs", adminOnly, platformOnly, svc.handleCreateConfig)
		api.PUT("/ziti/configs/:id", adminOnly, platformOnly, svc.handleUpdateConfig)
		api.DELETE("/ziti/configs/:id", adminOnly, platformOnly, svc.handleDeleteConfig)

		// Auth policies & JWT signers management: how every organization's
		// identities authenticate to the controller.
		api.GET("/ziti/auth-policies", adminOnly, platformOnly, svc.handleListAuthPolicies)
		api.POST("/ziti/auth-policies", adminOnly, platformOnly, svc.handleCreateAuthPolicy)
		api.PUT("/ziti/auth-policies/:id", adminOnly, platformOnly, svc.handleUpdateAuthPolicy)
		api.DELETE("/ziti/auth-policies/:id", adminOnly, platformOnly, svc.handleDeleteAuthPolicy)
		api.GET("/ziti/jwt-signers", adminOnly, platformOnly, svc.handleListJWTSigners)
		api.POST("/ziti/jwt-signers", adminOnly, platformOnly, svc.handleCreateJWTSigner)
		api.PUT("/ziti/jwt-signers/:id", adminOnly, platformOnly, svc.handleUpdateJWTSigner)
		api.DELETE("/ziti/jwt-signers/:id", adminOnly, platformOnly, svc.handleDeleteJWTSigner)

		// Terminators management. A terminator names the address a service
		// is hosted at. The delete reaches the organization's own terminators.
		api.GET("/ziti/terminators", operatorTier, svc.handleListTerminators)
		api.GET("/ziti/terminators/:id", operatorTier, svc.handleGetTerminator)
		api.DELETE("/ziti/terminators/:id", adminOnly, svc.handleDeleteTerminator)

		// Ziti session visibility: who is connected to which service right
		// now. The deletes reach the organization's own sessions and
		// identities.
		api.GET("/ziti/sessions", operatorTier, svc.handleListZitiSessions)
		api.DELETE("/ziti/sessions/:id", adminOnly, svc.handleDeleteZitiSession)
		api.POST("/ziti/sessions/batch-terminate", adminOnly, svc.handleBatchDeleteZitiSessions)

		// AI-driven network intelligence: behavioral baselines over live fabric
		// sessions, anomaly ledger, fused identity risk scores, policy-hygiene
		// recommendations, and quarantine response. Analysis mutates the
		// ledger/baselines and quarantine rewrites identity attributes, so
		// those are admin-only. The baselines, the ledger and the quarantine
		// list have no organization, the risk scores and recommendations are
		// computed over every identity, service and policy on the controller,
		// and quarantine takes any identity by its controller id, so every
		// route needs an install administrator. An organization's admin cuts
		// a user off with the kill switch, which stays in the organization.
		api.GET("/ziti/ai/insights", adminOnly, platformOnly, svc.handleZitiAIInsights)
		api.POST("/ziti/ai/analyze", adminOnly, platformOnly, svc.handleZitiAIAnalyze)
		api.GET("/ziti/ai/anomalies", adminOnly, platformOnly, svc.handleListZitiAnomalies)
		api.POST("/ziti/ai/anomalies/:id/status", adminOnly, platformOnly, svc.handleUpdateZitiAnomalyStatus)
		api.GET("/ziti/ai/identity-risk", adminOnly, platformOnly, svc.handleZitiIdentityRisk)
		api.GET("/ziti/ai/recommendations", adminOnly, platformOnly, svc.handleZitiAIRecommendations)
		api.POST("/ziti/ai/identities/:id/quarantine", adminOnly, platformOnly, svc.handleQuarantineZitiIdentity)
		api.POST("/ziti/ai/identities/:id/unquarantine", adminOnly, platformOnly, svc.handleUnquarantineZitiIdentity)
		// Controller version / OpenZiti v2.0 feature detection
		api.GET("/ziti/controller/features", adminOnly, platformOnly, svc.handleZitiControllerFeatures)

		// Phase 5: Certificates: the organization's certificate inventory.
		api.GET("/ziti/certificates", operatorTier, svc.handleListCertificates)
		api.GET("/ziti/certificates/expiry-alerts", operatorTier, svc.handleGetCertExpiryAlerts)
		api.POST("/ziti/certificates/:id/rotate", adminOnly, svc.handleRotateCertificate)

		// BrowZer management endpoints
		api.GET("/ziti/browzer/status", svc.handleBrowZerStatus)
		// BrowZer's bootstrap (ziti_browzer_config, the external JWT signer) is
		// one per install; the per-service toggles below it are per route.
		api.POST("/ziti/browzer/enable", adminOnly, platformOnly, svc.handleEnableBrowZer)
		api.POST("/ziti/browzer/disable", adminOnly, platformOnly, svc.handleDisableBrowZer)
		api.POST("/ziti/browzer/services/:id/enable", adminOnly, svc.handleEnableBrowZerOnService)
		api.POST("/ziti/browzer/services/:id/disable", adminOnly, svc.handleDisableBrowZerOnService)

		// BrowZer bootstrapper management panel endpoints. The panel shows the
		// install's bootstrapper, its certificate and every BrowZer target.
		api.GET("/ziti/browzer/management", adminOnly, platformOnly, svc.handleBrowZerManagement)
		// The bootstrapper's certificate, key and domain are the install's.
		api.POST("/ziti/browzer/certificates", adminOnly, platformOnly, svc.handleBrowZerCertUpload)
		api.DELETE("/ziti/browzer/certificates", adminOnly, platformOnly, svc.handleBrowZerCertRevert)
		api.PUT("/ziti/browzer/domain", adminOnly, platformOnly, svc.handleBrowZerDomainChange)
		api.POST("/ziti/browzer/restart", adminOnly, platformOnly, svc.handleBrowZerRestart)

		// Platform certificate management. One certificate and key serve every
		// organization's traffic; the reads return only the public certificate.
		api.GET("/certificates/platform", svc.handleGetPlatformCert)
		api.POST("/certificates/platform", adminOnly, platformOnly, svc.handleUploadPlatformCert)
		api.DELETE("/certificates/platform", adminOnly, platformOnly, svc.handleRevertPlatformCert)
		api.POST("/certificates/apisix/enable", adminOnly, platformOnly, svc.handleEnableAPISIXSSL)
		api.POST("/certificates/apisix/disable", adminOnly, platformOnly, svc.handleDisableAPISIXSSL)
		api.GET("/certificates/status", svc.handleGetCertStatus)

		// Forward-auth endpoint for APISIX
		api.POST("/auth/decide", svc.handleAuthDecide)
		api.GET("/auth/decide", svc.handleAuthDecide)

		// Policy DSL validation
		api.POST("/routes/validate-policy", svc.handleValidatePolicy)

		// Guacamole remote access. The connection list is broker internals —
		// hostname, port, protocol and the injected connection parameters of
		// every brokered target — so it carries the same adminOnly gate as the
		// app-publishing routes below, and for the same reason. The end-user
		// launcher reads /guacamole/my-connections instead, which returns the
		// PAM flags without the infrastructure. Connect stays open to any
		// authenticated user: launching a session the caller is entitled to is
		// the end-user path, and v151 gave it the org predicate it was missing.
		api.GET("/guacamole/connections", adminOnly, svc.handleListGuacamoleConnections)
		api.POST("/guacamole/connections/:routeId/connect", svc.handleGuacamoleConnect)
		api.PUT("/guacamole/connections/:routeId/credential", svc.requireAdminRole(), svc.handleSetGuacCredential)

		// Guacamole end-user self-service (PAM finalization): brokered-connection
		// catalog + the caller's own session-request status. Static paths avoid
		// the /connections/:routeId and /session-requests/:id wildcard conflicts.
		api.GET("/guacamole/my-connections", svc.handleListMyGuacConnections)
		api.GET("/guacamole/my-session-requests", svc.handleListMyGuacSessionRequests)

		// Guacamole pre-session approval lifecycle (Task 4 — PAM M3)
		api.POST("/guacamole/connections/:routeId/request", svc.handleRequestGuacSession)
		api.POST("/guacamole/session-requests/:id/approve", svc.requireAdminRole(), svc.handleApproveGuacSession)
		api.POST("/guacamole/session-requests/:id/deny", svc.requireAdminRole(), svc.handleDenyGuacSession)
		api.GET("/guacamole/session-requests", svc.requireAdminRole(), svc.handleListGuacSessionRequests)

		// Guacamole active-session management (Task 5 — PAM M3)
		api.GET("/guacamole/sessions", svc.requireAdminRole(), svc.handleListActiveGuacSessions)
		api.POST("/guacamole/sessions/:id/terminate", svc.requireAdminRole(), svc.handleTerminateGuacSession)
		api.POST("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handlePlaceGuacLegalHold)
		api.DELETE("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handleReleaseGuacLegalHold)
		api.GET("/guacamole/sessions/:id/legal-holds", svc.requireAdminRole(), svc.handleListGuacLegalHolds)

		// Guacamole transcript download (Task 3 — PAM M4)
		api.GET("/guacamole/sessions/:id/transcript", svc.requireAdminRole(), svc.handleGetGuacTranscript)

		// Guacamole session recording download (PAM A1). Streams the raw guacd
		// recording, transparently decrypting it when the file was sealed
		// (encrypted at rest) by the recording sealer. Plaintext recordings
		// stream through unchanged, so this works whether or not encryption is
		// configured.
		api.GET("/guacamole/sessions/:id/recording", svc.requireAdminRole(), svc.handleGetGuacRecording)

		// Moderated privileged sessions (PAM C3). A require_moderator connection
		// blocks the requester's connect until a moderator joins to watch live
		// (four-eyes / SOX-PCI). Requester opens + polls; moderator lists the
		// queue, joins (→ active, unblocking connect), or ends (kill switch).
		api.POST("/pam/moderation/request", svc.handleRequestModeration)
		api.GET("/pam/moderation/pending", svc.requireAdminRole(), svc.handleListPendingModeration)
		api.GET("/pam/moderation/:id", svc.handleGetModerationStatus)
		api.POST("/pam/moderation/:id/join", svc.requireAdminRole(), svc.handleJoinModeration)
		api.POST("/pam/moderation/:id/end", svc.handleEndModeration)

		// Guacamole live monitor — read-only connection sharing (Task 4 — PAM M4)
		api.POST("/guacamole/sessions/:id/share", svc.requireAdminRole(), svc.handleShareGuacSession)

		// Guacamole session history — DB-backed session rows + transcript availability
		// (admin console W1.3). Static path avoids the /sessions/:id wildcard conflict.
		api.GET("/guacamole/session-history", svc.requireAdminRole(), svc.handleListGuacSessionHistory)

		// PAM connection manager (Devolutions RDM parity): folder tree +
		// typed entries with vault-backed secrets, per-entry ACL, favorites,
		// passwordless launch (server-side credential injection), approval
		// gate, audited reveal, session ledger, and RDM import.
		api.GET("/pam/entry-types", svc.handlePamListEntryTypes)
		api.GET("/pam/folders", svc.handlePamListFolders)
		api.POST("/pam/folders", svc.requireAdminRole(), svc.handlePamCreateFolder)
		api.PUT("/pam/folders/:id", svc.requireAdminRole(), svc.handlePamUpdateFolder)
		api.DELETE("/pam/folders/:id", svc.requireAdminRole(), svc.handlePamDeleteFolder)
		api.GET("/pam/entries", svc.handlePamListEntries)
		api.POST("/pam/entries", svc.requireAdminRole(), svc.handlePamCreateEntry)
		api.GET("/pam/entries/:id", svc.handlePamGetEntry)
		// Update allows non-admins holding an `edit` grant (checked in-handler).
		api.PUT("/pam/entries/:id", svc.handlePamUpdateEntry)
		api.DELETE("/pam/entries/:id", svc.requireAdminRole(), svc.handlePamDeleteEntry)
		api.POST("/pam/entries/:id/favorite", svc.handlePamFavoriteEntry)
		api.DELETE("/pam/entries/:id/favorite", svc.handlePamUnfavoriteEntry)
		api.POST("/pam/entries/:id/connect", svc.requireFreshMFA("pam.connect"), svc.handlePamConnect)
		api.GET("/pam/entries/:id/ws", svc.handlePamWSConnect)
		api.POST("/pam/entries/:id/reveal", svc.requireFreshMFA("pam.reveal"), svc.handlePamRevealEntry)
		api.POST("/pam/entries/:id/request", svc.handlePamRequestAccess)

		// v105 checkout controls — break-glass, dual-control (two-person rule),
		// exclusivity. Break-glass and check-in share the reveal authorization
		// surface (in-handler); the second-person authorization queue and the
		// live-checkout ledger are admin-only.
		api.POST("/pam/entries/:id/break-glass", svc.requireFreshMFA("pam.break_glass"), svc.handlePamBreakGlass)
		api.POST("/pam/entries/:id/checkin", svc.handlePamCheckin)
		api.GET("/pam/checkout-authorizations", svc.requireAdminRole(), svc.handlePamListCheckoutAuthorizations)
		api.POST("/pam/checkout-authorizations/:id/:decision", svc.requireAdminRole(), svc.handlePamDecideCheckoutAuthorization)
		api.GET("/pam/checkouts/active", svc.requireAdminRole(), svc.handlePamListActiveCheckouts)

		// Privilege graph (C1) — the unified-architecture moat. Admin-only: it
		// exposes effective-access blast radius across IAM+IGA+PAM.
		api.GET("/pam/privilege-graph/secret/:id", svc.requireAdminRole(), svc.handleSecretPrivilegeGraph)
		api.GET("/pam/privilege-graph/entry/:id", svc.requireAdminRole(), svc.handleEntryPrivilegeGraph)
		api.GET("/pam/privilege-graph/user/:id", svc.requireAdminRole(), svc.handleUserPrivilegeGraph)

		// v109 SSH certificate authority + session brokering (`openidx connect`).
		// CA init/rotate is admin-only; anyone authenticated may request a
		// short-lived cert (host-side AuthorizedPrincipals still gates the
		// login). The brokered-session ledger list is admin-only.
		api.POST("/pam/ssh-ca/init", svc.requireAdminRole(), svc.handleInitSSHCA)
		api.GET("/pam/ssh-ca", svc.handleGetSSHCA)
		api.POST("/pam/connect/ssh", svc.requireFreshMFA("pam.connect_ssh"), svc.handleSSHConnect)
		// PAM B4: cloud console/CLI JIT elevation. STS AssumeRole → short-lived
		// credentials + optional federated console URL, recorded in
		// brokered_sessions (auto-expiring; no standing privilege).
		api.POST("/pam/connect/cloud", svc.requireFreshMFA("pam.connect_cloud"), svc.handleCloudConnect)
		api.POST("/pam/brokered-sessions", svc.requireFreshMFA("pam.broker_session"), svc.handleBrokerSession)
		api.GET("/pam/brokered-sessions", svc.requireAdminRole(), svc.handleListBrokeredSessions)
		api.POST("/pam/brokered-sessions/:id/end", svc.handleEndBrokeredSession)

		// Quick Links — admin-curated, user-searchable support/collaboration launcher.
		api.GET("/quick-links/my", svc.handleMyQuickLinks)
		api.GET("/quick-links", svc.requireAdminRole(), svc.handleListQuickLinks)
		api.POST("/quick-links", svc.requireAdminRole(), svc.handleCreateQuickLink)
		api.PUT("/quick-links/:id", svc.requireAdminRole(), svc.handleUpdateQuickLink)
		api.DELETE("/quick-links/:id", svc.requireAdminRole(), svc.handleDeleteQuickLink)
		api.GET("/pam/entries/:id/grants", svc.requireAdminRole(), svc.handlePamListEntryGrants)
		api.POST("/pam/entries/:id/grants", svc.requireAdminRole(), svc.handlePamAddEntryGrant)
		api.DELETE("/pam/entries/:id/grants/:grantId", svc.requireAdminRole(), svc.handlePamRemoveEntryGrant)
		api.GET("/pam/entry-requests", svc.requireAdminRole(), svc.handlePamListRequests)
		api.POST("/pam/entry-requests/:id/approve", svc.requireAdminRole(), svc.handlePamApproveRequest)
		api.POST("/pam/entry-requests/:id/deny", svc.requireAdminRole(), svc.handlePamDenyRequest)
		api.GET("/pam/my-entry-requests", svc.handlePamListMyRequests)
		api.GET("/pam/sessions", svc.requireAdminRole(), svc.handlePamListSessions)
		api.POST("/pam/sessions/:id/end", svc.handlePamEndSession)
		api.POST("/pam/import/rdm", svc.requireAdminRole(), svc.handlePamImportRDM)

		// PAM OpenZiti reach mode — per-entry zero-trust target hop toggle,
		// broker capability probe, and the tunneler binding list.
		api.GET("/pam/broker/status", svc.handlePamBrokerStatus)
		// The binding list is install-wide: one broker tunnel serves every
		// organization's entries.
		api.GET("/pam/broker/ziti-bindings", svc.requireAdminRole(), platformOnly, svc.handlePamZitiBindings)
		api.POST("/pam/entries/:id/ziti/enable", svc.requireAdminRole(), svc.handlePamEnableZiti)
		api.POST("/pam/entries/:id/ziti/disable", svc.requireAdminRole(), svc.handlePamDisableZiti)

		// Windows application delivery — app catalog + host pools on top of the
		// RemoteApp launch path. List/launch are operator-level (launch runs the
		// same ACL + approval gates as pam connect); mutations are admin-only.
		api.GET("/pam/apps", svc.handleWindowsAppList)
		// End-user launchable-apps view (portal tiles). Distinct /pam/my-apps
		// prefix so the static segment can't collide with /pam/apps/:id.
		api.GET("/pam/my-apps", svc.handleMyWindowsApps)
		api.POST("/pam/apps", svc.requireAdminRole(), svc.handleWindowsAppCreate)
		api.PUT("/pam/apps/:id", svc.requireAdminRole(), svc.handleWindowsAppUpdate)
		api.DELETE("/pam/apps/:id", svc.requireAdminRole(), svc.handleWindowsAppDelete)
		api.POST("/pam/apps/:id/launch", svc.requireFreshMFA("pam.app_launch"), svc.handleWindowsAppLaunch)
		api.GET("/pam/apps/:id/icon", svc.handleWindowsAppIcon)
		// Distinct prefix (not /pam/apps/import) so the static segment doesn't
		// collide with the /pam/apps/:id wildcard in gin's route tree.
		api.POST("/pam/app-import", svc.requireAdminRole(), svc.handleWindowsAppImport)
		api.GET("/pam/app-pools", svc.handleWindowsAppPoolList)
		api.POST("/pam/app-pools", svc.requireAdminRole(), svc.handleWindowsAppPoolCreate)
		api.PUT("/pam/app-pools/:id", svc.requireAdminRole(), svc.handleWindowsAppPoolUpdate)
		api.DELETE("/pam/app-pools/:id", svc.requireAdminRole(), svc.handleWindowsAppPoolDelete)
		api.POST("/pam/app-pools/:id/members", svc.requireAdminRole(), svc.handleWindowsAppPoolAddMember)
		api.DELETE("/pam/app-pools/:id/members/:memberId", svc.requireAdminRole(), svc.handleWindowsAppPoolRemoveMember)
		// Bind an enrolled agent to a windows_app_host so its discovery reports
		// route to that host. Distinct /pam/app-hosts prefix so the static
		// segment can't collide with the /pam/apps/:id wildcard in gin's tree.
		api.POST("/pam/app-hosts/:entryId/agent", svc.requireAdminRole(), svc.handleWindowsAppHostLinkAgent)
		api.DELETE("/pam/app-hosts/:entryId/agent", svc.requireAdminRole(), svc.handleWindowsAppHostUnlinkAgent)

		// Temporary access links for support/vendor access
		// PAM vendor access to internal SSH/RDP/VNC hosts is a privileged
		// operation — gate management to admins, matching the guacamole PAM
		// routes above. (The public token-redemption route is registered
		// separately on the root router, without auth.)
		api.GET("/temp-access", adminOnly, svc.handleListTempAccess)
		api.POST("/temp-access", adminOnly, svc.handleCreateTempAccess)
		api.GET("/temp-access/:id", adminOnly, svc.handleGetTempAccess)
		api.DELETE("/temp-access/:id", adminOnly, svc.handleRevokeTempAccess)
		api.GET("/temp-access/:id/usage", adminOnly, svc.handleGetTempAccessUsage)

		// Quick service creation (route + Ziti + BrowZer in one call): a route
		// create, gated like POST /routes.
		api.POST("/services/quick-create", adminOnly, svc.handleQuickCreate)

		// Service feature management endpoints. A service here is a proxy
		// route: the toggles publish it over Ziti, BrowZer or Guacamole, and the
		// status reads return each feature's stored configuration, which holds
		// the Guacamole target and its credentials.
		api.GET("/services/:id/features", adminOnly, svc.handleGetServiceFeatures)
		api.GET("/services/:id/status", adminOnly, svc.handleGetServiceStatus)
		api.GET("/services/status", adminOnly, svc.handleGetAllServicesStatus)
		api.POST("/services/:id/features/ziti/enable", adminOnly, svc.handleEnableZitiFeature)
		api.POST("/services/:id/features/ziti/disable", adminOnly, svc.handleDisableZitiFeature)
		api.POST("/services/:id/features/browzer/enable", adminOnly, svc.handleEnableBrowZerFeature)
		api.POST("/services/:id/features/browzer/disable", adminOnly, svc.handleDisableBrowZerFeature)
		api.POST("/services/:id/features/guacamole/enable", adminOnly, svc.handleEnableGuacamoleFeature)
		api.POST("/services/:id/features/guacamole/disable", adminOnly, svc.handleDisableGuacamoleFeature)

		// Health check endpoints. The integration checks say whether the
		// controller, Guacamole and BrowZer answer; they name no route, and the
		// operator dashboards read them. The per-service check dials one
		// route's upstream and returns the dial error, which names the upstream
		// address, so it is gated like the route itself.
		api.GET("/health/integrations", svc.handleHealthIntegrations)
		api.GET("/health/ziti", svc.handleHealthZiti)
		api.GET("/health/guacamole", svc.handleHealthGuacamole)
		api.GET("/health/browzer", svc.handleHealthBrowZer)
		api.GET("/services/:id/health", adminOnly, svc.handleHealthService)

		// Connection test endpoints: the server dials a route's upstream and
		// keeps the result, an operation on the route table.
		api.POST("/services/:id/test-connection", adminOnly, svc.handleTestConnection)
		api.GET("/services/:id/test-history", adminOnly, svc.handleGetConnectionTestHistory)

		// Ziti discovery and import: discovery lists the controller's services
		// that no route manages yet, and import turns them into proxy routes.
		// A service no organization owns is the install's (ziti_scope.go).
		api.GET("/ziti/discover", adminOnly, platformOnly, svc.handleDiscoverZitiServices)
		api.POST("/ziti/import", adminOnly, platformOnly, svc.handleImportZitiService)
		api.POST("/ziti/import/bulk", adminOnly, platformOnly, svc.handleBulkImportZitiServices)
		api.GET("/ziti/unmanaged/count", adminOnly, platformOnly, svc.handleGetUnmanagedServicesCount)

		// App publishing (register, discover, classify, publish). These are
		// admin management routes — registering an internal app and publishing
		// it as a proxy route exposes infrastructure — so they carry the shared
		// `adminOnly` gate like every sibling management surface (ziti/*,
		// guacamole credentials, temp-access). Without it any authenticated
		// user could register/discover/publish/delete apps.
		api.GET("/apps", adminOnly, svc.handleListApps)
		api.POST("/apps", adminOnly, svc.handleRegisterApp)
		api.GET("/apps/:appId", adminOnly, svc.handleGetApp)
		api.DELETE("/apps/:appId", adminOnly, svc.handleDeleteApp)
		api.POST("/apps/:appId/discover", adminOnly, svc.handleStartDiscovery)
		api.GET("/apps/:appId/paths", adminOnly, svc.handleListDiscoveredPaths)
		api.PUT("/apps/:appId/paths/:pathId", adminOnly, svc.handleUpdatePathClassification)
		api.POST("/apps/:appId/publish", adminOnly, svc.handlePublishPaths)
		api.POST("/apps/:appId/publish-app", adminOnly, svc.handlePublishApp)
		api.POST("/apps/:appId/consolidate", adminOnly, svc.handleConsolidateApp)
		api.GET("/apps/:appId/ziti-services", adminOnly, svc.handleGetAppZitiServices)

		// Relations & Integrity Doctor — adminOnly, like every neighbouring
		// management surface. Both handlers run under orgctx.WithBypassRLS by
		// design (the doctor is an install-wide diagnostic), so RLS cannot
		// scope them and the role gate is the only thing standing between a
		// plain tenant user and: an install-wide report naming every tenant's
		// apps, hosts, client ids and Ziti services; `?heal=safe`, which
		// applies every Safe fix across every tenant in one request; and
		// /health/fix, which applies one named fix — including tearing a
		// service off the controller and consolidating an app, which rewrites
		// another tenant's routes. handleHealthRelations' own comment already
		// assumed an admin ("an org-scoped admin request must see all rows");
		// this is the guard that comment assumed. Pinned by
		// health_doctor_gate_test.go against the real route table.
		api.GET("/health/relations", adminOnly, svc.handleHealthRelations)
		api.POST("/health/fix/:checkId", adminOnly, svc.handleHealthFix)

		// Unified audit log. The reads are the organization's audit trail, at
		// the tier of the console's Unified Audit page.
		api.GET("/audit/unified", auditTier, svc.handleGetUnifiedAuditEvents)
		api.GET("/audit/unified/services/:id", auditTier, svc.handleGetServiceAuditEvents)
		// The sync is the administrator's trigger for the background import,
		// which runs under the RLS bypass across every tenant.
		api.POST("/audit/unified/sync", adminOnly, svc.handleSyncExternalAuditEvents)
		api.GET("/audit/unified/summary", auditTier, svc.handleGetAuditEventsSummary)

		// Agent admin surface (enrollment-token CRUD, agent list / approve /
		// revoke, OAuth-based mobile enrollment, Android QR helpers). Inherits
		// the auth middleware applied to `api`; the fleet routes take the
		// operator tier of the console's Agent Fleet page, and a user's own
		// enrollment stays open.
		agentHandler := NewAgentAPIHandler(svc.logger, svc.db, svc.ziti(), svc.config)
		// Redis lets enrollment mint a push-enrollment ticket so a freshly-enrolled
		// device self-registers as a push-MFA approver in one step (FastPass).
		if svc.redis != nil {
			agentHandler.SetRedis(svc.redis.Client)
		}
		agentHandler.RegisterAgentAdminRoutes(api, operatorTier)
		agentHandler.StartGracePeriodEnforcer(context.Background(), 5*time.Minute)
		svc.agentHandler = agentHandler

		// Server-side Play Integrity verification (Phase 1+ Android client).
		// When unconfigured, NewPlayIntegrityVerifier returns (nil, nil) and
		// HandleReport persists agent-supplied tokens unverified — fine for
		// dev, flagged as a production warning by the config validator.
		if svc.config != nil {
			verifier, err := NewPlayIntegrityVerifier(
				context.Background(),
				svc.logger,
				[]byte(svc.config.PlayIntegrityServiceAccountJSON),
				svc.config.PlayIntegrityPackageName,
			)
			if err != nil {
				svc.logger.Warn("play integrity verifier init failed; running unverified",
					zap.Error(err))
			} else if verifier != nil {
				agentHandler.SetPlayIntegrityVerifier(verifier)
				svc.logger.Info("Play Integrity verifier enabled",
					zap.String("package", svc.config.PlayIntegrityPackageName))
			}
		}

		// Kiosk policy admin surface (Phase 3). Audits ride the agent handler
		// so kiosk + enrollment events appear together in unified_audit_events.
		kioskHandler := NewKioskAPIHandler(svc.logger, svc.db, agentHandler)
		kioskHandler.RegisterKioskAdminRoutes(api, adminOnly)

		// Remote-support session admin + signaling broker (Phase 4). Admin
		// HTTP + WS endpoints land here behind auth; the agent-side WS is
		// mounted on the public group below.
		remoteSupport := NewRemoteSupportHandler(svc.logger, svc.db, agentHandler)
		// The step-up gate goes on session start, at the same enforcement point as
		// the PAM launch: taking interactive control of a device is that same act.
		// The operator tier goes on the session routes: the console gives Remote
		// Support to operators.
		remoteSupport.RegisterRemoteSupportAdminRoutes(api, svc.requireFreshMFA("remote_support.start_session"), svc.requireAdminRole(), operatorTier)
		remoteSupport.StartJanitor(context.Background(), 5*time.Minute, time.Minute)
		if svc.guacamoleClient != nil {
			remoteSupport.SetGuacamoleClient(svc.guacamoleClient)
		}

		// Recording storage backend. Preference: S3 over filesystem so a
		// production deployment that configures both gets durability
		// and lifecycle management for free. Soft-disabled when neither
		// is set — start-session ignores `record: true` and the upload
		// endpoints respond 503 with a clear error.
		if svc.config != nil {
			var store recordingStore
			if svc.config.RecordingsS3Endpoint != "" && svc.config.RecordingsS3Bucket != "" {
				s3Store, s3Err := newS3RecordingStore(s3RecordingConfig{
					Endpoint:        svc.config.RecordingsS3Endpoint,
					Bucket:          svc.config.RecordingsS3Bucket,
					Region:          svc.config.RecordingsS3Region,
					Prefix:          svc.config.RecordingsS3Prefix,
					AccessKeyID:     svc.config.RecordingsS3AccessKey,
					SecretAccessKey: svc.config.RecordingsS3SecretKey,
					UseSSL:          svc.config.RecordingsS3UseSSL,
				})
				if s3Err != nil {
					svc.logger.Warn("S3 recording store init failed; will try filesystem fallback",
						zap.Error(s3Err))
				} else {
					store = s3Store
					svc.logger.Info("Remote-support recording enabled (S3)",
						zap.String("endpoint", svc.config.RecordingsS3Endpoint),
						zap.String("bucket", svc.config.RecordingsS3Bucket))
				}
			}
			if store == nil && svc.config.RecordingsStoragePath != "" {
				// Build the encryption keyring from config. Multi-key form
				// (recordings_encryption_keys) takes precedence for rotation;
				// the single-key form maps to id 0. Either may be empty for
				// plaintext-on-disk. A configured-but-malformed key is a
				// fail-closed error so a typo doesn't silently degrade to
				// plaintext.
				ring, ringErr := newRecordingKeyring(
					svc.config.RecordingsEncryptionKeys,
					svc.config.RecordingsEncryptionActiveKeyID,
					svc.config.RecordingsEncryptionKey,
				)
				keyConfigured := svc.config.RecordingsEncryptionKeys != "" || svc.config.RecordingsEncryptionKey != ""
				if ringErr != nil {
					svc.logger.Warn("recording encryption keyring invalid; filesystem store NOT enabled — fix the key config",
						zap.Error(ringErr))
				} else if keyConfigured && (ring == nil || !ring.Enabled()) {
					svc.logger.Warn("filesystem recording store NOT enabled — encryption key config present but produced an empty keyring")
				} else {
					fsStore, fsErr := newFilesystemRecordingStore(svc.config.RecordingsStoragePath, ring)
					if fsErr != nil {
						svc.logger.Warn("filesystem recording store init failed; recording disabled",
							zap.Error(fsErr))
					} else {
						store = fsStore
						svc.logger.Info("Remote-support recording enabled (filesystem)",
							zap.String("path", svc.config.RecordingsStoragePath),
							zap.Bool("encrypted_at_rest", ring.Enabled()))
					}
				}
			}
			if store != nil {
				remoteSupport.SetRecordingStore(store)
				remoteSupport.SetDefaultRetentionDays(svc.config.RecordingsDefaultRetentionDays)
				remoteSupport.SetGuacRecordingsRoot(svc.config.GuacamoleRecordingPath)
				// PAM A1: seal guacd's plaintext on-disk recordings at rest via
				// the same keyring. Built independently of the WebRTC store's
				// ring above (which is out of scope here and absent under the S3
				// backend) because guac recordings are always local files. Nil /
				// disabled ring → sealer inert (recordings stay plaintext).
				if guacRing, gErr := newRecordingKeyring(
					svc.config.RecordingsEncryptionKeys,
					svc.config.RecordingsEncryptionActiveKeyID,
					svc.config.RecordingsEncryptionKey,
				); gErr != nil {
					svc.logger.Warn("guac recording keyring invalid; guac recordings NOT sealed — fix the key config",
						zap.Error(gErr))
				} else if guacRing.Enabled() {
					remoteSupport.SetGuacRecordingRing(guacRing)
					svc.guacRecordingRing = guacRing
					svc.logger.Info("Guacamole recording encryption-at-rest enabled (PAM A1)")
				}
				// Sweep every hour. Cheap query — predicate index on
				// recording_finalized_at WHERE recording_purged_at IS NULL.
				remoteSupport.StartRecordingRetentionEnforcer(context.Background(), time.Hour)
			}
		}

		// Per-session TURN credential minter. Soft-disabled when the
		// shared secret / URIs aren't configured — callers can still
		// supply ice_servers explicitly on start-session.
		if svc.config != nil {
			var turnURIs []string
			for _, raw := range strings.Split(svc.config.TurnURIs, ",") {
				if t := strings.TrimSpace(raw); t != "" {
					turnURIs = append(turnURIs, t)
				}
			}
			minter := NewTurnMinter(TurnConfig{
				URIs:         turnURIs,
				StaticSecret: svc.config.TurnStaticSecret,
				Realm:        svc.config.TurnRealm,
				TTL:          time.Duration(svc.config.TurnCredentialTTLSeconds) * time.Second,
			})
			if minter != nil {
				remoteSupport.SetTurnMinter(minter)
				svc.logger.Info("TURN credential minter enabled",
					zap.Int("uris", len(turnURIs)),
					zap.String("realm", minter.Realm()))
			}
		}

		svc.remoteSupportHandler = remoteSupport
	}

	// Public agent surface: enrollment (carries an enrollment token), posture
	// report (carries X-Agent-ID + auth token), config (same). These run
	// OUTSIDE the JWT auth middleware because the agent doesn't have a tenant
	// JWT yet — its own credentials authenticate the request.
	if svc.agentHandler != nil {
		publicAgent := router.Group("/api/v1/access")
		svc.agentHandler.RegisterAgentPublicRoutes(publicAgent)
		// Agent-side remote-support WebSocket — authenticated via the same
		// X-Agent-ID + X-Auth-Token pattern as /agent/report.
		if svc.remoteSupportHandler != nil {
			svc.remoteSupportHandler.RegisterRemoteSupportPublicRoutes(publicAgent)
		}
		// Windows-app discovery report — an agent bound to a windows_app_host
		// posts the Prepare-OpenIDXAppHost.ps1 -Report JSON here. Same
		// X-Agent-ID + X-Auth-Token auth as /agent/report; the tenant is
		// resolved from the agent→host binding, so it sits outside JWT auth too.
		publicAgent.POST("/agent/windows-apps/report", svc.handleAgentWindowsAppReport)
	}

	// Tier-0 "dark platform" enroll door: the ONLY access-service route that
	// stays public when the platform goes dark. Trades an entitlement (session
	// bearer / enrollment token) for a one-time Ziti enrollment JWT so a native
	// client can join the overlay. It authenticates the request itself (verifies
	// the bearer against JWKS, or validates the enrollment token), so it sits
	// OUTSIDE the JWT middleware like the agent routes. Rate-limited + audited.
	// See docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md §4.
	router.POST("/api/v1/access/enroll",
		middleware.RateLimit(20, time.Minute), // tight per-IP budget for the public gate
		svc.handleEnroll)

	// Public agent downloads: per-OS installers, the wizard manifest, and the
	// Android APK (fetched during factory-reset provisioning before any auth
	// context exists). One param route avoids a gin static-vs-wildcard conflict.
	router.GET("/downloads/:file", svc.handleAgentDownload)

	// Temp access public endpoint (no auth - uses token)
	router.GET("/temp-access/:token", svc.handleUseTempAccess)

	// Catch-all reverse proxy (must be last)
	router.NoRoute(svc.handleProxy)
}

// ---- Route CRUD ----

func (s *Service) handleListRoutes(c *gin.Context) {
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

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        COALESCE(landing_path, '/'),
		        COALESCE(hosting_mode, 'identity'),
		        COALESCE(upstream_pool_id::text, ''),
		        created_at, updated_at,
		        -- ORDER BY id LIMIT 1 mirrors appForRoute + ziti_reconciler's pick when
		        -- more than one application links to the same route (Ruling 13: the
		        -- route<->application link is a convention, not a DB-enforced 1:1).
		        COALESCE((SELECT id::text FROM applications WHERE route_id = proxy_routes.id AND enabled = true ORDER BY id LIMIT 1), '') AS application_id,
		        COALESCE((SELECT name FROM applications WHERE route_id = proxy_routes.id AND enabled = true ORDER BY id LIMIT 1), '') AS application_name
		 FROM proxy_routes WHERE org_id = $3 ORDER BY priority DESC, name ASC LIMIT $1 OFFSET $2`, limit, offset, org.ID)
	if err != nil {
		s.logger.Error("Failed to list routes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list routes"})
		return
	}
	defer rows.Close()

	routes := []ProxyRoute{}
	for rows.Next() {
		var r ProxyRoute
		var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
		var remotePort *int
		var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte
		err := rows.Scan(&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
			&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
			&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
			&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
			&idpID, &r.RouteType, &remoteHost, &remotePort,
			&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
			&r.RequireDeviceTrust, &allowedCountries,
			&r.MaxRiskScore, &guacConnID,
			&r.LandingPath, &r.HostingMode, &r.UpstreamPoolID,
			&r.CreatedAt, &r.UpdatedAt,
			&r.ApplicationID, &r.ApplicationName)
		if err != nil {
			s.logger.Error("Failed to scan route", zap.Error(err))
			continue
		}
		if desc != nil {
			r.Description = *desc
		}
		if zitiServiceName != nil {
			r.ZitiServiceName = *zitiServiceName
		}
		if idpID != nil {
			r.IDPId = *idpID
		}
		if remoteHost != nil {
			r.RemoteHost = *remoteHost
		}
		if remotePort != nil {
			r.RemotePort = *remotePort
		}
		if inlinePolicy != nil {
			r.InlinePolicy = *inlinePolicy
		}
		if guacConnID != nil {
			r.GuacamoleConnectionID = *guacConnID
		}
		if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
			s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
			s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
			s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
			s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
			s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
			s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
			s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
		}
		if r.AllowedRoles == nil {
			r.AllowedRoles = []string{}
		}
		if r.AllowedGroups == nil {
			r.AllowedGroups = []string{}
		}
		if r.PolicyIDs == nil {
			r.PolicyIDs = []string{}
		}
		if r.CORSAllowedOrigins == nil {
			r.CORSAllowedOrigins = []string{}
		}
		if r.CustomHeaders == nil {
			r.CustomHeaders = map[string]string{}
		}
		if r.PostureCheckIDs == nil {
			r.PostureCheckIDs = []string{}
		}
		if r.AllowedCountries == nil {
			r.AllowedCountries = []string{}
		}
		routes = append(routes, r)
	}

	// Get total count. A discarded error reported "total": 0 in the same
	// response that carried the routes, which reads as a list that does not
	// know its own length.
	var total int
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM proxy_routes WHERE org_id = $1", org.ID).Scan(&total); err != nil {
		s.logger.Error("failed to count proxy routes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list routes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"routes": routes,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *Service) handleCreateRoute(c *gin.Context) {
	var req struct {
		Name               string            `json:"name" binding:"required"`
		Description        string            `json:"description"`
		FromURL            string            `json:"from_url" binding:"required"`
		ToURL              string            `json:"to_url" binding:"required"`
		PreserveHost       bool              `json:"preserve_host"`
		RequireAuth        *bool             `json:"require_auth"`
		AllowedRoles       []string          `json:"allowed_roles"`
		AllowedGroups      []string          `json:"allowed_groups"`
		PolicyIDs          []string          `json:"policy_ids"`
		IdleTimeout        int               `json:"idle_timeout"`
		AbsoluteTimeout    int               `json:"absolute_timeout"`
		CORSAllowedOrigins []string          `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string `json:"custom_headers"`
		Enabled            *bool             `json:"enabled"`
		Priority           int               `json:"priority"`
		IDPId              string            `json:"idp_id"`
		RouteType          string            `json:"route_type"`
		RemoteHost         string            `json:"remote_host"`
		RemotePort         int               `json:"remote_port"`
		ReverifyInterval   int               `json:"reverify_interval"`
		PostureCheckIDs    []string          `json:"posture_check_ids"`
		InlinePolicy       string            `json:"inline_policy"`
		RequireDeviceTrust bool              `json:"require_device_trust"`
		AllowedCountries   []string          `json:"allowed_countries"`
		MaxRiskScore       int               `json:"max_risk_score"`
		LandingPath        string            `json:"landing_path"`
		HostingMode        string            `json:"hosting_mode"`
		UpstreamPoolID     string            `json:"upstream_pool_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	landingPath := strings.TrimSpace(req.LandingPath)
	if landingPath == "" {
		landingPath = "/"
	}

	if name := identityCustomHeader(req.CustomHeaders); name != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
			"custom_headers cannot set %s: the proxy writes it from the signed-in session", name)})
		return
	}

	hostingMode, ok := normalizeHostingMode(req.HostingMode)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hosting_mode (expected identity, direct, or hop)"})
		return
	}

	id := uuid.New().String()
	requireAuth := true
	if req.RequireAuth != nil {
		requireAuth = *req.RequireAuth
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.IdleTimeout == 0 {
		req.IdleTimeout = 900
	}
	if req.AbsoluteTimeout == 0 {
		req.AbsoluteTimeout = 43200
	}
	if req.RouteType == "" {
		req.RouteType = "http"
	}
	if req.MaxRiskScore == 0 {
		req.MaxRiskScore = 100
	}

	// Validate inline policy if provided
	if req.InlinePolicy != "" {
		if err := ValidatePolicy(req.InlinePolicy); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
			return
		}
	}

	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	groupsJSON, _ := json.Marshal(req.AllowedGroups)
	policyJSON, _ := json.Marshal(req.PolicyIDs)
	corsJSON, _ := json.Marshal(req.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	postureJSON, _ := json.Marshal(req.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(req.AllowedCountries)

	var idpID *string
	if req.IDPId != "" {
		idpID = &req.IDPId
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// A pool id is resolved inside the caller's org before it is stored: the FK
	// alone would accept another tenant's pool and send this route's traffic to
	// their backends.
	poolID, err := s.resolvePoolForRoute(c.Request.Context(), org.ID, req.UpstreamPoolID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_routes (id, name, description, from_url, to_url, preserve_host,
		  require_auth, allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		  cors_allowed_origins, custom_headers, enabled, priority,
		  idp_id, route_type, remote_host, remote_port,
		  reverify_interval, posture_check_ids, inline_policy,
		  require_device_trust, allowed_countries, max_risk_score, landing_path, hosting_mode, org_id,
		  upstream_pool_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		         $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)`,
		id, req.Name, req.Description, req.FromURL, req.ToURL, req.PreserveHost,
		requireAuth, rolesJSON, groupsJSON, policyJSON, req.IdleTimeout, req.AbsoluteTimeout,
		corsJSON, headersJSON, enabled, req.Priority,
		idpID, req.RouteType, req.RemoteHost, req.RemotePort,
		req.ReverifyInterval, postureJSON, req.InlinePolicy,
		req.RequireDeviceTrust, countriesJSON, req.MaxRiskScore, landingPath, hostingMode, org.ID,
		poolID)
	if err != nil {
		// Another enabled route, in this organization or any other, already
		// serves the host from_url names.
		if s.answerRouteHostTaken(c, org.ID, req.FromURL, err) {
			return
		}
		s.logger.Error("Failed to create route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route"})
		return
	}

	// Auto-provision Guacamole connection for remote access routes
	route := &ProxyRoute{
		ID: id, Name: req.Name, RouteType: req.RouteType,
		RemoteHost: req.RemoteHost, RemotePort: req.RemotePort,
	}
	if err := s.provisionGuacamoleForRoute(c.Request.Context(), route); err != nil {
		s.logger.Warn("Guacamole provisioning failed", zap.Error(err))
	}

	// Mirror the route as an Applications launcher tile so it shows on the
	// Applications page (which reads `applications`) with working row actions.
	s.upsertAppTile(c.Request.Context(), id, req.Name, req.Description, req.FromURL, landingPath, org.ID)

	s.logAuditEvent(c, "proxy_route_created", id, "proxy_route", map[string]interface{}{
		"name":       req.Name,
		"from_url":   req.FromURL,
		"to_url":     req.ToURL,
		"route_type": req.RouteType,
	})

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "route created"})
}

func (s *Service) handleGetRoute(c *gin.Context) {
	route, err := s.getRouteByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		s.logger.Error("Failed to get route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}
	c.JSON(http.StatusOK, route)
}

func (s *Service) handleUpdateRoute(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name               *string           `json:"name"`
		Description        *string           `json:"description"`
		FromURL            *string           `json:"from_url"`
		ToURL              *string           `json:"to_url"`
		PreserveHost       *bool             `json:"preserve_host"`
		RequireAuth        *bool             `json:"require_auth"`
		AllowedRoles       []string          `json:"allowed_roles"`
		AllowedGroups      []string          `json:"allowed_groups"`
		PolicyIDs          []string          `json:"policy_ids"`
		IdleTimeout        *int              `json:"idle_timeout"`
		AbsoluteTimeout    *int              `json:"absolute_timeout"`
		CORSAllowedOrigins []string          `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string `json:"custom_headers"`
		Enabled            *bool             `json:"enabled"`
		Priority           *int              `json:"priority"`
		IDPId              *string           `json:"idp_id"`
		RouteType          *string           `json:"route_type"`
		RemoteHost         *string           `json:"remote_host"`
		RemotePort         *int              `json:"remote_port"`
		ReverifyInterval   *int              `json:"reverify_interval"`
		PostureCheckIDs    []string          `json:"posture_check_ids"`
		InlinePolicy       *string           `json:"inline_policy"`
		RequireDeviceTrust *bool             `json:"require_device_trust"`
		AllowedCountries   []string          `json:"allowed_countries"`
		MaxRiskScore       *int              `json:"max_risk_score"`
		LandingPath        *string           `json:"landing_path"`
		HostingMode        *string           `json:"hosting_mode"`
		// Tri-state on the wire, like every other pointer here: absent leaves
		// the link alone, "" clears it (back to to_url), an id sets it.
		UpstreamPoolID *string `json:"upstream_pool_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update
	existing, err := s.getRouteByID(c.Request.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}

	if name := identityCustomHeader(req.CustomHeaders); name != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
			"custom_headers cannot set %s: the proxy writes it from the signed-in session", name)})
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.FromURL != nil {
		existing.FromURL = *req.FromURL
	}
	if req.ToURL != nil {
		existing.ToURL = *req.ToURL
	}
	if req.PreserveHost != nil {
		existing.PreserveHost = *req.PreserveHost
	}
	if req.RequireAuth != nil {
		existing.RequireAuth = *req.RequireAuth
	}
	if req.AllowedRoles != nil {
		existing.AllowedRoles = req.AllowedRoles
	}
	if req.AllowedGroups != nil {
		existing.AllowedGroups = req.AllowedGroups
	}
	if req.PolicyIDs != nil {
		existing.PolicyIDs = req.PolicyIDs
	}
	if req.IdleTimeout != nil {
		existing.IdleTimeout = *req.IdleTimeout
	}
	if req.AbsoluteTimeout != nil {
		existing.AbsoluteTimeout = *req.AbsoluteTimeout
	}
	if req.CORSAllowedOrigins != nil {
		existing.CORSAllowedOrigins = req.CORSAllowedOrigins
	}
	if req.CustomHeaders != nil {
		existing.CustomHeaders = req.CustomHeaders
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.IDPId != nil {
		existing.IDPId = *req.IDPId
	}
	if req.RouteType != nil {
		existing.RouteType = *req.RouteType
	}
	if req.RemoteHost != nil {
		existing.RemoteHost = *req.RemoteHost
	}
	if req.RemotePort != nil {
		existing.RemotePort = *req.RemotePort
	}
	if req.ReverifyInterval != nil {
		existing.ReverifyInterval = *req.ReverifyInterval
	}
	if req.PostureCheckIDs != nil {
		existing.PostureCheckIDs = req.PostureCheckIDs
	}
	if req.InlinePolicy != nil {
		existing.InlinePolicy = *req.InlinePolicy
		if existing.InlinePolicy != "" {
			if err := ValidatePolicy(existing.InlinePolicy); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
				return
			}
		}
	}
	if req.RequireDeviceTrust != nil {
		existing.RequireDeviceTrust = *req.RequireDeviceTrust
	}
	if req.AllowedCountries != nil {
		existing.AllowedCountries = req.AllowedCountries
	}
	if req.MaxRiskScore != nil {
		existing.MaxRiskScore = *req.MaxRiskScore
	}
	if req.LandingPath != nil {
		existing.LandingPath = strings.TrimSpace(*req.LandingPath)
	}
	if existing.LandingPath == "" {
		existing.LandingPath = "/"
	}
	if req.HostingMode != nil {
		mode, ok := normalizeHostingMode(*req.HostingMode)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hosting_mode (expected identity, direct, or hop)"})
			return
		}
		existing.HostingMode = mode
	}
	if req.UpstreamPoolID != nil {
		existing.UpstreamPoolID = strings.TrimSpace(*req.UpstreamPoolID)
	}

	rolesJSON, _ := json.Marshal(existing.AllowedRoles)
	groupsJSON, _ := json.Marshal(existing.AllowedGroups)
	policyJSON, _ := json.Marshal(existing.PolicyIDs)
	corsJSON, _ := json.Marshal(existing.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(existing.CustomHeaders)
	postureJSON, _ := json.Marshal(existing.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(existing.AllowedCountries)

	var idpID *string
	if existing.IDPId != "" {
		idpID = &existing.IDPId
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Same rule as create: the pool must be this org's, or the route would be
	// pointed at another tenant's backends by id alone.
	poolID, err := s.resolvePoolForRoute(c.Request.Context(), org.ID, existing.UpstreamPoolID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE proxy_routes SET name=$1, description=$2, from_url=$3, to_url=$4,
		  preserve_host=$5, require_auth=$6, allowed_roles=$7, allowed_groups=$8,
		  policy_ids=$9, idle_timeout=$10, absolute_timeout=$11, cors_allowed_origins=$12,
		  custom_headers=$13, enabled=$14, priority=$15,
		  idp_id=$16, route_type=$17, remote_host=$18, remote_port=$19,
		  reverify_interval=$20, posture_check_ids=$21, inline_policy=$22,
		  require_device_trust=$23, allowed_countries=$24, max_risk_score=$25,
		  landing_path=$26, hosting_mode=$27, upstream_pool_id=$28, updated_at=NOW()
		 WHERE id=$29 AND org_id=$30`,
		existing.Name, existing.Description, existing.FromURL, existing.ToURL,
		existing.PreserveHost, existing.RequireAuth, rolesJSON, groupsJSON,
		policyJSON, existing.IdleTimeout, existing.AbsoluteTimeout, corsJSON,
		headersJSON, existing.Enabled, existing.Priority,
		idpID, existing.RouteType, existing.RemoteHost, existing.RemotePort,
		existing.ReverifyInterval, postureJSON, existing.InlinePolicy,
		existing.RequireDeviceTrust, countriesJSON, existing.MaxRiskScore,
		existing.LandingPath, existing.HostingMode, poolID, id, org.ID)
	if err != nil {
		// A new from_url, or enabling the route, puts it on a host another
		// enabled route already serves.
		if s.answerRouteHostTaken(c, org.ID, existing.FromURL, err) {
			return
		}
		s.logger.Error("Failed to update route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update route"})
		return
	}

	// Re-key the clientless edge for Ziti routes: a from_url (host) or hosting-
	// mode change must move the APISIX BrowZer route + bootstrapper target to the
	// new host and prune the old, instead of stranding the wiring under the old
	// host name. No-op for non-Ziti routes.
	if existing.ZitiEnabled {
		s.refreshBrowZerEdge(c.Request.Context())
	}

	// Keep the Applications launcher tile in sync (name/description/base_url),
	// and backfill one for a route created before tiles were auto-created.
	s.upsertAppTile(c.Request.Context(), id, existing.Name, existing.Description, existing.FromURL, existing.LandingPath, org.ID)

	c.JSON(http.StatusOK, gin.H{"message": "route updated"})
}

func (s *Service) handleDeleteRoute(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Deprovision Guacamole connection before deleting route
	s.deprovisionGuacamoleForRoute(c.Request.Context(), id)

	// Tear down the route's Ziti service + policies + name-keyed edge configs
	// BEFORE removing the row — the row delete alone leaves them orphaned on the
	// controller (there is no FK cascade to ziti_services). No-ops if the route
	// has no Ziti service.
	if zm := s.ziti(); zm != nil {
		if err := zm.TeardownZitiForRoute(c.Request.Context(), id); err != nil {
			s.logger.Warn("ziti teardown on route delete failed", logsafe.String("route_id", id), zap.Error(err))
		}
	}

	result, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM proxy_routes WHERE id=$1 AND org_id=$2", id, org.ID)
	if err != nil {
		s.logger.Error("Failed to delete route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete route"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	// Prune the deleted route's BrowZer edge wiring (APISIX route + bootstrapper
	// target) and reconcile, and remove its Applications launcher tile.
	s.refreshBrowZerEdge(c.Request.Context())
	s.deleteAppTile(c.Request.Context(), id)

	s.logAuditEvent(c, "proxy_route_deleted", id, "proxy_route", nil)
	c.JSON(http.StatusOK, gin.H{"message": "route deleted"})
}

// ---- Session management ----

func (s *Service) handleListSessions(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	// The IdP join is a LEFT JOIN because most sessions have no external
	// provider: proxy_sessions.idp_id is set only by the multi-IdP callback.
	// It is org-scoped on both sides so a session cannot name another tenant's
	// provider, which would put the shape of their federation setup on this
	// tenant's page.
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT s.id, s.user_id, s.route_id, s.ip_address, s.user_agent, s.started_at,
		        s.last_active_at, s.expires_at, s.revoked, COALESCE(i.name,'')
		 FROM proxy_sessions s
		 LEFT JOIN identity_providers i ON i.id = s.idp_id AND i.org_id = s.org_id
		 WHERE s.revoked=false AND s.expires_at > NOW() AND s.org_id = $1
		 ORDER BY s.last_active_at DESC LIMIT 100`, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()

	sessions := []ProxySession{}
	// A row that will not scan used to be skipped in silence. This is the list
	// an operator revokes sessions from, so a session that quietly falls out of
	// it is a session nobody revokes -- and the page cannot tell that apart
	// from a session that has ended. The count travels with the answer.
	unreadable := 0
	for rows.Next() {
		var sess ProxySession
		var routeID *string
		err := rows.Scan(&sess.ID, &sess.UserID, &routeID, &sess.IPAddress, &sess.UserAgent,
			&sess.StartedAt, &sess.LastActiveAt, &sess.ExpiresAt, &sess.Revoked, &sess.IDPName)
		if err != nil {
			unreadable++
			s.logger.Error("an active proxy session could not be read into the session list; "+
				"it will not appear on the sessions page and cannot be revoked from it", zap.Error(err))
			continue
		}
		if routeID != nil {
			sess.RouteID = *routeID
		}
		sessions = append(sessions, sess)
	}

	body := gin.H{"sessions": sessions}
	if unreadable > 0 {
		body["unreadable"] = unreadable
	}
	c.JSON(http.StatusOK, body)
}

// handleRevokeSession ends one of the organization's proxy sessions.
//
// A live session is the Redis blob under proxy_session:<hash of the cookie>, and
// the proxy and forward-auth read that and nothing else (getSessionFromRequest).
// The row keeps the same hash in session_token, so the revocation reaches the
// blob through the row. It used to mark the row and delete a key named after the
// row's id -- a key no session is stored under -- so a revoked session went on
// working until its blob expired, up to twelve hours later, and the answer was
// 200 whether or not anything had matched.
//
// Deleting the blob is the data plane's whole check, and it costs nothing per
// proxied request: every path that revokes a row deletes its blob (sign-out, the
// idle timeout, continuous verification, and this one), and the only write that
// could bring a deleted blob back, the idle window's refresh in
// updateSessionActivity, only updates a blob that still exists. A revoked marker
// read on every request would need exactly the same writes and add a round trip
// to each of them.
func (s *Service) handleRevokeSession(c *gin.Context) {
	id := c.Param("id")
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if _, perr := uuid.Parse(id); perr != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	var tokenHash string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		"UPDATE proxy_sessions SET revoked=true WHERE id=$1 AND org_id=$2 RETURNING session_token",
		id, org.ID).Scan(&tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	if err != nil {
		s.logger.Error("failed to revoke a proxy session", logsafe.String("session_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
		return
	}

	if err := s.redis.Client.Del(c.Request.Context(), "proxy_session:"+tokenHash).Err(); err != nil {
		// The row reads revoked and the session still works. Say which is
		// true; a retry finds the row again and deletes the blob.
		s.logger.Error("a proxy session was marked revoked but its live session could not be deleted; "+
			"it keeps working until it is", logsafe.String("session_id", id), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the session is marked revoked but is still live; retry"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}

// ---- OAuth Login Flow ----

// callbackScheme returns the external URL scheme for building OAuth callback /
// redirect URLs. Behind a TLS-terminating proxy (nginx/APISIX) the public
// request is HTTPS but reaches this service as HTTP, so honor X-Forwarded-Proto
// first; fall back to the request's own TLS state, then http. Without this the
// emitted redirect_uri is http:// and won't match the public https:// URL.
func callbackScheme(c *gin.Context) string {
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		if i := strings.IndexByte(proto, ','); i >= 0 { // may be a list; take the first
			proto = proto[:i]
		}
		if p := strings.TrimSpace(proto); p != "" {
			return p
		}
	}
	if c.Request != nil && c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func (s *Service) handleLogin(c *gin.Context) {
	// Check if a specific IDP is requested
	if idpID := c.Query("idp"); idpID != "" && idpID != "default" {
		s.handleLoginWithIDP(c, idpID)
		return
	}

	// Generate PKCE code verifier and challenge
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := generateState()

	// Store verifier and original URL in Redis. Only a target the proxy may
	// send a browser to is stored; anything else lands on the session page.
	redirectURL := s.redirectTarget(c, c.Query("redirect_url"), "/access/.auth/session")

	sessionData, _ := json.Marshal(map[string]string{
		"verifier":     verifier,
		"redirect_url": redirectURL,
	})
	s.redis.Client.Set(c.Request.Context(), "access_oauth_state:"+state, sessionData, 10*time.Minute)

	// Build OAuth authorization URL
	// Determine the callback host: prefer the request Host (preserves port from pass_host),
	// then X-Forwarded-Host, then extract from redirect_url.
	callbackHost := c.Request.Host
	if callbackHost == "" || callbackHost == fmt.Sprintf("access-service:%d", s.config.Port) {
		callbackHost = c.GetHeader("X-Forwarded-Host")
	}
	if callbackHost == "" {
		// Extract host from redirect_url if it's a full URL (e.g., http://demo.localtest.me:8088/)
		if parsed, err := url.Parse(redirectURL); err == nil && parsed.Host != "" {
			callbackHost = parsed.Host
		}
	}
	if callbackHost == "" {
		callbackHost = fmt.Sprintf("%s:%d", s.config.AccessProxyDomain, s.config.Port)
	}
	callbackURL := fmt.Sprintf("%s://%s/access/.auth/callback", callbackScheme(c), callbackHost)

	authURL := fmt.Sprintf("%s/oauth/authorize?client_id=access-proxy&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&scope=openid+profile+email",
		s.oauthIssuer,
		url.QueryEscape(callbackURL),
		url.QueryEscape(challenge),
		url.QueryEscape(state))

	c.Redirect(http.StatusFound, authURL)
}

func (s *Service) handleCallback(c *gin.Context) {
	// If login_session is present, the OAuth service is asking us to show a
	// login form. Anyone can put anything in the link, and the value goes into
	// the page, so only the shape the OAuth service mints is served.
	loginSession := c.Query("login_session")
	if loginSession != "" {
		if !loginSessionPattern.MatchString(loginSession) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login_session"})
			return
		}
		s.serveLoginPage(c, loginSession)
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// Retrieve stored state
	stateData, err := s.redis.Client.Get(c.Request.Context(), "access_oauth_state:"+state).Bytes()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state"})
		return
	}
	s.redis.Client.Del(c.Request.Context(), "access_oauth_state:"+state)

	var storedState struct {
		Verifier    string `json:"verifier"`
		RedirectURL string `json:"redirect_url"`
		IDPID       string `json:"idp_id"`
		IDPIssuer   string `json:"idp_issuer"`
	}
	json.Unmarshal(stateData, &storedState)

	// If this callback is from an external IDP, delegate to multi-IDP handler
	if storedState.IDPID != "" && storedState.IDPID != "default" {
		s.handleCallbackWithIDP(c, storedState.IDPID, storedState.IDPIssuer, storedState.Verifier, storedState.RedirectURL)
		return
	}

	// Exchange code for tokens (callback URL must match what was sent to the authorize endpoint)
	callbackHost := c.Request.Host
	if callbackHost == "" || callbackHost == fmt.Sprintf("access-service:%d", s.config.Port) {
		callbackHost = c.GetHeader("X-Forwarded-Host")
	}
	if callbackHost == "" {
		if parsed, err := url.Parse(storedState.RedirectURL); err == nil && parsed.Host != "" {
			callbackHost = parsed.Host
		}
	}
	if callbackHost == "" {
		callbackHost = fmt.Sprintf("%s:%d", s.config.AccessProxyDomain, s.config.Port)
	}
	callbackURL := fmt.Sprintf("%s://%s/access/.auth/callback", callbackScheme(c), callbackHost)

	tokenResp, err := s.exchangeCode(c.Request.Context(), code, storedState.Verifier, callbackURL)
	if err != nil {
		s.logger.Error("Failed to exchange code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	// Parse the access token to extract user info
	claims, err := s.parseTokenClaims(tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to parse token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse token"})
		return
	}

	// Create proxy session
	session, err := s.createSession(c, claims)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Set session cookie with SameSite=Lax for CSRF protection
	// The Secure flag is computed, not a literal, so the scanner cannot see it;
	// sessionCookieSecure (session_cookie.go) sets it from the request's real
	// transport and is covered by session_cookie_test.go.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "_openidx_proxy_session",
		Value:    session.SessionToken,
		MaxAge:   session.AbsoluteTimeout(),
		Path:     "/",
		Secure:   sessionCookieSecure(c, s.config),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	s.logAuditEvent(c, "proxy_session_created", session.UserID, "session", map[string]interface{}{
		"session_id": session.ID,
		"email":      session.Email,
	})

	// Redirect to original URL. It was checked when it was stored, and is
	// checked again here, where it is followed.
	c.Redirect(http.StatusFound, s.redirectTarget(c, storedState.RedirectURL, "/"))
}

func (s *Service) handleLogout(c *gin.Context) {
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err == nil && cookie != "" {
		// Find and revoke session
		var sessionID string
		err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(c.Request.Context()),
			//orgscope:ignore proxy data-plane logout; session looked up by globally-unique session_token hash, pre-org-resolution
			"SELECT id FROM proxy_sessions WHERE session_token=$1", hashToken(cookie)).Scan(&sessionID)
		if err == nil {
			// A logout that did not log anybody out. Both of these had their
			// errors discarded: the Redis key is what the proxy checks on every
			// request, so a failed Del leaves the session WORKING, and a failed
			// UPDATE leaves the durable record saying it is live. The cookie is
			// cleared either way, so the person is told they signed out.
			if _, uerr := s.db.Pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
				//orgscope:ignore proxy data-plane logout; revoke by primary key resolved from the unique session_token above
				"UPDATE proxy_sessions SET revoked=true WHERE id=$1", sessionID); uerr != nil {
				s.logger.Error("logout could not mark the session revoked", zap.Error(uerr))
			}
			if derr := s.redis.Client.Del(c.Request.Context(), "proxy_session:"+hashToken(cookie)).Err(); derr != nil {
				s.logger.Error("logout could not drop the session marker the proxy reads; "+
					"the session may still be usable", zap.Error(derr))
			}
		}
	}

	// The Secure flag is computed, not a literal, so the scanner cannot see it;
	// sessionCookieSecure (session_cookie.go) sets it from the request's real
	// transport and is covered by session_cookie_test.go.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "_openidx_proxy_session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   sessionCookieSecure(c, s.config),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Signing out needs no session, so this redirect is anybody's to write.
	c.Redirect(http.StatusFound, s.redirectTarget(c, c.Query("redirect_url"), "/access/.auth/login"))
}

func (s *Service) handleSessionInfo(c *gin.Context) {
	session := s.getSessionFromRequest(c, s.browserHost(c))
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no active session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    session.UserID,
		"email":      session.Email,
		"name":       session.Name,
		"roles":      session.Roles,
		"expires_at": session.ExpiresAt,
	})
}

// ---- Reverse Proxy ----

// proxyAssignmentDecision returns (allow, recordWouldDeny) for one request.
//
// A route with no application behind it keeps the legacy role/group verdict
// untouched. For an app-backed route the assignment predicate replaces that
// verdict under enforcement; in report mode the request is allowed and the gap
// is recorded so the report shows it before anyone loses access.
func proxyAssignmentDecision(applicationID string, assigned, enforce, legacyAllowed bool) (allow, recordWouldDeny bool) {
	if applicationID == "" {
		return legacyAllowed, false
	}
	if assigned {
		return true, false
	}
	if enforce {
		return false, true
	}
	return true, true
}

// recordAssignmentDecision durably records one assignment-gate decision.
//
// It writes to unified_audit_events (via the UnifiedAuditService this package
// already uses for its other 40k+ healthy rows) rather than relying on the
// audit-service POST in logAuditEvent, which lands in audit_events — a table
// the org-scoped RLS policy rejects these writes from, so on the live box it
// has taken a single row since June while unified_audit_events takes writes
// today. In report mode these records are the ONLY evidence that
// ACCESS_ASSIGNMENT_ENFORCE is safe to flip, so they must land somewhere that
// accepts them.
//
// This is a side-effect recorder only: it never influences the verdict, and
// every failure path below returns without changing the caller's behaviour.
//
// auditService is set post-construction (SetAuditService) and may be nil. A
// nil service is logged at WARN and never silently swallowed — a dropped
// decision record is the exact defect this exists to fix.
func (s *Service) recordAssignmentDecision(ctx context.Context, route *ProxyRoute, userID, appID, actorIP string, enforced bool) {
	eventType := appaccess.DecisionEventType(enforced)

	var routeID, routeName string
	if route != nil {
		routeID, routeName = route.ID, route.Name
	}
	details := appaccess.DecisionDetails(appaccess.EnforcementPointProxy, userID, appID, enforced,
		map[string]interface{}{"route": routeName})

	if s.auditService == nil {
		s.logger.Warn("assignment decision not recorded: unified audit service unavailable",
			zap.String("event_type", eventType),
			zap.String("user_id", userID),
			zap.String("application_id", appID),
			zap.String("route_id", routeID),
			zap.Bool("enforced", enforced))
		return
	}

	if err := s.auditService.RecordEvent(ctx, appaccess.SourceProxy, eventType,
		routeID, userID, actorIP, details); err != nil {
		s.logger.Warn("assignment decision not recorded: unified audit write failed",
			zap.String("event_type", eventType),
			zap.String("user_id", userID),
			zap.String("application_id", appID),
			zap.String("route_id", routeID),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}

func (s *Service) handleProxy(c *gin.Context) {
	// Find matching route by host header
	host := c.Request.Host
	route, err := s.findRouteByHost(c.Request.Context(), host)
	if err != nil || route == nil {
		// No matching route - return 404
		c.JSON(http.StatusNotFound, gin.H{"error": "no proxy route configured for this host"})
		return
	}

	if !route.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "route is disabled"})
		return
	}

	// Check authentication
	var session *ProxySession
	if route.RequireAuth {
		session = sessionOnRoute(s.getSessionFromRequest(c, host), route)
		// Enforce the route's idle timeout on the cookie session: if it has been
		// idle longer than idle_timeout, revoke it and re-auth. (Bearer tokens
		// carry their own JWT expiry, so this only applies to the cookie path.)
		if session != nil && isIdleExpired(route, session, time.Now()) {
			s.revokeIdleProxySession(c, session)
			s.logAuditEvent(c, "proxy_session_idle_expired", route.ID, "proxy_route", map[string]interface{}{
				"user_id":      session.UserID,
				"idle_timeout": route.IdleTimeout,
			})
			session = nil
		}
		if session == nil {
			// Also check for Bearer token
			session = s.getSessionFromBearer(c)
		}
		if session == nil {
			// Redirect to login, back to this path on this host afterwards.
			// RequestURI and not URL.String(): a request line in absolute form
			// names a scheme and host of its own, and they are not this one.
			loginURL := fmt.Sprintf("/access/.auth/login?redirect_url=%s",
				url.QueryEscape(c.Request.URL.RequestURI()))
			c.Redirect(http.StatusFound, loginURL)
			return
		}

		// Assignment overlay lookup. Resolve the application (if any) behind this
		// route before the role/group checks run — under enforcement the
		// assignment predicate must pre-empt those checks, not just override
		// their outcome after a denial has already fired. Cached (see
		// proxy_assignment_cache.go): forward-auth fires on every request the
		// proxy forwards, not once per page load.
		appID, appOrgID := s.appForRoute(c.Request.Context(), route.ID)

		// Under enforcement, an app-backed route's verdict comes solely from
		// assignment: the role/group check below is skipped entirely rather than
		// intersected with the assignment predicate — checking both would be the
		// intersect model this design rejected. Every other case — the route has
		// no application, or the flag is off — runs the role/group check exactly
		// as it always has, so both the verdict and its audit trail are
		// byte-for-byte unchanged there.
		assignmentReplacesLegacy := appID != "" && s.config.AccessAssignmentEnforce

		if !assignmentReplacesLegacy {
			// Check roles
			if len(route.AllowedRoles) > 0 && !hasAnyRole(session.Roles, route.AllowedRoles) {
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":  "insufficient_roles",
					"user_id": session.UserID,
					"path":    c.Request.URL.Path,
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
				return
			}

			// Check groups. Stored in allowed_groups and settable in the admin UI,
			// but historically never evaluated here.
			if len(route.AllowedGroups) > 0 &&
				!routeGroupsAllow(route.AllowedGroups, s.userGroupNames(c.Request.Context(), session.UserID)) {
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":  "insufficient_groups",
					"user_id": session.UserID,
					"path":    c.Request.URL.Path,
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
				return
			}
		}

		// Assignment overlay. When assignmentReplacesLegacy is false, reaching
		// this line means either the route has no application (appID == "", so
		// proxyAssignmentDecision below is a pass-through no-op) or the role and
		// group checks above just passed — either way the legacy verdict for
		// this request is allow, so legacyAllowed is true here. When
		// assignmentReplacesLegacy is true, proxyAssignmentDecision ignores the
		// legacyAllowed argument entirely (see its doc comment), so the value
		// passed is moot.
		var assigned, freshAssignment bool
		if appID != "" {
			assigned, freshAssignment = s.assignmentAllowed(c.Request.Context(), session.UserID, appOrgID, appID)
		}
		allow, wouldDeny := proxyAssignmentDecision(appID, assigned, s.config.AccessAssignmentEnforce, true)
		if wouldDeny {
			// Durable decision record, on BOTH branches: enforcement must not
			// be quieter than report mode. This is the write that has to
			// survive — see recordAssignmentDecision. The logAuditEvent calls
			// below are kept as-is (harmless duplication; audit_events may be
			// repaired later) but nothing depends on them landing.
			if !allow || freshAssignment {
				s.recordAssignmentDecision(c.Request.Context(), route, session.UserID, appID, c.ClientIP(), !allow)
			}
			if !allow {
				// A real denial under enforcement: audit it as an actual proxy
				// denial (action "proxy_access_denied" is the only action
				// logAuditEvent stamps outcome:"failure" for) so an operator
				// filtering the proxy audit stream for denials finds this
				// request, instead of it landing as a success-outcome
				// "would_deny" record indistinguishable from the report-mode
				// case below.
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":         "not_assigned",
					"user_id":        session.UserID,
					"path":           c.Request.URL.Path,
					"application_id": appID,
				})
			} else if freshAssignment {
				// Report mode: record the gap. This fires on every allowed
				// request from an unassigned caller to an app-backed route —
				// every asset load, not just the page — so it is throttled to
				// once per assignmentAllowed cache TTL per (user, application)
				// via the freshAssignment flag, rather than one audit POST per
				// request.
				s.logAuditEvent(c, "access.assignment.would_deny", appID, "application", map[string]interface{}{
					"enforcement_point": "proxy",
					"user_id":           session.UserID,
					"route":             route.Name,
				})
			}
		}
		if !allow {
			c.JSON(http.StatusForbidden, gin.H{"error": "not assigned to this application"})
			return
		}

		// ABAC overlay. The tenant's attribute policies are the second half of
		// the same rollout: authored on the ABAC Policies page, enforced here
		// and at /oauth/authorize, staged through ABAC_ENFORCE=off|observe|
		// enforce exactly like ACCESS_ASSIGNMENT_ENFORCE. With the flag off
		// this costs no query.
		if !s.abacGateAllows(c, route, session.UserID, appOrgID, appID) {
			return
		}

		// Context-aware access evaluation
		accessCtx, ctxErr := s.buildAccessContext(c, route, session)
		if ctxErr != nil {
			s.logger.Error("Failed to build access context", zap.Error(ctxErr))
			c.JSON(http.StatusForbidden, gin.H{"error": "context evaluation failed"})
			return
		}
		decision := s.evaluateAccessContext(accessCtx)
		if !decision.Allowed {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  decision.Reason,
				"user_id": session.UserID,
				"path":    c.Request.URL.Path,
			})
			if decision.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			c.JSON(http.StatusForbidden, gin.H{"error": decision.Reason})
			return
		}
		session.RiskScore = decision.RiskScore

		// Evaluate governance policies
		if len(route.PolicyIDs) > 0 {
			allowed, err := s.evaluatePolicies(c, route, session)
			if err != nil {
				s.logger.Error("Policy evaluation failed", zap.Error(err))
				// Fail closed
				c.JSON(http.StatusForbidden, gin.H{"error": "policy evaluation failed"})
				return
			}
			if !allowed {
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":  "policy_denied",
					"user_id": session.UserID,
					"path":    c.Request.URL.Path,
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied by policy"})
				return
			}
		}

		// Update session activity (also slides the idle-timeout window)
		s.updateSessionActivity(c, session)
	}

	// Proxy the request
	target, err := url.Parse(route.ToURL)
	if err != nil {
		s.logger.Error("Invalid upstream URL", zap.String("to_url", route.ToURL), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid upstream configuration"})
		return
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: proxyRewrite(target, route, session, c.ClientIP()),
	}

	// Use Ziti transport if the route has Ziti enabled and ZitiManager is available
	if route.ZitiEnabled && route.ZitiServiceName != "" && s.ziti() != nil && s.ziti().IsInitialized() {
		proxy.Transport = s.ziti().ZitiTransport(route.ZitiServiceName)
		s.logger.Debug("Proxying through Ziti overlay",
			zap.String("service", route.ZitiServiceName),
			zap.String("route", route.Name))
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.logger.Error("Proxy error", zap.String("route", route.Name), zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(gin.H{"error": "upstream unavailable"})
	}

	// Log successful proxy
	if session != nil {
		s.logAuditEvent(c, "proxy_access_allowed", route.ID, "proxy_route", map[string]interface{}{
			"user_id":  session.UserID,
			"path":     c.Request.URL.Path,
			"method":   c.Request.Method,
			"upstream": route.ToURL,
		})
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// ---- Helper methods ----

func (s *Service) getRouteByID(ctx context.Context, id string) (*ProxyRoute, error) {
	// Scope to the request's org when present. The proxy data-plane and the
	// continuous-verification background sweep call this with no org context;
	// route id is a globally-unique primary key, so the by-id lookup is safe and
	// the org filter is applied only for request-path (admin) callers.
	orgFilter := ""
	args := []interface{}{id}
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgFilter = " AND org_id=$2"
		args = append(args, org.ID)
	}

	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        COALESCE(landing_path, '/'),
		        COALESCE(hosting_mode, 'identity'),
		        COALESCE(upstream_pool_id::text, ''),
		        created_at, updated_at
		 FROM proxy_routes WHERE id=$1`+orgFilter, args...).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.LandingPath, &r.HostingMode, &r.UpstreamPoolID,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
		s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
		s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
		s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
		s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
		s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
		s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
		s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
	}
	if r.AllowedRoles == nil {
		r.AllowedRoles = []string{}
	}
	if r.AllowedGroups == nil {
		r.AllowedGroups = []string{}
	}
	if r.PolicyIDs == nil {
		r.PolicyIDs = []string{}
	}
	if r.CORSAllowedOrigins == nil {
		r.CORSAllowedOrigins = []string{}
	}
	if r.CustomHeaders == nil {
		r.CustomHeaders = map[string]string{}
	}
	if r.PostureCheckIDs == nil {
		r.PostureCheckIDs = []string{}
	}
	if r.AllowedCountries == nil {
		r.AllowedCountries = []string{}
	}
	return &r, nil
}

// EnsureZitiServicesForRoutes checks for Ziti-enabled proxy routes that don't have
// a corresponding Ziti service on the controller and creates them. This handles
// routes seeded via init-db.sql that need Ziti resources provisioned on first boot.
func (s *Service) EnsureZitiServicesForRoutes(ctx context.Context, zm *ZitiManager) {
	if zm == nil {
		return
	}

	// Wait for Ziti controller to be fully ready
	time.Sleep(15 * time.Second)

	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore startup infra provisioning across all orgs; reconciles Ziti controller services for every ziti-enabled route on boot
		`SELECT pr.id, pr.ziti_service_name, pr.to_url, COALESCE(pr.browzer_enabled, false)
		 FROM proxy_routes pr
		 WHERE pr.ziti_enabled = true
		   AND pr.ziti_service_name IS NOT NULL
		   AND pr.ziti_service_name != ''
		   AND NOT EXISTS (SELECT 1 FROM ziti_services zs WHERE zs.name = pr.ziti_service_name)`)
	if err != nil {
		s.logger.Error("Failed to query routes needing Ziti setup", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var routeID, serviceName, toURL string
		var browzerEnabled bool
		if err := rows.Scan(&routeID, &serviceName, &toURL, &browzerEnabled); err != nil {
			s.logger.Error("Failed to scan route", zap.Error(err))
			continue
		}

		host, port := parseHostPort(toURL)
		if host == "" || port == 0 {
			s.logger.Warn("Could not parse upstream for Ziti setup",
				zap.String("service", serviceName), zap.String("to_url", toURL))
			continue
		}

		// Check if the service already exists on the Ziti controller
		existingSvc, _ := zm.GetServiceByName(serviceName)
		if existingSvc != nil {
			s.logger.Info("Ziti service already exists, ensuring hosting",
				zap.String("service", serviceName))
			// Ensure it's being hosted
			zm.HostService(serviceName, host, port)
			// Add browzer-enabled if needed
			if browzerEnabled {
				s.ensureBrowZerAttribute(ctx, zm, existingSvc.ID)
			}
			continue
		}

		s.logger.Info("Creating Ziti service for seeded route",
			zap.String("route_id", routeID),
			zap.String("service", serviceName),
			zap.String("target", fmt.Sprintf("%s:%d", host, port)))

		if err := zm.SetupZitiForRoute(ctx, routeID, serviceName, host, port); err != nil {
			s.logger.Error("Failed to setup Ziti for seeded route",
				zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Add browzer-enabled attribute if route has browzer_enabled=true
		if browzerEnabled {
			svc, _ := zm.GetServiceByName(serviceName)
			if svc != nil {
				s.ensureBrowZerAttribute(ctx, zm, svc.ID)
			}
		}

		s.logger.Info("Ziti service created for seeded route", zap.String("service", serviceName))
	}
}

// ensureBrowZerAttribute adds the "browzer-enabled" role attribute to a Ziti service if not present
func (s *Service) ensureBrowZerAttribute(ctx context.Context, zm *ZitiManager, zitiServiceID string) {
	attrs, err := zm.GetServiceRoleAttributes(ctx, zitiServiceID)
	if err != nil {
		s.logger.Warn("Failed to get service role attributes", zap.Error(err))
		return
	}
	for _, a := range attrs {
		if a == "browzer-enabled" {
			return // already has it
		}
	}
	attrs = append(attrs, "browzer-enabled")
	if err := zm.PatchServiceRoleAttributes(ctx, zitiServiceID, attrs); err != nil {
		s.logger.Error("Failed to add browzer-enabled attribute", zap.Error(err))
	} else {
		s.logger.Info("Added browzer-enabled attribute to service", zap.String("ziti_id", zitiServiceID))
	}
}

// EnsureBrowZerRouterService creates the browzer-router-zt Ziti service with all required policies
// and ensures it's hosted. All operations are idempotent; safe to call on every startup.
// browzerRouterHostPort returns where the access-proxy dials the BrowZer
// path/vhost router: the configured BROWZER_ROUTER_HOST/PORT, else the compose
// defaults (browzer-router:80).
func (s *Service) browzerRouterHostPort() (string, int) {
	host, port := BrowZerRouterHost, BrowZerRouterPort
	if s.config != nil {
		if s.config.BrowZerRouterHost != "" {
			host = s.config.BrowZerRouterHost
		}
		if s.config.BrowZerRouterPort != 0 {
			port = s.config.BrowZerRouterPort
		}
	}
	return host, port
}

func (s *Service) EnsureBrowZerRouterService(ctx context.Context, zm *ZitiManager) {
	if zm == nil {
		return
	}

	routerHost, routerPort := s.browzerRouterHostPort()
	s.logger.Info("Ensuring BrowZer router Ziti service",
		zap.String("service", BrowZerRouterServiceName),
		zap.String("host", routerHost),
		zap.Int("port", routerPort))

	// 1. Create or find the service
	var serviceID string
	err := zm.SetupZitiForRoute(ctx, "", BrowZerRouterServiceName, routerHost, routerPort)
	if err != nil {
		s.logger.Debug("SetupZitiForRoute returned (service may already exist)", zap.Error(err))
	}

	// Look up the service ID (it should exist now, either just created or from a previous run)
	svc, svcErr := zm.GetServiceByName(BrowZerRouterServiceName)
	if svcErr != nil || svc == nil {
		// GetServiceByName iterates ListServices which can be unreliable; try DB fallback
		var dbZitiID string
		if dbErr := zm.GetDB().Pool.QueryRow(ctx,
			//orgscope:ignore startup infra provisioning; the BrowZer router is an install-wide Ziti service identified by its globally-unique name
			"SELECT ziti_id FROM ziti_services WHERE name=$1", BrowZerRouterServiceName).Scan(&dbZitiID); dbErr == nil {
			serviceID = dbZitiID
			s.logger.Info("Found router service ID from DB", zap.String("ziti_id", serviceID))
		} else {
			s.logger.Warn("Could not find browzer-router-zt service ID from API or DB", zap.Error(svcErr))
		}
	} else {
		serviceID = svc.ID
	}

	// 2. Ensure all role attributes are present
	if serviceID != "" {
		attrs, attrErr := zm.GetServiceRoleAttributes(ctx, serviceID)
		if attrErr == nil {
			needPatch := false
			for _, need := range []string{BrowZerRouterServiceName, "browzer-enabled"} {
				found := false
				for _, a := range attrs {
					if a == need {
						found = true
						break
					}
				}
				if !found {
					attrs = append(attrs, need)
					needPatch = true
				}
			}
			if needPatch {
				if patchErr := zm.PatchServiceRoleAttributes(ctx, serviceID, attrs); patchErr != nil {
					s.logger.Error("Failed to patch router service attributes", zap.Error(patchErr))
				} else {
					s.logger.Info("Updated router service role attributes", zap.Strings("attrs", attrs))
				}
			}
		}
	}

	// 3. Ensure bind/dial service policies (idempotent — will get 400 if they exist)
	bindName := fmt.Sprintf("openidx-bind-%s", BrowZerRouterServiceName)
	if _, bErr := zm.CreateServicePolicy(ctx, bindName, "Bind",
		[]string{"#" + BrowZerRouterServiceName}, []string{"#access-proxy-clients"}); bErr != nil {
		s.logger.Debug("Bind policy (may already exist)", zap.Error(bErr))
	}
	dialName := fmt.Sprintf("openidx-dial-%s", BrowZerRouterServiceName)
	if _, dErr := zm.CreateServicePolicy(ctx, dialName, "Dial",
		[]string{"#" + BrowZerRouterServiceName}, []string{"#access-proxy-clients"}); dErr != nil {
		s.logger.Debug("Dial policy (may already exist)", zap.Error(dErr))
	}

	// 4. Ensure service-edge-router policy (allows edge routers to handle this service)
	serpName := fmt.Sprintf("openidx-serp-%s", BrowZerRouterServiceName)
	if serpErr := zm.EnsureServiceEdgeRouterPolicy(ctx, serpName,
		[]string{"#" + BrowZerRouterServiceName}, []string{"#all"}); serpErr != nil {
		s.logger.Debug("Service-edge-router policy (may already exist)", zap.Error(serpErr))
	}

	// 5. Wait for SDK to discover the service, then host it
	s.logger.Info("Waiting for Ziti SDK to discover browzer-router-zt service...")
	time.Sleep(10 * time.Second)

	if hostErr := zm.HostService(BrowZerRouterServiceName, routerHost, routerPort); hostErr != nil {
		s.logger.Error("Failed to host BrowZer router Ziti service", zap.Error(hostErr))
	} else {
		s.logger.Info("BrowZer router Ziti service hosted successfully")
	}
}

// handleQuickCreate creates a proxy route with Ziti and BrowZer enabled in a single API call.
// This eliminates the multi-step process of creating a route, enabling Ziti, and enabling BrowZer separately.
func (s *Service) handleQuickCreate(c *gin.Context) {
	var req struct {
		Name           string   `json:"name" binding:"required"`
		TargetURL      string   `json:"target_url" binding:"required"`
		Domain         string   `json:"domain" binding:"required"`
		PathPrefix     string   `json:"path_prefix"`
		ZitiEnabled    bool     `json:"ziti_enabled"`
		BrowzerEnabled bool     `json:"browzer_enabled"`
		AllowedRoles   []string `json:"allowed_roles"`
		AllowedGroups  []string `json:"allowed_groups"`
		RouteType      string   `json:"route_type"`
		RequireAuth    *bool    `json:"require_auth"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// BrowZer implies Ziti
	if req.BrowzerEnabled {
		req.ZitiEnabled = true
	}

	if req.RouteType == "" {
		req.RouteType = "http"
	}
	requireAuth := true
	if req.RequireAuth != nil {
		requireAuth = *req.RequireAuth
	}

	// Validate path_prefix if set
	if req.PathPrefix != "" && !strings.HasPrefix(req.PathPrefix, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path_prefix must start with /"})
		return
	}

	// Build from_url from domain + optional path prefix
	fromURL := "http://" + req.Domain
	if req.PathPrefix != "" {
		fromURL += req.PathPrefix
	}

	// Create the proxy route
	routeID := uuid.New().String()
	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	groupsJSON, _ := json.Marshal(req.AllowedGroups)

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_routes (id, name, from_url, to_url, require_auth, enabled, priority,
		  route_type, allowed_roles, allowed_groups,
		  idle_timeout, absolute_timeout, max_risk_score,
		  allowed_countries, cors_allowed_origins, custom_headers, policy_ids, posture_check_ids, org_id)
		 VALUES ($1, $2, $3, $4, $5, true, 0,
		         $6, $7, $8,
		         900, 43200, 100,
		         '[]', '[]', '{}', '[]', '[]', $9)`,
		routeID, req.Name, fromURL, req.TargetURL, requireAuth,
		req.RouteType, rolesJSON, groupsJSON, org.ID)
	if err != nil {
		if s.answerRouteHostTaken(c, org.ID, fromURL, err) {
			return
		}
		s.logger.Error("Failed to create route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route"})
		return
	}

	s.logger.Info("Quick-create: route created", zap.String("route_id", routeID), zap.String("name", req.Name))

	// Get user ID from context
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	result := gin.H{
		"id":      routeID,
		"name":    req.Name,
		"domain":  req.Domain,
		"message": "route created",
	}

	// Enable Ziti if requested
	if req.ZitiEnabled && s.featureManager != nil {
		// Parse target URL to get host/port for Ziti
		host, port := parseHostPort(req.TargetURL)
		serviceName := fmt.Sprintf("openidx-%s", req.Name)

		zitiConfig := &FeatureConfig{
			ZitiServiceName: serviceName,
			ZitiHost:        host,
			ZitiPort:        port,
		}

		if err := s.featureManager.EnableFeature(c.Request.Context(), routeID, FeatureZiti, zitiConfig, userID); err != nil {
			s.logger.Error("Quick-create: failed to enable Ziti", zap.Error(err))
			result["ziti_error"] = err.Error()
		} else {
			result["ziti_enabled"] = true
			result["ziti_service_name"] = serviceName
			s.logger.Info("Quick-create: Ziti enabled", zap.String("service", serviceName))
		}
	}

	// Enable BrowZer if requested (Ziti must have succeeded)
	if req.BrowzerEnabled && s.featureManager != nil && result["ziti_error"] == nil {
		if err := s.featureManager.EnableFeature(c.Request.Context(), routeID, FeatureBrowZer, &FeatureConfig{}, userID); err != nil {
			s.logger.Error("Quick-create: failed to enable BrowZer", zap.Error(err))
			result["browzer_error"] = err.Error()
		} else {
			result["browzer_enabled"] = true
			s.logger.Info("Quick-create: BrowZer enabled")
		}

		if req.PathPrefix != "" {
			result["path_prefix"] = req.PathPrefix
			result["note"] = fmt.Sprintf("Path-based BrowZer routing: %s%s → router → backend", req.Domain, req.PathPrefix)
		} else {
			result["note"] = fmt.Sprintf("For Docker Compose: add '%s' as a network alias to the browzer-bootstrapper service", req.Domain)
		}
	}

	s.logAuditEvent(c, "service_quick_created", routeID, "proxy_route", map[string]interface{}{
		"name":            req.Name,
		"domain":          req.Domain,
		"path_prefix":     req.PathPrefix,
		"ziti_enabled":    req.ZitiEnabled,
		"browzer_enabled": req.BrowzerEnabled,
	})

	c.JSON(http.StatusCreated, result)
}

func (s *Service) findRouteByHost(ctx context.Context, host string) (*ProxyRoute, error) {
	// A request that names no host matches no route.
	if strings.TrimSpace(host) == "" {
		return nil, pgx.ErrNoRows
	}
	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	// The route whose host is the request's, exactly: proxy_route_host()
	// normalizes both (migration v211), and the unique index on the enabled
	// routes' hosts makes the answer the one route that holds the host, in
	// whichever organization. It was from_url LIKE '%' || host || '%', highest
	// priority first, so another organization's route containing the host
	// anywhere in its from_url and given a higher priority took the host's
	// traffic.
	// Bypass RLS: route resolution runs before the org is known — the host IS
	// what resolves the tenant.
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore proxy data-plane route resolution; the reverse proxy matches an inbound request to its route by host before any user/org is resolved
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        created_at, updated_at, org_id::text
		 FROM proxy_routes WHERE host = proxy_route_host($1) AND enabled = true
		 LIMIT 1`, host).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.CreatedAt, &r.UpdatedAt, &r.OrgID)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
		s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
		s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
		s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
		s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
		s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
		s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
		s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
	}
	if r.AllowedRoles == nil {
		r.AllowedRoles = []string{}
	}
	if r.AllowedGroups == nil {
		r.AllowedGroups = []string{}
	}
	if r.PolicyIDs == nil {
		r.PolicyIDs = []string{}
	}
	if r.CORSAllowedOrigins == nil {
		r.CORSAllowedOrigins = []string{}
	}
	if r.CustomHeaders == nil {
		r.CustomHeaders = map[string]string{}
	}
	if r.PostureCheckIDs == nil {
		r.PostureCheckIDs = []string{}
	}
	if r.AllowedCountries == nil {
		r.AllowedCountries = []string{}
	}
	return &r, nil
}

func (s *Service) createSession(c *gin.Context, claims map[string]interface{}) (*ProxySession, error) {
	id := uuid.New().String()
	token := generateSessionToken()
	tokenHash := hashToken(token)

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	expiresAt := time.Now().Add(12 * time.Hour)

	// Proxy data-plane login: the session belongs to the route the user signed
	// in on -- the one holding the host whose callback this is -- and to that
	// route's organization. It used to take the organization the tenant
	// resolver chose, which for a proxied host is the default organization, and
	// no route at all: the session was listed and revocable under the wrong
	// organization, and continuous verification, which joins a session to its
	// route to find reverify_interval, never saw one. A callback on a host no
	// route holds (the access service's own) keeps the resolver's organization,
	// with a default-org fallback so the data-plane never fails to mint a
	// session.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(c.Request.Context()); oerr == nil {
		orgID = org.ID
	}
	var routeID *string
	if route, rerr := s.findRouteByHost(c.Request.Context(), s.browserHost(c)); rerr == nil && route != nil && route.OrgID != "" {
		orgID, routeID = route.OrgID, &route.ID
	}

	_, err := s.db.Pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
		//orgscope:ignore proxy data-plane login; the row is written with the organization of the route the callback's host resolves to, which may not be the request's resolved organization
		`INSERT INTO proxy_sessions (id, user_id, session_token, ip_address, user_agent, expires_at, org_id, route_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, userID, tokenHash, c.ClientIP(), c.Request.UserAgent(), expiresAt, orgID, routeID)
	if err != nil {
		return nil, err
	}

	// Store session data in Redis for fast access. host binds the session to
	// the host whose callback set its cookie: getSessionFromRequest refuses it
	// anywhere else. org_id is the organization its roles hold in. The user's
	// OpenIDX access token is not kept: nothing read it back, and a copy in
	// Redis is a credential for OpenIDX's own APIs.
	sessionData, _ := json.Marshal(map[string]interface{}{
		"id":          id,
		"user_id":     userID,
		"email":       email,
		"name":        name,
		"roles":       roles,
		"org_id":      orgID,
		"host":        sessionHost(s.browserHost(c)),
		"expires":     expiresAt.Unix(),
		"last_active": time.Now().Unix(),
	})
	s.redis.Client.Set(c.Request.Context(), "proxy_session:"+tokenHash, sessionData, 12*time.Hour)

	session := &ProxySession{
		ID:           id,
		UserID:       userID,
		SessionToken: token,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Email:        email,
		Name:         name,
		Roles:        roles,
		StartedAt:    time.Now(),
		LastActiveAt: time.Now(),
		ExpiresAt:    expiresAt,
		orgID:        orgID,
	}
	if routeID != nil {
		session.RouteID = *routeID
	}
	return session, nil
}

// sessionOnRoute returns session when it may be used on route: a session signed
// in on one organization's route carries that organization's roles, and is not
// accepted on another organization's route, even on the same host -- a host
// can pass from one organization to another once the first disables its
// route. A bearer session carries its token's own organization binding.
func sessionOnRoute(session *ProxySession, route *ProxyRoute) *ProxySession {
	if session == nil || route == nil || session.orgID == "" || session.orgID == route.OrgID {
		return session
	}
	return nil
}

func (sess *ProxySession) AbsoluteTimeout() int {
	return int(time.Until(sess.ExpiresAt).Seconds())
}

// getSessionFromRequest returns the proxy session the request's cookie names,
// when it is live and was issued for host, the host the browser addressed.
//
// The session cookie is host-only, so a browser only ever sends it to the host
// it was set on, and every proxied host gets a session of its own. The session
// was nonetheless looked up by its token alone, and whoever held a copy of the
// cookie -- an application it was forwarded to, or anyone reading that
// application's logs -- could present it at any other route and be the user
// there. A session is now good on the host it was issued for and refused on
// every other, as is one issued before sessions carried their host.
func (s *Service) getSessionFromRequest(c *gin.Context, host string) *ProxySession {
	cookie, err := c.Cookie(proxySessionCookie)
	if err != nil || cookie == "" {
		return nil
	}

	tokenHash := hashToken(cookie)
	data, err := s.redis.Client.Get(c.Request.Context(), "proxy_session:"+tokenHash).Bytes()
	if err != nil {
		return nil
	}

	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil
	}

	issuedFor, _ := sessionData["host"].(string)
	if issuedFor == "" || issuedFor != sessionHost(host) {
		if issuedFor != "" {
			s.logger.Warn("a proxy session was presented on a host it was not issued for; refusing it",
				logsafe.String("session_id", fmt.Sprint(sessionData["id"])),
				logsafe.String("issued_for", issuedFor), logsafe.String("host", sessionHost(host)))
		}
		return nil
	}

	// Check expiry
	expires, _ := sessionData["expires"].(float64)
	if time.Now().Unix() > int64(expires) {
		return nil
	}
	// The absolute expiry has to survive the read, not just gate it. This
	// function used to consume `expires` for the check above and drop it, while
	// handleSessionInfo reports session.ExpiresAt -- so /access/.auth/session
	// answered every live session with the zero time, and a consumer reading it
	// to decide when to re-authenticate was told the session had already ended.
	expiresAt := time.Unix(int64(expires), 0)

	var roles []string
	if r, ok := sessionData["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	var lastActive time.Time
	if la, ok := sessionData["last_active"].(float64); ok && la > 0 {
		lastActive = time.Unix(int64(la), 0)
	}

	orgID, _ := sessionData["org_id"].(string)
	return &ProxySession{
		ID:           fmt.Sprint(sessionData["id"]),
		UserID:       fmt.Sprint(sessionData["user_id"]),
		Email:        fmt.Sprint(sessionData["email"]),
		Name:         fmt.Sprint(sessionData["name"]),
		Roles:        roles,
		LastActiveAt: lastActive,
		ExpiresAt:    expiresAt,
		orgID:        orgID,
	}
}

// isIdleExpired reports whether a cookie-backed proxy session has been idle
// longer than the route's idle_timeout. Returns false when the route sets no
// idle_timeout (<= 0) or the session carries no last-active stamp (older
// sessions predating this field ride their absolute expiry). Pure + unit-tested.
func isIdleExpired(route *ProxyRoute, session *ProxySession, now time.Time) bool {
	if route == nil || route.IdleTimeout <= 0 || session == nil || session.LastActiveAt.IsZero() {
		return false
	}
	return now.Sub(session.LastActiveAt) > time.Duration(route.IdleTimeout)*time.Second
}

func (s *Service) getSessionFromBearer(c *gin.Context) *ProxySession {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// SECURITY (P0-1): verify the bearer's signature + expiry against the OAuth
	// JWKS before trusting any claim. A forged/unsigned token must yield no
	// session — the request then falls through to unauthenticated handling,
	// exactly as a missing cookie does. Never build a ProxySession from
	// unverified claims. If JWKS is unconfigured, verification fails → no
	// session (fail-closed: bearer auth is unavailable, never forgeable).
	//
	// The token must also name the organization it was minted in, which
	// VerifyBearerToken enforces. It is not compared with the organization
	// the tenant resolver chose for this request, as the API validators
	// compare it: a proxied request is resolved by the route its host
	// matched (findRouteByHost reads across organizations), not by
	// X-Org-Slug, so the resolver's answer says nothing about which tenant's
	// application is being reached.
	claims, err := middleware.VerifyBearerToken(s.oauthJWKSURL, token)
	if err != nil {
		s.logger.Debug("bearer token rejected", zap.Error(err))
		return nil
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	return &ProxySession{
		UserID: userID,
		Email:  email,
		Name:   name,
		Roles:  roles,
		bearer: authHeader,
	}
}

func (s *Service) updateSessionActivity(c *gin.Context, session *ProxySession) {
	ctx := c.Request.Context()

	// Throttle: the blob's last_active only needs freshness within a fraction of
	// idle_timeout, so skip the per-request heartbeat if it was stamped within the
	// last 30s. Keeps the hot path from doing an extra DB write + three Redis ops
	// on every proxied request; the idle window still slides with <=30s lag.
	// (session.LastActiveAt was just read from the blob by getSessionFromRequest;
	// bearer sessions have it zero, so they skip the throttle and no-op below on
	// the empty id / absent cookie.)
	if !session.LastActiveAt.IsZero() && time.Since(session.LastActiveAt) < 30*time.Second {
		return
	}

	//silentwrite:ok the idle window is enforced from the Redis blob refreshed immediately below, not from this column; the only reader of proxy_sessions.last_active_at is the admin sessions list's "Last active" column (service.go:1641), which goes stale by one heartbeat -- at most 30 seconds -- and corrects itself on the next proxied request
	s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore proxy data-plane activity heartbeat; updates the active session by its primary key on every proxied request
		"UPDATE proxy_sessions SET last_active_at=NOW() WHERE id=$1", session.ID)

	// Slide the idle window: refresh the Redis blob's last_active, preserving the
	// remaining absolute TTL so absolute expiry (the "expires" field) still applies
	// independently. Best-effort — a failure just means the next request re-reads a
	// slightly stale last_active.
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err != nil || cookie == "" {
		return
	}
	key := "proxy_session:" + hashToken(cookie)
	data, err := s.redis.Client.Get(ctx, key).Bytes()
	if err != nil {
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return
	}
	m["last_active"] = time.Now().Unix()
	ttl := s.redis.Client.TTL(ctx, key).Val()
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if nb, mErr := json.Marshal(m); mErr == nil {
		// SetXX, not Set: a revocation may have deleted the blob between the
		// read above and this write, and a plain SET would bring the session
		// back for up to twelve more hours. SetXX only updates a blob that
		// still exists.
		s.redis.Client.SetXX(ctx, key, nb, ttl)
	}
}

// revokeIdleProxySession tears down an idle-expired cookie session: it deletes
// the Redis blob and marks the proxy_sessions row revoked (both best-effort).
func (s *Service) revokeIdleProxySession(c *gin.Context, session *ProxySession) {
	if cookie, err := c.Cookie("_openidx_proxy_session"); err == nil && cookie != "" {
		s.redis.Client.Del(c.Request.Context(), "proxy_session:"+hashToken(cookie))
	}
	if session != nil && session.ID != "" {
		if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
			//orgscope:ignore data-plane revoke of the idle session by its primary key
			"UPDATE proxy_sessions SET revoked=true WHERE id=$1", session.ID); err != nil {
			s.logger.Error("idle-timeout revocation could not mark the session revoked",
				logsafe.String("session_id", session.ID), zap.Error(err))
		}
	}
}

func (s *Service) evaluatePolicies(c *gin.Context, route *ProxyRoute, session *ProxySession) (bool, error) {
	for _, policyID := range route.PolicyIDs {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"user_id":            session.UserID,
			"roles":              session.Roles,
			"ip":                 c.ClientIP(),
			"time":               time.Now().Format(time.RFC3339),
			"path":               c.Request.URL.Path,
			"method":             c.Request.Method,
			"route":              route.Name,
			"risk_score":         session.RiskScore,
			"device_trusted":     session.DeviceTrusted,
			"auth_methods":       session.AuthMethods,
			"location":           session.Location,
			"device_fingerprint": session.DeviceFingerprint,
		})

		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost,
			fmt.Sprintf("%s/api/v1/governance/policies/%s/evaluate", s.governanceURL, policyID),
			bytes.NewReader(reqBody))
		if err != nil {
			return false, fmt.Errorf("failed to build evaluate request for policy %s: %w", policyID, err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Service-to-service auth: governance requires a user JWT on /evaluate;
		// the proxy has no user JWT to forward, so it presents the shared
		// internal-service secret instead. Without this the call is 401'd and
		// the policy check fails closed (denies all traffic to the route).
		if s.config.InternalServiceToken != "" {
			req.Header.Set("X-Internal-Token", s.config.InternalServiceToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate policy %s: %w", policyID, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// A non-200 (e.g. 401 from a missing/mismatched internal token) is a
		// misconfiguration, not a policy decision. Surface it as an error so it
		// fails closed *visibly* in the logs rather than masquerading as a deny.
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("policy %s evaluate returned %d: %s", policyID, resp.StatusCode, string(body))
		}

		var result struct {
			Allowed        bool `json:"allowed"`
			StepUpRequired bool `json:"step_up_required"`
		}
		json.Unmarshal(body, &result)

		if !result.Allowed {
			if result.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			return false, nil
		}
	}
	return true, nil
}

// exchangeCode exchanges an authorization code for tokens
func (s *Service) exchangeCode(ctx context.Context, code, verifier, redirectURI string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"access-proxy"},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(s.oauthInternalURL+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// parseTokenClaims decodes JWT claims WITHOUT verifying the signature or expiry.
//
// SECURITY: only call this on a token obtained over a trusted back channel — i.e.
// one just returned by a server-to-server code exchange against our own OAuth
// token endpoint (handleCallback) or an external IdP's token endpoint
// (multi_idp), per OIDC Core §3.1.3.7. NEVER call it on a client-supplied bearer:
// that is the P0-1 unsigned-JWT auth bypass. The bearer path
// (getSessionFromBearer) uses middleware.VerifyBearerToken, which verifies the
// signature + expiry against the OAuth JWKS — use that for any client token.
func (s *Service) parseTokenClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return claims, nil
}

func (s *Service) logAuditEvent(c *gin.Context, action, targetID, targetType string, details map[string]interface{}) {
	if s.auditURL == "" {
		return
	}

	event := map[string]interface{}{
		"event_type":  "authorization",
		"category":    "access_proxy",
		"action":      action,
		"outcome":     "success",
		"target_id":   targetID,
		"target_type": targetType,
		"actor_ip":    c.ClientIP(),
		"details":     details,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	// WHO. Every event this file posts left actor_id empty, so the audit
	// trail's actor column — the one the console filters on and an auditor
	// reads first — was blank for every credential reveal, every recording
	// download and every proxy decision. Some handlers put the id into
	// `details.user_id` on their way past, which is a JSON blob, not a column:
	// "who revealed this credential" was not a question the trail could answer.
	if userID := c.GetString("user_id"); userID != "" {
		event["actor_id"] = userID
		event["actor_type"] = "user"
	}

	if action == "proxy_access_denied" {
		event["outcome"] = "failure"
	}

	// The tenant the action happened in, carried to the audit service.
	//
	// Without it every event this file posts -- every credential reveal, every
	// recording download, every proxy allow and deny -- was filed under the
	// DEFAULT organisation. The ingest endpoint is server-to-server and carries
	// no JWT, and cmd/audit-service mounts TenantResolver globally, so steps 2
	// and 3 of its resolution order cannot fire (the middleware's own comment
	// says so) and the request lands on step 4, the default-org fallback. On a
	// multi-tenant install that means the most sensitive reads in the product
	// were invisible in the audit log of the tenant they belonged to and
	// visible in somebody else's.
	//
	// X-Org-Slug is step 1 of that order and exists for exactly this: the
	// resolver LOOKS THE SLUG UP, so an unknown one is a 400 rather than a free
	// write into an arbitrary tenant. Nothing is trusted that was not already.
	orgSlug := ""
	if org, err := orgctx.From(c.Request.Context()); err == nil {
		orgSlug = org.Slug
	}

	body, _ := json.Marshal(event)
	go func() {
		req, err := http.NewRequest(http.MethodPost, s.auditURL+"/api/v1/audit/events",
			bytes.NewReader(body))
		if err != nil {
			s.logger.Warn("Failed to build audit event request", zap.Error(err))
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if orgSlug != "" {
			req.Header.Set("X-Org-Slug", orgSlug)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.logger.Warn("Failed to log audit event", zap.Error(err))
			return
		}
		defer resp.Body.Close()
		// The status was thrown away. handleLogEvent answers 400 for a body it
		// refuses and 500 when the write fails, and both were discarded here --
		// so an audit event the trail rejected disappeared with nothing logged
		// anywhere. A dropped audit row is the one loss that must never be
		// silent.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			s.logger.Warn("Audit event was refused by the audit service",
				zap.Int("status", resp.StatusCode),
				logsafe.String("action", action),
				logsafe.String("org_slug", orgSlug))
		}
	}()
}

// Utility functions

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		roleSet[r] = true
	}
	for _, r := range requiredRoles {
		if roleSet[r] {
			return true
		}
	}
	return false
}

// proxyOwnedHeaders are the headers these proxies assert *about* the caller.
//
// The standard library deletes Forwarded and the X-Forwarded-{For,Host,Proto}
// trio from the outbound request on the Rewrite path, but it knows nothing
// about these, and an upstream cannot tell a header the proxy vouched for
// from one the caller typed. So every one of them is deleted before the
// verified values are written — including on the paths that write none, which
// is where the hole was: a route with require_auth false, or an overlay
// connection whose Ziti identity did not resolve, forwarded the caller's own
// X-Forwarded-User straight through to an upstream that has no reason to
// doubt it.
//
// They are the identity headers (proxyIdentityHeaders, and the
// X-Auth-Request-* family deleteProxyOwnedHeaders removes by prefix) and
// X-Real-IP.
var proxyOwnedHeaders = append(append([]string{}, proxyIdentityHeaders...), "X-Real-IP")

// proxyRewrite builds the ReverseProxy.Rewrite hook for one proxied request.
//
// It replaces a Director, and the change is not only that Director is
// deprecated as of Go 1.26. Under Director the standard library hands the
// upstream the CLIENT'S OWN forwarding headers: it never deletes Forwarded,
// X-Forwarded-Host or X-Forwarded-Proto, and it folds the inbound
// X-Forwarded-For into the outbound one. A request arriving at this ZTNA data
// path with
//
//	X-Forwarded-For: 9.9.9.9
//	X-Forwarded-Host: evil.example.com
//	Forwarded: for=9.9.9.9
//
// reached the upstream with X-Forwarded-Host and Forwarded intact, and with
// X-Forwarded-For reading "<resolved client>, <peer>" — the same address
// twice whenever there is no front proxy. An upstream that generates absolute
// URLs from X-Forwarded-Host, or reads the leftmost X-Forwarded-For entry as
// "the real client", was being fed attacker-controlled provenance by a proxy
// whose entire job is to be the thing the upstream can trust.
//
// Rewrite deletes Forwarded and all three X-Forwarded-* headers before this
// func runs, so every value set below is one this proxy determined itself.
// ProxyRequest.SetXForwarded is deliberately NOT used: it takes the raw peer
// out of In.RemoteAddr, whereas clientIP is gin's resolved address, which
// honours the deployment's trusted-proxy list — the whole point of
// configuring one.
//
// It takes everything it needs as arguments so the forwarding contract is
// testable without a Service, a database or a gin engine. The headers an
// upstream receives from this path are a security boundary, and a boundary
// that can only be exercised end to end does not get exercised.
//
// session may be nil, for a route that does not require auth.
func proxyRewrite(target *url.URL, route *ProxyRoute, session *ProxySession, clientIP string) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = target.Scheme
		pr.Out.URL.Host = target.Host
		pr.Out.URL.Path = singleJoiningSlash(target.Path, pr.In.URL.Path)
		// RawQuery is left exactly as the standard library prepared it. On the
		// Rewrite path it has already been stripped of unparsable parameters,
		// which is the request-smuggling guard the Director path never applied;
		// re-assigning the inbound query here would throw that away.

		if route.PreserveHost {
			pr.Out.Host = pr.In.Host
		} else {
			pr.Out.Host = target.Host
		}

		// Identity, from the verified session and nowhere else. The caller's
		// own copies go first, so an unauthenticated route cannot forward one.
		deleteProxyOwnedHeaders(pr.Out.Header)

		// The proxy's own credentials stay with the proxy. Its session cookie
		// authenticates the browser to the proxy on this host; forwarded, it
		// let the application, or anyone reading its logs, replay the user's
		// session. A bearer the proxy authenticated this request with is an
		// OpenIDX access token that may call OpenIDX's own APIs. Every other
		// cookie, and an Authorization header the proxy did not consume, is
		// the application's own and goes through untouched.
		stripProxySessionCookie(pr.Out.Header)
		if session != nil && session.bearer != "" {
			removeHeaderValue(pr.Out.Header, "Authorization", session.bearer)
		}

		if session != nil {
			pr.Out.Header.Set("X-Forwarded-User", session.UserID)
			pr.Out.Header.Set("X-Forwarded-Email", session.Email)
			pr.Out.Header.Set("X-Forwarded-Name", session.Name)
			pr.Out.Header.Set("X-Forwarded-Roles", strings.Join(session.Roles, ","))
		}

		// Provenance, all of it this proxy's own observation of the request.
		pr.Out.Header.Set("X-Forwarded-For", clientIP)
		pr.Out.Header.Set("X-Real-IP", clientIP)
		pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		// The old code hardcoded "http" here, which was wrong for a direct-TLS
		// deployment. Behind a TLS-terminating load balancer In.TLS is nil and
		// the answer is still "http", exactly as before.
		if pr.In.TLS != nil {
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		} else {
			pr.Out.Header.Set("X-Forwarded-Proto", "http")
		}

		// Operator-configured headers last, so a route can deliberately
		// override the provenance above. Not the identity: a route that could
		// set X-Forwarded-User would name every one of its users as somebody
		// else, so those are the session's alone (the route API refuses them,
		// and one stored before it did is skipped here).
		for k, v := range route.CustomHeaders {
			if isProxyIdentityHeader(k) {
				continue
			}
			pr.Out.Header.Set(k, v)
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// abacGateAllows applies the tenant's attribute-based policies to a proxied
// request. Returns true when the request may proceed; false means a 403 has
// already been written, matching the assignment gate's contract above it.
func (s *Service) abacGateAllows(c *gin.Context, route *ProxyRoute, userID, orgID, appID string) bool {
	if s.config == nil {
		return true
	}
	mode := abac.ParseMode(s.config.ABACEnforce)
	if mode == abac.ModeOff || orgID == "" {
		return true
	}
	ctx := c.Request.Context()

	attrs, err := abac.SubjectAttributes(ctx, s.db, userID, orgID)
	if err != nil {
		s.logger.Warn("abac gate: subject attributes unavailable",
			logsafe.String("user_id", userID), zap.Error(err))
	}

	allow, wouldDeny, res := abac.Gate(ctx, s.db, orgID, mode, abac.EvaluationRequest{
		UserAttributes: attrs,
		ResourceType:   abac.ResourceTypeApplication,
		ResourceID:     appID,
	})
	if wouldDeny {
		s.recordABACDecision(ctx, route, userID, appID, c.ClientIP(), res.PolicyID, res.Reason, !allow)
	}
	if !allow {
		s.logger.Info("abac gate denied proxy request",
			logsafe.String("user_id", userID),
			logsafe.String("application_id", appID),
			logsafe.String("policy_id", res.PolicyID))
		c.JSON(http.StatusForbidden, gin.H{"error": "denied by policy", "reason": res.Reason})
		return false
	}
	return true
}

// recordABACDecision is recordAssignmentDecision's counterpart for the ABAC
// gate: same table, same canonical details keys, written on BOTH the observe
// and enforce branches so enforcement is never quieter than report mode.
func (s *Service) recordABACDecision(ctx context.Context, route *ProxyRoute, userID, appID, actorIP, policyID, policyReason string, enforced bool) {
	eventType := appaccess.ABACDecisionEventType(enforced)

	var routeID, routeName string
	if route != nil {
		routeID, routeName = route.ID, route.Name
	}
	details := appaccess.ABACDecisionDetails(appaccess.EnforcementPointProxy, userID, appID, policyID, policyReason, enforced,
		map[string]interface{}{"route": routeName})

	if s.auditService == nil {
		s.logger.Warn("abac decision not recorded: unified audit service unavailable",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("application_id", appID),
			zap.Bool("enforced", enforced))
		return
	}
	if err := s.auditService.RecordEvent(ctx, appaccess.SourceProxy, eventType,
		routeID, userID, actorIP, details); err != nil {
		s.logger.Warn("abac decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("application_id", appID),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}
