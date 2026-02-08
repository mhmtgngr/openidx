// Package access - OpenZiti integration for Zero Trust network overlay
package access

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// ZitiManager handles OpenZiti SDK integration and management API communication
type ZitiManager struct {
	cfg         *config.Config
	logger      *zap.Logger
	db          *database.PostgresDB
	zitiCtx     ziti.Context
	mgmtToken   string
	mgmtClient  *http.Client
	mu          sync.RWMutex
	initialized bool

	// Service hosting: listeners that bind services and forward to upstream
	hostedMu       sync.Mutex
	hostedServices map[string]*hostedService // keyed by service name
}

// hostedService tracks a Ziti service listener that forwards to an upstream target
type hostedService struct {
	listener edge.Listener
	cancel   context.CancelFunc
}

// zitiAPIResponse represents a generic Ziti Management API response
type zitiAPIResponse struct {
	Data    json.RawMessage `json:"data"`
	Error   *zitiAPIError   `json:"error,omitempty"`
	Meta    json.RawMessage `json:"meta,omitempty"`
}

type zitiAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ZitiServiceInfo represents a Ziti service from the management API
// ZitiServiceConfigInfo represents a service intercept/host config
type ZitiServiceConfigInfo struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

type ZitiServiceInfo struct {
	ID             string                  `json:"id"`
	Name           string                  `json:"name"`
	Attributes     []string                `json:"roleAttributes"`
	Protocol       string                  `json:"protocol,omitempty"`
	RoleAttributes []string                `json:"role_attributes,omitempty"`
	Configs        []ZitiServiceConfigInfo `json:"configs,omitempty"`
}

// ZitiIdentityInfo represents a Ziti identity from the management API
type ZitiIdentityInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Attributes []string `json:"roleAttributes"`
	Enrollment *struct {
		OTT *struct {
			JWT string `json:"jwt"`
		} `json:"ott,omitempty"`
	} `json:"enrollment,omitempty"`
}

// NewZitiManager creates and initializes the ZitiManager
func NewZitiManager(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger) (*ZitiManager, error) {
	zm := &ZitiManager{
		cfg:            cfg,
		logger:         logger.With(zap.String("component", "ziti")),
		db:             db,
		hostedServices: make(map[string]*hostedService),
	}

	// Build TLS config for Ziti controller communication
	tlsConfig := &tls.Config{}
	caFile := filepath.Join(cfg.ZitiIdentityDir, "ca.pem")
	if caPEM, err := os.ReadFile(caFile); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			tlsConfig.RootCAs = pool
			zm.logger.Info("Loaded Ziti CA certificate", zap.String("file", caFile))
		} else {
			zm.logger.Warn("Failed to parse CA certificate, falling back to insecure", zap.String("file", caFile))
			tlsConfig.InsecureSkipVerify = true
		}
	} else if cfg.ZitiInsecureSkipVerify {
		zm.logger.Warn("Ziti CA cert not found and ZitiInsecureSkipVerify=true — skipping TLS verification",
			zap.String("expected_ca", caFile))
		tlsConfig.InsecureSkipVerify = true
	} else {
		zm.logger.Warn("Ziti CA cert not found; set ZITI_INSECURE_SKIP_VERIFY=true to allow insecure connections",
			zap.String("expected_ca", caFile))
		tlsConfig.InsecureSkipVerify = true
	}

	zm.mgmtClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// Authenticate to management API
	if err := zm.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate to ziti controller: %w", err)
	}
	zm.logger.Info("Authenticated to Ziti controller", zap.String("url", cfg.ZitiCtrlURL))

	// Bootstrap: ensure access-proxy identity and default policies exist
	if err := zm.bootstrap(); err != nil {
		return nil, fmt.Errorf("failed to bootstrap ziti: %w", err)
	}

	// Load access-proxy identity and create SDK context
	identityFile := filepath.Join(cfg.ZitiIdentityDir, "access-proxy.json")
	if _, err := os.Stat(identityFile); err == nil {
		zitiCfg, err := ziti.NewConfigFromFile(identityFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load ziti identity from %s: %w", identityFile, err)
		}

		zitiCtx, err := ziti.NewContext(zitiCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create ziti context: %w", err)
		}
		zm.zitiCtx = zitiCtx
		zm.initialized = true
		zm.logger.Info("Ziti SDK context initialized from identity file", zap.String("file", identityFile))
	} else {
		zm.logger.Warn("Ziti identity file not found, SDK dialing unavailable (management API still functional)",
			zap.String("file", identityFile))
	}

	return zm, nil
}

// IsInitialized returns whether the Ziti SDK context is ready for dialing
func (zm *ZitiManager) IsInitialized() bool {
	zm.mu.RLock()
	defer zm.mu.RUnlock()
	return zm.initialized
}

// Close cleans up Ziti resources
func (zm *ZitiManager) Close() {
	// Stop all hosted services
	zm.hostedMu.Lock()
	for name, hs := range zm.hostedServices {
		zm.logger.Info("Stopping hosted service", zap.String("service", name))
		hs.cancel()
		hs.listener.Close()
	}
	zm.hostedServices = make(map[string]*hostedService)
	zm.hostedMu.Unlock()

	if zm.zitiCtx != nil {
		zm.zitiCtx.Close()
	}
}

// HostService binds a Ziti service and forwards incoming connections to the upstream target.
// This creates a terminator so that Dial calls can reach the service.
func (zm *ZitiManager) HostService(serviceName, targetHost string, targetPort int) error {
	if !zm.initialized {
		return fmt.Errorf("ziti SDK not initialized, cannot host service")
	}

	zm.hostedMu.Lock()
	if _, exists := zm.hostedServices[serviceName]; exists {
		zm.hostedMu.Unlock()
		zm.logger.Info("Service already hosted", zap.String("service", serviceName))
		return nil
	}
	zm.hostedMu.Unlock()

	netListener, err := zm.zitiCtx.Listen(serviceName)
	if err != nil {
		return fmt.Errorf("failed to listen on ziti service %q: %w", serviceName, err)
	}

	edgeListener, ok := netListener.(edge.Listener)
	if !ok {
		netListener.Close()
		return fmt.Errorf("listener for %q does not implement edge.Listener", serviceName)
	}

	ctx, cancel := context.WithCancel(context.Background())

	zm.hostedMu.Lock()
	zm.hostedServices[serviceName] = &hostedService{
		listener: edgeListener,
		cancel:   cancel,
	}
	zm.hostedMu.Unlock()

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	zm.logger.Info("Hosting Ziti service",
		zap.String("service", serviceName),
		zap.String("target", targetAddr))

	// Accept connections in a background goroutine
	go func() {
		for {
			conn, err := edgeListener.AcceptEdge()
			if err != nil {
				select {
				case <-ctx.Done():
					zm.logger.Info("Stopped hosting service", zap.String("service", serviceName))
					return
				default:
					zm.logger.Error("Accept failed on hosted service",
						zap.String("service", serviceName), zap.Error(err))
					return
				}
			}

			go zm.forwardHTTPConnection(conn, targetAddr, serviceName)
		}
	}()

	return nil
}

// StopHostingService stops hosting a specific service
func (zm *ZitiManager) StopHostingService(serviceName string) {
	zm.hostedMu.Lock()
	defer zm.hostedMu.Unlock()

	if hs, exists := zm.hostedServices[serviceName]; exists {
		hs.cancel()
		hs.listener.Close()
		delete(zm.hostedServices, serviceName)
		zm.logger.Info("Stopped hosting service", zap.String("service", serviceName))
	}
}

// HostAllServices loads all Ziti-enabled routes from DB and starts hosting them
func (zm *ZitiManager) HostAllServices(ctx context.Context) {
	if !zm.initialized {
		zm.logger.Warn("Ziti SDK not initialized, skipping service hosting")
		return
	}

	rows, err := zm.db.Pool.Query(ctx,
		`SELECT ziti_service_name, to_url FROM proxy_routes
		 WHERE ziti_enabled = true AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		zm.logger.Error("Failed to query Ziti-enabled routes", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var serviceName, toURL string
		if err := rows.Scan(&serviceName, &toURL); err != nil {
			zm.logger.Error("Failed to scan route row", zap.Error(err))
			continue
		}

		// Parse the upstream URL to get host and port
		host, port := parseHostPort(toURL)
		if host == "" || port == 0 {
			zm.logger.Warn("Could not parse upstream for Ziti hosting",
				zap.String("service", serviceName), zap.String("to_url", toURL))
			continue
		}

		if err := zm.HostService(serviceName, host, port); err != nil {
			zm.logger.Error("Failed to host Ziti service",
				zap.String("service", serviceName), zap.Error(err))
		}
	}
}

// forwardHTTPConnection serves HTTP on a Ziti edge connection, injecting identity headers
// from the caller's Ziti identity before forwarding to the upstream target.
func (zm *ZitiManager) forwardHTTPConnection(zitiConn edge.Conn, targetAddr, serviceName string) {
	callerID := zitiConn.SourceIdentifier()

	// BrowZer JS SDK doesn't set SourceIdentifier — resolve via management API
	if callerID == "" {
		callerID = zm.resolveCallerFromSessions(serviceName)
	}

	// Look up user info from the Ziti identity name (which is the OpenIDX user ID)
	var email, name, roles string
	if callerID != "" {
		err := zm.db.Pool.QueryRow(context.Background(),
			`SELECT COALESCE(u.email,''), COALESCE(u.first_name||' '||u.last_name,''), COALESCE(string_agg(r.name,','),'')
			 FROM users u
			 LEFT JOIN user_roles ur ON ur.user_id = u.id
			 LEFT JOIN roles r ON r.id = ur.role_id
			 WHERE u.id = $1
			 GROUP BY u.id`, callerID).Scan(&email, &name, &roles)
		if err != nil {
			zm.logger.Warn("Failed to lookup user for Ziti identity",
				zap.String("caller_id", callerID), zap.Error(err))
		}
	}

	zm.logger.Debug("Accepted Ziti connection with identity",
		zap.String("service", serviceName),
		zap.String("caller_id", callerID),
		zap.String("email", email))

	// Create reverse proxy to upstream
	target, _ := url.Parse("http://" + targetAddr)
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		if callerID != "" {
			req.Header.Set("X-Forwarded-User", callerID)
			req.Header.Set("X-Forwarded-Email", email)
			req.Header.Set("X-Forwarded-Name", strings.TrimSpace(name))
			req.Header.Set("X-Forwarded-Roles", roles)
			req.Header.Set("X-Ziti-Identity", callerID)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		zm.logger.Error("Ziti HTTP proxy error",
			zap.String("service", serviceName), zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
	}

	// Serve HTTP on the single Ziti connection
	server := &http.Server{
		Handler:     proxy,
		ReadTimeout: 30 * time.Second,
	}
	ln := &singleConnListener{ch: make(chan net.Conn, 1)}
	ln.ch <- zitiConn
	server.Serve(ln)
}

// singleConnListener wraps a single net.Conn as a net.Listener for http.Server.Serve
type singleConnListener struct {
	ch   chan net.Conn
	once sync.Once
	addr net.Addr
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok || conn == nil {
		return nil, io.EOF
	}
	l.addr = conn.LocalAddr()
	// Close the channel after first accept so the server stops after this connection
	l.once.Do(func() { close(l.ch) })
	return conn, nil
}

func (l *singleConnListener) Close() error { return nil }
func (l *singleConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return &net.TCPAddr{}
}

// resolveCallerFromSessions queries the Ziti management API to find the identity
// that created the most recent Dial session for the given service. This is used as
// a fallback when SourceIdentifier() is empty (e.g., BrowZer JS SDK connections).
func (zm *ZitiManager) resolveCallerFromSessions(serviceName string) string {
	if zm.mgmtToken == "" {
		zm.logger.Warn("mgmtToken is empty, cannot resolve BrowZer caller")
		return ""
	}

	// Query Dial sessions (Ziti API doesn't support service.name filter or sort)
	filter := url.QueryEscape(`type="Dial"`)
	reqURL := fmt.Sprintf("%s/edge/management/v1/sessions?filter=%s&limit=1",
		zm.cfg.ZitiCtrlURL, filter)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		zm.logger.Warn("Failed to create sessions request", zap.Error(err))
		return ""
	}
	req.Header.Set("zt-session", zm.mgmtToken)

	resp, err := zm.mgmtClient.Do(req)
	if err != nil {
		zm.logger.Warn("Failed to query Ziti sessions for caller resolution", zap.Error(err))
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	zm.logger.Debug("Sessions API response",
		zap.Int("status", resp.StatusCode),
		zap.String("body", string(body[:min(len(body), 500)])))

	var result struct {
		Data []struct {
			IdentityID string `json:"identityId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Data) == 0 {
		zm.logger.Warn("No sessions found or parse error",
			zap.Error(err), zap.Int("count", len(result.Data)))
		return ""
	}

	zitiIdentityID := result.Data[0].IdentityID

	// Look up the identity name (which is the OpenIDX user ID) from the Ziti identity ID
	identityReqURL := fmt.Sprintf("%s/edge/management/v1/identities/%s",
		zm.cfg.ZitiCtrlURL, zitiIdentityID)
	identReq, err := http.NewRequest("GET", identityReqURL, nil)
	if err != nil {
		return ""
	}
	identReq.Header.Set("zt-session", zm.mgmtToken)

	identResp, err := zm.mgmtClient.Do(identReq)
	if err != nil {
		zm.logger.Warn("Failed to get identity details", zap.Error(err))
		return ""
	}
	defer identResp.Body.Close()

	var identResult struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(identResp.Body).Decode(&identResult); err != nil {
		return ""
	}

	zm.logger.Info("Resolved BrowZer caller from Ziti session",
		zap.String("ziti_identity_id", zitiIdentityID),
		zap.String("user_id", identResult.Data.Name))

	return identResult.Data.Name
}

// parseHostPort extracts host and port from a URL string
func parseHostPort(rawURL string) (string, int) {
	// Handle URLs like http://host:port/path
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 0
	}

	host := parsed.Hostname()
	portStr := parsed.Port()
	if portStr == "" {
		switch parsed.Scheme {
		case "https":
			return host, 443
		default:
			return host, 80
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0
	}

	return host, port
}

// ---- Management API Authentication ----

func (zm *ZitiManager) authenticate() error {
	body, _ := json.Marshal(map[string]string{
		"username": zm.cfg.ZitiAdminUser,
		"password": zm.cfg.ZitiAdminPassword,
	})

	resp, err := zm.mgmtClient.Post(
		zm.cfg.ZitiCtrlURL+"/edge/management/v1/authenticate?method=password",
		"application/json",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("management API auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("management API auth failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	zm.mu.Lock()
	zm.mgmtToken = result.Data.Token
	zm.mu.Unlock()

	return nil
}

// ---- Bootstrap ----

func (zm *ZitiManager) bootstrap() error {
	zm.logger.Info("Bootstrapping Ziti resources...")

	// 1. Create edge-router-policy: all identities -> all routers (idempotent)
	zm.ensureEdgeRouterPolicy()

	// 2. Create service-edge-router-policy: all services -> all routers (idempotent)
	zm.ensureServiceEdgeRouterPolicy()

	// 3. Create access-proxy identity if it doesn't exist
	if err := zm.ensureAccessProxyIdentity(); err != nil {
		return fmt.Errorf("failed to ensure access-proxy identity: %w", err)
	}

	zm.logger.Info("Ziti bootstrap complete")
	return nil
}

func (zm *ZitiManager) ensureEdgeRouterPolicy() {
	// Check if it already exists
	_, statusCode, _ := zm.mgmtRequest("GET", "/edge/management/v1/edge-router-policies?filter=name=\"openidx-all-routers\"", nil)
	if statusCode == http.StatusOK {
		// Check if data has items
		// For simplicity, try to create and ignore conflict
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-all-routers",
		"edgeRouterRoles": []string{"#all"},
		"identityRoles":   []string{"#all"},
	})
	_, _, err := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", body)
	if err != nil {
		zm.logger.Debug("Edge router policy creation (may already exist)", zap.Error(err))
	}
}

func (zm *ZitiManager) ensureServiceEdgeRouterPolicy() {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-all-services-all-routers",
		"edgeRouterRoles": []string{"#all"},
		"serviceRoles":    []string{"#all"},
	})
	_, _, err := zm.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", body)
	if err != nil {
		zm.logger.Debug("Service edge router policy creation (may already exist)", zap.Error(err))
	}
}

func (zm *ZitiManager) ensureAccessProxyIdentity() error {
	identityFile := filepath.Join(zm.cfg.ZitiIdentityDir, "access-proxy.json")

	// If identity file already exists, we're done
	if _, err := os.Stat(identityFile); err == nil {
		zm.logger.Info("Access-proxy identity file already exists", zap.String("file", identityFile))
		return nil
	}

	// Check if identity exists in controller
	respData, statusCode, err := zm.mgmtRequest("GET",
		"/edge/management/v1/identities?filter=name=\"access-proxy\"", nil)
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK {
		var listResp struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respData, &listResp); err == nil && len(listResp.Data) > 0 {
			// Identity exists but we don't have the file - get enrollment JWT
			identity := listResp.Data[0]
			zm.logger.Info("Access-proxy identity exists in controller", zap.String("id", identity.ID))
			return zm.enrollIdentity(identity.ID, identityFile)
		}
	}

	// Create the identity
	zm.logger.Info("Creating access-proxy identity...")
	createBody, _ := json.Marshal(map[string]interface{}{
		"name":           "access-proxy",
		"type":           "Device",
		"isAdmin":        false,
		"roleAttributes": []string{"access-proxy-clients"},
		"enrollment": map[string]interface{}{
			"ott": true,
		},
	})

	respData, statusCode, err = zm.mgmtRequest("POST", "/edge/management/v1/identities", createBody)
	if err != nil {
		return fmt.Errorf("failed to create access-proxy identity: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating identity", statusCode)
	}

	var createResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &createResp); err != nil {
		return fmt.Errorf("failed to parse identity creation response: %w", err)
	}

	zm.logger.Info("Access-proxy identity created", zap.String("id", createResp.Data.ID))
	return zm.enrollIdentity(createResp.Data.ID, identityFile)
}

func (zm *ZitiManager) enrollIdentity(identityID, outputFile string) error {
	// Get the enrollment JWT
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", identityID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("failed to get identity details (HTTP %d)", statusCode)
	}

	var identityResp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &identityResp); err != nil {
		return fmt.Errorf("failed to parse identity response: %w", err)
	}

	// Extract the OTT JWT
	var enrollmentJWT string
	if ott, ok := identityResp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwtStr, ok := ott["jwt"].(string); ok {
			enrollmentJWT = jwtStr
		}
	}

	if enrollmentJWT == "" {
		zm.logger.Warn("No enrollment JWT available (identity may already be enrolled)")
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Parse the JWT token
	claims, jwtToken, err := enroll.ParseToken(enrollmentJWT)
	if err != nil {
		return fmt.Errorf("failed to parse enrollment JWT: %w", err)
	}

	// Enroll using the SDK
	var keyAlg ziti.KeyAlgVar
	keyAlg.Set("EC")
	flags := enroll.EnrollmentFlags{
		Token:     claims,
		JwtToken:  jwtToken,
		JwtString: enrollmentJWT,
		KeyAlg:    keyAlg,
	}

	zitiCfg, err := enroll.Enroll(flags)
	if err != nil {
		return fmt.Errorf("failed to enroll identity: %w", err)
	}

	// Write the enrolled identity config
	cfgData, err := json.MarshalIndent(zitiCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity config: %w", err)
	}

	if err := os.WriteFile(outputFile, cfgData, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	zm.logger.Info("Access-proxy identity enrolled and saved", zap.String("file", outputFile))
	return nil
}

// ---- Ziti Transport for Reverse Proxy ----

// ZitiTransport returns an http.RoundTripper that dials through the Ziti overlay
func (zm *ZitiManager) ZitiTransport(serviceName string) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			zm.logger.Debug("Dialing through Ziti overlay",
				zap.String("service", serviceName),
				zap.String("original_addr", addr))

			conn, err := zm.zitiCtx.Dial(serviceName)
			if err != nil {
				return nil, fmt.Errorf("ziti dial %q failed: %w", serviceName, err)
			}
			return conn, nil
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// ---- Management API CRUD Operations ----

// CreateService creates a Ziti service via the management API
func (zm *ZitiManager) CreateService(ctx context.Context, name string, attrs []string) (string, error) {
	if attrs == nil {
		attrs = []string{name}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":           name,
		"roleAttributes": attrs,
		"encryptionRequired": true,
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return "", fmt.Errorf("failed to create ziti service: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse service response: %w", err)
	}

	zm.logger.Info("Created Ziti service", zap.String("name", name), zap.String("id", resp.Data.ID))
	return resp.Data.ID, nil
}

// DeleteService deletes a Ziti service via the management API
func (zm *ZitiManager) DeleteService(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting service", statusCode)
	}
	return nil
}

// CreateIdentity creates a Ziti identity via the management API
func (zm *ZitiManager) CreateIdentity(ctx context.Context, name, identityType string, attrs []string) (zitiID string, enrollmentJWT string, err error) {
	if identityType == "" {
		identityType = "Device"
	}
	if attrs == nil {
		attrs = []string{}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":           name,
		"type":           identityType,
		"isAdmin":        false,
		"roleAttributes": attrs,
		"enrollment": map[string]interface{}{
			"ott": true,
		},
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/identities", body)
	if err != nil {
		return "", "", fmt.Errorf("failed to create ziti identity: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", "", fmt.Errorf("unexpected status %d creating identity: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", "", fmt.Errorf("failed to parse identity response: %w", err)
	}

	// Extract enrollment JWT
	if ott, ok := resp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwt, ok := ott["jwt"].(string); ok {
			enrollmentJWT = jwt
		}
	}

	// If JWT not in create response, fetch it
	if enrollmentJWT == "" {
		enrollmentJWT, _ = zm.GetIdentityEnrollmentJWT(ctx, resp.Data.ID)
	}

	zm.logger.Info("Created Ziti identity",
		zap.String("name", name),
		zap.String("id", resp.Data.ID),
		zap.Bool("has_jwt", enrollmentJWT != ""))

	return resp.Data.ID, enrollmentJWT, nil
}

// DeleteIdentity deletes a Ziti identity via the management API
func (zm *ZitiManager) DeleteIdentity(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting identity", statusCode)
	}
	return nil
}

// GetIdentityEnrollmentJWT retrieves the enrollment JWT for an identity
func (zm *ZitiManager) GetIdentityEnrollmentJWT(ctx context.Context, zitiID string) (string, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d getting identity", statusCode)
	}

	var resp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", err
	}

	if ott, ok := resp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwt, ok := ott["jwt"].(string); ok {
			return jwt, nil
		}
	}

	return "", fmt.Errorf("no enrollment JWT available for identity %s", zitiID)
}

// CreateServicePolicy creates a Bind or Dial service policy
func (zm *ZitiManager) CreateServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":          name,
		"type":          policyType, // "Bind" or "Dial"
		"semantic":      "AnyOf",
		"serviceRoles":  serviceRoles,
		"identityRoles": identityRoles,
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/service-policies", body)
	if err != nil {
		return "", fmt.Errorf("failed to create service policy: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service policy: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", err
	}

	return resp.Data.ID, nil
}

// DeleteServicePolicy deletes a service policy
func (zm *ZitiManager) DeleteServicePolicy(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting service policy", statusCode)
	}
	return nil
}

// ListServices lists all Ziti services from the management API
func (zm *ZitiManager) ListServices(ctx context.Context) ([]ZitiServiceInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/services", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing services", statusCode)
	}

	var resp struct {
		Data []ZitiServiceInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListIdentities lists all Ziti identities from the management API
func (zm *ZitiManager) ListIdentities(ctx context.Context) ([]ZitiIdentityInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/identities", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing identities", statusCode)
	}

	var resp struct {
		Data []ZitiIdentityInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ---- Route Ziti Setup/Teardown ----

// SetupZitiForRoute creates all Ziti resources needed for a proxy route
func (zm *ZitiManager) SetupZitiForRoute(ctx context.Context, routeID, serviceName, host string, port int) error {
	// 1. Create the Ziti service with host.v1 config so the tunneler knows where to forward
	body, _ := json.Marshal(map[string]interface{}{
		"name":               serviceName,
		"roleAttributes":     []string{serviceName},
		"encryptionRequired": true,
		"configs":            []string{}, // will attach config after creating it
	})

	// Create a host.v1 config that tells Ziti where to forward traffic
	configBody, _ := json.Marshal(map[string]interface{}{
		"name":     fmt.Sprintf("openidx-host-%s", serviceName),
		"configTypeId": "NH5p4FpGR",  // host.v1 config type
		"data": map[string]interface{}{
			"protocol":       "tcp",
			"address":        host,
			"port":           port,
			"forwardProtocol": true,
			"allowedProtocols": []string{"tcp"},
			"forwardAddress":  true,
			"allowedAddresses": []string{host},
			"forwardPort":     true,
			"allowedPortRanges": []map[string]int{
				{"low": port, "high": port},
			},
		},
	})

	configData, configStatus, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", configBody)
	var configID string
	if err == nil && (configStatus == http.StatusCreated || configStatus == http.StatusOK) {
		var configResp struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(configData, &configResp) == nil {
			configID = configResp.Data.ID
			zm.logger.Info("Created host.v1 config", zap.String("id", configID))
		}
	} else {
		zm.logger.Warn("Failed to create host.v1 config, creating service without it",
			zap.Int("status", configStatus), zap.Error(err))
	}

	// Create service, optionally attaching the config
	svcPayload := map[string]interface{}{
		"name":               serviceName,
		"roleAttributes":     []string{serviceName},
		"encryptionRequired": true,
	}
	if configID != "" {
		svcPayload["configs"] = []string{configID}
	}
	body, _ = json.Marshal(svcPayload)

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return fmt.Errorf("failed to create ziti service: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating service: %s", statusCode, string(respData))
	}

	var svcResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &svcResp); err != nil {
		return fmt.Errorf("failed to parse service response: %w", err)
	}
	zitiServiceID := svcResp.Data.ID
	zm.logger.Info("Created Ziti service", zap.String("name", serviceName), zap.String("id", zitiServiceID))

	// 2. Persist to ziti_services table
	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO ziti_services (ziti_id, name, host, port, route_id) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (name) DO UPDATE SET ziti_id=$1, host=$3, port=$4, route_id=$5, updated_at=NOW()`,
		zitiServiceID, serviceName, host, port, routeID)
	if err != nil {
		zm.logger.Error("Failed to persist ziti service to DB", zap.Error(err))
	}

	// 3. Create Bind policy: access-proxy can host this service
	// Use "#" prefix for role-based matching (the service has roleAttributes=[serviceName])
	bindPolicyID, err := zm.CreateServicePolicy(ctx,
		fmt.Sprintf("openidx-bind-%s", serviceName),
		"Bind",
		[]string{"#" + serviceName},
		[]string{"#access-proxy-clients"})
	if err != nil {
		zm.logger.Warn("Failed to create Bind policy", zap.Error(err))
	} else {
		zm.db.Pool.Exec(ctx,
			`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ziti_id) DO NOTHING`,
			bindPolicyID, fmt.Sprintf("openidx-bind-%s", serviceName), "Bind",
			`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
	}

	// 4. Create Dial policy: access-proxy can dial this service
	dialPolicyID, err := zm.CreateServicePolicy(ctx,
		fmt.Sprintf("openidx-dial-%s", serviceName),
		"Dial",
		[]string{"#" + serviceName},
		[]string{"#access-proxy-clients"})
	if err != nil {
		zm.logger.Warn("Failed to create Dial policy", zap.Error(err))
	} else {
		zm.db.Pool.Exec(ctx,
			`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ziti_id) DO NOTHING`,
			dialPolicyID, fmt.Sprintf("openidx-dial-%s", serviceName), "Dial",
			`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
	}

	// 5. Create Service Edge Router Policy so the service is available on all edge routers
	serBody, _ := json.Marshal(map[string]interface{}{
		"name":            fmt.Sprintf("openidx-serp-%s", serviceName),
		"semantic":        "AnyOf",
		"serviceRoles":    []string{"#" + serviceName},
		"edgeRouterRoles": []string{"#all"},
	})
	_, serpStatus, serpErr := zm.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", serBody)
	if serpErr != nil || (serpStatus != http.StatusCreated && serpStatus != http.StatusOK) {
		zm.logger.Warn("Failed to create service edge router policy", zap.Error(serpErr), zap.Int("status", serpStatus))
	}

	// 6. Ensure an Edge Router Policy exists so identities can use routers
	erpBody, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-erp-access-proxy",
		"semantic":        "AnyOf",
		"edgeRouterRoles": []string{"#all"},
		"identityRoles":   []string{"#access-proxy-clients"},
	})
	_, erpStatus, erpErr := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", erpBody)
	if erpErr != nil || (erpStatus != http.StatusCreated && erpStatus != http.StatusOK) {
		// May already exist, which is fine
		zm.logger.Debug("Edge router policy creation returned", zap.Int("status", erpStatus))
	}

	// 7. Update the proxy route
	_, err = zm.db.Pool.Exec(ctx,
		"UPDATE proxy_routes SET ziti_enabled=true, ziti_service_name=$1, updated_at=NOW() WHERE id=$2",
		serviceName, routeID)
	if err != nil {
		return fmt.Errorf("failed to update proxy route: %w", err)
	}

	// 8. Start hosting the service so it has a terminator
	if err := zm.HostService(serviceName, host, port); err != nil {
		zm.logger.Error("Failed to host service (no terminator will exist)",
			zap.String("service", serviceName), zap.Error(err))
		// Don't fail the setup — management resources are created, hosting can be retried
	}

	zm.logger.Info("Ziti setup complete for route",
		zap.String("route_id", routeID),
		zap.String("service", serviceName))
	return nil
}

// TeardownZitiForRoute removes all Ziti resources for a proxy route
func (zm *ZitiManager) TeardownZitiForRoute(ctx context.Context, routeID string) error {
	// Find service for this route
	var zitiServiceID, serviceName string
	err := zm.db.Pool.QueryRow(ctx,
		"SELECT ziti_id, name FROM ziti_services WHERE route_id=$1", routeID).Scan(&zitiServiceID, &serviceName)
	if err != nil {
		zm.logger.Debug("No ziti service found for route", zap.String("route_id", routeID))
	} else {
		// Stop hosting the service first
		zm.StopHostingService(serviceName)
		// Delete service policies first
		rows, _ := zm.db.Pool.Query(ctx,
			"SELECT ziti_id FROM ziti_service_policies WHERE name LIKE $1",
			fmt.Sprintf("%%-%s", serviceName))
		if rows != nil {
			for rows.Next() {
				var policyZitiID string
				rows.Scan(&policyZitiID)
				zm.DeleteServicePolicy(ctx, policyZitiID)
			}
			rows.Close()
		}
		zm.db.Pool.Exec(ctx, "DELETE FROM ziti_service_policies WHERE name LIKE $1",
			fmt.Sprintf("%%-%s", serviceName))

		// Delete the service
		zm.DeleteService(ctx, zitiServiceID)
		zm.db.Pool.Exec(ctx, "DELETE FROM ziti_services WHERE route_id=$1", routeID)
	}

	// Update the route
	_, err = zm.db.Pool.Exec(ctx,
		"UPDATE proxy_routes SET ziti_enabled=false, ziti_service_name=NULL, updated_at=NOW() WHERE id=$1",
		routeID)
	if err != nil {
		return fmt.Errorf("failed to update proxy route: %w", err)
	}

	zm.logger.Info("Ziti teardown complete for route", zap.String("route_id", routeID))
	return nil
}

// GetControllerVersion checks connectivity to the Ziti controller
func (zm *ZitiManager) GetControllerVersion(ctx context.Context) (map[string]interface{}, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", statusCode)
	}

	var result map[string]interface{}
	json.Unmarshal(respData, &result)
	return result, nil
}

// ---- Internal helpers ----

func (zm *ZitiManager) mgmtRequest(method, path string, body []byte) ([]byte, int, error) {
	zm.mu.RLock()
	token := zm.mgmtToken
	zm.mu.RUnlock()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, zm.cfg.ZitiCtrlURL+path, reqBody)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("zt-session", token)
	}

	resp, err := zm.mgmtClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("management API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// Re-authenticate on 401 and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		if err := zm.authenticate(); err != nil {
			return respBody, resp.StatusCode, fmt.Errorf("re-authentication failed: %w", err)
		}

		zm.mu.RLock()
		token = zm.mgmtToken
		zm.mu.RUnlock()

		// Retry
		if body != nil {
			reqBody = bytes.NewReader(body)
		}
		req, _ = http.NewRequest(method, zm.cfg.ZitiCtrlURL+path, reqBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("zt-session", token)

		resp, err = zm.mgmtClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()

		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, resp.StatusCode, err
		}
	}

	return respBody, resp.StatusCode, nil
}

// ---- Methods for Feature Manager and Health Checks ----

// CheckControllerHealth verifies connectivity to the Ziti controller
func (zm *ZitiManager) CheckControllerHealth(ctx context.Context) (bool, error) {
	_, err := zm.GetControllerVersion(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetServiceByName retrieves a Ziti service by its name
func (zm *ZitiManager) GetServiceByName(serviceName string) (*ZitiServiceInfo, error) {
	services, err := zm.ListServices(context.Background())
	if err != nil {
		return nil, err
	}

	for _, svc := range services {
		if svc.Name == serviceName {
			return &svc, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", serviceName)
}

// GetService retrieves a Ziti service by its ID
func (zm *ZitiManager) GetService(zitiID string) (*ZitiServiceInfo, error) {
	services, err := zm.ListServices(context.Background())
	if err != nil {
		return nil, err
	}

	for _, svc := range services {
		if svc.ID == zitiID {
			return &svc, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", zitiID)
}

// TestServiceDial tests if a Ziti service is dialable
func (zm *ZitiManager) TestServiceDial(ctx context.Context, serviceName string) (bool, error) {
	if zm.zitiCtx == nil {
		return false, fmt.Errorf("Ziti context not initialized")
	}

	// Check if service exists first
	_, err := zm.GetServiceByName(serviceName)
	if err != nil {
		return false, err
	}

	// For now, just return true if the service exists
	// In a full implementation, we would attempt to dial the service
	return true, nil
}

// ZitiAuditEvent represents an audit event from Ziti
type ZitiAuditEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Identity  string    `json:"identity,omitempty"`
	Service   string    `json:"service,omitempty"`
	Router    string    `json:"router,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// GetAuditEvents retrieves audit events from Ziti controller
func (zm *ZitiManager) GetAuditEvents(ctx context.Context, since *time.Time) ([]ZitiAuditEvent, error) {
	// Note: The Ziti controller may not have a built-in audit API
	// This is a placeholder for integration with Ziti's metrics/events
	// In production, you might use Ziti's event streaming or metrics endpoints

	// For now, return an empty slice
	return []ZitiAuditEvent{}, nil
}

// CreateService (overloaded) creates a Ziti service with host/port config
func (zm *ZitiManager) CreateServiceWithConfig(ctx context.Context, name, host string, port int) (*ZitiServiceInfo, error) {
	attrs := []string{"openidx-managed"}

	zitiID, err := zm.CreateService(ctx, name, attrs)
	if err != nil {
		return nil, err
	}

	// Store in database
	id := uuid.New().String()
	_, err = zm.db.Pool.Exec(ctx, `
		INSERT INTO ziti_services (id, ziti_id, name, protocol, host, port, enabled)
		VALUES ($1, $2, $3, 'tcp', $4, $5, true)
	`, id, zitiID, name, host, port)
	if err != nil {
		zm.logger.Warn("Failed to save service to DB", zap.Error(err))
	}

	return &ZitiServiceInfo{
		ID:   zitiID,
		Name: name,
	}, nil
}
