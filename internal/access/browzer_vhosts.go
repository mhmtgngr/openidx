package access

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// browzerVHostOpts carries the static inputs for the public per-app nginx
// vhosts. The front nginx (oidx-nginx) TLS-terminates each <app>.tdv.org and
// forwards to the BrowZer bootstrapper, which serves the clientless overlay.
type browzerVHostOpts struct {
	// bootstrapperPass is the upstream the public vhost forwards to (the BrowZer
	// bootstrapper), e.g. "https://127.0.0.1:8445".
	bootstrapperPass string
	// sslCert/sslKey are the cert paths AS SEEN BY the front nginx container.
	sslCert string
	sslKey  string
	// hopBasePort is the base for assignHopPorts — the OIDC callback bypass on a
	// hop-mode route targets that route's hop port.
	hopBasePort int
	// oidcCallbacks are path suffixes (e.g. "signin-oidc") that external-IdP apps
	// receive as a top-level cross-site form_post. BrowZer's WASM/service-worker
	// can't intercept a cross-origin POST navigation, so those land on the
	// bootstrapper, which 403s non-GET. For hop-mode routes we route them straight
	// to the hop (the real app), bypassing the bootstrapper.
	oidcCallbacks []string
}

// SplitCSV splits a comma-separated list, trimming whitespace and dropping
// empty entries. Used to parse config lists like BROWZER_OIDC_CALLBACK_PATHS.
func SplitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildBrowZerVHostConfig renders the public per-app nginx server blocks for the
// BrowZer-enabled routes. Each block TLS-terminates <hostname> and forwards to
// the bootstrapper (which demuxes by Host). Hop-mode routes additionally get an
// OIDC form_post callback bypass to their hop port. Deterministic: the input
// order is preserved (queryBrowZerRoutes already orders by priority, name).
func buildBrowZerVHostConfig(routes []browzerRouteInfo, opts browzerVHostOpts) string {
	if opts.bootstrapperPass == "" {
		opts.bootstrapperPass = "https://127.0.0.1:8445"
	}
	if opts.sslCert == "" {
		opts.sslCert = "/etc/nginx/tdv-fullchain.pem"
	}
	if opts.sslKey == "" {
		opts.sslKey = "/etc/nginx/tdv-key.pem"
	}

	// Hop port map (only hop-mode routes have a host-side upstream to bypass to).
	var hopNames []string
	for _, r := range routes {
		if r.hostingMode == HostingModeHop {
			hopNames = append(hopNames, r.serviceName)
		}
	}
	ports := assignHopPorts(hopNames, opts.hopBasePort)

	var b strings.Builder
	b.WriteString("# Auto-generated BrowZer public vhosts — do not edit manually\n")
	for _, r := range routes {
		if r.hostname == "" {
			continue
		}
		fmt.Fprintf(&b, "\nserver {\n")
		b.WriteString("    listen 443 ssl;\n")
		fmt.Fprintf(&b, "    server_name %s;\n", r.hostname)
		fmt.Fprintf(&b, "    ssl_certificate %s;\n", opts.sslCert)
		fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", opts.sslKey)

		// OIDC form_post callback bypass — hop-mode only (it owns a host-side
		// upstream). The regex matches the callback suffix at any base path
		// (e.g. /fm/signin-oidc) so it is app-path agnostic.
		if r.hostingMode == HostingModeHop && len(opts.oidcCallbacks) > 0 {
			fmt.Fprintf(&b, "    location ~ /(%s)$ {\n", strings.Join(opts.oidcCallbacks, "|"))
			fmt.Fprintf(&b, "        proxy_pass http://127.0.0.1:%d;\n", ports[r.serviceName])
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto https;\n")
			b.WriteString("    }\n")
		}

		b.WriteString("    location / {\n")
		fmt.Fprintf(&b, "        proxy_pass %s;\n", opts.bootstrapperPass)
		b.WriteString("        proxy_ssl_verify off;\n")
		b.WriteString("        proxy_ssl_server_name on;\n")
		b.WriteString("        proxy_ssl_name $host;\n")
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto https;\n")
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		b.WriteString("        proxy_read_timeout 86400s;\n")
		b.WriteString("    }\n}\n")
	}
	return b.String()
}

// GenerateBrowZerVHostConfig queries the BrowZer-enabled routes and renders the
// public nginx vhost config. Lock-free (mirrors GenerateBrowZerHopConfig): it
// only reads tm fields and calls queryBrowZerRoutes (which does not take tm.mu).
func (tm *BrowZerTargetManager) GenerateBrowZerVHostConfig(ctx context.Context) ([]byte, error) {
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}
	cfg := buildBrowZerVHostConfig(routes, browzerVHostOpts{
		bootstrapperPass: tm.bootstrapperPass,
		sslCert:          tm.vhostSSLCert,
		sslKey:           tm.vhostSSLKey,
		hopBasePort:      tm.hopPort,
		oidcCallbacks:    tm.oidcCallbacks,
	})
	return []byte(cfg), nil
}

// WriteBrowZerVHostConfig generates the public vhost config and writes it to the
// shared config file. Mirrors WriteBrowZerHopConfig's locking discipline.
func (tm *BrowZerTargetManager) WriteBrowZerVHostConfig(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeVHostConfigLocked(ctx)
}

// writeVHostConfigLocked writes the public vhost config; callers must hold tm.mu
// (RegenerateConfigs reuses it under the lock).
func (tm *BrowZerTargetManager) writeVHostConfigLocked(ctx context.Context) error {
	if tm.vhostConfigPath == "" {
		tm.logger.Debug("No vhost config path configured, skipping write")
		return nil
	}
	data, err := tm.GenerateBrowZerVHostConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate vhost config: %w", err)
	}
	if err := writeFileAtomic(tm.vhostConfigPath, data); err != nil {
		return err
	}
	tm.logger.Info("BrowZer public vhost config written", zap.String("path", tm.vhostConfigPath))
	return nil
}
