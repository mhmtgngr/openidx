// Package openapi_test proves the published OpenAPI documents describe the
// routes the binaries actually serve.
//
// The admin API's spec had 19 paths against 176 registered ones when this gate
// was written: it named the dashboard, settings, applications, directories, the
// vault and MFA configuration, and was silent about ISPM, AI agents and
// recommendations, privacy, federation, lifecycle, bulk operations, audit
// archival, continuous auth, notifications and email templates — every one of
// them routed and reachable. A spec that covers an eighth of a surface is worse
// than none: it reads as complete.
//
// So the gate is a census, not a sample. It mounts the same route groups
// cmd/admin-api mounts and fails on any (method, path) the spec does not carry.
package openapi_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	adminhandlers "github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/credentials"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/vault"
)

// adminAPIRoutes mounts every group cmd/admin-api/main.go mounts under /api/v1.
// The services are zero values: registration only reads the receiver's method
// set, never its fields, so no database is needed — and a gate that needed one
// would not run in the unit job.
func adminAPIRoutes(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")

	admin.RegisterRoutes(v1, &admin.Service{})
	organization.RegisterRoutes(v1, &organization.Service{})
	notifications.RegisterRoutes(v1, &notifications.Service{})
	adminhandlers.RegisterAllRoutes(v1, nil, zap.NewNop(), admin.RequireAdmin())

	selfheal := adminhandlers.NewSelfHealHandler(zap.NewNop(), t.TempDir(), t.TempDir(), nil)
	adminhandlers.SelfHealRoutes(v1, selfheal, admin.RequireAdmin(), admin.RequireAdmin())

	// cmd/admin-api puts vault, credential rotation and the PAM overview behind
	// an extra RequireAdmin on a sub-group of v1; the paths are the same.
	vaultGroup := v1.Group("")
	(&vault.Service{}).RegisterRoutes(vaultGroup)
	(&credentials.Service{}).RegisterRoutes(vaultGroup)
	admin.RegisterPAMRoutes(vaultGroup, &admin.Service{})

	return r.Routes()
}

var ginParam = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

// specPath converts gin's /x/:id to OpenAPI's /x/{id}.
func specPath(p string) string { return ginParam.ReplaceAllString(p, "{$1}") }

// documentedOperations reads the (path, method) pairs out of an OpenAPI
// document. The parse is deliberately shallow — indentation, not YAML — so the
// gate has no dependency the unit job would have to carry, and the shape it
// assumes is the shape the file has: two spaces for a path, four for a method.
func documentedOperations(t *testing.T, file string) map[string]map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var (
		out     = map[string]map[string]bool{}
		inPaths bool
		cur     string
	)
	pathKey := regexp.MustCompile(`^ {2}(/\S*):\s*$`)
	methodKey := regexp.MustCompile(`^ {4}(get|put|post|delete|patch|head|options):\s*$`)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			break // next top-level key ends the paths block
		}
		if m := pathKey.FindStringSubmatch(line); m != nil {
			cur = m[1]
			if out[cur] == nil {
				out[cur] = map[string]bool{}
			}
			continue
		}
		if m := methodKey.FindStringSubmatch(line); m != nil && cur != "" {
			out[cur][m[1]] = true
		}
	}
	return out
}

func specFile(name string) string { return filepath.Join("..", "..", "api", "openapi", name) }

func TestAdminAPISpecCoversEveryRoute(t *testing.T) {
	documented := documentedOperations(t, specFile("admin-api.yaml"))
	if len(documented) == 0 {
		t.Fatal("parsed no paths out of admin-api.yaml — the parser and the file disagree")
	}

	var undocumented []string
	for _, rt := range adminAPIRoutes(t) {
		p := specPath(rt.Path)
		if documented[p][strings.ToLower(rt.Method)] {
			continue
		}
		undocumented = append(undocumented, rt.Method+" "+p)
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("%d admin-api route(s) are served but absent from api/openapi/admin-api.yaml.\n"+
			"Document them (an operation with a summary, tags and an x-openidx-handler is enough) "+
			"or stop routing them:\n  %s",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}
}

// TestAdminAPISpecDocumentsNoPhantomRoutes is the other half: a spec that
// promises an endpoint the binary does not serve sends an integrator to a 404.
func TestAdminAPISpecDocumentsNoPhantomRoutes(t *testing.T) {
	served := map[string]map[string]bool{}
	for _, rt := range adminAPIRoutes(t) {
		p := specPath(rt.Path)
		if served[p] == nil {
			served[p] = map[string]bool{}
		}
		served[p][strings.ToLower(rt.Method)] = true
	}

	var phantom []string
	for p, methods := range documentedOperations(t, specFile("admin-api.yaml")) {
		for m := range methods {
			if !served[p][m] {
				phantom = append(phantom, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%d operation(s) in api/openapi/admin-api.yaml are not routed by cmd/admin-api:\n  %s",
			len(phantom), strings.Join(phantom, "\n  "))
	}
}
