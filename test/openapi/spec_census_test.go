// Package openapi_test proves the published OpenAPI documents describe the
// routes the binaries actually serve.
//
// A partial spec is worse than none: nothing in it says it is partial, so an
// integrator reads the silence as "no such endpoint". So the gate is a census,
// not a sample, and it runs in both directions — a served route with no
// operation fails, and an operation nobody serves fails too, because a
// documented endpoint that 404s costs an integrator more than an undocumented
// one.
package openapi_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

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

// assertSpecMatchesRoutes compares one spec against one live route table.
func assertSpecMatchesRoutes(t *testing.T, spec string, routes []gin.RouteInfo) {
	t.Helper()
	file := specFile(spec)
	documented := documentedOperations(t, file)
	if len(documented) == 0 {
		t.Fatalf("parsed no paths out of %s — the parser and the file disagree", spec)
	}

	served := map[string]map[string]bool{}
	var undocumented []string
	for _, rt := range routes {
		p, m := specPath(rt.Path), strings.ToLower(rt.Method)
		if served[p] == nil {
			served[p] = map[string]bool{}
		}
		served[p][m] = true
		if !documented[p][m] {
			undocumented = append(undocumented, rt.Method+" "+p)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("%d route(s) are served but absent from api/openapi/%s.\n"+
			"Document them (a summary, tags and an x-openidx-handler is enough) "+
			"or stop routing them:\n  %s",
			len(undocumented), spec, strings.Join(undocumented, "\n  "))
	}

	var phantom []string
	for p, methods := range documented {
		for m := range methods {
			if !served[p][m] {
				phantom = append(phantom, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%d operation(s) in api/openapi/%s are not routed:\n  %s",
			len(phantom), spec, strings.Join(phantom, "\n  "))
	}
}
