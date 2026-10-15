package access

// THE AGENT API HAS A WRITTEN CONTRACT, AND THIS HOLDS THE TWO TOGETHER.
//
// api/agent-v1.yaml describes the routes the endpoint agents call. Five
// server/client mismatches in three weeks (posture check_type vs type, the
// tunnel_status shape, the push-approval fields, the mobile zitiDial decoding,
// the notification mark-read body) all had the same cause: nothing wrote the
// wire shape down, so each side spelled it from memory. The file is the
// contract; this test is what stops the file and the Go code from drifting
// apart silently.
//
// Two checks, both in both directions. For every Go request and response
// struct a handler decodes or encodes (agentContractSchemas), each JSON tag
// must be a property of the schema named for it, and each property must be a
// JSON tag. For every answer a handler builds as a gin.H literal, which
// reflection cannot see (agentContractLiterals), the keys the handler writes
// are read out of its source with go/ast and compared the same way. A field
// renamed, added or dropped on one side only fails here, with the field named.

import (
	"fmt"
	goast "go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// agentContractPath is the contract, relative to the repository root.
const agentContractPath = "api/agent-v1.yaml"

// agentContractSchemas maps each Go wire type to the schema named for it
// (components.schemas.<schema>). The schema's x-openidx-go-type must name the
// Go type too, so a reader of the YAML finds the type without this file.
//
// Add a line for every struct a handler on the agent surface decodes a request
// into or encodes an answer from. A type that is not here is a type the
// contract does not hold.
var agentContractSchemas = []struct {
	goType string // the Go type, as the message and x-openidx-go-type name it
	typ    reflect.Type
	schema string
}{
	{"enrollRequest", reflect.TypeOf(enrollRequest{}), "EnrollRequest"},
	{"deviceKeyRequest", reflect.TypeOf(deviceKeyRequest{}), "DeviceKey"},
	{"enrollResponse", reflect.TypeOf(enrollResponse{}), "EnrollCredentials"},
	{"agentConfigResponse", reflect.TypeOf(agentConfigResponse{}), "AgentConfig"},
	{"agentCheck", reflect.TypeOf(agentCheck{}), "AgentCheck"},
	{"kioskPolicyRow", reflect.TypeOf(kioskPolicyRow{}), "KioskPolicy"},
	{"agentRemoteSupportInfo", reflect.TypeOf(agentRemoteSupportInfo{}), "RemoteSupportInfo"},
	{"windowsAppDiscoveryJob", reflect.TypeOf(windowsAppDiscoveryJob{}), "WindowsAppDiscoveryJob"},
	{"agentNetworkPolicy", reflect.TypeOf(agentNetworkPolicy{}), "AgentNetworkPolicy"},
	{"agentReport", reflect.TypeOf(agentReport{}), "AgentReport"},
	{"checkResult", reflect.TypeOf(checkResult{}), "CheckResult"},
	{"checkResultDetail", reflect.TypeOf(checkResultDetail{}), "CheckResultDetail"},
	{"agentTunnelStatus", reflect.TypeOf(agentTunnelStatus{}), "TunnelStatus"},
	{"agentTunnelService", reflect.TypeOf(agentTunnelService{}), "TunnelService"},
	{"consentDecisionRequest", reflect.TypeOf(consentDecisionRequest{}), "ConsentDecision"},
	{"discoveryReport", reflect.TypeOf(discoveryReport{}), "WindowsAppDiscoveryReport"},
	{"discoveryReport.Host", structFieldType(discoveryReport{}, "Host"), "WindowsAppDiscoveryHost"},
	{"discoveryApp", reflect.TypeOf(discoveryApp{}), "WindowsAppDiscoveryApp"},
	{"darkEnrollRequest", reflect.TypeOf(darkEnrollRequest{}), "OverlayEnrollRequest"},
}

// agentContractLiterals maps the answers handlers build as gin.H literals to
// the functions that build them. The test parses those functions and collects
// every key written into a gin.H: a literal's own keys, and `m["key"] = v` on
// a variable that holds one. A literal with an `error` key is an error answer
// and counts toward ErrorResponse instead; everything else is the success
// answer the schema describes.
var agentContractLiterals = []struct {
	schema string
	file   string
	funcs  []string
}{
	{"EnrollResponse", "agent_api.go", []string{"writeEnrollResponse", "mintPushEnrollExtra", "HandleEnroll"}},
	{"ReportResponse", "agent_api.go", []string{"HandleReport"}},
	{"DeviceKeyResponse", "agent_device_key.go", []string{"HandleRegisterDeviceKey"}},
	{"ConsentResponse", "remote_support_api.go", []string{"HandleAgentConsent"}},
	{"WindowsAppDiscoveryResponse", "windows_apps_discovery.go", []string{"handleAgentWindowsAppReport"}},
	{"OverlayEnrollResponse", "enroll_handler.go", []string{"handleEnroll"}},
}

// agentContractErrorSources are the functions whose error answers, with those
// of agentContractLiterals, make up ErrorResponse.
var agentContractErrorSources = []struct {
	file  string
	funcs []string
}{
	{"agent_auth.go", []string{"refuseRevokedAgent", "requireEnrolledAgent"}},
	{"agent_api.go", []string{"refuseRevokedReenrolment", "HandleEnrollOAuth", "HandleConfig"}},
	{"agent_device_key.go", []string{"requireDeviceSignature", "enrolmentProof"}},
	{"remote_support_api.go", []string{"HandleAgentWS"}},
}

// TestAgentAPIContractIsAnOpenAPIDocument is the parse guard the service specs
// get from scripts/check-openapi-parses.sh, for a file that script does not
// scan: the document is YAML, OpenAPI 3.0, has paths, every local $ref
// resolves, its version is the product's, and every schema this test checks
// says which Go type it is checked against.
func TestAgentAPIContractIsAnOpenAPIDocument(t *testing.T) {
	doc, root := loadAgentContract(t)

	if v := fmt.Sprint(doc["openapi"]); !strings.HasPrefix(v, "3.0.") {
		t.Errorf("%s: openapi is %q; the service specs are OpenAPI 3.0.x and so is this one", agentContractPath, v)
	}
	paths, _ := doc["paths"].(map[string]interface{})
	if len(paths) == 0 {
		t.Fatalf("%s parses but has no paths: it is not an OpenAPI document", agentContractPath)
	}

	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := doc["info"].(map[string]interface{})
	if got, want := fmt.Sprint(info["version"]), strings.TrimSpace(string(version)); got != want {
		t.Errorf("%s: info.version is %s and VERSION is %s; the contract describes the server at that version", agentContractPath, got, want)
	}

	var dangling []string
	walkRefs(doc, func(ref string) {
		if _, ok := resolveRef(doc, ref); !ok {
			dangling = append(dangling, ref)
		}
	})
	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("%s refers to what it does not define:\n  %s", agentContractPath, strings.Join(dangling, "\n  "))
	}

	for _, e := range agentContractSchemas {
		s := schemaNode(t, doc, e.schema)
		if got := fmt.Sprint(s["x-openidx-go-type"]); got != e.goType {
			t.Errorf("schema %s: x-openidx-go-type is %q; this test checks it against %s, and the file should say so",
				e.schema, got, e.goType)
		}
	}
}

// TestAgentAPIContractMatchesTheGoTypes holds each Go wire struct to the
// schema named for it, in both directions.
func TestAgentAPIContractMatchesTheGoTypes(t *testing.T) {
	doc, _ := loadAgentContract(t)
	for _, e := range agentContractSchemas {
		if e.typ == nil {
			t.Errorf("%s: no such Go type; fix agentContractSchemas", e.goType)
			continue
		}
		tags := jsonTagNames(e.typ)
		props := map[string]bool{}
		schemaProperties(t, doc, schemaNode(t, doc, e.schema), props, map[string]bool{})
		reportFieldDrift(t, "Go type "+e.goType, tags, "schema "+e.schema, props)
	}
}

// TestAgentAPIContractMatchesTheHandlerAnswers holds the answers handlers
// build as gin.H literals, and the one struct declared inside a handler, to
// the schemas named for them, in both directions.
func TestAgentAPIContractMatchesTheHandlerAnswers(t *testing.T) {
	doc, _ := loadAgentContract(t)

	errorKeys := map[string]bool{}
	for _, e := range agentContractLiterals {
		keys, _ := ginLiteralKeys(t, e.file, e.funcs)
		props := map[string]bool{}
		schemaProperties(t, doc, schemaNode(t, doc, e.schema), props, map[string]bool{})
		where := fmt.Sprintf("gin.H in %s (%s)", strings.Join(e.funcs, ", "), e.file)
		reportFieldDrift(t, where, keys.success, "schema "+e.schema, props)
		for k := range keys.errors {
			errorKeys[k] = true
		}
	}
	for _, e := range agentContractErrorSources {
		keys, _ := ginLiteralKeys(t, e.file, e.funcs)
		for k := range keys.errors {
			errorKeys[k] = true
		}
		for k := range keys.success {
			t.Errorf("%s (%s) writes a gin.H without an error key, with %q; it is listed as an error source only",
				strings.Join(e.funcs, ", "), e.file, k)
		}
	}
	props := map[string]bool{}
	schemaProperties(t, doc, schemaNode(t, doc, "ErrorResponse"), props, map[string]bool{})
	reportFieldDrift(t, "the handlers' gin.H error answers", errorKeys, "schema ErrorResponse", props)

	// HandleReport's enforcement_actions are a struct declared inside the
	// handler, out of reflection's reach; its tags come from the source too.
	_, local := ginLiteralKeys(t, "agent_api.go", []string{"HandleReport"})
	tags, ok := local["actionEntry"]
	if !ok {
		t.Fatal("HandleReport no longer declares actionEntry; point EnforcementAction at what replaced it")
	}
	props = map[string]bool{}
	schemaProperties(t, doc, schemaNode(t, doc, "EnforcementAction"), props, map[string]bool{})
	reportFieldDrift(t, "Go type actionEntry (inside HandleReport)", tags, "schema EnforcementAction", props)
}

// TestAgentAPIContractRoutesAreServed is the census the service specs get
// from test/openapi: every operation the contract documents is a route the
// access service mounts, and every route the agent's own credential surface
// mounts (RegisterAgentPublicRoutes) is in the contract. A documented endpoint
// that 404s costs an integrator more than an undocumented one.
func TestAgentAPIContractRoutesAreServed(t *testing.T) {
	doc, _ := loadAgentContract(t)
	documented := documentedAgentOperations(t, doc)

	gin.SetMode(gin.TestMode)
	// Zero-valued handles: the constructor is pure assignment and registration
	// reads the receiver's method set, which is what a route census wants (the
	// same stub test/openapi uses for access-service.yaml).
	r := gin.New()
	RegisterRoutes(r, NewService(&database.PostgresDB{}, &database.RedisClient{}, &config.Config{}, zap.NewNop()))
	served := map[string]bool{}
	for _, rt := range r.Routes() {
		served[rt.Method+" "+ginPathToSpec(rt.Path)] = true
	}
	var phantom []string
	for op := range documented {
		if !served[op] {
			phantom = append(phantom, op)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%d operation(s) in %s are not routed by the access service:\n  %s",
			len(phantom), agentContractPath, strings.Join(phantom, "\n  "))
	}

	public := gin.New()
	NewAgentAPIHandler(zap.NewNop(), nil, nil, nil).RegisterAgentPublicRoutes(public.Group("/api/v1/access"))
	var undocumented []string
	for _, rt := range public.Routes() {
		if op := rt.Method + " " + ginPathToSpec(rt.Path); !documented[op] {
			undocumented = append(undocumented, op)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("%d public agent route(s) are served but absent from %s:\n  %s",
			len(undocumented), agentContractPath, strings.Join(undocumented, "\n  "))
	}
}

// ---------------------------------------------------------------- the file

// loadAgentContract parses the contract and returns it with the repository
// root it was read from.
func loadAgentContract(t *testing.T) (map[string]interface{}, string) {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, agentContractPath))
	if err != nil {
		t.Fatalf("the agent API contract is missing: %v", err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not YAML: %v", agentContractPath, err)
	}
	return doc, root
}

// repoRoot walks up from the package directory, which is where go test runs,
// to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package directory")
		}
		dir = parent
	}
}

// resolveRef follows a local JSON pointer ("#/components/schemas/X").
func resolveRef(doc map[string]interface{}, ref string) (interface{}, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	var node interface{} = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := node.(map[string]interface{})
		if !ok {
			return nil, false
		}
		if node, ok = m[part]; !ok {
			return nil, false
		}
	}
	return node, true
}

// walkRefs calls fn with every $ref in the document.
func walkRefs(node interface{}, fn func(ref string)) {
	switch n := node.(type) {
	case map[string]interface{}:
		for k, v := range n {
			if k == "$ref" {
				if s, ok := v.(string); ok {
					fn(s)
				}
				continue
			}
			walkRefs(v, fn)
		}
	case []interface{}:
		for _, v := range n {
			walkRefs(v, fn)
		}
	}
}

// schemaNode is components.schemas.<name>, which must exist.
func schemaNode(t *testing.T, doc map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	node, ok := resolveRef(doc, "#/components/schemas/"+name)
	if !ok {
		t.Fatalf("%s defines no schema %s", agentContractPath, name)
	}
	m, ok := node.(map[string]interface{})
	if !ok {
		t.Fatalf("%s: schema %s is not a mapping", agentContractPath, name)
	}
	return m
}

// schemaProperties collects the effective property names of a schema: its
// own properties, those of what it $refs, and those of every allOf, oneOf and
// anyOf branch. The union is what a Go struct that decodes both shapes of a
// field declares, and the two-shape schemas (CheckResult) are written as a
// oneOf of the shapes.
func schemaProperties(t *testing.T, doc map[string]interface{}, node interface{}, out map[string]bool, seen map[string]bool) {
	t.Helper()
	m, ok := node.(map[string]interface{})
	if !ok {
		return
	}
	if ref, ok := m["$ref"].(string); ok {
		if seen[ref] {
			return
		}
		seen[ref] = true
		target, ok := resolveRef(doc, ref)
		if !ok {
			t.Fatalf("%s: %s does not resolve", agentContractPath, ref)
		}
		schemaProperties(t, doc, target, out, seen)
	}
	if props, ok := m["properties"].(map[string]interface{}); ok {
		for name := range props {
			out[name] = true
		}
	}
	for _, combinator := range []string{"allOf", "oneOf", "anyOf"} {
		if branches, ok := m[combinator].([]interface{}); ok {
			for _, b := range branches {
				schemaProperties(t, doc, b, out, seen)
			}
		}
	}
}

// documentedAgentOperations reads the "METHOD /path" pairs out of the document.
func documentedAgentOperations(t *testing.T, doc map[string]interface{}) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	paths, _ := doc["paths"].(map[string]interface{})
	for p, item := range paths {
		ops, _ := item.(map[string]interface{})
		for method := range ops {
			switch method {
			case "get", "put", "post", "delete", "patch", "head", "options":
				out[strings.ToUpper(method)+" "+p] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s documents no operations", agentContractPath)
	}
	return out
}

var ginPathParam = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

// ginPathToSpec converts gin's /x/:id to OpenAPI's /x/{id}.
func ginPathToSpec(p string) string { return ginPathParam.ReplaceAllString(p, "{$1}") }

// ----------------------------------------------------------------- Go types

// structFieldType is the type of a named field, for a struct declared inline
// in another struct; nil when there is no such field.
func structFieldType(v interface{}, field string) reflect.Type {
	f, ok := reflect.TypeOf(v).FieldByName(field)
	if !ok {
		return nil
	}
	return f.Type
}

// jsonTagNames returns the names encoding/json would use for a struct's
// fields: the json tag's name, or the field name without one; never an
// unexported field or one tagged "-". An embedded struct's fields are
// promoted, as encoding/json promotes them.
func jsonTagNames(typ reflect.Type) map[string]bool {
	out := map[string]bool{}
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" && !f.Anonymous { // unexported
			continue
		}
		name, tagged := jsonName(f.Tag)
		if name == "-" {
			continue
		}
		if f.Anonymous && !tagged {
			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for n := range jsonTagNames(ft) {
					out[n] = true
				}
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
	}
	return out
}

// jsonName is the name part of a json struct tag, and whether there was one.
func jsonName(tag reflect.StructTag) (string, bool) {
	v, ok := tag.Lookup("json")
	if !ok {
		return "", false
	}
	if i := strings.Index(v, ","); i >= 0 {
		v = v[:i]
	}
	return v, true
}

// reportFieldDrift fails the test for every name on one side only.
func reportFieldDrift(t *testing.T, leftWhat string, left map[string]bool, rightWhat string, right map[string]bool) {
	t.Helper()
	var onlyLeft, onlyRight []string
	for n := range left {
		if !right[n] {
			onlyLeft = append(onlyLeft, n)
		}
	}
	for n := range right {
		if !left[n] {
			onlyRight = append(onlyRight, n)
		}
	}
	sort.Strings(onlyLeft)
	sort.Strings(onlyRight)
	if len(onlyLeft) > 0 {
		t.Errorf("%s has %s, which %s does not: add it to %s, or rename one side to match the other",
			leftWhat, strings.Join(onlyLeft, ", "), rightWhat, agentContractPath)
	}
	if len(onlyRight) > 0 {
		t.Errorf("%s has %s, which %s does not: the contract promises a field the code does not have",
			rightWhat, strings.Join(onlyRight, ", "), leftWhat)
	}
}

// -------------------------------------------------------- gin.H answers

// ginKeys are the keys handlers write into gin.H answers, by kind.
type ginKeys struct {
	success map[string]bool
	errors  map[string]bool
}

// ginLiteralKeys parses file (a path relative to this package) and returns
// the keys the named functions write into gin.H answers, plus the JSON tags of
// every struct type declared inside those functions, by type name.
func ginLiteralKeys(t *testing.T, file string, funcs []string) (ginKeys, map[string]map[string]bool) {
	t.Helper()
	f, err := goparser.ParseFile(gotoken.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	want := map[string]bool{}
	for _, n := range funcs {
		want[n] = true
	}
	keys := ginKeys{success: map[string]bool{}, errors: map[string]bool{}}
	localTypes := map[string]map[string]bool{}
	found := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*goast.FuncDecl)
		if !ok || !want[fn.Name.Name] || fn.Body == nil {
			continue
		}
		found[fn.Name.Name] = true
		// Variables holding a gin.H, and whether that gin.H is an error
		// answer. Declarations precede their index assignments in source
		// order, which is the order goast.Inspect walks.
		isErrorVar := map[string]bool{}
		goast.Inspect(fn.Body, func(n goast.Node) bool {
			switch n := n.(type) {
			case *goast.AssignStmt:
				for i, lhs := range n.Lhs {
					if i < len(n.Rhs) {
						if lit, ok := n.Rhs[i].(*goast.CompositeLit); ok && isGinH(lit) {
							if id, ok := lhs.(*goast.Ident); ok {
								isErrorVar[id.Name] = ginLiteralHasKey(lit, "error")
							}
						}
					}
					idx, ok := lhs.(*goast.IndexExpr)
					if !ok {
						continue
					}
					id, ok := idx.X.(*goast.Ident)
					if !ok {
						continue
					}
					isErr, tracked := isErrorVar[id.Name]
					if !tracked {
						continue
					}
					if k, ok := stringLiteral(idx.Index); ok {
						keys.bucket(isErr)[k] = true
					}
				}
			case *goast.CompositeLit:
				if isGinH(n) {
					bucket := keys.bucket(ginLiteralHasKey(n, "error"))
					for _, k := range ginLiteralKeyNames(n) {
						bucket[k] = true
					}
				}
			case *goast.TypeSpec:
				if st, ok := n.Type.(*goast.StructType); ok {
					localTypes[n.Name.Name] = structTypeTagNames(st)
				}
			}
			return true
		})
	}
	for _, n := range funcs {
		if !found[n] {
			t.Fatalf("%s declares no function %s; point agentContractLiterals at what replaced it", file, n)
		}
	}
	return keys, localTypes
}

func (k ginKeys) bucket(isError bool) map[string]bool {
	if isError {
		return k.errors
	}
	return k.success
}

// isGinH reports whether a composite literal is a gin.H{...}.
func isGinH(lit *goast.CompositeLit) bool {
	sel, ok := lit.Type.(*goast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*goast.Ident)
	return ok && pkg.Name == "gin" && sel.Sel.Name == "H"
}

// ginLiteralKeyNames returns the string keys of a map literal, in order.
func ginLiteralKeyNames(lit *goast.CompositeLit) []string {
	var out []string
	for _, e := range lit.Elts {
		kv, ok := e.(*goast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := stringLiteral(kv.Key); ok {
			out = append(out, k)
		}
	}
	return out
}

func ginLiteralHasKey(lit *goast.CompositeLit, key string) bool {
	for _, k := range ginLiteralKeyNames(lit) {
		if k == key {
			return true
		}
	}
	return false
}

// stringLiteral is the value of a string literal expression.
func stringLiteral(e goast.Expr) (string, bool) {
	lit, ok := e.(*goast.BasicLit)
	if !ok || lit.Kind != gotoken.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// structTypeTagNames reads a struct type's JSON names out of its source, as
// jsonTagNames reads them out of a reflect.Type.
func structTypeTagNames(st *goast.StructType) map[string]bool {
	out := map[string]bool{}
	for _, f := range st.Fields.List {
		var tag reflect.StructTag
		if f.Tag != nil {
			if s, err := strconv.Unquote(f.Tag.Value); err == nil {
				tag = reflect.StructTag(s)
			}
		}
		name, _ := jsonName(tag)
		if name == "-" {
			continue
		}
		for _, id := range f.Names {
			if !goast.IsExported(id.Name) {
				continue
			}
			if name == "" {
				out[id.Name] = true
			} else {
				out[name] = true
			}
		}
	}
	return out
}
