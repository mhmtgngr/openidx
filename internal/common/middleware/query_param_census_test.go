package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// The request logger redacts query parameters by NAME. That makes the redaction
// exactly as good as somebody's memory, and it was not good: "access_token" and
// "refresh_token" were listed, "id_token_hint" was not; "token" was listed,
// "session_token" was not; "code" -- the OAuth authorization code, read from the
// query string by five live callback routes -- was not listed at all, so every
// SSO and social login wrote one into the log in clear.
//
// A list of remembered names cannot cover what nobody remembered, so this guard
// inverts it, the way tools/orgscope was inverted for org_id: derive the CENSUS
// from the code. Every parameter name the tree passes to c.Query or
// c.DefaultQuery must be classified — either the redaction rules catch it, or it
// appears below as public with a reason. A new parameter cannot arrive
// unclassified, because adding one without a decision turns this red.
//
// What the guard does NOT do is decide which side a name belongs on. That is a
// judgement, and it is recorded here in writing rather than inferred.
//
// The reasons are grouped: a per-name sentence for eighty pagination parameters
// would be noise, and noise is what stops being read.
var publicQueryParams = map[string]string{
	// Pagination, sorting and windowing. Nothing here identifies a subject or
	// authorises anything; they are the shape of the page being asked for.
	"page": "pagination", "page_size": "pagination", "limit": "pagination",
	"offset": "pagination", "count": "pagination", "startIndex": "pagination (SCIM)",
	"start": "time window", "end": "time window", "start_date": "time window",
	"end_date": "time window", "start_time": "time window", "end_time": "time window",
	"since": "time window", "from": "time window", "to": "time window",
	"days": "time window", "period": "time window", "threshold_days": "time window",

	// Filters. Server-side selectors over data the caller is already authorised
	// to read; the authorisation is the handler's job, not the log's.
	"q": "search term", "search": "search term", "filter": "filter expression",
	"status": "filter", "type": "filter", "category": "filter", "categories": "filter",
	"severity": "filter", "risk_level": "filter", "min_score": "filter",
	"active_only": "filter", "enabled": "filter", "enabled_only": "filter",
	"unread": "filter", "favorites": "filter", "orphaned": "filter",
	"include_acknowledged": "filter", "full": "filter", "replace": "filter",
	"classification": "filter", "class": "filter", "impact": "filter",
	"outcome": "filter", "decision": "filter", "action": "filter",
	"consent_type": "filter", "alert_type": "filter", "event_type": "filter",
	"event_types": "filter", "resource_type": "filter", "scope_type": "filter",
	"target_type": "filter", "method": "filter", "proto": "filter",
	"channel": "filter", "source": "filter", "endpoint": "filter",
	"format": "response format", "heal": "action flag",

	// Identifiers of objects. A UUID in a log is what makes the log useful, and
	// it is not a credential: holding one grants nothing without a token.
	"user_id": "object id", "org": "org slug or id",
	// `agent_id` was here until the agent surface started authenticating. It was
	// declared public because GET /agent/config read it out of the query string
	// — which was the whole problem: the id was not a credential, it was the
	// entire identification, and anyone could name any device. agent_auth.go
	// made the id come from the verified credential instead, so nothing reads
	// the parameter any more and the entry went with it.
	"actor_id": "object id", "assigned_to": "object id",
	"requester_id": "object id", "target_id": "object id", "route_id": "object id",
	"folder_id": "object id", "session_id": "object id", "workflow_id": "object id",
	"service": "object name", "name": "object name", "domain": "domain name",
	"username": "the subject's login name, which the log already carries as user_id",

	// OAuth/OIDC parameters that are public BY SPECIFICATION. These are the ones
	// worth being explicit about, because they sit next to the ones that are not.
	"client_id":                "RFC 6749 §2.2: a public identifier, not a secret",
	"redirect_uri":             "public; registered per client and shown to the user",
	"redirect_url":             "the same, spelled the other way by some handlers",
	"response_type":            "public: the flow being requested",
	"scope":                    "public: the permissions being requested",
	"code_challenge":           "RFC 7636: the PKCE challenge is public; the VERIFIER is the secret and is POSTed",
	"code_challenge_method":    "public: S256 or plain",
	"post_logout_redirect_uri": "public; registered per client",
	"idp":                      "public: which identity provider to use",
	"idp_hint":                 "public: the same, as a hint",
	"sp_entity_id":             "public SAML entity identifier",
	"error":                    "an error code the server itself produced",
	"error_description":        "the matching human-readable text",
}

// TestEveryQueryParameterIsClassified derives the census and checks it.
func TestEveryQueryParameterIsClassified(t *testing.T) {
	root := censusRepoRoot(t)
	params, scanned := queryParamCensus(t, root)

	// A census of nothing would pass silently, which is the failure this repo has
	// already been bitten by.
	if scanned < 100 {
		t.Fatalf("scanned only %d non-test Go files — the walk is looking in the wrong place", scanned)
	}
	if len(params) < 50 {
		t.Fatalf("census found only %d query parameters — the matcher is not seeing c.Query calls", len(params))
	}

	var unclassified []string
	for name, where := range params {
		if logsafe.IsSensitiveFieldName(name, nil) {
			continue // redacted, and that is a decision
		}
		if _, ok := publicQueryParams[name]; ok {
			continue // public, with a reason, and that is a decision
		}
		unclassified = append(unclassified, name+"  (read at "+where+")")
	}
	sort.Strings(unclassified)

	if len(unclassified) != 0 {
		t.Errorf("query parameter(s) neither redacted nor declared public — decide which, "+
			"because the request logger writes an undeclared one into every log line for the request:\n  %s\n\n"+
			"To redact: add the name to DefaultSanitizedFields, or a word of it to sensitiveWords.\n"+
			"To keep: add it to publicQueryParams in this file with the reason it is safe.",
			strings.Join(unclassified, "\n  "))
	}
}

// The other half of the same guard: an entry in publicQueryParams that the tree
// no longer reads is a decision about nothing, and a register nobody prunes is a
// register nobody trusts.
func TestPublicQueryParamsHasNoStaleEntries(t *testing.T) {
	root := censusRepoRoot(t)
	params, _ := queryParamCensus(t, root)

	var stale []string
	for name := range publicQueryParams {
		if _, ok := params[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)

	if len(stale) != 0 {
		t.Errorf("publicQueryParams declares parameter(s) no handler reads any more — delete them:\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// And a reason is mandatory, so "add it to the list" cannot become the fix
// somebody applies without thinking about it.
func TestEveryPublicQueryParamHasAReason(t *testing.T) {
	for name, reason := range publicQueryParams {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("publicQueryParams[%q] has no reason — say why the value is safe in a log", name)
		}
	}
}

// queryParamCensus returns name -> "file:line of the first read", over every
// c.Query / c.DefaultQuery call in non-test Go source.
func queryParamCensus(t *testing.T, root string) (map[string]string, int) {
	t.Helper()
	fset := token.NewFileSet()
	params := map[string]string{}
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Query" && sel.Sel.Name != "DefaultQuery") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name := strings.Trim(lit.Value, `"`)
			if name == "" {
				return true
			}
			if _, seen := params[name]; !seen {
				params[name] = rel + ":" + posLine(fset, call.Pos())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return params, scanned
}

func posLine(fset *token.FileSet, p token.Pos) string {
	line := fset.Position(p).Line
	if line == 0 {
		return "0"
	}
	var b []byte
	for line > 0 {
		b = append([]byte{byte('0' + line%10)}, b...)
		line /= 10
	}
	return string(b)
}

func censusRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root above the test directory")
	return ""
}
