package oauth

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// A syntactically valid S256 challenge: 43 base64url characters.
const testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func TestLiveAuthorizeEnforcesPKCE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const redirect = "https://app.example.test/callback"

	cases := []struct {
		name      string
		client    *OAuthClient
		challenge string
		method    string
		wantErr   string // "" means the request must be accepted
	}{
		{
			name:    "public client without a code_challenge",
			client:  &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{redirect}},
			wantErr: "invalid_request",
		},
		{
			name:    "confidential client the operator marked pkce_required",
			client:  &OAuthClient{ClientID: "c", Type: "confidential", RedirectURIs: []string{redirect}, PKCERequired: true},
			wantErr: "invalid_request",
		},
		{
			name:      "public client with a valid S256 challenge (control)",
			client:    &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{redirect}},
			challenge: testCodeChallenge,
			method:    "S256",
		},
		{
			name:      "unsupported code_challenge_method",
			client:    &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{redirect}},
			challenge: testCodeChallenge,
			method:    "MD5",
			wantErr:   "invalid_request",
		},
		{
			name:      "code_challenge that is not base64url",
			client:    &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{redirect}},
			challenge: "not!base64url!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			method:    "S256",
			wantErr:   "invalid_request",
		},
		{
			// Valid base64url, but 22 characters. RFC 7636 §4.1 fixes the
			// range at 43..128: a shorter verifier has too little entropy to
			// be worth verifying.
			name:      "well-formed code_challenge that is too short",
			client:    &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{redirect}},
			challenge: "YWJjZGVmZ2hpamtsbW5vcA",
			method:    "S256",
			wantErr:   "invalid_request",
		},
		{
			name:   "confidential client without pkce_required (control)",
			client: &OAuthClient{ClientID: "c", Type: "confidential", RedirectURIs: []string{redirect}},
		},
	}

	// The same table, run against /oauth/authorize/v2's validator. The whole
	// point of moving the rule into pkce_policy.go is that the two endpoints
	// answer identically; asserting it here is what keeps the second one from
	// silently reverting to a client.Type check.
	t.Run("the v2 handler answers the same table", func(t *testing.T) {
		h := newTestAuthorizeHandler(t)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := h.validatePKCEParameters(tc.client, &AuthorizeRequest{
					ClientID:            tc.client.ClientID,
					RedirectURI:         redirect,
					ResponseType:        "code",
					CodeChallenge:       tc.challenge,
					CodeChallengeMethod: tc.method,
				})
				if tc.wantErr != "" && err == nil {
					t.Fatalf("/oauth/authorize/v2 accepted what /oauth/authorize refuses")
				}
				if tc.wantErr == "" && err != nil {
					t.Fatalf("/oauth/authorize/v2 refused what /oauth/authorize accepts: %v", err)
				}
			})
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newLoginUITestService(t, "", tc.client)

			q := url.Values{
				"client_id":     {tc.client.ClientID},
				"redirect_uri":  {redirect},
				"response_type": {"code"},
				"state":         {"st-1"},
			}
			if tc.challenge != "" {
				q.Set("code_challenge", tc.challenge)
			}
			if tc.method != "" {
				q.Set("code_challenge_method", tc.method)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)

			svc.handleAuthorize(c)

			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatalf("Location is not a URL: %v", err)
			}

			if tc.wantErr != "" {
				// RFC 6749 §4.1.2.1: reported to the client at its registered
				// redirect_uri, not rendered for a user who cannot act on it.
				if got := loc.Query().Get("error"); got != tc.wantErr {
					t.Fatalf("PKCE was not enforced: status=%d location=%q error=%q want %q",
						w.Code, w.Header().Get("Location"), got, tc.wantErr)
				}
				if loc.Query().Get("state") != "st-1" {
					t.Errorf("state must be echoed so the client can correlate: %q", w.Header().Get("Location"))
				}
				return
			}

			if w.Code != http.StatusFound || loc.Query().Get("error") != "" {
				t.Fatalf("a compliant request was refused: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			session := loc.Query().Get("login_session")
			if session == "" {
				t.Fatalf("no login_session in %q", w.Header().Get("Location"))
			}
			raw, err := svc.redis.Client.Get(c.Request.Context(), "login_session:"+session).Result()
			if err != nil {
				t.Fatalf("login_session was not written: %v", err)
			}
			var params map[string]string
			if err := json.Unmarshal([]byte(raw), &params); err != nil {
				t.Fatalf("login_session is not a JSON object: %v", err)
			}
			// The pending request is what the mint site reads. If PKCE is
			// required, what it carries is what the token endpoint will have
			// to verify against — an empty challenge there makes
			// handleTokenRequest's `if authCode.CodeChallenge != ""` vacuous.
			if tc.challenge != "" && params["code_challenge"] != tc.challenge {
				t.Errorf("pending request carries code_challenge=%q, want %q — the mint site reads this map",
					params["code_challenge"], tc.challenge)
			}
		})
	}
}

// pkceEntryPointDisposition records, for every function in this package that
// takes a code_challenge FROM A REQUEST, why that is safe:
//
//   - "enforces": the function itself calls validatePKCERequest.
//   - anything else: a specific reason it is exempt.
//
// TestEveryPKCEEntryPointEnforcesTheRule below finds the real set by parsing
// this package's source and fails if it finds a function that is not a key
// here, or a key here that no longer reads a request-supplied challenge.
//
// The reason this guard exists rather than a list of handlers to check: the
// rule was spelled out in exactly one of five such functions, and the one that
// had it was not the one on the mounted route. The scope and response_type
// checks on that same handler went missing the same way. A new authorization
// entry point must now decide, in the commit that adds it, which of these two
// lines it is on.
var pkceEntryPointDisposition = map[string]string{
	"handleAuthorize":        "enforces",
	"handleSSOAuthorize":     "enforces",
	"handleAuthorizeConsent": "enforces",
	"handleNativeLoginInit":  "enforces",

	// parseAuthorizeRequest only copies query parameters into an
	// AuthorizeRequest. Its single caller, HandleAuthorizeRequest, runs
	// validatePKCEParameters — which is validatePKCERequest — on the result
	// before anything else reads it.
	"parseAuthorizeRequest": "exempt: parses only; its caller HandleAuthorizeRequest validates the result",
}

func TestEveryPKCEEntryPointEnforcesTheRule(t *testing.T) {
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]bool{}    // function name -> reads a request challenge
	enforces := map[string]bool{} // function name -> calls validatePKCERequest

	for _, path := range goFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "validatePKCERequest", "validatePKCEParameters":
						enforces[fn.Name.Name] = true
					case "Query", "PostForm", "DefaultQuery":
						// c.Query("code_challenge") — straight off the request.
						for _, arg := range node.Args {
							if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
								strings.Contains(lit.Value, "code_challenge") {
								found[fn.Name.Name] = true
							}
						}
					}
				case *ast.Ident:
					if node.Name == "validatePKCERequest" {
						enforces[fn.Name.Name] = true
					}
				case *ast.StructType:
					// An anonymous request struct bound from the body with a
					// `json:"code_challenge"` field is the same thing.
					for _, f := range node.Fields.List {
						if f.Tag != nil && strings.Contains(f.Tag.Value, `json:"code_challenge"`) {
							found[fn.Name.Name] = true
						}
					}
				}
				return true
			})
		}
	}

	if len(found) == 0 {
		t.Fatal("this guard found no function reading a request-supplied code_challenge — it has stopped measuring anything")
	}

	for name := range found {
		reason, listed := pkceEntryPointDisposition[name]
		if !listed {
			t.Errorf("%s takes a code_challenge from a request but is not in pkceEntryPointDisposition. "+
				"Either call validatePKCERequest in it and record it as \"enforces\", or add a specific reason it is exempt", name)
			continue
		}
		if reason == "enforces" && !enforces[name] {
			t.Errorf("%s is recorded as enforcing PKCE but does not call validatePKCERequest", name)
		}
	}
	for name, reason := range pkceEntryPointDisposition {
		if !found[name] {
			t.Errorf("pkceEntryPointDisposition lists %s (%q) but it no longer reads a request-supplied code_challenge — remove the stale entry", name, reason)
		}
	}
}
