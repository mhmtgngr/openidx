package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/cell"
)

// CELL.GUARD'S BLIND SPOT: THE MOUNT IS MEASURED, WHAT CAN REACH IT IS NOT.
//
// cmd/cell_guard_census_test.go records which binaries mount cell.Guard, and it
// reads that off the text of main.go. That was the right thing to measure once
// -- a guard nothing mounts is the shape this branch keeps finding -- but it
// says nothing about the question underneath: the guard refuses a request by
// reading ONE key out of the gin context, and only some of the ways a caller
// can authenticate ever put anything there.
//
// That gap already produced a defect once. identity-service's authentication
// middleware bound roles by hand and never bound the cell claim, so mounting
// the guard there would have produced a service that answers 200 to every
// misdirected request while the census recorded it as guarded. The fix was
// BindSubjectClaims; what was NOT fixed is that nothing measures the property
// -- the census would have gone on reporting success either way.
//
// So this is a census of CREDENTIAL KINDS rather than of mounts: for every way
// this package lets a caller authenticate, is a misdirected credential refused,
// and if not, WHY NOT. Two of the three cannot be refused, and both reasons are
// real -- but they were nowhere written down, which is the part that mattered:
// an operator reading "access-service mounts cell.Guard" has no way to learn
// that one of its two authenticated paths can never produce a 421.
//
// WHAT IS LATENT HERE AND WHAT IS LIVE. Nothing below is a live defect. The
// API-key exemption is correct today for the reason recorded against it. What
// is live is only the silence: the exemptions are now measured, so a change
// that makes one of them false fails the build instead of shipping.

// guardBlindTo is the register: credential kinds cell.Guard cannot refuse, with
// the reason. The list only shrinks -- a kind that becomes refusable fails the
// run below, and a kind not listed here must be refused.
var guardBlindTo = map[string]string{
	"api_key": "An API key is not minted by a cell and carries no claims: AuthWithAPIKey looks it " +
		"up by its globally-unique hash in THIS process's own database (internal/apikeys " +
		"ValidateAPIKey) and binds user_id, org_id, scopes and roles from the row. So a key that " +
		"validated here IS a row this cell holds, and there is nothing misdirected to refuse. The " +
		"cost is on the other side and is NOT fixable here: a valid key belonging to a tenant in " +
		"another cell is simply absent from this database, so it comes back 401 'invalid API key' " +
		"-- a credential error for what is really a routing error. Telling those two apart needs " +
		"the tenant directory (internal/common/celldir), and cell.Guard deliberately has no " +
		"database dependency; the edge is where that lookup belongs.",
	"anonymous": "SoftAuth passes a request with no Authorization header straight through, which is " +
		"its whole purpose. A request that names no caller names no tenant either, so there is no " +
		"cell it could have been misdirected from. Whatever it reaches has to be safe to serve " +
		"unauthenticated regardless of which cell answered.",
}

// censusKey is generated once: RSA keygen dominates this file's runtime.
var censusKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// censusAPIKeys validates any key at all, so what is measured is the branch the
// middleware takes rather than a lookup.
type censusAPIKeys struct{}

func (censusAPIKeys) ValidateAPIKey(_ context.Context, _ string) (*APIKeyInfo, error) {
	return &APIKeyInfo{KeyID: "k-census", ServiceAccountID: "sa-census", OrgID: "org-census"}, nil
}

// credential is one way a caller can authenticate against this package.
type credential struct {
	kind string
	// auth is the middleware a service mounts in front of cell.Guard.
	auth func(jwksURL string) gin.HandlerFunc
	// authorization is the header value, given the cell the credential names.
	// An empty return means the request carries no Authorization header.
	authorization func(t *testing.T, mintedIn string) string
}

func credentialKinds() []credential {
	return []credential{
		{
			kind: "jwt",
			auth: Auth,
			authorization: func(t *testing.T, mintedIn string) string {
				return "Bearer " + censusToken(t, mintedIn)
			},
		},
		{
			// The same middleware, on its JWT branch: Auth is literally
			// AuthWithAPIKey(jwksURL, nil), and access-service mounts the
			// validator form. Measured separately because the API-key branch
			// returns before the JWT branch is reached, and a change there
			// could take the cell claim with it.
			kind: "jwt_via_apikey_middleware",
			auth: func(jwksURL string) gin.HandlerFunc {
				return AuthWithAPIKey(jwksURL, censusAPIKeys{})
			},
			authorization: func(t *testing.T, mintedIn string) string {
				return "Bearer " + censusToken(t, mintedIn)
			},
		},
		{
			kind: "jwt_soft",
			auth: SoftAuth,
			authorization: func(t *testing.T, mintedIn string) string {
				return "Bearer " + censusToken(t, mintedIn)
			},
		},
		{
			kind: "api_key",
			auth: func(jwksURL string) gin.HandlerFunc {
				return AuthWithAPIKey(jwksURL, censusAPIKeys{})
			},
			// An API key has no cell to name; that is the point of the entry.
			authorization: func(_ *testing.T, _ string) string { return "Bearer oidx_census" },
		},
		{
			kind:          "anonymous",
			auth:          SoftAuth,
			authorization: func(_ *testing.T, _ string) string { return "" },
		},
	}
}

func censusToken(t *testing.T, mintedIn string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":    "11111111-1111-1111-1111-111111111111",
		"org_id": "22222222-2222-2222-2222-222222222222",
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	if mintedIn != "" {
		claims[cell.Claim] = mintedIn
	}
	return signRS256(t, censusKey, "census-kid", claims)
}

// callWith mounts auth then cell.Guard, exactly the order every binary uses,
// and reports the status and whether the handler ran.
func callWith(t *testing.T, c credential, serving, mintedIn string) (status int, served bool) {
	t.Helper()
	jwks := newFlippableJWKSServer(t, "census-kid", censusKey.Public().(*rsa.PublicKey))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(c.auth(jwks.srv.URL))
	r.Use(cell.Guard(serving, nil))
	r.GET("/probe", func(ctx *gin.Context) {
		served = true
		ctx.String(http.StatusOK, "served")
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if h := c.authorization(t, mintedIn); h != "" {
		req.Header.Set("Authorization", h)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, served
}

// EVERY CREDENTIAL KIND IS EITHER REFUSED WHEN IT NAMES ANOTHER CELL, OR
// REGISTERED WITH THE REASON IT CANNOT BE.
func TestEveryCredentialKindIsRefusedOrRegistered(t *testing.T) {
	for _, c := range credentialKinds() {
		c := c
		t.Run(c.kind, func(t *testing.T) {
			status, served := callWith(t, c, "eu-1", "us-1")
			_, registered := guardBlindTo[c.kind]

			if !registered {
				if status != http.StatusMisdirectedRequest {
					t.Fatalf("a %s credential minted in us-1 reached a process serving eu-1 and got %d, not 421.\n"+
						"cell.Guard refuses by reading the %q key out of the gin context, and only an "+
						"authentication middleware puts it there. Either this path stopped binding the claim "+
						"-- in which case every misdirected request is being served while the mount census "+
						"still reports this service as guarded -- or the kind belongs in guardBlindTo WITH "+
						"THE REASON.", c.kind, status, cell.Claim)
				}
				if served {
					t.Errorf("%s: the handler ran behind a 421", c.kind)
				}
				return
			}

			if status == http.StatusMisdirectedRequest {
				t.Errorf("guardBlindTo says cell.Guard cannot refuse a %s credential, but it just did (421). "+
					"Delete the entry -- the register is one line shorter and the reason is stale.", c.kind)
			}
		})
	}
}

// THE CONTROL. Without it the test above proves only that these paths refuse
// something: a middleware that rejected every request would satisfy it. The
// same credential, naming the cell that is serving, has to be served.
func TestTheSameCredentialNamingTheServingCellIsServed(t *testing.T) {
	for _, c := range credentialKinds() {
		c := c
		t.Run(c.kind, func(t *testing.T) {
			status, served := callWith(t, c, "eu-1", "eu-1")
			if status != http.StatusOK || !served {
				t.Fatalf("a %s credential minted in eu-1 was not served by the process serving eu-1: got %d "+
					"(handler ran: %v). The 421 in the sibling test would then be measuring the "+
					"authentication, not the cell.", c.kind, status, served)
			}
		})
	}
}

// AND THE REGISTER CANNOT NAME A KIND THAT DOES NOT EXIST, which is how a
// register stops describing the tree without anything failing.
func TestTheBlindSpotRegisterDoesNotRot(t *testing.T) {
	known := map[string]bool{}
	for _, c := range credentialKinds() {
		known[c.kind] = true
	}
	var stale []string
	for kind := range guardBlindTo {
		if !known[kind] {
			stale = append(stale, kind)
		}
	}
	sort.Strings(stale)
	for _, kind := range stale {
		t.Errorf("guardBlindTo names the credential kind %q, which credentialKinds no longer produces. "+
			"Either the kind was removed -- delete the line -- or this census stopped seeing a way to "+
			"authenticate, which is worse than the gap it was written to close.", kind)
	}
}

// WHAT THE API-KEY EXEMPTION ACTUALLY LOOKS LIKE, spelled out rather than
// inferred from a status code, because the reason in the register turns on it:
// the guard is not lenient on this path, it is BLIND on it -- the key it reads
// was never set.
func TestAnAPIKeyLeavesTheCellKeyUnset(t *testing.T) {
	jwks := newFlippableJWKSServer(t, "census-kid", censusKey.Public().(*rsa.PublicKey))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthWithAPIKey(jwks.srv.URL, censusAPIKeys{}))

	var present bool
	r.GET("/probe", func(ctx *gin.Context) {
		_, present = ctx.Get(cell.Claim)
		ctx.String(http.StatusOK, "served")
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer oidx_census")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("the API-key path did not authenticate: %d %s", w.Code, w.Body.String())
	}
	if present {
		t.Errorf("the API-key branch now binds %q. That is not a failure -- it means an API key can name "+
			"a cell, so cell.Guard can refuse a misdirected one, so the api_key entry in guardBlindTo is "+
			"wrong and the 401 it describes is fixable after all.", cell.Claim)
	}
}
