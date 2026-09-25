package provisioning

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// An RFC 7643 / RFC 7644 compliance test of the inbound SCIM server, through
// the real routes -- the real bearer-token middleware included -- against a
// migrated PostgreSQL. It covers what the issue asks a SCIM compliance suite
// to cover: create, read, replace, patch and delete of Users and Groups,
// filtering, PATCH semantics, pagination, discovery, and ETags as far as
// /ServiceProviderConfig claims them (it claims none, and the test holds the
// server to that).
//
// The requests are the shapes Microsoft Entra ID and Okta send: capitalised
// PATCH ops, "active" as a string, emails[type eq "work"].value, and
// members[value eq "..."] removals.

const scimTestOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations

type scimHarness struct {
	t      *testing.T
	svc    *Service
	router *gin.Engine
	token  string
	key    *rsa.PrivateKey
}

func newSCIMHarness(t *testing.T) *scimHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil
	}
	t.Cleanup(cleanup)
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(context.Background(), -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)

	cfg := &config.Config{OAuthIssuer: "https://issuer.example.test", OAuthJWKSURL: jwks.URL}
	h := &scimHarness{t: t, svc: NewService(db, nil, cfg, zap.NewNop()), key: key}
	h.token = h.mint(key, cfg.OAuthIssuer)

	h.router = gin.New()
	h.router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: scimTestOrg}))
		c.Next()
	})
	RegisterRoutes(h.router, h.svc)
	return h
}

func (h *scimHarness) mint(key *rsa.PrivateKey, issuer string) string {
	h.t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "sub": "scim-client", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(key)
	require.NoError(h.t, err)
	return tok
}

type scimResp struct {
	code   int
	header http.Header
	raw    []byte
	body   map[string]interface{}
}

func (r scimResp) str(key string) string {
	v, _ := r.body[key].(string)
	return v
}

func (h *scimHarness) call(method, path string, body interface{}, token ...string) scimResp {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(h.t, err)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "idp.example.test"
	if rd != nil {
		req.Header.Set("Content-Type", scimMediaType)
	}
	tok := h.token
	if len(token) > 0 {
		tok = token[0]
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	out := scimResp{code: w.Code, header: w.Header(), raw: w.Body.Bytes()}
	if len(out.raw) > 0 {
		_ = json.Unmarshal(out.raw, &out.body)
	}
	return out
}

// expect fails unless the response has the status, and checks the envelope
// every SCIM response shares: the media type, and on an error the RFC 7644
// §3.12 schema with the status as a string and, when asked, the scimType.
func (h *scimHarness) expect(r scimResp, code int, scimType string) {
	h.t.Helper()
	require.Equalf(h.t, code, r.code, "status; body: %s", r.raw)
	if code == http.StatusNoContent {
		require.Empty(h.t, r.raw, "a 204 carries no body")
		return
	}
	require.Truef(h.t, strings.HasPrefix(r.header.Get("Content-Type"), scimMediaType),
		"Content-Type %q, want %s", r.header.Get("Content-Type"), scimMediaType)
	if code >= 400 {
		require.Equal(h.t, []interface{}{"urn:ietf:params:scim:api:messages:2.0:Error"}, r.body["schemas"], "error schema")
		require.Equal(h.t, fmt.Sprint(code), r.str("status"), "error status is the HTTP status, as a string")
		if scimType != "" {
			require.Equal(h.t, scimType, r.str("scimType"))
		}
	}
}

func resources(r scimResp) []map[string]interface{} {
	raw, _ := r.body["Resources"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(map[string]interface{}))
	}
	return out
}

func memberValues(res map[string]interface{}) []string {
	raw, _ := res["members"].([]interface{})
	var out []string
	for _, m := range raw {
		out = append(out, m.(map[string]interface{})["value"].(string))
	}
	sort.Strings(out)
	return out
}

func sorted(v ...string) []string {
	sort.Strings(v)
	return v
}

func patchOp(ops ...map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops}
}

func op(kind, path string, value interface{}) map[string]interface{} {
	o := map[string]interface{}{"op": kind}
	if path != "" {
		o["path"] = path
	}
	if value != nil {
		o["value"] = value
	}
	return o
}

func newUser(userName, email, externalID string) map[string]interface{} {
	u := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName,
		"name":     map[string]string{"givenName": "Grace", "familyName": "Hopper"},
		"emails":   []map[string]interface{}{{"value": email, "type": "work", "primary": true}},
	}
	if externalID != "" {
		u["externalId"] = externalID
	}
	return u
}

func (h *scimHarness) createUser(userName string) string {
	h.t.Helper()
	r := h.call(http.MethodPost, "/scim/v2/Users", newUser(userName, userName+"@example.test", "ext-"+userName))
	h.expect(r, http.StatusCreated, "")
	return r.str("id")
}

func TestSCIMServerDiscoveryIsRFC7644(t *testing.T) {
	h := newSCIMHarness(t)
	if h == nil {
		return
	}

	t.Run("ServiceProviderConfig claims only what the server does", func(t *testing.T) {
		r := h.call(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
		h.expect(r, http.StatusOK, "")
		require.Equal(t, []interface{}{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, r.body["schemas"])
		supported := func(feature string) bool {
			f, ok := r.body[feature].(map[string]interface{})
			require.Truef(t, ok, "%s is required (RFC 7643 §5)", feature)
			b, ok := f["supported"].(bool)
			require.Truef(t, ok, "%s.supported is required", feature)
			return b
		}
		require.True(t, supported("patch"))
		require.True(t, supported("filter"))
		require.EqualValues(t, scimMaxResults, r.body["filter"].(map[string]interface{})["maxResults"])
		// The server implements none of these; claiming one is a promise a
		// client would act on.
		require.False(t, supported("bulk"))
		require.False(t, supported("sort"))
		require.False(t, supported("changePassword"))
		require.False(t, supported("etag"))
		schemes, _ := r.body["authenticationSchemes"].([]interface{})
		require.NotEmpty(t, schemes)
		for _, s := range schemes {
			m := s.(map[string]interface{})
			for _, k := range []string{"type", "name", "description"} {
				require.NotEmptyf(t, m[k], "authenticationSchemes[].%s is required", k)
			}
		}
	})

	t.Run("ResourceTypes is a ListResponse of ResourceType resources", func(t *testing.T) {
		r := h.call(http.MethodGet, "/scim/v2/ResourceTypes", nil)
		h.expect(r, http.StatusOK, "")
		require.Equal(t, []interface{}{scimSchemaListResp}, r.body["schemas"])
		byID := map[string]map[string]interface{}{}
		for _, rt := range resources(r) {
			byID[rt["id"].(string)] = rt
		}
		require.Equal(t, "/Users", byID["User"]["endpoint"])
		require.Equal(t, scimSchemaUser, byID["User"]["schema"])
		require.Equal(t, "/Groups", byID["Group"]["endpoint"])
		require.Equal(t, scimSchemaGroup, byID["Group"]["schema"])
		one := h.call(http.MethodGet, "/scim/v2/ResourceTypes/User", nil)
		h.expect(one, http.StatusOK, "")
		require.Equal(t, "User", one.str("id"))
		h.expect(h.call(http.MethodGet, "/scim/v2/ResourceTypes/Printer", nil), http.StatusNotFound, "")
	})

	t.Run("Schemas lists the User and Group schemas", func(t *testing.T) {
		r := h.call(http.MethodGet, "/scim/v2/Schemas", nil)
		h.expect(r, http.StatusOK, "")
		var ids []string
		for _, s := range resources(r) {
			ids = append(ids, s["id"].(string))
		}
		require.ElementsMatch(t, []string{scimSchemaUser, scimSchemaGroup}, ids)
		one := h.call(http.MethodGet, "/scim/v2/Schemas/"+scimSchemaUser, nil)
		h.expect(one, http.StatusOK, "")
		require.NotEmpty(t, one.body["attributes"])
		h.expect(h.call(http.MethodGet, "/scim/v2/Schemas/urn:nope", nil), http.StatusNotFound, "")
	})

	t.Run("no token, or a token from another key, is refused", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/scim/v2/Users", nil, "").code)
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		forged := h.mint(other, "https://issuer.example.test")
		require.Equal(t, http.StatusUnauthorized, h.call(http.MethodGet, "/scim/v2/Users", nil, forged).code)
	})
}

func TestSCIMServerUsersAreRFC7644(t *testing.T) {
	h := newSCIMHarness(t)
	if h == nil {
		return
	}

	var id string
	t.Run("POST creates: 201, Location, the stored representation", func(t *testing.T) {
		r := h.call(http.MethodPost, "/scim/v2/Users", newUser("bjensen", "bjensen@example.test", "701984"))
		h.expect(r, http.StatusCreated, "")
		id = r.str("id")
		require.NotEmpty(t, id)
		meta := r.body["meta"].(map[string]interface{})
		require.Equal(t, "User", meta["resourceType"])
		require.Equal(t, "http://idp.example.test/scim/v2/Users/"+id, meta["location"])
		require.Equal(t, meta["location"], r.header.Get("Location"), "Location header equals meta.location (RFC 7644 §3.3)")
		require.Contains(t, r.body["schemas"], scimSchemaUser)
		require.Equal(t, "bjensen", r.str("userName"))
		require.Equal(t, "701984", r.str("externalId"))
		require.Equal(t, true, r.body["active"], "active defaults to true when the client leaves it out")
		require.Equal(t, "Grace", r.body["name"].(map[string]interface{})["givenName"])
	})

	t.Run("GET reads it back", func(t *testing.T) {
		r := h.call(http.MethodGet, "/scim/v2/Users/"+id, nil)
		h.expect(r, http.StatusOK, "")
		require.Equal(t, id, r.str("id"))
		require.Equal(t, "701984", r.str("externalId"))
		require.Equal(t, "bjensen@example.test", r.body["emails"].([]interface{})[0].(map[string]interface{})["value"])
	})

	t.Run("POST refuses what it cannot store", func(t *testing.T) {
		h.expect(h.call(http.MethodPost, "/scim/v2/Users", newUser("bjensen", "other@example.test", "")), http.StatusConflict, scimTypeUniqueness)
		h.expect(h.call(http.MethodPost, "/scim/v2/Users", newUser("", "x@example.test", "")), http.StatusBadRequest, scimTypeInvalidValue)
		h.expect(h.call(http.MethodPost, "/scim/v2/Users", `{"userName": `), http.StatusBadRequest, scimTypeInvalidSyntax)
	})

	t.Run("an unknown id is 404 for every method", func(t *testing.T) {
		unknown := "/scim/v2/Users/00000000-0000-4000-8000-00000000dead"
		h.expect(h.call(http.MethodGet, unknown, nil), http.StatusNotFound, "")
		h.expect(h.call(http.MethodGet, "/scim/v2/Users/not-a-uuid", nil), http.StatusNotFound, "")
		h.expect(h.call(http.MethodPut, unknown, newUser("ghost", "ghost@example.test", "")), http.StatusNotFound, "")
		h.expect(h.call(http.MethodPatch, unknown, patchOp(op("replace", "active", false))), http.StatusNotFound, "")
		h.expect(h.call(http.MethodDelete, unknown, nil), http.StatusNotFound, "")
	})

	t.Run("PUT replaces", func(t *testing.T) {
		u := newUser("bjensen", "babs@example.test", "701985")
		u["name"] = map[string]string{"givenName": "Barbara", "familyName": "Jensen"}
		r := h.call(http.MethodPut, "/scim/v2/Users/"+id, u)
		h.expect(r, http.StatusOK, "")
		require.Equal(t, "701985", r.str("externalId"))
		require.Equal(t, "Barbara", r.body["name"].(map[string]interface{})["givenName"])
		g := h.call(http.MethodGet, "/scim/v2/Users/"+id, nil)
		require.Equal(t, "babs@example.test", g.body["emails"].([]interface{})[0].(map[string]interface{})["value"])
	})

	t.Run("PATCH semantics", func(t *testing.T) {
		patch := func(ops ...map[string]interface{}) scimResp {
			return h.call(http.MethodPatch, "/scim/v2/Users/"+id, patchOp(ops...))
		}
		r := patch(op("replace", "active", false))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, false, r.body["active"])

		// A PUT that says nothing about active leaves it alone.
		r = h.call(http.MethodPut, "/scim/v2/Users/"+id, newUser("bjensen", "babs@example.test", "701985"))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, false, r.body["active"], "a PUT without active must not re-enable the account")

		// Microsoft Entra: capitalised op, active as a string.
		r = patch(op("Replace", "active", "True"))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, true, r.body["active"])

		// No path: the value is attributes of the resource itself.
		r = patch(op("replace", "", map[string]interface{}{"externalId": "702000", "name": map[string]interface{}{"familyName": "Jensen-Smith"}}))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, "702000", r.str("externalId"))
		require.Equal(t, "Jensen-Smith", r.body["name"].(map[string]interface{})["familyName"])
		require.Equal(t, "Grace", r.body["name"].(map[string]interface{})["givenName"], "a replace of one sub-attribute keeps the others")

		r = patch(op("Replace", `emails[type eq "work"].value`, "barbara@example.test"))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, "barbara@example.test", r.body["emails"].([]interface{})[0].(map[string]interface{})["value"])

		r = patch(op("replace", "name.givenName", "Babs"), op("replace", "userName", "babs"))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, "babs", r.str("userName"), "several operations apply in order, in one request")

		before := h.call(http.MethodGet, "/scim/v2/Users/"+id, nil).raw
		h.expect(patch(op("remove", "", nil)), http.StatusBadRequest, scimTypeNoTarget)
		h.expect(patch(op("replace", "nickName", "Babs")), http.StatusBadRequest, scimTypeInvalidPath)
		h.expect(patch(op("replace", "active", "maybe")), http.StatusBadRequest, scimTypeInvalidValue)
		h.expect(patch(op("move", "active", false)), http.StatusBadRequest, "")
		h.expect(h.call(http.MethodPatch, "/scim/v2/Users/"+id, patchOp()), http.StatusBadRequest, "")
		// A refused PATCH changes nothing, not even the operations before
		// the one that failed.
		h.expect(patch(op("replace", "userName", "renamed"), op("replace", "nickName", "x")), http.StatusBadRequest, scimTypeInvalidPath)
		require.JSONEq(t, string(before), string(h.call(http.MethodGet, "/scim/v2/Users/"+id, nil).raw))
	})

	t.Run("DELETE: 204, then gone", func(t *testing.T) {
		h.expect(h.call(http.MethodDelete, "/scim/v2/Users/"+id, nil), http.StatusNoContent, "")
		h.expect(h.call(http.MethodGet, "/scim/v2/Users/"+id, nil), http.StatusNotFound, "")
		h.expect(h.call(http.MethodDelete, "/scim/v2/Users/"+id, nil), http.StatusNotFound, "")
	})
}

func TestSCIMServerFilteringAndPagination(t *testing.T) {
	h := newSCIMHarness(t)
	if h == nil {
		return
	}
	const n = 7
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, h.createUser(fmt.Sprintf("page-user-%02d", i)))
	}

	list := func(query string) scimResp {
		return h.call(http.MethodGet, "/scim/v2/Users?"+query, nil)
	}

	t.Run("filters", func(t *testing.T) {
		for _, tc := range []struct {
			filter string
			want   []string
		}{
			{`userName eq "page-user-03"`, []string{ids[3]}},
			{`userName eq "PAGE-USER-03"`, []string{ids[3]}}, // userName is caseExact=false
			{`externalId eq "ext-page-user-04"`, []string{ids[4]}},
			{`emails.value eq "page-user-05@example.test"`, []string{ids[5]}},
			{`userName eq "nobody"`, nil},
		} {
			r := list("filter=" + url.QueryEscape(tc.filter))
			h.expect(r, http.StatusOK, "")
			require.Equal(t, []interface{}{scimSchemaListResp}, r.body["schemas"])
			require.EqualValuesf(t, len(tc.want), r.body["totalResults"], "filter %s", tc.filter)
			var got []string
			for _, res := range resources(r) {
				got = append(got, res["id"].(string))
			}
			require.Equal(t, tc.want, got, "filter %s", tc.filter)
			if len(tc.want) == 0 {
				require.Equal(t, "[]", strings.TrimSpace(string(mustJSON(t, r.body["Resources"]))), "an empty page is Resources: [], not null")
			}
		}
		for _, f := range []string{`userName co "page"`, `userName eq "a" and active eq true`, `title eq "x"`, `userName`} {
			h.expect(list("filter="+url.QueryEscape(f)), http.StatusBadRequest, scimTypeInvalidFilter)
		}
	})

	t.Run("pages visit every user exactly once", func(t *testing.T) {
		total := int(list("count=0").body["totalResults"].(float64))
		require.GreaterOrEqual(t, total, n)
		seen := map[string]bool{}
		for start := 1; start <= total; start += 3 {
			r := list(fmt.Sprintf("startIndex=%d&count=3", start))
			h.expect(r, http.StatusOK, "")
			require.EqualValues(t, total, r.body["totalResults"])
			require.EqualValues(t, start, r.body["startIndex"])
			page := resources(r)
			require.EqualValues(t, len(page), r.body["itemsPerPage"])
			require.LessOrEqual(t, len(page), 3)
			for _, res := range page {
				id := res["id"].(string)
				require.Falsef(t, seen[id], "user %s appeared on two pages", id)
				seen[id] = true
			}
		}
		require.Len(t, seen, total)
		for _, id := range ids {
			require.True(t, seen[id])
		}
	})

	t.Run("paging parameters are clamped as RFC 7644 §3.4.2.4 says", func(t *testing.T) {
		r := list("count=0")
		h.expect(r, http.StatusOK, "")
		require.Empty(t, resources(r), "count=0 returns totalResults only")
		require.Positive(t, r.body["totalResults"].(float64))

		r = list("startIndex=0&count=2")
		h.expect(r, http.StatusOK, "")
		require.EqualValues(t, 1, r.body["startIndex"], "a startIndex below 1 is 1")
		require.Len(t, resources(r), 2)

		r = list("startIndex=-5&count=-1")
		h.expect(r, http.StatusOK, "")
		require.Empty(t, resources(r), "a negative count is 0")

		r = list("count=100000")
		h.expect(r, http.StatusOK, "")
		require.LessOrEqual(t, len(resources(r)), scimMaxResults)

		h.expect(list("count=many"), http.StatusBadRequest, scimTypeInvalidValue)
	})
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestSCIMServerGroupsAreRFC7644(t *testing.T) {
	h := newSCIMHarness(t)
	if h == nil {
		return
	}
	alice, bob := h.createUser("grp-alice"), h.createUser("grp-bob")

	var id string
	t.Run("POST creates with members", func(t *testing.T) {
		r := h.call(http.MethodPost, "/scim/v2/Groups", map[string]interface{}{
			"schemas": []string{scimSchemaGroup}, "displayName": "Tour Guides", "externalId": "g-1",
			"members": []map[string]string{{"value": alice}},
		})
		h.expect(r, http.StatusCreated, "")
		id = r.str("id")
		require.Equal(t, r.body["meta"].(map[string]interface{})["location"], r.header.Get("Location"))
		require.Equal(t, "g-1", r.str("externalId"))
		require.Equal(t, []string{alice}, memberValues(r.body))
		require.Equal(t, "grp-alice", r.body["members"].([]interface{})[0].(map[string]interface{})["display"])
	})

	t.Run("POST refuses what it cannot store", func(t *testing.T) {
		h.expect(h.call(http.MethodPost, "/scim/v2/Groups", map[string]interface{}{"displayName": "Tour Guides"}), http.StatusConflict, scimTypeUniqueness)
		h.expect(h.call(http.MethodPost, "/scim/v2/Groups", map[string]interface{}{"displayName": " "}), http.StatusBadRequest, scimTypeInvalidValue)
	})

	t.Run("GET, list and filter", func(t *testing.T) {
		r := h.call(http.MethodGet, "/scim/v2/Groups/"+id, nil)
		h.expect(r, http.StatusOK, "")
		require.Equal(t, []string{alice}, memberValues(r.body))
		for _, f := range []string{`displayName eq "tour guides"`, `externalId eq "g-1"`} {
			l := h.call(http.MethodGet, "/scim/v2/Groups?filter="+url.QueryEscape(f), nil)
			h.expect(l, http.StatusOK, "")
			require.Len(t, resources(l), 1, f)
			require.Equal(t, []string{alice}, memberValues(resources(l)[0]), "the list returns members, which are returned by default")
		}
		l := h.call(http.MethodGet, "/scim/v2/Groups?excludedAttributes=members", nil)
		h.expect(l, http.StatusOK, "")
		require.NotEmpty(t, resources(l))
		require.Nil(t, resources(l)[0]["members"], "excludedAttributes=members leaves them out")
		h.expect(h.call(http.MethodGet, "/scim/v2/Groups?filter="+url.QueryEscape(`displayName sw "Tour"`), nil), http.StatusBadRequest, scimTypeInvalidFilter)
	})

	patch := func(ops ...map[string]interface{}) scimResp {
		return h.call(http.MethodPatch, "/scim/v2/Groups/"+id, patchOp(ops...))
	}
	t.Run("PATCH membership", func(t *testing.T) {
		r := patch(op("Add", "members", []map[string]string{{"value": bob}}))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, sorted(alice, bob), memberValues(r.body))

		r = patch(op("remove", fmt.Sprintf(`members[value eq "%s"]`, alice), nil))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, []string{bob}, memberValues(r.body))

		r = patch(op("remove", "members", []map[string]string{{"value": bob}}))
		h.expect(r, http.StatusOK, "")
		require.Empty(t, memberValues(r.body))

		r = patch(op("replace", "members", []map[string]string{{"value": alice}, {"value": bob}}))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, sorted(alice, bob), memberValues(r.body))

		// A change to another attribute leaves the members alone.
		r = patch(op("replace", "", map[string]interface{}{"displayName": "Guides"}))
		h.expect(r, http.StatusOK, "")
		require.Equal(t, "Guides", r.str("displayName"))
		require.Equal(t, sorted(alice, bob), memberValues(r.body))

		r = patch(op("remove", "members", nil))
		h.expect(r, http.StatusOK, "")
		require.Empty(t, memberValues(r.body))

		h.expect(patch(op("replace", "owner", "x")), http.StatusBadRequest, scimTypeInvalidPath)
		h.expect(patch(op("add", fmt.Sprintf(`members[value eq "%s"]`, alice), nil)), http.StatusBadRequest, scimTypeInvalidPath)
		h.expect(patch(op("remove", "", nil)), http.StatusBadRequest, scimTypeNoTarget)
	})

	t.Run("PUT replaces, members included", func(t *testing.T) {
		patch(op("add", "members", []map[string]string{{"value": alice}}))
		r := h.call(http.MethodPut, "/scim/v2/Groups/"+id, map[string]interface{}{"schemas": []string{scimSchemaGroup}, "displayName": "Guides"})
		h.expect(r, http.StatusOK, "")
		require.Empty(t, memberValues(r.body), "a PUT without members is a group without members")
		h.expect(h.call(http.MethodPut, "/scim/v2/Groups/00000000-0000-4000-8000-00000000dead", map[string]interface{}{"displayName": "x"}), http.StatusNotFound, "")
	})

	t.Run("deleting a user takes them out of the group", func(t *testing.T) {
		patch(op("add", "members", []map[string]string{{"value": alice}, {"value": bob}}))
		h.expect(h.call(http.MethodDelete, "/scim/v2/Users/"+alice, nil), http.StatusNoContent, "")
		require.Equal(t, []string{bob}, memberValues(h.call(http.MethodGet, "/scim/v2/Groups/"+id, nil).body))
	})

	t.Run("DELETE: 204, then gone", func(t *testing.T) {
		h.expect(h.call(http.MethodDelete, "/scim/v2/Groups/"+id, nil), http.StatusNoContent, "")
		h.expect(h.call(http.MethodGet, "/scim/v2/Groups/"+id, nil), http.StatusNotFound, "")
		h.expect(h.call(http.MethodDelete, "/scim/v2/Groups/"+id, nil), http.StatusNotFound, "")
	})

	t.Run("no ETags, because none are claimed", func(t *testing.T) {
		// /ServiceProviderConfig says etag.supported=false (the discovery test
		// holds it to that). A server that sent ETags or honoured If-Match
		// while saying so would be half a feature a client cannot rely on.
		r := h.call(http.MethodGet, "/scim/v2/Users/"+bob, nil)
		h.expect(r, http.StatusOK, "")
		require.Empty(t, r.header.Get("ETag"))
		require.Nil(t, r.body["meta"].(map[string]interface{})["version"])
	})
}

// --- Outbound ---------------------------------------------------------------

// scimTarget is a downstream SCIM service provider that records what it is
// sent.
type scimTarget struct {
	mu       sync.Mutex
	requests []recordedSCIMRequest
	next     int
}

type recordedSCIMRequest struct {
	method, path, auth, contentType string
	body                            map[string]interface{}
}

func (st *scimTarget) handler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rec := recordedSCIMRequest{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type")}
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &rec.body)
	}
	st.requests = append(st.requests, rec)
	w.Header().Set("Content-Type", scimMediaType)
	switch r.Method {
	case http.MethodPost:
		st.next++
		rec.body["id"] = fmt.Sprintf("remote-%d", st.next)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rec.body)
	case http.MethodPut:
		_ = json.NewEncoder(w).Encode(rec.body)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// take returns and forgets what the target has been sent.
func (st *scimTarget) take() []recordedSCIMRequest {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.requests
	st.requests = nil
	return out
}

func remoteMembers(body map[string]interface{}) []string {
	return memberValues(body)
}

func TestSCIMOutboundProvisionsToATarget(t *testing.T) {
	h := newSCIMHarness(t)
	if h == nil {
		return
	}
	target := &scimTarget{}
	srv := httptest.NewServer(http.HandlerFunc(target.handler))
	t.Cleanup(srv.Close)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimTestOrg})
	_, err := h.svc.CreateTargetApp(ctx, scimTestOrg, &TargetAppInput{
		Name: "recording-target", BaseURL: srv.URL + "/scim/v2", AuthType: "bearer", BearerToken: "downstream-token",
		ProvisionUsers: true, ProvisionGroups: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	require.NoError(t, err)

	worker := &outboundWorker{svc: h.svc, cfg: outboundWorkerConfigDefaults(), logger: zap.NewNop()}
	drain := func() []recordedSCIMRequest {
		t.Helper()
		for {
			n, err := worker.drainBatch(orgctx.WithBypassRLS(context.Background()))
			require.NoError(t, err)
			if n == 0 {
				break
			}
		}
		var stuck int
		require.NoError(t, h.svc.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
			`SELECT count(*) FROM scim_provisioning_queue WHERE state <> 'done'`).Scan(&stuck))
		require.Zero(t, stuck, "every outbound operation was delivered")
		return target.take()
	}
	one := func(reqs []recordedSCIMRequest, method, path string) recordedSCIMRequest {
		t.Helper()
		var found []recordedSCIMRequest
		for _, r := range reqs {
			if r.method == method && r.path == path {
				found = append(found, r)
			}
		}
		require.Lenf(t, found, 1, "%s %s among %+v", method, path, reqs)
		require.Equal(t, "Bearer downstream-token", found[0].auth)
		if found[0].body != nil {
			require.True(t, strings.HasPrefix(found[0].contentType, scimMediaType))
		}
		return found[0]
	}

	var alice, bob string
	var remoteAlice, remoteBob, remoteGroup string
	t.Run("create", func(t *testing.T) {
		alice, bob = h.createUser("out-alice"), h.createUser("out-bob")
		reqs := drain()
		require.Len(t, reqs, 2)
		for _, r := range reqs {
			require.Equal(t, http.MethodPost, r.method)
			require.Equal(t, "/scim/v2/Users", r.path)
			require.Equal(t, true, r.body["active"])
			switch r.body["externalId"] {
			case alice:
				require.Equal(t, "out-alice", r.body["userName"])
				require.Equal(t, "out-alice@example.test", r.body["emails"].([]interface{})[0].(map[string]interface{})["value"])
				remoteAlice = r.body["id"].(string)
			case bob:
				remoteBob = r.body["id"].(string)
			default:
				t.Fatalf("a user created downstream without its local id as externalId: %+v", r.body)
			}
		}
		require.NotEmpty(t, remoteAlice)
		require.NotEmpty(t, remoteBob)
	})

	t.Run("update", func(t *testing.T) {
		h.expect(h.call(http.MethodPatch, "/scim/v2/Users/"+alice, patchOp(op("replace", "name.familyName", "Liddell"))), http.StatusOK, "")
		r := one(drain(), http.MethodPut, "/scim/v2/Users/"+remoteAlice)
		require.Equal(t, "Liddell", r.body["name"].(map[string]interface{})["familyName"])
		require.Equal(t, alice, r.body["externalId"])
	})

	t.Run("group membership", func(t *testing.T) {
		g := h.call(http.MethodPost, "/scim/v2/Groups", map[string]interface{}{
			"displayName": "Outbound Crew", "members": []map[string]string{{"value": alice}}})
		h.expect(g, http.StatusCreated, "")
		gid := g.str("id")
		r := one(drain(), http.MethodPost, "/scim/v2/Groups")
		require.Equal(t, "Outbound Crew", r.body["displayName"])
		require.Equal(t, gid, r.body["externalId"])
		require.Equal(t, []string{remoteAlice}, remoteMembers(r.body), "the downstream group names the downstream user")
		remoteGroup = r.body["id"].(string)

		h.expect(h.call(http.MethodPatch, "/scim/v2/Groups/"+gid, patchOp(op("add", "members", []map[string]string{{"value": bob}}))), http.StatusOK, "")
		r = one(drain(), http.MethodPut, "/scim/v2/Groups/"+remoteGroup)
		require.Equal(t, sorted(remoteAlice, remoteBob), remoteMembers(r.body))

		h.expect(h.call(http.MethodPatch, "/scim/v2/Groups/"+gid, patchOp(op("remove", fmt.Sprintf(`members[value eq "%s"]`, alice), nil))), http.StatusOK, "")
		r = one(drain(), http.MethodPut, "/scim/v2/Groups/"+remoteGroup)
		require.Equal(t, []string{remoteBob}, remoteMembers(r.body))

		h.expect(h.call(http.MethodDelete, "/scim/v2/Groups/"+gid, nil), http.StatusNoContent, "")
		one(drain(), http.MethodDelete, "/scim/v2/Groups/"+remoteGroup)
	})

	t.Run("deactivate", func(t *testing.T) {
		h.expect(h.call(http.MethodPatch, "/scim/v2/Users/"+bob, patchOp(op("replace", "active", false))), http.StatusOK, "")
		r := one(drain(), http.MethodPatch, "/scim/v2/Users/"+remoteBob)
		ops := r.body["Operations"].([]interface{})
		require.Len(t, ops, 1)
		o := ops[0].(map[string]interface{})
		require.Equal(t, "replace", o["op"])
		require.Equal(t, "active", o["path"])
		require.Equal(t, false, o["value"])
	})

	t.Run("delete", func(t *testing.T) {
		h.expect(h.call(http.MethodDelete, "/scim/v2/Users/"+alice, nil), http.StatusNoContent, "")
		one(drain(), http.MethodDelete, "/scim/v2/Users/"+remoteAlice)
	})
}
