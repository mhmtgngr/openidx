package oauth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
)

// txtZone answers TXT lookups from a table, the way the domain's DNS would: the
// records published at each name, and names whose server does not answer.
type txtZone struct {
	mu      sync.Mutex
	records map[string][]string
	broken  map[string]bool
	asked   []string
	// deadline is how long each lookup was given, or -1 for no deadline.
	deadline []time.Duration
}

func newTXTZone() *txtZone {
	return &txtZone{records: map[string][]string{}, broken: map[string]bool{}}
}

func (z *txtZone) publish(name string, values ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.records[name] = values
}

func (z *txtZone) LookupTXT(ctx context.Context, name string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.asked = append(z.asked, name)
	if d, ok := ctx.Deadline(); ok {
		z.deadline = append(z.deadline, time.Until(d))
	} else {
		z.deadline = append(z.deadline, -1)
	}
	if z.broken[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if values, ok := z.records[name]; ok {
		return values, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// tenantRoutes mounts the admin service's route table -- the tenant routes
// among it -- as cmd/admin-api mounts it beside the organization API, with its
// TXT lookups answered by zone.
func (h *tokenHarness) tenantRoutes(zone admin.TXTResolver) func(*gin.RouterGroup) {
	svc := admin.NewService(h.db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	svc.SetTXTResolver(zone)
	return func(v1 *gin.RouterGroup) { admin.RegisterRoutes(v1, svc) }
}

// A TENANT DOMAIN IS VERIFIED ONLY BY ITS DNS RECORD.
//
// A verified tenant domain decides which organization's login-page branding --
// logo, texts, custom CSS -- the public branding endpoint serves at that host.
// Driven through admin.RegisterRoutes behind the chain cmd/admin-api mounts,
// with tokens minted from database rows and the TXT lookups answered by a zone
// the test controls, and read back through identity's public branding endpoint:
//
//   - a claim is verified only when _openidx-challenge.<domain> holds exactly
//     openidx-domain-verification=<its token>; the token echoed back in the
//     request, the bare prefix, the token alone, a near miss and a failing
//     server all leave it unverified, for an organization's admin and for the
//     platform admin alike, and the branding endpoint keeps serving defaults;
//   - a squatter's unverified claim does not stop the domain's owner from
//     claiming it, and the owner's verification removes the squatter's claim
//     and keeps the domain from being claimed again elsewhere;
//   - an organization claims a domain once, and a name that is not a DNS name
//     is refused.
func TestATenantDomainIsVerifiedOnlyByItsDNSRecord(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("dns-a"), h.seedOrg("dns-b")
	adminA := h.accessToken(orgA, h.seedUser(orgA.ID, "dns-admin-a", "admin"))
	adminB := h.accessToken(orgB, h.seedUser(orgB.ID, "dns-admin-b", "admin"))
	platform := h.accessToken(defaultOrg, h.seedUser(middleware.DefaultOrgID, "dns-platform", "super_admin"))
	titleA := "A's sign-in " + h.suffix
	h.exec(`INSERT INTO tenant_branding (org_id, login_page_title) VALUES ($1::uuid, $2)`, orgA.ID, titleA)
	h.exec(`INSERT INTO tenant_branding (org_id, login_page_title) VALUES ($1::uuid, $2)`, orgB.ID, "B's sign-in "+h.suffix)

	zone := newTXTZone()
	api := h.adminAPIAfterAuth(h.tenantRoutes(zone))
	call := func(method, path, bearer, body string) *httptest.ResponseRecorder {
		t.Helper()
		return serve(api, method, path, "application/json", body, "Authorization", "Bearer "+bearer)
	}
	type claim struct {
		ID                 string `json:"id"`
		Domain             string `json:"domain"`
		Verified           bool   `json:"verified"`
		VerificationToken  string `json:"verification_token"`
		VerificationRecord *struct {
			Type, Name, Value string
		} `json:"verification_record"`
	}
	add := func(org, bearer, domain string) (claim, *httptest.ResponseRecorder) {
		t.Helper()
		w := call(http.MethodPost, "/api/v1/tenants/"+org+"/domains", bearer, `{"domain":"`+domain+`","domain_type":"custom"}`)
		var cl claim
		if w.Code == http.StatusCreated {
			if err := json.Unmarshal(w.Body.Bytes(), &cl); err != nil {
				t.Fatalf("decode claim: %v: %s", err, w.Body.String())
			}
		}
		return cl, w
	}
	verify := func(org, bearer string, cl claim, body string) *httptest.ResponseRecorder {
		t.Helper()
		return call(http.MethodPost, "/api/v1/tenants/"+org+"/domains/"+cl.ID+"/verify", bearer, body)
	}
	verified := func(cl claim) string {
		return h.scalar(`SELECT COALESCE((SELECT verified::text FROM tenant_domains WHERE id = $1::uuid), 'gone')`, cl.ID)
	}
	loginTitle := func(domain string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/branding?domain="+domain, nil)
		w := httptest.NewRecorder()
		h.identityAPI.ServeHTTP(w, req)
		var b struct {
			Title string `json:"login_page_title"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &b) != nil {
			t.Fatalf("branding for %s: %d %s", domain, w.Code, w.Body.String())
		}
		return b.Title
	}

	domain := "login." + h.suffix + ".example.test"
	challenge := "_openidx-challenge." + domain

	// B claims A's domain first. The claim holds nothing, and does not stop A.
	squat, w := add(orgB.ID, adminB, domain)
	if w.Code != http.StatusCreated {
		t.Fatalf("B claiming %s: %d %s, want 201", domain, w.Code, w.Body.String())
	}
	own, w := add(orgA.ID, adminA, domain)
	if w.Code != http.StatusCreated {
		t.Fatalf("A claiming %s after B's unverified claim: %d %s, want 201", domain, w.Code, w.Body.String())
	}
	if own.VerificationToken == "" || own.VerificationToken == squat.VerificationToken {
		t.Fatalf("A's claim token %q, B's %q: want a token of A's own", own.VerificationToken, squat.VerificationToken)
	}
	if r := own.VerificationRecord; r == nil || r.Type != "TXT" || r.Name != challenge ||
		r.Value != "openidx-domain-verification="+own.VerificationToken {
		t.Fatalf("A's claim shows the record %+v, want TXT %s = openidx-domain-verification=%s", r, challenge, own.VerificationToken)
	}
	if got := h.scalar(`SELECT verification_token FROM tenant_domains WHERE id = $1::uuid`, own.ID); got != own.VerificationToken {
		t.Errorf("A's stored token %q, shown %q", got, own.VerificationToken)
	}
	if _, w := add(orgA.ID, adminA, domain); w.Code != http.StatusConflict {
		t.Errorf("A claiming %s a second time: %d %s, want 409", domain, w.Code, w.Body.String())
	}

	// What used to verify a domain -- the token the list had just shown, sent
	// back -- verifies nothing now, and neither does any record but the exact
	// one, nor a DNS server that does not answer.
	for _, attempt := range []struct {
		name    string
		records []string
		broken  bool
		want    int
	}{
		{"the token echoed back, nothing published", nil, false, http.StatusBadRequest},
		{"the bare prefix", []string{"openidx-domain-verification="}, false, http.StatusBadRequest},
		{"the token without the prefix", []string{own.VerificationToken}, false, http.StatusBadRequest},
		{"a trailing space", []string{"openidx-domain-verification=" + own.VerificationToken + " "}, false, http.StatusBadRequest},
		{"B's token", []string{"openidx-domain-verification=" + squat.VerificationToken}, false, http.StatusBadRequest},
		{"a server that does not answer", nil, true, http.StatusBadGateway},
	} {
		zone.mu.Lock()
		delete(zone.records, challenge)
		zone.broken[challenge] = attempt.broken
		zone.mu.Unlock()
		if attempt.records != nil {
			zone.publish(challenge, append([]string{"v=spf1 -all"}, attempt.records...)...)
		}
		if w := verify(orgA.ID, adminA, own, `{"token":"`+own.VerificationToken+`"}`); w.Code != attempt.want {
			t.Errorf("A verifying with %s: %d %s, want %d", attempt.name, w.Code, w.Body.String(), attempt.want)
		}
		if got := verified(own); got != "false" {
			t.Fatalf("A verifying with %s: the claim is verified=%s", attempt.name, got)
		}
	}
	zone.mu.Lock()
	zone.broken[challenge] = false
	zone.mu.Unlock()
	if got := loginTitle(domain); got == titleA {
		t.Fatalf("the login page at %s shows A's branding before any record was published", domain)
	}

	// B cannot verify with A's record, and A can.
	zone.publish(challenge, "v=spf1 -all", "openidx-domain-verification="+own.VerificationToken)
	if w := verify(orgB.ID, adminB, squat, ""); w.Code != http.StatusBadRequest || verified(squat) != "false" {
		t.Errorf("B verifying %s against A's record: %d %s, claim verified=%s; want 400 and unverified", domain, w.Code, w.Body.String(), verified(squat))
	}
	if w := verify(orgA.ID, adminA, own, ""); w.Code != http.StatusOK {
		t.Fatalf("A verifying %s with its record published: %d %s, want 200", domain, w.Code, w.Body.String())
	}
	if got := h.scalar(`SELECT (verified AND verified_at IS NOT NULL)::text FROM tenant_domains WHERE id = $1::uuid`, own.ID); got != "true" {
		t.Errorf("A's claim after verification: verified with a time = %s", got)
	}
	if got := verified(squat); got != "gone" {
		t.Errorf("B's unverified claim to %s after A verified it: %s, want it removed", domain, got)
	}
	if got := loginTitle(domain); got != titleA {
		t.Errorf("the login page at %s shows %q, want A's branding", domain, got)
	}
	if _, w := add(orgB.ID, adminB, domain); w.Code != http.StatusConflict {
		t.Errorf("B claiming %s once A verified it: %d %s, want 409", domain, w.Code, w.Body.String())
	}
	if w := verify(orgA.ID, adminA, own, ""); w.Code != http.StatusOK {
		t.Errorf("A verifying a verified domain again: %d, want 200", w.Code)
	}
	// A claim of B's to the domain that got in anyway -- written by hand here,
	// by a race in life -- cannot be verified while A holds it, even with its
	// own record published beside A's.
	late := claim{ID: h.scalar(`INSERT INTO tenant_domains (org_id, domain, verification_token) VALUES ($1::uuid, $2, 'late-token')
		RETURNING id::text`, orgB.ID, domain)}
	zone.publish(challenge, "openidx-domain-verification="+own.VerificationToken, "openidx-domain-verification=late-token")
	if w := verify(orgB.ID, adminB, late, ""); w.Code != http.StatusConflict || verified(late) != "false" || verified(own) != "true" {
		t.Errorf("B verifying %s while A holds it: %d %s, B's claim verified=%s, A's=%s; want 409 and A keeping it",
			domain, w.Code, w.Body.String(), verified(late), verified(own))
	}
	// A claim written by hand with no token cannot be verified by publishing
	// the bare prefix, which is all its expected value would be.
	bare := "bare." + h.suffix + ".example.test"
	tokenless := claim{ID: h.scalar(`INSERT INTO tenant_domains (org_id, domain) VALUES ($1::uuid, $2) RETURNING id::text`, orgA.ID, bare)}
	zone.publish("_openidx-challenge."+bare, "openidx-domain-verification=")
	if w := verify(orgA.ID, adminA, tokenless, ""); w.Code != http.StatusBadRequest || verified(tokenless) != "false" {
		t.Errorf("A verifying a claim with no token against the bare prefix: %d %s; want 400 and unverified", w.Code, w.Body.String())
	}
	h.exec(`DELETE FROM tenant_domains WHERE id = $1::uuid`, tokenless.ID)

	// Each lookup named the claim's record and had a deadline.
	zone.mu.Lock()
	for i, name := range zone.asked {
		if name != challenge && !strings.HasPrefix(name, "_openidx-challenge.") {
			t.Errorf("lookup %d asked for %s", i, name)
		}
		if d := zone.deadline[i]; d <= 0 || d > 5*time.Second {
			t.Errorf("lookup %d of %s was given %v, want a deadline of at most 5s", i, name, d)
		}
	}
	zone.mu.Unlock()

	// The platform admin may act in B, and proves control the same way.
	other := "portal." + h.suffix + ".example.test"
	forB, w := add(orgB.ID, platform, other)
	if w.Code != http.StatusCreated {
		t.Fatalf("the platform admin claiming %s for B: %d %s, want 201", other, w.Code, w.Body.String())
	}
	if w := verify(orgB.ID, platform, forB, `{"token":"`+forB.VerificationToken+`"}`); w.Code != http.StatusBadRequest || verified(forB) != "false" {
		t.Errorf("the platform admin verifying %s with no record: %d %s; want 400 and unverified", other, w.Code, w.Body.String())
	}
	zone.publish("_openidx-challenge."+other, "openidx-domain-verification="+forB.VerificationToken)
	if w := verify(orgB.ID, platform, forB, ""); w.Code != http.StatusOK || verified(forB) != "true" {
		t.Errorf("the platform admin verifying %s with B's record published: %d %s; want 200 and verified", other, w.Code, w.Body.String())
	}

	// The list shows a pending claim's record, and none once verified.
	pending, w := add(orgA.ID, adminA, "Pending."+h.suffix+".Example.Test.")
	if w.Code != http.StatusCreated || pending.Domain != "pending."+h.suffix+".example.test" {
		t.Fatalf("A claiming a name in capitals with a trailing dot: %d %s, want 201 stored as pending.%s.example.test",
			w.Code, w.Body.String(), h.suffix)
	}
	w = call(http.MethodGet, "/api/v1/tenants/"+orgA.ID+"/domains", adminA, "")
	var list struct {
		Data []claim `json:"data"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Data) != 2 {
		t.Fatalf("A listing its domains: %d %s, want its two claims", w.Code, w.Body.String())
	}
	for _, d := range list.Data {
		switch {
		case d.Verified && d.VerificationRecord != nil:
			t.Errorf("verified %s still shows a record to publish: %+v", d.Domain, d.VerificationRecord)
		case !d.Verified && (d.VerificationRecord == nil || d.VerificationRecord.Name != "_openidx-challenge."+d.Domain):
			t.Errorf("pending %s shows the record %+v", d.Domain, d.VerificationRecord)
		}
	}

	// Anything but a DNS name is refused, and nothing is stored.
	for _, bad := range []string{"", "localhost", "203.0.113.7", "*.example.test", "login..example.test",
		"-login.example.test", "login_page.example.test", "login.example.test/path", strings.Repeat("a", 64) + ".example.test"} {
		if _, w := add(orgA.ID, adminA, bad); w.Code != http.StatusBadRequest {
			t.Errorf("A claiming %q: %d %s, want 400", bad, w.Code, w.Body.String())
		}
	}
	if got := h.scalar(`SELECT COUNT(*)::text FROM tenant_domains WHERE org_id = $1::uuid`, orgA.ID); got != "2" {
		t.Errorf("A holds %s claims after the refused ones, want 2", got)
	}
}
