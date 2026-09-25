//go:build samlinterop

package saml_test

import (
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// browser is the part of a web browser SAML's browser profiles depend on:
// cookies per host, redirects, and submitting the auto-posting forms that
// carry SAMLRequest and SAMLResponse. It stops where a flow leaves the
// systems under test (a redirect to one of the stopAt prefixes), because
// those endpoints do not exist.
type browser struct {
	t      *testing.T
	client *http.Client
	stopAt []string
	// cookies added to every request to a host, as a browser that already
	// holds them would send them.
	extraCookies map[string]string
}

// localhostJar is a cookie jar that keeps cookies marked Secure usable over
// plain http://localhost, as browsers do: they treat localhost as a secure
// context. Go's jar does not, and Keycloak marks its session cookies Secure.
type localhostJar struct{ inner *cookiejar.Jar }

func (j localhostJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		c.Secure = false
	}
	j.inner.SetCookies(u, cookies)
}

func (j localhostJar) Cookies(u *url.URL) []*http.Cookie { return j.inner.Cookies(u) }

func newBrowser(t *testing.T, stopAt ...string) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{
		t: t,
		client: &http.Client{
			Jar:           localhostJar{jar},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		stopAt:       stopAt,
		extraCookies: map[string]string{},
	}
}

// page is what the browser ended on.
type page struct {
	status int
	url    string
	body   string
	// stoppedAt is the URL of a redirect to a stopAt prefix.
	stoppedAt string
	// posted records every SAML message the browser carried in a form.
	posted []postedMessage
}

type postedMessage struct {
	action, param, value, relayState string
}

func (b *browser) do(req *http.Request) *http.Response {
	b.t.Helper()
	for host, cookie := range b.extraCookies {
		if req.URL.Host == host {
			req.Header.Add("Cookie", cookie)
		}
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func (b *browser) get(target string) *page {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.run(b.do(req))
}

func (b *browser) post(target string, form url.Values) *page {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.run(b.do(req))
}

var (
	formRE  = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"[^>]*>(.*?)</form>`)
	inputRE = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	nameRE  = regexp.MustCompile(`(?i)\bname="([^"]*)"`)
	valueRE = regexp.MustCompile(`(?i)\bvalue="([^"]*)"`)
)

// samlForm finds an auto-posting form that carries a SAML message.
func samlForm(body string) (action string, fields url.Values, ok bool) {
	for _, m := range formRE.FindAllStringSubmatch(body, -1) {
		fields = url.Values{}
		for _, in := range inputRE.FindAllString(m[2], -1) {
			n := nameRE.FindStringSubmatch(in)
			if n == nil {
				continue
			}
			v := ""
			if vm := valueRE.FindStringSubmatch(in); vm != nil {
				v = html.UnescapeString(vm[1])
			}
			fields.Set(html.UnescapeString(n[1]), v)
		}
		if fields.Get("SAMLResponse") != "" || fields.Get("SAMLRequest") != "" {
			return html.UnescapeString(m[1]), fields, true
		}
	}
	return "", nil, false
}

// run follows redirects and submits SAML forms until the flow settles.
func (b *browser) run(resp *http.Response) *page {
	b.t.Helper()
	p := &page{}
	for step := 0; step < 40; step++ {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		p.status, p.url, p.body = resp.StatusCode, resp.Request.URL.String(), string(body)

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
			if err != nil {
				b.t.Fatalf("bad redirect from %s: %v", p.url, err)
			}
			for _, prefix := range b.stopAt {
				if strings.HasPrefix(loc.String(), prefix) {
					p.stoppedAt = loc.String()
					return p
				}
			}
			req, _ := http.NewRequest(http.MethodGet, loc.String(), nil)
			resp = b.do(req)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			if action, fields, ok := samlForm(p.body); ok {
				param := "SAMLResponse"
				if fields.Get("SAMLRequest") != "" {
					param = "SAMLRequest"
				}
				p.posted = append(p.posted, postedMessage{action: action, param: param, value: fields.Get(param), relayState: fields.Get("RelayState")})
				for _, prefix := range b.stopAt {
					if strings.HasPrefix(action, prefix) {
						p.stoppedAt = action
						return p
					}
				}
				req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(fields.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp = b.do(req)
				continue
			}
		}
		return p
	}
	b.t.Fatalf("the flow did not settle; last page %d %s", p.status, p.url)
	return nil
}

// lastResponse is the last SAMLResponse the browser carried.
func (p *page) lastResponse() (postedMessage, bool) {
	for i := len(p.posted) - 1; i >= 0; i-- {
		if p.posted[i].param == "SAMLResponse" {
			return p.posted[i], true
		}
	}
	return postedMessage{}, false
}
