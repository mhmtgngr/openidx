package access

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// structFieldNames lists a struct's field names by reflection, so the check
// below is over what the type actually has rather than a list someone has to
// remember to update.
func structFieldNames(v interface{}) []string {
	t := reflect.TypeOf(v)
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return names
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// The gates on an anonymous vendor link, tested directly.
//
// `GET /temp-access/:token` is one of a handful of routes this product serves
// with no authentication at all, and public_surface_test.go requires each such
// route to carry a written justification. This route's justification IS this
// list of checks — so these four conditions are the entire security argument
// for handing an outsider RDP or SSH to an internal host, and until now not one
// of them had a test. They were inline `if`s inside a DB-backed handler, so
// covering them meant standing up Postgres, which is why nobody had.
//
// tempLinkGate is a pure function precisely so that the argument the register
// makes is provable by a test that runs anywhere.

func activeLink() TempAccessLink {
	return TempAccessLink{
		Name:      "vendor-rdp",
		Status:    "active",
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestEveryGateTheRegisterClaims(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		link       func(TempAccessLink) TempAccessLink
		clientIP   string
		wantRefuse bool
		wantStatus int
		wantTitle  string
	}{
		{
			name:       "a live link inside its window is let through",
			link:       func(l TempAccessLink) TempAccessLink { return l },
			wantRefuse: false,
		},
		{
			// The window is the whole point of a temporary link: after it, the
			// vendor's access is gone without anyone having to remember to
			// remove it.
			name: "expired",
			link: func(l TempAccessLink) TempAccessLink {
				l.ExpiresAt = now.Add(-time.Second)
				return l
			},
			wantRefuse: true, wantStatus: http.StatusGone, wantTitle: "Access Link Expired",
		},
		{
			// Revocation is what an operator reaches for when a link leaks. It
			// has to bite on the very next redemption, not at expiry.
			name: "revoked",
			link: func(l TempAccessLink) TempAccessLink {
				l.Status = "revoked"
				return l
			},
			wantRefuse: true, wantStatus: http.StatusForbidden, wantTitle: "Access Link Revoked",
		},
		{
			name: "use cap reached",
			link: func(l TempAccessLink) TempAccessLink {
				l.MaxUses, l.CurrentUses = 3, 3
				return l
			},
			wantRefuse: true, wantStatus: http.StatusForbidden, wantTitle: "Access Link Exhausted",
		},
		{
			name: "use cap not yet reached",
			link: func(l TempAccessLink) TempAccessLink {
				l.MaxUses, l.CurrentUses = 3, 2
				return l
			},
			wantRefuse: false,
		},
		{
			// MaxUses 0 means unlimited. A link that has been used a hundred
			// times must not start refusing because someone read the zero as a
			// cap.
			name: "max_uses zero is unlimited, not a cap of zero",
			link: func(l TempAccessLink) TempAccessLink {
				l.MaxUses, l.CurrentUses = 0, 100
				return l
			},
			wantRefuse: false,
		},
		{
			name: "client IP is on the allowlist",
			link: func(l TempAccessLink) TempAccessLink {
				l.AllowedIPs = []string{"198.51.100.7", "203.0.113.9"}
				return l
			},
			clientIP: "203.0.113.9", wantRefuse: false,
		},
		{
			name: "client IP is not on the allowlist",
			link: func(l TempAccessLink) TempAccessLink {
				l.AllowedIPs = []string{"198.51.100.7"}
				return l
			},
			clientIP:   "203.0.113.9",
			wantRefuse: true, wantStatus: http.StatusForbidden, wantTitle: "Access Denied",
		},
		{
			// An empty allowlist means "any address", which is the default a
			// link is created with. Reading it as "no address" would refuse
			// every link ever made from the console.
			name:       "an empty allowlist does not refuse everyone",
			link:       func(l TempAccessLink) TempAccessLink { return l },
			clientIP:   "203.0.113.9",
			wantRefuse: false,
		},
		{
			// Expiry is checked before the allowlist, so an expired link tells
			// the vendor it expired rather than blaming their address.
			name: "an expired link reports expiry, not the address",
			link: func(l TempAccessLink) TempAccessLink {
				l.ExpiresAt = now.Add(-time.Hour)
				l.AllowedIPs = []string{"198.51.100.7"}
				return l
			},
			clientIP:   "203.0.113.9",
			wantRefuse: true, wantStatus: http.StatusGone, wantTitle: "Access Link Expired",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tempLinkGate(tc.link(activeLink()), tc.clientIP, now)
			if got.Refuse != tc.wantRefuse {
				t.Fatalf("Refuse = %v, want %v (verdict %+v)", got.Refuse, tc.wantRefuse, got)
			}
			if !tc.wantRefuse {
				if got.Status != 0 || got.Title != "" || got.Message != "" {
					t.Errorf("an allowed redemption carries a refusal: %+v", got)
				}
				return
			}
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.Title != tc.wantTitle {
				t.Errorf("Title = %q, want %q", got.Title, tc.wantTitle)
			}
			if got.Message == "" {
				t.Error("a refusal with no message tells the vendor nothing")
			}
		})
	}
}

// The allowlist, now that it understands ranges (roadmap V0.4).
//
// This replaces TestTheAllowlistIsExactMatchOnly, which pinned the old string
// equality so the fix could not land silently. It did its job: an operator who
// wrote 203.0.113.0/24 had allowed no address at all, including their own.
func TestTheAllowlistUnderstandsRangesAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed []string
		client  string
		want    bool
	}{
		{"an address inside a v4 CIDR", []string{"203.0.113.0/24"}, "203.0.113.9", true},
		{"an address outside a v4 CIDR", []string{"203.0.113.0/24"}, "203.0.114.9", false},
		{"the network address itself", []string{"203.0.113.0/24"}, "203.0.113.0", true},
		{"a /32 is still a single host", []string{"203.0.113.9/32"}, "203.0.113.9", true},
		{"a /32 does not admit its neighbour", []string{"203.0.113.9/32"}, "203.0.113.10", false},
		{"a bare address still works", []string{"198.51.100.7"}, "198.51.100.7", true},
		{"mixed ranges and addresses", []string{"198.51.100.7", "203.0.113.0/24"}, "203.0.113.5", true},

		// IPv6 written two ways is one address. As strings these never matched.
		{"IPv6 in its compressed form", []string{"2001:db8::1"}, "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"IPv6 inside a prefix", []string{"2001:db8::/32"}, "2001:db8:1234::9", true},
		{"IPv6 outside a prefix", []string{"2001:db8::/32"}, "2001:db9::9", false},

		// A proxy in front of the service can present a v4 client as
		// IPv4-mapped IPv6; it must still match the v4 rule an operator wrote.
		{"an IPv4-mapped client against a v4 rule", []string{"203.0.113.9"}, "::ffff:203.0.113.9", true},
		{"an IPv4-mapped client against a v4 CIDR", []string{"203.0.113.0/24"}, "::ffff:203.0.113.9", true},

		// Anything unparseable matches nothing rather than everything.
		{"a garbage rule admits nobody", []string{"not-an-ip"}, "203.0.113.9", false},
		{"a garbage client is refused", []string{"203.0.113.0/24"}, "definitely-not-an-ip", false},
		{"an empty entry is skipped, not treated as a wildcard", []string{"", "203.0.113.0/24"}, "203.0.113.9", true},
		{"whitespace around an entry is tolerated", []string{"  203.0.113.0/24  "}, "203.0.113.9", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := activeLink()
			link.AllowedIPs = tc.allowed
			v := tempLinkGate(link, tc.client, time.Now())
			if allowed := !v.Refuse; allowed != tc.want {
				t.Errorf("client %q against %v: allowed = %v, want %v",
					tc.client, tc.allowed, allowed, tc.want)
			}
		})
	}
}

// TestABadAllowlistIsRefusedAtCreation. The old failure mode was silent: a CIDR
// entry matched nothing, the link looked issued, and the vendor could not
// connect with no indication why. Ranges work now, but a typo still should not
// produce a link that refuses everyone — so the list is validated where the
// operator can still fix it.
func TestABadAllowlistIsRefusedAtCreation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		wantErr bool
	}{
		{"addresses and ranges", []string{"203.0.113.9", "198.51.100.0/24", "2001:db8::/32"}, false},
		{"empty list means no restriction", nil, false},
		{"blank entries are tolerated", []string{"", "  "}, false},
		{"a hostname is not an address", []string{"vendor.example.com"}, true},
		{"a malformed range", []string{"203.0.113.0/33"}, true},
		{"a truncated address", []string{"203.0.113"}, true},
		{"one bad entry rejects the list", []string{"203.0.113.9", "nonsense"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAllowedIPs(tc.entries)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateAllowedIPs(%v) error = %v, want error: %v", tc.entries, err, tc.wantErr)
			}
			if tc.wantErr && !containsFold(err.Error(), "allowed_ips") {
				t.Errorf("the error does not name the field the operator must fix: %v", err)
			}
		})
	}
}

// TestALinkPointsSomewhereRealOrIsNotIssued.
//
// The address was built as fmt.Sprintf("https://%s/temp-access/%s", domain,
// token) with domain falling back to browzer.localtest.me when
// access_proxy_domain was unset. localtest.me resolves to 127.0.0.1, so the
// link was issued, looked correct in the console, could be mailed to a vendor,
// and pointed at the vendor's own machine. An unset base is now a refusal at
// issuance, where the operator can still fix it.
func TestALinkPointsSomewhereRealOrIsNotIssued(t *testing.T) {
	const token = "0123456789abcdef"

	for _, unset := range []string{"", "   ", "\t"} {
		if _, err := tempAccessURL(unset, token); err == nil {
			t.Errorf("tempAccessURL(%q) returned a URL. An unconfigured base must refuse: a link "+
				"that resolves nowhere is worse than no link, because it is sent before anyone "+
				"discovers it is broken.", unset)
		} else if !containsFold(err.Error(), "access_proxy_domain") {
			t.Errorf("the refusal does not name the setting the operator must fix: %v", err)
		}
	}

	got, err := tempAccessURL(" vendor.example.com ", token)
	if err != nil {
		t.Fatalf("a configured domain must produce a URL: %v", err)
	}
	if want := "https://vendor.example.com/temp-access/" + token; got != want {
		t.Errorf("tempAccessURL() = %q, want %q", got, want)
	}

	// The old fallback must not come back under any input, including the one
	// that used to trigger it.
	for _, in := range []string{"", "localhost", "vendor.example.com"} {
		if u, err := tempAccessURL(in, token); err == nil && containsFold(u, "localtest.me") {
			t.Errorf("tempAccessURL(%q) = %q — the test-domain fallback is back", in, u)
		}
	}
}

// TestTheNotifiedPartyIsTheIssuer pins who a used-link notification reaches.
//
// notify_on_use was stored, selected back into the struct, and never compared to
// anything — the same shape as require_mfa, on the same row. It notifies now,
// and this is the decision half: the recipient is the link's issuer, never a
// value carried on the link itself.
//
// The empty-issuer case is the one that must stay red if the creation-side rule
// is ever relaxed: a link with no resolvable issuer notifies nobody, which is a
// switch that is on and does nothing.
func TestTheNotifiedPartyIsTheIssuer(t *testing.T) {
	const issuer = "6f1b2a4e-0d3c-4f5a-9b8e-1c2d3e4f5a6b"
	for _, tc := range []struct {
		name string
		link TempAccessLink
		want string
	}{
		{"the switch is off", TempAccessLink{NotifyOnUse: false, CreatedBy: issuer}, ""},
		{"the switch is on", TempAccessLink{NotifyOnUse: true, CreatedBy: issuer}, issuer},
		{"on, but nobody to tell", TempAccessLink{NotifyOnUse: true, CreatedBy: ""}, ""},
		{"a padded id still resolves", TempAccessLink{NotifyOnUse: true, CreatedBy: " " + issuer + " "}, issuer},
		{"whitespace is not a recipient", TempAccessLink{NotifyOnUse: true, CreatedBy: "   "}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tempLinkNotifyRecipient(tc.link); got != tc.want {
				t.Errorf("tempLinkNotifyRecipient() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNoNotifyEmailFieldSurvives. notify_on_use is real now — it notifies the
// link's creator — but notify_email was a free-text recipient the product had
// no way to deliver to, and reinstating it would be the same
// stored-and-never-sent switch. The creator is also who needs to know: it is
// their vendor and their link, and they are deliverable through the channels
// they have already configured.
func TestNoNotifyEmailFieldSurvives(t *testing.T) {
	for name, fields := range map[string][]string{
		"CreateTempAccessRequest": structFieldNames(CreateTempAccessRequest{}),
		"TempAccessLink":          structFieldNames(TempAccessLink{}),
	} {
		for _, f := range fields {
			if containsFold(f, "notifyemail") {
				t.Errorf("%s has field %q. If notifications should reach an arbitrary address, "+
					"that needs a sender and a reason to trust the address — not a column that "+
					"is stored and never read.", name, f)
			}
		}
	}
}

// TestALinkMustNameAPamEntry pins the shape the whole V0.1 change rests on.
//
// A link used to carry its own protocol/host/port and redemption redirected to
// a Guacamole connection built from them at issuance with an empty parameter
// map — no ZTNA check, always the direct broker, no recording, no credential.
// It now names a pam_entries row instead, and that row carries every one of
// those decisions, so the launch core can be reused as-is.
//
// The binding tag is the load-bearing part: without `required` a caller could
// omit the entry, the link would be created with a NULL target, and redemption
// would refuse it as legacy — a link that can never be used, issued silently.
// The absent fields matter too: leaving TargetHost on the request would let a
// caller name a host the entry does not point at.
func TestALinkMustNameAPamEntry(t *testing.T) {
	f, ok := reflect.TypeOf(CreateTempAccessRequest{}).FieldByName("PamEntryID")
	if !ok {
		t.Fatal("CreateTempAccessRequest has no PamEntryID: a vendor link must name the entry " +
			"it launches, or none of the PAM controls apply to it")
	}
	if b := f.Tag.Get("binding"); !containsFold(b, "required") {
		t.Errorf("PamEntryID binding is %q, want it to include `required`. Without that a link "+
			"can be created with no target and is then refused at redemption as legacy — issued "+
			"and unusable, with nothing saying so at creation time.", b)
	}

	// The target's shape is the entry's business now.
	for _, gone := range []string{"TargetHost", "TargetPort", "Protocol", "Username"} {
		if _, present := reflect.TypeOf(CreateTempAccessRequest{}).FieldByName(gone); present {
			t.Errorf("CreateTempAccessRequest still has %s. The target comes from the PAM entry; "+
				"accepting it here again lets a caller point a link at a host the entry does not "+
				"broker, which is how this feature bypassed every control in the first place.", gone)
		}
	}
}

// TestNoMFAFieldSurvives keeps the register honest by construction.
//
// public_surface_test.go used to justify this anonymous route by saying the
// handler checked "expiry, revocation, use count, allowed IPs and MFA". It
// checked the first four; require_mfa was stored, selected back and never
// compared. Re-adding a field of that name without wiring it is the exact
// mistake to prevent, so this asserts the request type carries no MFA-shaped
// field. Vendor MFA arrives with the identity in VENDOR-ACCESS-ROADMAP V1, not
// as a flag on an anonymous URL.
func TestNoMFAFieldSurvives(t *testing.T) {
	for _, typ := range []struct {
		name   string
		fields []string
	}{
		{"CreateTempAccessRequest", structFieldNames(CreateTempAccessRequest{})},
		{"TempAccessLink", structFieldNames(TempAccessLink{})},
	} {
		for _, f := range typ.fields {
			if containsFold(f, "mfa") {
				t.Errorf("%s has field %q. If a second factor is being added to vendor links, "+
					"it must be COMPARED to something in tempLinkGate, and the justification in "+
					"public_surface_test.go updated to say so — a stored-and-never-read flag is "+
					"what this test exists to stop.", typ.name, f)
			}
		}
	}
}
