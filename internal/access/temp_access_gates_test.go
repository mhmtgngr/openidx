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

// TestTheAllowlistIsExactMatchOnly pins a known limitation so the fix for it
// arrives with a red proof.
//
// AllowedIPs is compared with string equality, so a CIDR range matches nothing
// and an operator who writes one has allowed no address at all. That direction
// is safe — it fails closed, locking out the vendor and the operator alike
// rather than admitting anyone — which is why it is roadmap item V0.4 and not
// an emergency. This test exists so that item cannot land silently: implementing
// CIDR turns this test red, and whoever does it must delete it deliberately.
func TestTheAllowlistIsExactMatchOnly(t *testing.T) {
	link := activeLink()
	link.AllowedIPs = []string{"203.0.113.0/24"}

	v := tempLinkGate(link, "203.0.113.9", time.Now())
	if !v.Refuse {
		t.Fatal("an address inside the CIDR was allowed — CIDR support has been added.\n" +
			"That is roadmap item V0.4 and it is welcome; delete this test as part of it,\n" +
			"and make sure the fix is covered by a test that asserts the NEW behaviour.")
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
