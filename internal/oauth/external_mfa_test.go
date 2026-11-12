package oauth

import (
	"reflect"
	"testing"

	"github.com/openidx/openidx/internal/identity"
)

// An external (vendor) user's sign-in is held to strong factors whatever the
// rest of the evaluation decided: always challenged, never skipped by a
// remembered browser, never offered SMS, email or an administrator's bypass
// code, and refused outright with no strong factor at all. Anyone else's
// evaluation passes through untouched.
func TestHoldExternalToStrongFactors(t *testing.T) {
	external := &identity.User{ID: "u-ext", UserType: "external"}
	internal := &identity.User{ID: "u-int", UserType: "internal"}

	lenient := mfaEvaluation{
		Methods: []string{"sms", "totp", "email", "backup", "bypass"}, Enabled: true,
		BrowserTrusted: true, SkipMFA: true, Challenge: false,
		EnrollmentDue: &mfaEnrollmentDue{Methods: []string{"webauthn"}},
	}
	if got := holdExternalToStrongFactors(internal, lenient); !reflect.DeepEqual(got, lenient) {
		t.Errorf("an internal user's evaluation changed: %+v", got)
	}
	if got := holdExternalToStrongFactors(nil, lenient); !reflect.DeepEqual(got, lenient) {
		t.Errorf("a missing user's evaluation changed: %+v", got)
	}

	got := holdExternalToStrongFactors(external, lenient)
	if !got.Challenge || got.SkipMFA || got.EnrollmentRequired || got.EnrollmentDue != nil || !got.External {
		t.Errorf("an external user with an authenticator was not challenged: %+v", got)
	}
	if want := []string{"totp", "backup"}; !reflect.DeepEqual(got.Methods, want) {
		t.Errorf("methods offered to an external user = %v, want %v", got.Methods, want)
	}

	codeOnly := mfaEvaluation{Methods: []string{"sms", "email", "bypass"}, Enabled: true, Challenge: true}
	got = holdExternalToStrongFactors(external, codeOnly)
	if got.Challenge || !got.EnrollmentRequired || len(got.Methods) != 0 {
		t.Errorf("an external user with only code factors was let through: %+v", got)
	}
	if want := []string{"totp", "webauthn", "push"}; !reflect.DeepEqual(got.RequiredMethods, want) {
		t.Errorf("required methods = %v, want %v", got.RequiredMethods, want)
	}
	// Inline enrolment offers what the login page can set up, never a code.
	if m := inlineEnrollMethods(got, "external", true); !reflect.DeepEqual(m, []string{"totp", "webauthn"}) {
		t.Errorf("inline enrolment for an external user = %v, want [totp webauthn]", m)
	}
}

func TestInlineEnrollMethodsNeverOfferCodes(t *testing.T) {
	cases := []struct {
		ev   mfaEvaluation
		typ  string
		want []string
		sms  bool
	}{
		{mfaEvaluation{RequiredMethods: []string{"email", "sms"}}, "internal", []string{}, false},
		{mfaEvaluation{RequiredMethods: []string{"email", "totp"}}, "internal", []string{"totp"}, false},
		{mfaEvaluation{}, "internal", []string{"totp", "webauthn"}, false},
		{mfaEvaluation{RequiredMethods: []string{"email"}, External: true}, "external", []string{}, false},
		{mfaEvaluation{RequiredMethods: []string{"push", "webauthn"}}, "", []string{"webauthn"}, false},
		// SMS only when deliverable, only when named, never for external users.
		{mfaEvaluation{RequiredMethods: []string{"sms", "totp"}}, "internal", []string{"sms", "totp"}, true},
		{mfaEvaluation{RequiredMethods: []string{"sms"}}, "internal", []string{}, false},
		{mfaEvaluation{}, "internal", []string{"totp", "webauthn"}, true},
		{mfaEvaluation{RequiredMethods: []string{"sms", "totp"}, External: true}, "external", []string{"totp"}, true},
	}
	for _, c := range cases {
		if got := inlineEnrollMethods(c.ev, c.typ, c.sms); !reflect.DeepEqual(got, c.want) {
			t.Errorf("inlineEnrollMethods(%v, %q) = %v, want %v", c.ev.RequiredMethods, c.typ, got, c.want)
		}
	}
}
