package oauth

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/identity"
)

// mfaEvaluation is the outcome of the "does this password login need a second
// factor?" decision: which factors the user has enrolled, whether this browser
// is already trusted, and what the risk engine says.
//
// It exists because that decision used to have to be identical on two browser
// login paths — the JSON one the console SPA drives (POST /oauth/login) and a
// server-rendered one every public client got (POST /oauth/authorize/callback).
// They were two independent implementations and only the JSON one evaluated
// MFA at all, so any user with TOTP/push enrolled could skip their second
// factor entirely by signing in through the hosted page. That page is gone —
// there is one login UI — so this is now the single implementation rather than
// the shared one, and it stays a separate unit because the decision is the
// part worth testing on its own.
type mfaEvaluation struct {
	// Enabled reports that the user has at least one PRIMARY factor enrolled
	// (TOTP, WebAuthn, push, SMS, email OTP). Backup and bypass codes are
	// supplemental and never independently force MFA.
	Enabled bool
	// Methods are the offerable methods, risk-filtered and FastPass-ordered.
	Methods []string
	// BrowserTrusted reports a live "remember this browser" grant.
	BrowserTrusted bool
	// RequireMFA is the risk engine's verdict on its own.
	RequireMFA bool
	// DenyAccess means the login must be refused outright.
	DenyAccess bool
	// SkipMFA means a trusted browser at acceptable risk stands in for the factor.
	SkipMFA bool
	// PolicyRequired reports that an admin-authored mfa_policies row matched this
	// login. It can only ever ADD to the challenge decision, never remove from it.
	PolicyRequired bool
	// RequiredMethods are the methods the matched policy requires. Empty when no
	// policy matched, or when the one that did accepts any enrolled factor.
	RequiredMethods []string
	// EnrollmentDue is set while the user has none of RequiredMethods: inside the
	// policy's grace period, or after it when they sign in with a bypass code.
	// The login response carries it so the sign-in page can tell them.
	EnrollmentDue *mfaEnrollmentDue
	// GraceBegan reports that this login started the user's grace period.
	GraceBegan bool
	// EnrollmentRequired means the grace period is over and the user has neither
	// a required method nor a bypass code: the login must be refused.
	EnrollmentRequired bool
	// Challenge is the final answer: this login must be completed with a second
	// factor before an authorization code may be issued.
	Challenge   bool
	RiskScore   int
	RiskLevel   string
	RiskFactors []string
}

// evaluateMFA decides whether a just-authenticated password login has to be
// completed with a second factor. riskScore/riskFactors are the caller's
// pre-computed values (the risk service already ran for the login record); they
// are returned back, possibly refined by the adaptive assessment.
func (s *Service) evaluateMFA(
	ctx context.Context,
	user *identity.User,
	clientIP, userAgent, fingerprint, location string,
	deviceTrusted bool,
	riskScore int,
	riskFactors []string,
) mfaEvaluation {
	ev := mfaEvaluation{RiskScore: riskScore, RiskFactors: riskFactors, RiskLevel: "medium"}
	if s.identityService == nil || user == nil {
		return ev
	}

	// Gather available MFA methods. MFA enforcement must key on ANY enrolled
	// primary factor (TOTP, WebAuthn, push, SMS, email OTP) — not TOTP alone.
	totpStatus, _ := s.identityService.GetTOTPStatus(ctx, user.ID)
	totpEnabled := totpStatus != nil && totpStatus.Enabled
	if totpEnabled {
		ev.Methods = append(ev.Methods, "totp")
		ev.Enabled = true
	}
	if creds, _ := s.identityService.GetWebAuthnCredentials(ctx, user.ID); len(creds) > 0 {
		ev.Methods = append(ev.Methods, "webauthn")
		ev.Enabled = true
	}
	pushDevices, _ := s.identityService.GetPushDevices(ctx, user.ID)
	if len(pushDevices) > 0 {
		ev.Methods = append(ev.Methods, "push")
		ev.Enabled = true
	}
	// FastPass preference: an enrolled phone IS the authenticator, so offer push
	// first. Purely a reordering — it never adds a method or weakens the verdict.
	if hasEnrolledPushApprover(pushDevices) {
		ev.Methods = preferMethod(ev.Methods, "push")
	}
	if smsEnr, _ := s.identityService.GetSMSEnrollment(ctx, user.ID); smsEnr != nil && smsEnr.Verified && smsEnr.Enabled {
		ev.Methods = append(ev.Methods, "sms")
		ev.Enabled = true
	}
	if emailEnr, _ := s.identityService.GetEmailOTPEnrollment(ctx, user.ID); emailEnr != nil && emailEnr.Enabled {
		ev.Methods = append(ev.Methods, "email")
		ev.Enabled = true
	}
	// The primary factors the user has, before the risk filter below narrows
	// what this challenge offers. A policy asks what the user HAS.
	enrolled := append([]string(nil), ev.Methods...)
	// Supplemental factors — offered alongside a primary one, never on their own.
	if n, _ := s.identityService.GetBackupCodeCount(ctx, user.ID); n > 0 {
		ev.Methods = append(ev.Methods, "backup")
	}
	if ok, _ := s.identityService.HasActiveBypassCode(ctx, user.ID); ok {
		ev.Methods = append(ev.Methods, "bypass")
	}

	// A trusted browser can stand in for the factor.
	if fingerprint != "" {
		tb, _ := s.identityService.IsTrustedBrowser(ctx, user.ID, fingerprint)
		ev.BrowserTrusted = tb != nil
	}

	// Adaptive risk assessment (replaces the hardcoded threshold when available).
	var assessment *identity.RiskAssessment
	var lat, lon float64
	if s.riskService != nil {
		if geo, _ := s.riskService.GeoIPLookup(ctx, clientIP); geo != nil {
			lat, lon = geo.Lat, geo.Lon
		}
	}
	if a, err := s.identityService.AssessLoginRisk(ctx, &identity.LoginContext{
		UserID:         user.ID,
		Username:       user.UserName,
		IPAddress:      clientIP,
		UserAgent:      userAgent,
		Latitude:       lat,
		Longitude:      lon,
		DeviceID:       fingerprint,
		BrowserHash:    fingerprint,
		KnownDevice:    deviceTrusted,
		TrustedBrowser: ev.BrowserTrusted,
	}); err == nil && a != nil {
		assessment = a
		ev.RiskScore = a.Score
		ev.RiskFactors = a.Factors
		ev.RiskLevel = a.Level
	}

	if assessment != nil {
		ev.RequireMFA = assessment.RequiresMFA && ev.Enabled && !ev.BrowserTrusted
		ev.DenyAccess = assessment.DenyAccess
		// Filter the offerable methods by what the risk policy allows.
		if ev.RequireMFA && len(assessment.AllowedMethods) > 0 {
			allowed := make(map[string]bool, len(assessment.AllowedMethods))
			for _, m := range assessment.AllowedMethods {
				allowed[m] = true
			}
			filtered := []string{}
			for _, m := range ev.Methods {
				if allowed[m] {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) > 0 {
				ev.Methods = filtered
			}
		}
	} else {
		// Legacy fallback: hardcoded threshold.
		ev.RequireMFA = ev.RiskScore >= 70 && ev.Enabled && !ev.BrowserTrusted
		ev.DenyAccess = ev.RiskScore >= 70 && !ev.Enabled
	}

	ev.SkipMFA = ev.BrowserTrusted && ev.RiskScore < 70

	// A policy can only RAISE the requirement, so evaluate it after everything
	// else that feeds the decision. Failing open (treating an error as "no
	// policy matched") is deliberate: this evaluator ORs the policy in, it
	// never uses it to skip a challenge the risk engine or TOTP already
	// require, so a DB hiccup here just reproduces today's pre-policy
	// behaviour instead of locking someone out. It is asked on every login,
	// with or without an enrolled factor, because a policy that requires
	// particular methods has something to say to a user who has none.
	var policy *identity.MFAPolicy
	if required, matched, err := s.identityService.IsMFARequired(ctx, user.ID, clientIP); err != nil {
		s.logger.Warn("MFA policy evaluation failed, treating as not required", zap.Error(err))
	} else if required {
		policy = matched
	}

	requiredMethods := policyRequiredMethods(policy)
	if policy == nil || len(requiredMethods) == 0 {
		// Any enrolled factor satisfies the policy. It counts only for a user
		// who has one, and a remembered browser stands in for it, exactly as
		// for the risk engine's own verdict.
		ev.PolicyRequired = policy != nil && ev.Enabled && !ev.SkipMFA
		ev.Challenge = challengeRequired(ev.Enabled, ev.SkipMFA, ev.RequireMFA, totpEnabled, ev.PolicyRequired)
		return ev
	}

	ev.PolicyRequired = true
	ev.RequiredMethods = requiredMethods
	if offered := requiredMethodsOffered(ev.Methods, enrolled, requiredMethods); len(offered) > 0 {
		// The user has a required method: the challenge offers those, plus an
		// administrator's bypass code, and nothing else. Not SMS under a policy
		// that names WebAuthn, and not a remembered browser either: the product
		// does not record which factor a browser was remembered with.
		ev.Methods = offered
		ev.SkipMFA = false
		ev.Challenge = true
		return ev
	}

	// The user has none of the required methods: the policy's grace period,
	// counted from the first sign-in that found them without one. If that
	// start cannot be read or recorded, the window is treated as opening now,
	// so a database error never ends a window early; the start is recorded on
	// a later sign-in.
	now := time.Now()
	start, began, err := s.identityService.MFAGraceStart(ctx, policy.ID, user.ID)
	if err != nil {
		s.logger.Warn("MFA grace period unavailable, treating it as starting now",
			zap.String("policy_id", policy.ID), zap.Error(err))
		start, began = now, false
	}
	// A policy with no grace period records the start too, so that raising
	// the period later counts from the same first sign-in; but no period
	// began.
	ev.GraceBegan = began && policy.GracePeriodHours > 0
	deadline := start.Add(time.Duration(policy.GracePeriodHours) * time.Hour)
	switch outcome := graceOutcome(now, deadline, policy.GracePeriodHours, hasMethod(ev.Methods, "bypass")); outcome {
	case graceOpen:
		// Meanwhile the user signs in as under a policy that accepts any factor:
		// a user with a factor is challenged with the factors they have.
		ev.EnrollmentDue = &mfaEnrollmentDue{Methods: requiredMethods, Deadline: deadline}
		ev.PolicyRequired = ev.Enabled && !ev.SkipMFA
		ev.Challenge = challengeRequired(ev.Enabled, ev.SkipMFA, ev.RequireMFA, totpEnabled, ev.PolicyRequired)
	case graceOverWithBypass:
		// The administrator's bypass code is the way back in, so that the user
		// can add a required method.
		ev.EnrollmentDue = &mfaEnrollmentDue{Methods: requiredMethods, Deadline: deadline, Overdue: true}
		ev.Methods = []string{"bypass"}
		ev.SkipMFA = false
		ev.Challenge = true
	default:
		ev.EnrollmentRequired = true
		ev.Challenge = false
	}
	return ev
}

// mfaEnrollmentDue tells a user signing in that their organization requires a
// method they have not added: by when (Deadline), or, when Overdue, that the
// time has passed and a bypass code let them in to add one.
type mfaEnrollmentDue struct {
	Methods  []string  `json:"methods"`
	Deadline time.Time `json:"deadline"`
	Overdue  bool      `json:"overdue,omitempty"`
}

// mfaPolicyMethods are the methods a policy can require: the primary factors
// evaluateMFA offers. Backup and bypass codes are recovery, not a method a
// policy can ask for.
var mfaPolicyMethods = map[string]bool{"totp": true, "webauthn": true, "push": true, "sms": true, "email": true}

// policyRequiredMethods returns the matched policy's required methods,
// lower-cased, de-duplicated and limited to the methods above. The admin API
// accepts no others, so the filter only matters for a row written by hand.
func policyRequiredMethods(policy *identity.MFAPolicy) []string {
	if policy == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range policy.RequiredMethods {
		m = strings.ToLower(strings.TrimSpace(m))
		if mfaPolicyMethods[m] && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// requiredMethodsOffered is what a challenge under a method-requiring policy
// offers a user who has at least one of the methods: the required methods among
// those this challenge would offer (risk-filtered, FastPass-ordered), and when
// the risk filter left none of them, the required methods among those the user
// has. An active bypass code is added, being the administrator's recovery path.
// Empty means the user has none of the required methods.
func requiredMethodsOffered(offerable, enrolled, required []string) []string {
	offered := intersectMethods(offerable, required)
	if len(offered) == 0 {
		offered = intersectMethods(enrolled, required)
	}
	if len(offered) > 0 && hasMethod(offerable, "bypass") {
		offered = append(offered, "bypass")
	}
	return offered
}

func intersectMethods(methods, allowed []string) []string {
	var out []string
	for _, m := range methods {
		if hasMethod(allowed, m) && !hasMethod(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func hasMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

type graceState int

const (
	graceOpen graceState = iota
	graceOverWithBypass
	graceOver
)

// graceOutcome is the rule for a user with none of a policy's required methods.
// Until the deadline they sign in as before. After it, only an administrator's
// bypass code lets them in, and the login is refused without one. A grace
// period of 0 hours has no "until" at all, whichever way this host's clock and
// the database's disagree about the moment the start was recorded.
func graceOutcome(now, deadline time.Time, graceHours int, hasBypass bool) graceState {
	if graceHours > 0 && now.Before(deadline) {
		return graceOpen
	}
	if hasBypass {
		return graceOverWithBypass
	}
	return graceOver
}

// challengeRequired is the single rule deciding whether a password login must be
// completed with a second factor.
//
// A policy can only RAISE the requirement: it is ORed in, never consulted to
// skip. A user with no enrolled factor is never challenged whatever the policy
// says — requiring a factor from someone who has none is a lockout with extra
// steps; they belong in the enrollment-gap report instead.
func challengeRequired(enabled, skipMFA, riskRequires, totpEnabled, policyRequires bool) bool {
	if !enabled || skipMFA {
		return false
	}
	return riskRequires || totpEnabled || policyRequires
}
