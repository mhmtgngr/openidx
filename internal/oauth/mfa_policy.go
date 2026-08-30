package oauth

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/identity"
)

// mfaEvaluation is the outcome of the "does this password login need a second
// factor?" decision: which factors the user has enrolled, whether this browser
// is already trusted, and what the risk engine says.
//
// It exists because that decision has to be identical on BOTH browser login
// paths — the JSON one the console SPA drives (POST /oauth/login) and the
// server-rendered one every public client gets (POST /oauth/authorize/callback).
// They used to be two independent implementations and only the JSON one
// evaluated MFA at all, so any user with TOTP/push enrolled could skip their
// second factor entirely by signing in through the hosted page.
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
	// behaviour instead of locking someone out.
	if s.identityService != nil && user != nil {
		if required, _, err := s.identityService.IsMFARequired(ctx, user.ID, clientIP); err != nil {
			s.logger.Warn("MFA policy evaluation failed, treating as not required", zap.Error(err))
		} else {
			ev.PolicyRequired = required
		}
	}

	ev.Challenge = challengeRequired(ev.Enabled, ev.SkipMFA, ev.RequireMFA, totpEnabled, ev.PolicyRequired)
	return ev
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
