package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
)

// A CHANGE TO SOMEONE'S SECOND FACTORS NEEDS THEM, NOT ONLY THEIR TOKEN.
//
// Every self-service route that removes, replaces or adds a second factor used
// to need a bearer token and nothing else. The console keeps that token in
// localStorage, so anything that can read it -- a cross-site script, a
// malicious extension, an unlocked machine -- could turn its owner's second
// factor off (POST /users/me/mfa/disable), point it at an authenticator of its
// own (setup, then enable: EnrollTOTP replaces the credential), or add one of
// its own and keep a way in after the token expired.
//
// Such a request now carries proof from the account holder in its own JSON
// body: the account's password (current_password), or, where the change
// removes or replaces the TOTP credential, a current code from that credential
// (totp_code). The code goes through VerifyTOTP, so it is throttled and
// accepted once. The password is checked the way sign-in checks it, and a
// wrong one counts against the same lockout, so a stolen token does not become
// a way to guess the password without limit.
//
// A first factor on an account that has none needs no proof: there is nothing
// yet to protect, and a user who signs in through an identity provider has no
// password to give.

// factorChange is what a request does to the caller's second factors, which
// decides the proof it must carry.
type factorChange int

const (
	// removesTOTP turns the TOTP credential off. A current code from it, or
	// the password.
	removesTOTP factorChange = iota + 1
	// enrollsTOTP stores a TOTP credential in place of the caller's. With one
	// enabled, that is a replacement: a current code from it, or the password.
	// With none, it adds a factor, as addsFactor.
	enrollsTOTP
	// removesFactor removes another second factor. The password.
	removesFactor
	// addsFactor adds a second factor, replaces the backup codes, or remembers
	// a browser so that sign-ins from it skip the second factor. The password,
	// when the account already has a second factor.
	addsFactor
	// changesPhoneCall starts a phone-call enrollment, which re-points a
	// verified phone-call factor at the new number in place. The password,
	// when one is verified; otherwise the enrollment is pending until its
	// verification, which is addsFactor's.
	changesPhoneCall
	// changesSignInMethod links or unlinks an external account (a social
	// provider) that signs in to this one. It adds or removes a way in as
	// surely as a factor does, so an account that has a password or a second
	// factor to protect needs the password, or a current TOTP code; an account
	// with neither has nothing it could give.
	changesSignInMethod
)

// factorProof is the proof a request carries, read from its JSON body.
type factorProof struct {
	CurrentPassword string `json:"current_password"`
	TOTPCode        string `json:"totp_code"`
}

// proofNeed is what a particular request must prove.
type proofNeed struct {
	required bool
	// totp: a current TOTP code is accepted as well as the password.
	totp bool
}

// The machine-readable refusals. All are 403: the console answers a 401 by
// asking the user to sign in again, and the token here is valid.
const (
	reauthRequired    = "reauthentication_required"
	reauthFailed      = "reauthentication_failed"
	reauthLocked      = "reauthentication_locked"
	reauthUnavailable = "reauthentication_unavailable"
)

// errNoAccountPassword: the account has no password this service can check --
// it signs in through Azure AD or another identity provider, or never set one.
var errNoAccountPassword = errors.New("this account has no password this service can check")

// requireFactorProof is the route middleware for a self-service route that
// changes the caller's second factors. It runs after authentication, so the
// caller is the token's subject.
func (s *Service) requireFactorProof(change factorChange) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		need, err := s.factorProofNeeded(c.Request.Context(), userID, change)
		if err != nil {
			s.logger.Error("could not decide whether a factor change needs proof; refusing it",
				zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		if !need.required {
			c.Next()
			return
		}
		if !s.checkFactorProof(c, userID, need, readFactorProof(c)) {
			return
		}
		c.Next()
	}
}

// readFactorProof reads the proof fields out of the request's JSON body and
// puts the body back for the handler. A body that is not JSON carries no proof.
func readFactorProof(c *gin.Context) factorProof {
	var proof factorProof
	if c.Request.Body == nil {
		return proof
	}
	body, err := io.ReadAll(c.Request.Body)
	_ = c.Request.Body.Close()
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &proof)
	}
	return proof
}

// factorProofNeeded decides what this request must prove, from what the
// caller's account holds now.
func (s *Service) factorProofNeeded(ctx context.Context, userID string, change factorChange) (proofNeed, error) {
	switch change {
	case removesTOTP:
		enabled, err := s.totpEnabled(ctx, userID)
		return proofNeed{required: true, totp: enabled}, err
	case enrollsTOTP:
		enabled, err := s.totpEnabled(ctx, userID)
		if err != nil || enabled {
			return proofNeed{required: true, totp: true}, err
		}
		has, err := s.hasSecondFactor(ctx, userID)
		return proofNeed{required: has}, err
	case removesFactor:
		return proofNeed{required: true}, nil
	case addsFactor:
		has, err := s.hasSecondFactor(ctx, userID)
		return proofNeed{required: has}, err
	case changesPhoneCall:
		org, err := orgctx.From(ctx)
		if err != nil {
			return proofNeed{}, err
		}
		var verified bool
		err = s.db.Pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM mfa_phone_call
			                WHERE user_id = $1 AND org_id = $2 AND verified AND enabled)`,
			userID, org.ID).Scan(&verified)
		return proofNeed{required: verified}, err
	case changesSignInMethod:
		hasPassword, err := s.hasCheckablePassword(ctx, userID)
		if err != nil {
			return proofNeed{}, err
		}
		hasFactor, err := s.hasSecondFactor(ctx, userID)
		if err != nil {
			return proofNeed{}, err
		}
		totp, err := s.totpEnabled(ctx, userID)
		return proofNeed{required: hasPassword || hasFactor, totp: totp}, err
	}
	// An unknown kind is a programming error; demand the strongest proof.
	return proofNeed{required: true}, nil
}

func (s *Service) totpEnabled(ctx context.Context, userID string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var enabled bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = $1 AND org_id = $2 AND enabled)`,
		userID, org.ID).Scan(&enabled)
	return enabled, err
}

// hasSecondFactor reports whether the account holds any second factor: every
// factor sign-in asks for (evaluateMFA, internal/oauth/mfa_policy.go), a
// verified phone-call number, and unused backup codes.
func (s *Service) hasSecondFactor(ctx context.Context, userID string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var has bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = $1 AND org_id = $2 AND enabled)
		    OR EXISTS (SELECT 1 FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2)
		    OR EXISTS (SELECT 1 FROM mfa_push_devices WHERE user_id = $1 AND org_id = $2)
		    OR EXISTS (SELECT 1 FROM mfa_sms WHERE user_id = $1 AND org_id = $2 AND verified AND enabled)
		    OR EXISTS (SELECT 1 FROM mfa_email_otp WHERE user_id = $1 AND org_id = $2 AND enabled)
		    OR EXISTS (SELECT 1 FROM mfa_phone_call WHERE user_id = $1 AND org_id = $2 AND verified AND enabled)
		    OR EXISTS (SELECT 1 FROM mfa_backup_codes WHERE user_id = $1 AND org_id = $2 AND NOT used)`,
		userID, org.ID).Scan(&has)
	return has, err
}

// checkFactorProof verifies the proof a request carries against what it needs,
// and answers the refusal itself. It returns true when the request may go on.
//
// One proof is checked per request: the password when one is given, otherwise
// a TOTP code where the change accepts one.
func (s *Service) checkFactorProof(c *gin.Context, userID string, need proofNeed, proof factorProof) bool {
	ctx := c.Request.Context()
	var (
		method string
		ok     bool
		err    error
	)
	switch {
	case proof.CurrentPassword != "":
		method = "password"
		ok, err = s.verifyAccountPassword(ctx, userID, proof.CurrentPassword)
	case need.totp && proof.TOTPCode != "":
		method = "totp"
		ok, err = s.VerifyTOTP(ctx, userID, proof.TOTPCode)
	default:
		s.refuseFactorChange(c, userID, need, reauthRequired, "")
		return false
	}
	if ok && err == nil {
		return true
	}

	s.logAuditEvent(auditCtx(c), "identity", "security", "user.reauthentication_failed", "failure",
		getActorID(c), userID, "user", map[string]interface{}{
			"route":  c.FullPath(),
			"method": method,
		})
	switch {
	case errors.Is(err, errNoAccountPassword):
		s.refuseFactorChange(c, userID, need, reauthRequired, method)
	case errors.Is(err, ErrAccountLocked), errors.Is(err, ErrTOTPLockedOut):
		s.refuseFactorChange(c, userID, need, reauthLocked, method)
	default:
		if err != nil {
			s.logger.Warn("factor-change proof could not be checked",
				zap.String("user_id", logsafe.Clean(userID)), zap.String("method", method), zap.Error(err))
		}
		s.refuseFactorChange(c, userID, need, reauthFailed, method)
	}
	return false
}

// refuseFactorChange answers a request whose proof is missing or wrong. It
// says which proofs this account can give for this change, so a client can ask
// for the right one; when there is none, the answer says so instead.
func (s *Service) refuseFactorChange(c *gin.Context, userID string, need proofNeed, code, tried string) {
	ctx := c.Request.Context()
	var accepts []string
	if hasPassword, err := s.hasCheckablePassword(ctx, userID); err == nil && hasPassword {
		accepts = append(accepts, "current_password")
	}
	if need.totp {
		accepts = append(accepts, "totp_code")
	}

	var description string
	switch {
	case code == reauthLocked:
		description = "Too many attempts. Try again later."
	case code == reauthFailed && tried == "password":
		description = "The password is not correct."
	case code == reauthFailed:
		description = "The code is not correct, or it has already been used."
	case len(accepts) == 2:
		description = "Confirm this change with your current password or a code from your authenticator app."
	case len(accepts) == 1 && accepts[0] == "totp_code":
		description = "Confirm this change with a code from your authenticator app."
	default:
		description = "Confirm this change with your current password."
	}
	if len(accepts) == 0 && code != reauthLocked {
		code = reauthUnavailable
		description = "This change needs your password, and your account has none here. Ask an administrator to make the change."
	}
	if accepts == nil {
		accepts = []string{}
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":             code,
		"error_description": description,
		"accepts":           accepts,
	})
}

// hasCheckablePassword reports whether verifyAccountPassword could accept a
// password for this account.
func (s *Service) hasCheckablePassword(ctx context.Context, userID string) (bool, error) {
	acct, err := s.passwordAccount(ctx, userID)
	if err != nil {
		return false, err
	}
	return acct.checkable(s.directoryService != nil), nil
}

type passwordAccount struct {
	username     string
	passwordHash string
	source       string
	directoryID  string
	lockedUntil  *time.Time
}

func (a passwordAccount) viaDirectory(haveDirectory bool) bool {
	return (a.source == "ldap" || a.source == "active_directory") && a.directoryID != "" && haveDirectory
}

func (a passwordAccount) checkable(haveDirectory bool) bool {
	if a.viaDirectory(haveDirectory) {
		return true
	}
	return a.source != "azure_ad" && a.passwordHash != ""
}

func (s *Service) passwordAccount(ctx context.Context, userID string) (passwordAccount, error) {
	var a passwordAccount
	org, err := orgctx.From(ctx)
	if err != nil {
		return a, err
	}
	err = s.db.Pool.QueryRow(ctx, `
		SELECT username, COALESCE(password_hash, ''), COALESCE(source, ''), COALESCE(directory_id::text, ''), locked_until
		FROM users WHERE id = $1 AND org_id = $2`, userID, org.ID).
		Scan(&a.username, &a.passwordHash, &a.source, &a.directoryID, &a.lockedUntil)
	return a, err
}

// verifyAccountPassword checks the account holder's password the way
// AuthenticateUser does: against the directory for an LDAP or Active Directory
// account, against the stored hash otherwise. A wrong password counts against
// the account's lockout, and a locked account is refused before the password
// is looked at, exactly as at sign-in; a right one clears the count.
func (s *Service) verifyAccountPassword(ctx context.Context, userID, password string) (bool, error) {
	acct, err := s.passwordAccount(ctx, userID)
	if err != nil {
		return false, err
	}
	if acct.lockedUntil != nil && time.Now().Before(*acct.lockedUntil) {
		return false, ErrAccountLocked
	}
	if !acct.checkable(s.directoryService != nil) {
		return false, errNoAccountPassword
	}

	if acct.viaDirectory(s.directoryService != nil) {
		if err := s.directoryService.AuthenticateUser(ctx, acct.directoryID, acct.username, password); err != nil {
			s.countFailedReauthentication(ctx, userID)
			return false, nil
		}
	} else {
		ok, _, verr := pwhash.Verify(acct.passwordHash, password)
		if verr != nil {
			s.logger.Error("Stored password hash is unreadable",
				zap.String("user_id", logsafe.Clean(userID)), zap.Error(verr))
		}
		if verr != nil || !ok {
			s.countFailedReauthentication(ctx, userID)
			return false, nil
		}
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET failed_login_count = 0, locked_until = NULL
		WHERE id = $1 AND org_id = $2 AND (failed_login_count > 0 OR locked_until IS NOT NULL)`,
		userID, org.ID); err != nil {
		s.logger.Warn("could not clear the failed-login count after a confirmed password", zap.Error(err))
	}
	return true, nil
}

// countFailedReauthentication applies the sign-in lockout to a wrong password
// given as proof. The error is logged and swallowed: the proof has already
// been refused.
func (s *Service) countFailedReauthentication(ctx context.Context, userID string) {
	if err := s.recordFailedLoginForUser(ctx, userID); err != nil {
		s.logger.Error("could not count a wrong password given as proof; the lockout may not bind",
			zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
	}
}
