package identity

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/openidx/openidx/internal/common/netutil"

	"golang.org/x/crypto/bcrypt"
)

// ValidatePasswordPolicyChecks validates a password against policy requirements
// and returns a list of all violation messages. An empty slice means the password is valid.
func (s *Service) ValidatePasswordPolicyChecks(password string) []string {
	var violations []string

	if len(password) < 8 {
		violations = append(violations, "password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if !hasUpper {
		violations = append(violations, "password must contain at least one uppercase letter")
	}
	if !hasLower {
		violations = append(violations, "password must contain at least one lowercase letter")
	}
	if !hasDigit {
		violations = append(violations, "password must contain at least one digit")
	}
	if !hasSpecial {
		violations = append(violations, "password must contain at least one special character")
	}

	return violations
}

// CheckPasswordHistory checks whether the given password was previously used by the user.
// Returns true if the password was previously used.
func (s *Service) CheckPasswordHistory(ctx context.Context, userID, newPassword string, historyCount int) (bool, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT password_hash FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, historyCount)
	if err != nil {
		return false, fmt.Errorf("failed to query password history: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return false, fmt.Errorf("failed to scan password history row: %w", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)); err == nil {
			return true, nil
		}
	}

	return false, nil
}

// SavePasswordHistory stores a password hash in the password_history table for the given user.
func (s *Service) SavePasswordHistory(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)
	`, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("failed to save password history: %w", err)
	}
	return nil
}

// CheckCompromisedPassword checks if a password has been exposed in known data breaches
// using the HaveIBeenPwned k-anonymity API.
// Uses SSRF protection to ensure requests only go to the legitimate HIBP API.
func (s *Service) CheckCompromisedPassword(ctx context.Context, password string) (bool, int, error) {
	h := sha1.New()
	h.Write([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	prefix := fullHash[:5]
	suffix := fullHash[5:]

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	// SSRF protection: validate URL before making request
	if err := netutil.KnownPublicAPIs.HIBP.ValidateURL(url); err != nil {
		return false, 0, fmt.Errorf("SSRF validation failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, 0, fmt.Errorf("failed to create HIBP request: %w", err)
	}
	req.Header.Set("User-Agent", "OpenIDX-Security-Check")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("HIBP API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read HIBP response: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.ToUpper(parts[0]) == suffix {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return true, count, nil
		}
	}

	return false, 0, nil
}

// CheckPasswordExpiration checks if a user's password has expired based on a 90-day maximum age.
func (s *Service) CheckPasswordExpiration(ctx context.Context, userID string) (bool, int, error) {
	var passwordChangedAt *time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT password_changed_at FROM users WHERE id = $1
	`, userID).Scan(&passwordChangedAt)
	if err != nil {
		return false, 0, fmt.Errorf("failed to query user password_changed_at: %w", err)
	}

	maxAgeDays := 90

	if passwordChangedAt == nil {
		return true, 0, nil
	}

	elapsed := time.Since(*passwordChangedAt)
	maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
	remaining := maxAge - elapsed
	daysRemaining := int(remaining.Hours() / 24)

	if daysRemaining < 0 {
		daysRemaining = 0
	}

	expired := elapsed > maxAge

	return expired, daysRemaining, nil
}
