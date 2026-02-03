// Package access - Enhanced device health checks for Duo feature parity
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DeviceHealthCheck represents an enhanced device health check
type DeviceHealthCheck struct {
	CheckType   string                 `json:"check_type"`
	Passed      bool                   `json:"passed"`
	Details     map[string]interface{} `json:"details"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Remediation string                 `json:"remediation,omitempty"`
}

// DeviceHealthReport represents a complete device health assessment
type DeviceHealthReport struct {
	DeviceID      string              `json:"device_id"`
	IdentityID    string              `json:"identity_id"`
	OverallPassed bool                `json:"overall_passed"`
	Score         float64             `json:"score"` // 0.0 - 1.0
	Checks        []DeviceHealthCheck `json:"checks"`
	AssessedAt    time.Time           `json:"assessed_at"`
	ExpiresAt     *time.Time          `json:"expires_at,omitempty"`
	Critical      int                 `json:"critical_failures"`
	High          int                 `json:"high_failures"`
	Medium        int                 `json:"medium_failures"`
	Low           int                 `json:"low_failures"`
}

// DevicePostureData represents device posture information reported by the client
type DevicePostureData struct {
	OS              string  `json:"os"`
	OSVersion       string  `json:"os_version"`
	OSBuild         string  `json:"os_build,omitempty"`
	PatchDate       string  `json:"patch_date,omitempty"` // YYYY-MM-DD
	Jailbroken      *bool   `json:"jailbroken,omitempty"`
	Rooted          *bool   `json:"rooted,omitempty"`
	DiskEncrypted   *bool   `json:"disk_encrypted,omitempty"`
	ScreenLockEnabled *bool `json:"screen_lock_enabled,omitempty"`
	ScreenLockTimeout *int  `json:"screen_lock_timeout,omitempty"` // seconds
	FirewallEnabled *bool   `json:"firewall_enabled,omitempty"`
	AntivirusActive *bool   `json:"antivirus_active,omitempty"`
	AntivirusName   string  `json:"antivirus_name,omitempty"`
	DeviceName      string  `json:"device_name,omitempty"`
	DeviceModel     string  `json:"device_model,omitempty"`
	SerialNumber    string  `json:"serial_number,omitempty"`
	Domain          string  `json:"domain,omitempty"`
	MACAddresses    []string `json:"mac_addresses,omitempty"`
	RunningProcesses []string `json:"running_processes,omitempty"`
}

// OSVersionRequirement defines minimum OS version requirements
type OSVersionRequirement struct {
	OS         string `json:"os"`
	MinVersion string `json:"min_version"`
}

// Enhanced check types that Duo supports but basic posture checks don't
const (
	CheckTypeOSVersion   = "OS_VERSION"
	CheckTypePatchLevel  = "PATCH_LEVEL"
	CheckTypeIntegrity   = "INTEGRITY"     // Jailbreak/root detection
	CheckTypeEncryption  = "ENCRYPTION"    // Disk encryption
	CheckTypeScreenLock  = "SCREEN_LOCK"   // Screen lock settings
	CheckTypeFirewall    = "FIREWALL"      // Firewall status
	CheckTypeAntivirus   = "ANTIVIRUS"     // Antivirus status
	CheckTypeDomain      = "DOMAIN"        // Domain membership
	CheckTypeMAC         = "MAC"           // MAC address whitelist
	CheckTypeProcess     = "PROCESS"       // Required running processes
	CheckTypeMFA         = "MFA"           // MFA status
)

// EvaluateDeviceHealth runs all enabled posture checks against device data
func (zm *ZitiManager) EvaluateDeviceHealth(ctx context.Context, identityID string, posture *DevicePostureData) (*DeviceHealthReport, error) {
	// Get all enabled posture checks
	checks, err := zm.ListPostureChecks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get posture checks: %w", err)
	}

	report := &DeviceHealthReport{
		IdentityID:    identityID,
		OverallPassed: true,
		Score:         1.0,
		Checks:        make([]DeviceHealthCheck, 0),
		AssessedAt:    time.Now(),
	}

	for _, check := range checks {
		if !check.Enabled {
			continue
		}

		result := zm.evaluateCheck(&check, posture)
		report.Checks = append(report.Checks, result)

		if !result.Passed {
			report.OverallPassed = false
			switch result.Severity {
			case "critical":
				report.Critical++
			case "high":
				report.High++
			case "medium":
				report.Medium++
			case "low":
				report.Low++
			}
		}

		// Store result in database
		zm.RecordPostureResult(ctx, identityID, check.ID, result.Passed, result.Details)
	}

	// Calculate score
	if len(report.Checks) > 0 {
		passed := 0
		for _, c := range report.Checks {
			if c.Passed {
				passed++
			}
		}
		report.Score = float64(passed) / float64(len(report.Checks))
	}

	// Set expiration (re-check required after 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)
	report.ExpiresAt = &expiresAt

	return report, nil
}

// evaluateCheck evaluates a single posture check against device data
func (zm *ZitiManager) evaluateCheck(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		CheckType: check.CheckType,
		Severity:  check.Severity,
		Details:   make(map[string]interface{}),
	}

	switch check.CheckType {
	case CheckTypeOSVersion:
		result = zm.evaluateOSVersion(check, posture)
	case CheckTypePatchLevel:
		result = zm.evaluatePatchLevel(check, posture)
	case CheckTypeIntegrity:
		result = zm.evaluateIntegrity(check, posture)
	case CheckTypeEncryption:
		result = zm.evaluateEncryption(check, posture)
	case CheckTypeScreenLock:
		result = zm.evaluateScreenLock(check, posture)
	case CheckTypeFirewall:
		result = zm.evaluateFirewall(check, posture)
	case CheckTypeAntivirus:
		result = zm.evaluateAntivirus(check, posture)
	case "OS":
		result = zm.evaluateOS(check, posture)
	case CheckTypeDomain:
		result = zm.evaluateDomain(check, posture)
	case CheckTypeMAC:
		result = zm.evaluateMAC(check, posture)
	case CheckTypeProcess:
		result = zm.evaluateProcess(check, posture)
	default:
		result.Passed = true
		result.Message = "Unknown check type, skipping"
	}

	result.CheckType = check.CheckType
	result.Severity = check.Severity
	if check.RemediationHint != "" {
		result.Remediation = check.RemediationHint
	}

	return result
}

// evaluateOSVersion checks if the OS version meets minimum requirements
func (zm *ZitiManager) evaluateOSVersion(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{
			"os":            posture.OS,
			"os_version":    posture.OSVersion,
		},
	}

	// Get required OS and version from parameters
	requiredOS, _ := check.Parameters["os"].(string)
	minVersion, _ := check.Parameters["min_version"].(string)

	if requiredOS == "" || minVersion == "" {
		result.Passed = true
		result.Message = "OS version check not configured"
		return result
	}

	// Check if OS matches
	if !strings.EqualFold(posture.OS, requiredOS) {
		result.Passed = true // Different OS, not applicable
		result.Message = fmt.Sprintf("Check not applicable (different OS: %s)", posture.OS)
		return result
	}

	// Compare versions
	if compareVersions(posture.OSVersion, minVersion) >= 0 {
		result.Passed = true
		result.Message = fmt.Sprintf("OS version %s meets minimum requirement %s", posture.OSVersion, minVersion)
	} else {
		result.Passed = false
		result.Message = fmt.Sprintf("OS version %s is below minimum requirement %s", posture.OSVersion, minVersion)
		result.Remediation = fmt.Sprintf("Update your %s to version %s or higher", posture.OS, minVersion)
	}

	return result
}

// evaluatePatchLevel checks if security patches are current
func (zm *ZitiManager) evaluatePatchLevel(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{
			"patch_date": posture.PatchDate,
		},
	}

	maxAgeDays, _ := check.Parameters["max_age_days"].(float64)
	if maxAgeDays == 0 {
		maxAgeDays = 30 // Default 30 days
	}

	if posture.PatchDate == "" {
		result.Passed = false
		result.Message = "Security patch date not reported"
		result.Remediation = "Update your device to the latest security patch"
		return result
	}

	patchDate, err := time.Parse("2006-01-02", posture.PatchDate)
	if err != nil {
		result.Passed = false
		result.Message = "Invalid patch date format"
		return result
	}

	daysSincePatch := time.Since(patchDate).Hours() / 24
	result.Details["days_since_patch"] = int(daysSincePatch)

	if daysSincePatch <= maxAgeDays {
		result.Passed = true
		result.Message = fmt.Sprintf("Security patch is current (%.0f days old)", daysSincePatch)
	} else {
		result.Passed = false
		result.Message = fmt.Sprintf("Security patch is outdated (%.0f days old, max allowed: %.0f)", daysSincePatch, maxAgeDays)
		result.Remediation = "Install the latest security updates for your device"
	}

	return result
}

// evaluateIntegrity checks for jailbreak/root detection
func (zm *ZitiManager) evaluateIntegrity(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	allowJailbroken, _ := check.Parameters["allow_jailbroken"].(bool)
	allowRooted, _ := check.Parameters["allow_rooted"].(bool)

	// Check jailbreak status (iOS)
	if posture.Jailbroken != nil {
		result.Details["jailbroken"] = *posture.Jailbroken
		if *posture.Jailbroken && !allowJailbroken {
			result.Passed = false
			result.Message = "Device is jailbroken"
			result.Remediation = "Access is not allowed from jailbroken devices for security reasons"
			return result
		}
	}

	// Check root status (Android/Linux)
	if posture.Rooted != nil {
		result.Details["rooted"] = *posture.Rooted
		if *posture.Rooted && !allowRooted {
			result.Passed = false
			result.Message = "Device is rooted"
			result.Remediation = "Access is not allowed from rooted devices for security reasons"
			return result
		}
	}

	result.Passed = true
	result.Message = "Device integrity check passed"
	return result
}

// evaluateEncryption checks if disk encryption is enabled
func (zm *ZitiManager) evaluateEncryption(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	requireFullDisk, _ := check.Parameters["require_full_disk"].(bool)

	if posture.DiskEncrypted == nil {
		result.Passed = false
		result.Message = "Disk encryption status not reported"
		result.Remediation = "Enable full disk encryption on your device"
		return result
	}

	result.Details["disk_encrypted"] = *posture.DiskEncrypted

	if requireFullDisk && !*posture.DiskEncrypted {
		result.Passed = false
		result.Message = "Full disk encryption is not enabled"
		result.Remediation = "Enable BitLocker (Windows), FileVault (macOS), or device encryption (mobile)"
		return result
	}

	result.Passed = true
	result.Message = "Disk encryption is enabled"
	return result
}

// evaluateScreenLock checks screen lock configuration
func (zm *ZitiManager) evaluateScreenLock(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	requirePin, _ := check.Parameters["require_pin"].(bool)
	minTimeout, _ := check.Parameters["min_timeout_seconds"].(float64)

	if posture.ScreenLockEnabled == nil {
		result.Passed = false
		result.Message = "Screen lock status not reported"
		result.Remediation = "Enable screen lock with a PIN, password, or biometric"
		return result
	}

	result.Details["screen_lock_enabled"] = *posture.ScreenLockEnabled
	if posture.ScreenLockTimeout != nil {
		result.Details["screen_lock_timeout"] = *posture.ScreenLockTimeout
	}

	if requirePin && !*posture.ScreenLockEnabled {
		result.Passed = false
		result.Message = "Screen lock is not enabled"
		result.Remediation = "Enable screen lock with a PIN, password, or biometric authentication"
		return result
	}

	if minTimeout > 0 && posture.ScreenLockTimeout != nil {
		if float64(*posture.ScreenLockTimeout) > minTimeout {
			result.Passed = false
			result.Message = fmt.Sprintf("Screen lock timeout (%ds) exceeds maximum allowed (%.0fs)", *posture.ScreenLockTimeout, minTimeout)
			result.Remediation = fmt.Sprintf("Set screen lock timeout to %.0f seconds or less", minTimeout)
			return result
		}
	}

	result.Passed = true
	result.Message = "Screen lock configuration is compliant"
	return result
}

// evaluateFirewall checks if firewall is enabled
func (zm *ZitiManager) evaluateFirewall(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	requireEnabled, _ := check.Parameters["require_enabled"].(bool)

	if posture.FirewallEnabled == nil {
		result.Passed = false
		result.Message = "Firewall status not reported"
		result.Remediation = "Enable the system firewall"
		return result
	}

	result.Details["firewall_enabled"] = *posture.FirewallEnabled

	if requireEnabled && !*posture.FirewallEnabled {
		result.Passed = false
		result.Message = "Firewall is not enabled"
		result.Remediation = "Enable Windows Firewall (Windows), Firewall (macOS), or iptables/ufw (Linux)"
		return result
	}

	result.Passed = true
	result.Message = "Firewall is enabled"
	return result
}

// evaluateAntivirus checks if antivirus is active
func (zm *ZitiManager) evaluateAntivirus(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	requireRunning, _ := check.Parameters["require_running"].(bool)

	if posture.AntivirusActive == nil {
		result.Passed = false
		result.Message = "Antivirus status not reported"
		result.Remediation = "Install and enable antivirus software"
		return result
	}

	result.Details["antivirus_active"] = *posture.AntivirusActive
	if posture.AntivirusName != "" {
		result.Details["antivirus_name"] = posture.AntivirusName
	}

	if requireRunning && !*posture.AntivirusActive {
		result.Passed = false
		result.Message = "Antivirus is not active"
		result.Remediation = "Install and enable antivirus software (Windows Defender, Malwarebytes, etc.)"
		return result
	}

	result.Passed = true
	if posture.AntivirusName != "" {
		result.Message = fmt.Sprintf("Antivirus (%s) is active", posture.AntivirusName)
	} else {
		result.Message = "Antivirus is active"
	}
	return result
}

// evaluateOS checks basic OS requirements
func (zm *ZitiManager) evaluateOS(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{
			"os": posture.OS,
		},
	}

	allowedOS, ok := check.Parameters["operating_systems"].([]interface{})
	if !ok || len(allowedOS) == 0 {
		result.Passed = true
		result.Message = "No OS restrictions configured"
		return result
	}

	for _, os := range allowedOS {
		osStr, _ := os.(string)
		if strings.EqualFold(posture.OS, osStr) {
			result.Passed = true
			result.Message = fmt.Sprintf("Operating system %s is allowed", posture.OS)
			return result
		}
	}

	result.Passed = false
	result.Message = fmt.Sprintf("Operating system %s is not in the allowed list", posture.OS)
	return result
}

// evaluateDomain checks domain membership
func (zm *ZitiManager) evaluateDomain(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{
			"domain": posture.Domain,
		},
	}

	requiredDomains, ok := check.Parameters["domains"].([]interface{})
	if !ok || len(requiredDomains) == 0 {
		result.Passed = true
		result.Message = "No domain requirements configured"
		return result
	}

	if posture.Domain == "" {
		result.Passed = false
		result.Message = "Device is not joined to a domain"
		result.Remediation = "Join the device to an approved domain"
		return result
	}

	for _, domain := range requiredDomains {
		domainStr, _ := domain.(string)
		if strings.EqualFold(posture.Domain, domainStr) || strings.HasSuffix(strings.ToLower(posture.Domain), "."+strings.ToLower(domainStr)) {
			result.Passed = true
			result.Message = fmt.Sprintf("Device is joined to approved domain: %s", posture.Domain)
			return result
		}
	}

	result.Passed = false
	result.Message = fmt.Sprintf("Device domain %s is not in the approved list", posture.Domain)
	return result
}

// evaluateMAC checks MAC address whitelist
func (zm *ZitiManager) evaluateMAC(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{
			"mac_addresses": posture.MACAddresses,
		},
	}

	allowedMACs, ok := check.Parameters["mac_addresses"].([]interface{})
	if !ok || len(allowedMACs) == 0 {
		result.Passed = true
		result.Message = "No MAC address restrictions configured"
		return result
	}

	if len(posture.MACAddresses) == 0 {
		result.Passed = false
		result.Message = "No MAC addresses reported by device"
		return result
	}

	for _, deviceMAC := range posture.MACAddresses {
		normalizedDeviceMAC := normalizeMAC(deviceMAC)
		for _, allowedMAC := range allowedMACs {
			macStr, _ := allowedMAC.(string)
			if normalizeMAC(macStr) == normalizedDeviceMAC {
				result.Passed = true
				result.Message = "MAC address is in the approved list"
				return result
			}
		}
	}

	result.Passed = false
	result.Message = "None of the device MAC addresses are in the approved list"
	return result
}

// evaluateProcess checks for required running processes
func (zm *ZitiManager) evaluateProcess(check *PostureCheck, posture *DevicePostureData) DeviceHealthCheck {
	result := DeviceHealthCheck{
		Details: map[string]interface{}{},
	}

	requiredProcess, _ := check.Parameters["process"].(string)
	if requiredProcess == "" {
		result.Passed = true
		result.Message = "No process check configured"
		return result
	}

	if len(posture.RunningProcesses) == 0 {
		result.Passed = false
		result.Message = "Process list not reported"
		result.Remediation = fmt.Sprintf("Ensure %s is running", requiredProcess)
		return result
	}

	for _, proc := range posture.RunningProcesses {
		if strings.EqualFold(proc, requiredProcess) || strings.Contains(strings.ToLower(proc), strings.ToLower(requiredProcess)) {
			result.Passed = true
			result.Details["found_process"] = proc
			result.Message = fmt.Sprintf("Required process %s is running", requiredProcess)
			return result
		}
	}

	result.Passed = false
	result.Message = fmt.Sprintf("Required process %s is not running", requiredProcess)
	result.Remediation = fmt.Sprintf("Start the %s application", requiredProcess)
	return result
}

// --- Helper Functions ---

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	parts1 := splitVersion(v1)
	parts2 := splitVersion(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}

	return 0
}

func splitVersion(version string) []int {
	var parts []int
	current := 0
	for _, c := range version {
		if c >= '0' && c <= '9' {
			current = current*10 + int(c-'0')
		} else if c == '.' {
			parts = append(parts, current)
			current = 0
		}
	}
	parts = append(parts, current)
	return parts
}

// normalizeMAC normalizes a MAC address to lowercase without separators
func normalizeMAC(mac string) string {
	var result strings.Builder
	for _, c := range strings.ToLower(mac) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// SeedEnhancedPostureChecks creates default enhanced posture checks
func (zm *ZitiManager) SeedEnhancedPostureChecks(ctx context.Context) error {
	defaultChecks := []PostureCheck{
		{
			Name:            "Windows 10+ Required",
			CheckType:       CheckTypeOSVersion,
			Parameters:      map[string]interface{}{"os": "Windows", "min_version": "10.0.0"},
			Enabled:         false,
			Severity:        "high",
			RemediationHint: "Upgrade to Windows 10 or higher",
		},
		{
			Name:            "macOS 12+ Required",
			CheckType:       CheckTypeOSVersion,
			Parameters:      map[string]interface{}{"os": "macOS", "min_version": "12.0.0"},
			Enabled:         false,
			Severity:        "high",
			RemediationHint: "Upgrade to macOS Monterey (12) or higher",
		},
		{
			Name:            "Security Patch Current (30 days)",
			CheckType:       CheckTypePatchLevel,
			Parameters:      map[string]interface{}{"max_age_days": float64(30)},
			Enabled:         false,
			Severity:        "critical",
			RemediationHint: "Install the latest security updates",
		},
		{
			Name:            "No Jailbreak/Root",
			CheckType:       CheckTypeIntegrity,
			Parameters:      map[string]interface{}{"allow_jailbroken": false, "allow_rooted": false},
			Enabled:         false,
			Severity:        "critical",
			RemediationHint: "Access denied from compromised devices",
		},
		{
			Name:            "Full Disk Encryption Required",
			CheckType:       CheckTypeEncryption,
			Parameters:      map[string]interface{}{"require_full_disk": true},
			Enabled:         false,
			Severity:        "high",
			RemediationHint: "Enable BitLocker, FileVault, or device encryption",
		},
		{
			Name:            "Screen Lock Required",
			CheckType:       CheckTypeScreenLock,
			Parameters:      map[string]interface{}{"require_pin": true, "min_timeout_seconds": float64(300)},
			Enabled:         false,
			Severity:        "medium",
			RemediationHint: "Enable screen lock with 5-minute timeout or less",
		},
		{
			Name:            "Firewall Enabled",
			CheckType:       CheckTypeFirewall,
			Parameters:      map[string]interface{}{"require_enabled": true},
			Enabled:         false,
			Severity:        "medium",
			RemediationHint: "Enable the system firewall",
		},
		{
			Name:            "Antivirus Active",
			CheckType:       CheckTypeAntivirus,
			Parameters:      map[string]interface{}{"require_running": true},
			Enabled:         false,
			Severity:        "high",
			RemediationHint: "Install and enable antivirus software",
		},
	}

	for _, check := range defaultChecks {
		// Check if already exists by name
		existing, _ := zm.GetPostureCheckByName(ctx, check.Name)
		if existing != nil {
			continue
		}

		if err := zm.CreatePostureCheck(ctx, &check); err != nil {
			zm.logger.Warn("Failed to seed posture check",
				zm.logger.With([]interface{}{"name", check.Name, "error", err.Error()}...).Sugar())
		}
	}

	return nil
}

// GetPostureCheckByName retrieves a posture check by name
func (zm *ZitiManager) GetPostureCheckByName(ctx context.Context, name string) (*PostureCheck, error) {
	query := `
		SELECT id, ziti_id, name, check_type, parameters, enabled, severity, remediation_hint, created_at, updated_at
		FROM posture_checks
		WHERE name = $1
	`

	var check PostureCheck
	var paramsJSON []byte
	err := zm.db.Pool.QueryRow(ctx, query, name).Scan(
		&check.ID,
		&check.ZitiID,
		&check.Name,
		&check.CheckType,
		&paramsJSON,
		&check.Enabled,
		&check.Severity,
		&check.RemediationHint,
		&check.CreatedAt,
		&check.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if len(paramsJSON) > 0 {
		json.Unmarshal(paramsJSON, &check.Parameters)
	}

	return &check, nil
}
