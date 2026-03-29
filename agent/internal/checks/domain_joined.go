package checks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DomainCheck verifies whether the device is joined to an Active Directory or
// Kerberos realm.
//
// Linux: runs `realm list` to query the sssd/realmd realm membership. If realm
// is unavailable, falls back to checking for the existence of /etc/krb5.conf.
//
// macOS: runs `dsconfigad -show` and checks whether a domain is configured.
//
// All other operating systems receive a StatusWarn result.
type DomainCheck struct{}

// Name implements Check.
func (c *DomainCheck) Name() string { return "domain_joined" }

// Run implements Check.
func (c *DomainCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkMacOS()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("domain join check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

func (c *DomainCheck) checkLinux() *CheckResult {
	details := map[string]interface{}{
		"os": "linux",
	}

	// Try realm list first.
	out, err := exec.Command("realm", "list").Output()
	if err == nil {
		output := strings.TrimSpace(string(out))
		if output == "" {
			details["method"] = "realm"
			return &CheckResult{
				Status:      StatusFail,
				Score:       0,
				Details:     details,
				Message:     "device is not joined to any realm",
				Remediation: "Join the device to a domain with `sudo realm join <domain>`.",
			}
		}
		// Extract the domain name from the first line of realm list output.
		domain := strings.SplitN(output, "\n", 2)[0]
		details["method"] = "realm"
		details["domain"] = domain
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: fmt.Sprintf("device is joined to realm: %s", domain),
		}
	}

	// Fall back to krb5.conf existence.
	if _, err := os.Stat("/etc/krb5.conf"); err == nil {
		details["method"] = "krb5.conf"
		details["domain"] = "unknown (krb5.conf present)"
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "/etc/krb5.conf exists; device appears to be Kerberos-configured",
		}
	}

	details["method"] = "none"
	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "device is not domain-joined (realm unavailable and /etc/krb5.conf not found)",
		Remediation: "Join the device to a domain using realmd or configure Kerberos.",
	}
}

func (c *DomainCheck) checkMacOS() *CheckResult {
	details := map[string]interface{}{
		"os":     "darwin",
		"method": "dsconfigad",
	}

	out, err := exec.Command("dsconfigad", "-show").Output()
	if err != nil {
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     "dsconfigad -show returned an error; device is not domain-joined",
			Remediation: "Bind the device to an Active Directory domain via System Settings > Users & Groups > Network Account Server.",
		}
	}

	output := string(out)
	if strings.Contains(output, "Active Directory Domain") {
		// Extract the domain value if possible.
		domain := "unknown"
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "Active Directory Domain") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					domain = strings.TrimSpace(parts[1])
				}
				break
			}
		}
		details["domain"] = domain
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: fmt.Sprintf("device is joined to Active Directory domain: %s", domain),
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "device is not joined to an Active Directory domain",
		Remediation: "Bind the device to an Active Directory domain via System Settings > Users & Groups > Network Account Server.",
	}
}
