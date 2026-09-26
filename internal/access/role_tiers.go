package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// THE CONSOLE'S ROLE TIERS, ENFORCED ON THE ROUTES BEHIND ITS PAGES.
//
// The admin console shows a page to a caller whose roles reach the page's tier:
// navigation.ts itemVisible calls hasMinRole in web/admin-console/src/lib/roles.ts
// with the item's minRole. The tiers are ordered user 0, auditor 1, operator 2,
// admin 3, super_admin 4; a caller's level is the highest any of their roles
// reaches; a role outside that order counts as user; and compliance_reader
// counts as auditor, but only for the audit domain's pages (the third argument
// of hasMinRole, domain === 'audit'). The quick links already filter on the
// same order, so the gates below read it from quickLinkRoleRank rather than
// keeping a second copy.
//
// Pages the console gives to operators -- Remote Support, Agent Fleet, Devices,
// Users, the Ops Cockpit, Network Topology -- and to auditors -- Unified Audit
// -- were backed by routes that asked only for authentication, so a caller the
// console would never show the page to could call the routes behind it. These
// gates hold the routes to the page's tier.
//
// They check roles and nothing else. requireAdminRole also asks an admin WRITE
// for a recently verified second factor under STEPUP_GATE; these do not,
// because the operator routes include ending a remote session and uploading its
// recording, which the step-up census deliberately keeps free of a freshness
// check (stepup_route_census_test.go). A route that needs a fresh factor carries
// requireFreshMFA as well.

// complianceReaderRole reaches the auditor tier in the audit domain only.
const complianceReaderRole = "compliance_reader"

// callerTierRank returns the highest tier rank the roles reach, as the
// console's roleLevel computes it.
func callerTierRank(roles []string, auditDomain bool) int {
	best := quickLinkRank("user")
	for _, r := range roles {
		if r == complianceReaderRole {
			if auditDomain {
				best = max(best, quickLinkRank("auditor"))
			}
			continue
		}
		best = max(best, quickLinkRank(r))
	}
	return best
}

// requireTier admits a caller whose roles reach tier. DevAdminBypass admits
// everyone, as it does for requireAdminRole: it makes every caller an admin,
// and admin is above every tier gated here.
func (s *Service) requireTier(tier string, auditDomain bool) gin.HandlerFunc {
	need := quickLinkRank(tier)
	return func(c *gin.Context) {
		if s.config != nil && s.config.DevAdminBypass {
			c.Next()
			return
		}
		if callerTierRank(pamCallerRoles(c), auditDomain) >= need {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": tier + " access required"})
	}
}

// requireOperatorTier admits operator, admin and super_admin: the console's
// operator pages.
func (s *Service) requireOperatorTier() gin.HandlerFunc { return s.requireTier("operator", false) }

// requireAuditTier admits auditor, compliance_reader, operator, admin and
// super_admin: the console's audit pages.
func (s *Service) requireAuditTier() gin.HandlerFunc { return s.requireTier("auditor", true) }
