package auth

// Role represents a user role in the system
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleOperator Role = "operator"
	RoleAuditor  Role = "auditor"
	RoleUser     Role = "user"
)

// RoleHierarchy defines role inheritance relationships.
// Each role inherits all permissions from roles in its inherited list.
// For example, Admin inherits from Operator, Auditor, and User.
var RoleHierarchy = map[Role][]Role{
	RoleAdmin: {
		RoleOperator,
		RoleAuditor,
		RoleUser,
	},
	RoleOperator: {
		RoleUser,
	},
	RoleAuditor: {
		RoleUser,
	},
	RoleUser: {}, // Base role, no inheritance
}

// Permission represents a granular permission on a resource
type Permission struct {
	Resource string
	Action   string
}

// HasPermission checks if the role has been granted a specific permission.
// It checks both direct permissions and inherited permissions.
func (r Role) HasPermission(p Permission) bool {
	// Check direct permissions
	for _, perm := range DefaultPermissions[r] {
		if perm.Resource == p.Resource && perm.Action == p.Action {
			return true
		}
	}

	// Check inherited permissions
	if inherited, exists := RoleHierarchy[r]; exists {
		for _, parentRole := range inherited {
			if parentRole.HasPermission(p) {
				return true
			}
		}
	}

	return false
}

// Inherits checks if the role inherits from the specified child role.
// Returns true if the child role is in the role's inheritance chain.
func (r Role) Inherits(child Role) bool {
	if inherited, exists := RoleHierarchy[r]; exists {
		for _, parentRole := range inherited {
			if parentRole == child {
				return true
			}
			// Recursively check nested inheritance
			if parentRole.Inherits(child) {
				return true
			}
		}
	}
	return false
}

// DefaultPermissions defines the default permission set for each role.
var DefaultPermissions = map[Role][]Permission{
	RoleAdmin: {
		// User management
		{Resource: "users", Action: "create"},
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "update"},
		{Resource: "users", Action: "delete"},
		{Resource: "users", Action: "impersonate"},

		// Role management
		{Resource: "roles", Action: "create"},
		{Resource: "roles", Action: "read"},
		{Resource: "roles", Action: "update"},
		{Resource: "roles", Action: "delete"},
		{Resource: "roles", Action: "assign"},

		// Policy management
		{Resource: "policies", Action: "create"},
		{Resource: "policies", Action: "read"},
		{Resource: "policies", Action: "update"},
		{Resource: "policies", Action: "delete"},
		{Resource: "policies", Action: "execute"},

		// Access reviews
		{Resource: "reviews", Action: "create"},
		{Resource: "reviews", Action: "read"},
		{Resource: "reviews", Action: "update"},
		{Resource: "reviews", Action: "delete"},
		{Resource: "reviews", Action: "approve"},
		{Resource: "reviews", Action: "deny"},

		// Audit logs
		{Resource: "audit", Action: "read"},
		{Resource: "audit", Action: "export"},
		{Resource: "audit", Action: "purge"},

		// System settings
		{Resource: "settings", Action: "read"},
		{Resource: "settings", Action: "update"},

		// Applications
		{Resource: "applications", Action: "create"},
		{Resource: "applications", Action: "read"},
		{Resource: "applications", Action: "update"},
		{Resource: "applications", Action: "delete"},

		// API Keys
		{Resource: "apikeys", Action: "create"},
		{Resource: "apikeys", Action: "read"},
		{Resource: "apikeys", Action: "update"},
		{Resource: "apikeys", Action: "delete"},

		// Directory integration
		{Resource: "directory", Action: "read"},
		{Resource: "directory", Action: "configure"},
		{Resource: "directory", Action: "sync"},

		// SCIM provisioning
		{Resource: "scim", Action: "read"},
		{Resource: "scim", Action: "write"},
		{Resource: "scim", Action: "configure"},

		// Dashboard
		{Resource: "dashboard", Action: "read"},
	},

	RoleOperator: {
		// User management (read and update only)
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "update"},

		// Role management (read only)
		{Resource: "roles", Action: "read"},

		// Policy management (read and execute)
		{Resource: "policies", Action: "read"},
		{Resource: "policies", Action: "execute"},

		// Access reviews (read and approve/deny)
		{Resource: "reviews", Action: "read"},
		{Resource: "reviews", Action: "approve"},
		{Resource: "reviews", Action: "deny"},

		// Audit logs (read and export)
		{Resource: "audit", Action: "read"},
		{Resource: "audit", Action: "export"},

		// System settings (read only)
		{Resource: "settings", Action: "read"},

		// Applications (read and update)
		{Resource: "applications", Action: "read"},
		{Resource: "applications", Action: "update"},

		// API Keys (create, read, delete)
		{Resource: "apikeys", Action: "create"},
		{Resource: "apikeys", Action: "read"},
		{Resource: "apikeys", Action: "delete"},

		// Directory integration (read and sync)
		{Resource: "directory", Action: "read"},
		{Resource: "directory", Action: "sync"},

		// SCIM provisioning (read and write)
		{Resource: "scim", Action: "read"},
		{Resource: "scim", Action: "write"},

		// Dashboard
		{Resource: "dashboard", Action: "read"},
	},

	RoleAuditor: {
		// User management (read only)
		{Resource: "users", Action: "read"},

		// Role management (read only)
		{Resource: "roles", Action: "read"},

		// Policy management (read only)
		{Resource: "policies", Action: "read"},

		// Access reviews (read only)
		{Resource: "reviews", Action: "read"},

		// Audit logs (full access)
		{Resource: "audit", Action: "read"},
		{Resource: "audit", Action: "export"},

		// System settings (read only)
		{Resource: "settings", Action: "read"},

		// Applications (read only)
		{Resource: "applications", Action: "read"},

		// API Keys (read only)
		{Resource: "apikeys", Action: "read"},

		// Directory integration (read only)
		{Resource: "directory", Action: "read"},

		// SCIM provisioning (read only)
		{Resource: "scim", Action: "read"},

		// Dashboard
		{Resource: "dashboard", Action: "read"},
	},

	RoleUser: {
		// User self-management
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "update"},

		// Policy management (execute only - for self-service access)
		{Resource: "policies", Action: "execute"},

		// Access reviews (participate in reviews for own access)
		{Resource: "reviews", Action: "read"},

		// Applications (read only - for SSO access)
		{Resource: "applications", Action: "read"},

		// API Keys (manage own keys)
		{Resource: "apikeys", Action: "create"},
		{Resource: "apikeys", Action: "read"},
		{Resource: "apikeys", Action: "delete"},

		// Dashboard
		{Resource: "dashboard", Action: "read"},
	},
}
