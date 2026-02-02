package openidx.authz

import future.keywords.if
import future.keywords.in

default allow := false

# ─── Admin bypass ────────────────────────────────────────────────
# Admins can access everything
allow if {
    "admin" in input.user.roles
}

# ─── Authenticated read access ───────────────────────────────────
# Any authenticated user can read (GET/HEAD/OPTIONS)
allow if {
    input.method in {"GET", "HEAD", "OPTIONS"}
    input.user.authenticated
}

# ─── Resource ownership ─────────────────────────────────────────
# Users can modify their own resources
allow if {
    input.resource.owner != ""
    input.resource.owner == input.user.id
}

# ─── Fine-grained RBAC ──────────────────────────────────────────
# Map roles to specific resource types and methods

allow if {
    required_role := role_permissions[input.resource.type][input.method]
    required_role in input.user.roles
}

role_permissions := {
    "user": {
        "GET": "user-viewer",
        "POST": "user-admin",
        "PUT": "user-admin",
        "DELETE": "user-admin"
    },
    "group": {
        "GET": "group-viewer",
        "POST": "group-admin",
        "PUT": "group-admin",
        "DELETE": "group-admin"
    },
    "role": {
        "GET": "role-viewer",
        "POST": "role-admin",
        "PUT": "role-admin",
        "DELETE": "role-admin"
    },
    "application": {
        "GET": "app-viewer",
        "POST": "app-admin",
        "PUT": "app-admin",
        "DELETE": "app-admin"
    },
    "policy": {
        "GET": "policy-viewer",
        "POST": "policy-admin",
        "PUT": "policy-admin",
        "DELETE": "policy-admin"
    },
    "review": {
        "GET": "auditor",
        "POST": "auditor",
        "PUT": "auditor",
        "DELETE": "admin"
    },
    "organization": {
        "GET": "org-viewer",
        "POST": "org-admin",
        "PUT": "org-admin",
        "DELETE": "org-admin"
    },
    "route": {
        "GET": "access-viewer",
        "POST": "access-admin",
        "PUT": "access-admin",
        "DELETE": "access-admin"
    },
    "certificate": {
        "GET": "security-viewer",
        "POST": "security-admin",
        "PUT": "security-admin",
        "DELETE": "security-admin"
    },
    "identity": {
        "GET": "identity-viewer",
        "POST": "identity-admin",
        "PUT": "identity-admin",
        "DELETE": "identity-admin"
    }
}

# ─── Helpdesk role ───────────────────────────────────────────────
# Helpdesk can view and update users but not delete or create
allow if {
    "helpdesk" in input.user.roles
    input.resource.type == "user"
    input.method in {"GET", "PUT"}
}

# Helpdesk can view sessions
allow if {
    "helpdesk" in input.user.roles
    input.resource.type == "session"
    input.method == "GET"
}

# ─── Auditor role ────────────────────────────────────────────────
# Auditors can read audit events, reviews, and reports
allow if {
    "auditor" in input.user.roles
    input.resource.type in {"event", "report", "review", "statistic"}
    input.method == "GET"
}

# Auditors can create reports
allow if {
    "auditor" in input.user.roles
    input.resource.type == "report"
    input.method == "POST"
}

# ─── Self-service portal ────────────────────────────────────────
# Authenticated users can access portal endpoints
allow if {
    input.user.authenticated
    contains(input.path, "/portal/")
    input.method in {"GET", "POST", "PUT"}
}

# Authenticated users can manage their own notifications
allow if {
    input.user.authenticated
    contains(input.path, "/notifications")
}

# ─── Tenant isolation ───────────────────────────────────────────
# If tenant_id is set on both user and resource, they must match
deny[msg] if {
    input.user.tenant_id != ""
    input.resource.tenant_id != ""
    input.user.tenant_id != input.resource.tenant_id
    msg := "cross-tenant access denied"
}

# ─── Separation of duties ───────────────────────────────────────
# Prevent conflicting role combinations
deny[msg] if {
    conflicting_roles := sod_rules[_]
    all_present := [role | role := conflicting_roles[_]; role in input.user.roles]
    count(all_present) == count(conflicting_roles)
    msg := sprintf("separation of duties violation: conflicting roles %v", [conflicting_roles])
}

sod_rules := [
    ["approver", "requester"],
    ["auditor", "admin"]
]

# ─── Final decision ─────────────────────────────────────────────
# Deny overrides allow
final_allow if {
    allow
    count(deny) == 0
}
