package openidx.authz

import future.keywords.if
import future.keywords.in

default allow := false

# ─── Admin bypass ────────────────────────────────────────────────
# Admins can access everything
allow if {
    "admin" in input.user.roles
}

# ─── Privileged read access ──────────────────────────────────────
# This used to read "any authenticated user can GET anything", which made
# every rule below it unreachable -- the fine-grained RBAC table, the helpdesk
# and auditor rules and the path-scoped self-service rules were all consulted
# only for writes. Turning ENABLE_OPA_AUTHZ on therefore WIDENED read access
# on admin-api, governance and provisioning rather than restricting it: any
# authenticated end user could read every admin resource those services serve.
#
# Reads are now granted by role, using the role names the product actually
# issues (see internal/auth: super_admin > admin > operator > auditor > user).
# `admin` already has the bypass above. End users reach their own data through
# the path-scoped self-service rules further down, not through this.
allow if {
    input.method in {"GET", "HEAD", "OPTIONS"}
    some role in {"super_admin", "operator", "auditor"}
    role in input.user.roles
}

allow if {
    "super_admin" in input.user.roles
}

# ─── Resource ownership ─────────────────────────────────────────
# REMOVED, because it could never fire. The rule was:
#
#     allow if {
#         input.resource.owner != ""
#         input.resource.owner == input.user.id
#     }
#
# OPAAuthz builds its input from the REQUEST -- method, matched route, and the
# caller's claims. It never loads the row being addressed, so it cannot know who
# owns it: internal/common/opa.ResourceContext has an Owner field and nothing has
# ever set it, leaving input.resource.owner permanently absent and the first
# condition permanently false. Writing an owner in from what the middleware DOES
# know would be worse than deleting the rule -- it would compare the caller to
# themselves and read like a working ownership check.
#
# Ownership is enforced where the row is actually read: identity-service's
# self-service tier and the per-route ownership checks catalogued in
# internal/identity/authz_surface_test.go (a WHERE clause carrying the token's
# user id, or an explicit comparison), and access-service's assignment gate.
# internal/common/opa/policy_input_test.go fails if a rule here reads an input
# field the product does not send.

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

# ─── Groups-based access ────────────────────────────────────────
# Members of admin-group get full access
allow if {
    some group in input.user.groups
    group == "admin-group"
}

# ─── Tenant isolation ───────────────────────────────────────────
# REMOVED, for the same reason and with more at stake. The rule was:
#
#     deny[msg] if {
#         input.user.tenant_id != ""
#         input.resource.tenant_id != ""
#         input.user.tenant_id != input.resource.tenant_id
#         msg := "cross-tenant access denied"
#     }
#
# input.resource.tenant_id is not a field ResourceContext even has, so the second
# condition was never satisfiable and this deny has never produced a message. It
# read as the install's cross-tenant control and was not one.
#
# Cross-tenant access is refused at the database, not at an HTTP gate: every
# tenant-scoped table carries org_id under FORCE ROW LEVEL SECURITY, the policy
# reads app.org_id from the connection, and the request's org is resolved once by
# the TenantResolver middleware into orgctx. tools/orgscope fails the build on a
# table or a query that escapes that, derived from the migration registry rather
# than from a list. That is a stronger control than this rule described, and it
# does not depend on OPA being switched on.

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
