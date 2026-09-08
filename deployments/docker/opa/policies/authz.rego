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

# FIVE ROWS WERE REMOVED FROM THIS TABLE because no request OPA ever sees can
# match them. This policy guards admin-api, governance and provisioning -- the
# three services that wire OPAAuthz -- and none of them serves a group, a role,
# an identity, a certificate or a proxy route:
#
#     "group", "role", "identity"  -> identity-service, which does not wire OPA
#     "certificate"                -> admin-api's certificate surface is not
#                                     registered under the v1 group OPA guards
#     "route"                      -> access-service, which does not wire OPA
#
# So `group-viewer`, `group-admin`, `role-admin`, `identity-admin`,
# `security-admin` and `access-admin` were role names an operator could read
# here as enforced permissions, and granting or withholding them changed
# nothing. Guarding those services is the real fix and each is its own decision
# (identity-service has eight deliberately anonymous routes; access-service has
# fourteen; audit-service has an open service-to-service ingest endpoint), so
# until one is made the table names only what it governs.
# internal/common/middleware/opa_resource_census_test.go derives these keys from
# this file and fails if one becomes unreachable again.
role_permissions := {
    "user": {
        "GET": "user-viewer",
        "POST": "user-admin",
        "PUT": "user-admin",
        "DELETE": "user-admin"
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
# Auditors can read audit events, reviews and statistics.
#
# "report" USED TO BE IN THIS SET, and there was a second rule below it letting
# an auditor POST one. Neither could fire. The only /reports routes in the
# product are audit-service's, and audit-service does not wire OPAAuthz -- only
# admin-api, governance and provisioning do -- so no request this policy ever
# sees carries resource type "report". The rules read as auditor permissions on
# reporting and governed nothing.
#
# Guarding audit-service is the real fix and it is not a one-line change: its
# read/export/stream routes authenticate with middleware.Auth, while
# POST /api/v1/audit/events is deliberately left open for network-isolated
# service-to-service ingestion (cmd/audit-service/main.go). Putting OPA in front
# of that service means deciding what happens to the ingest path, which is how
# every credential reveal and posture verdict reaches the trail. Until that is
# answered, the policy says what it governs.
allow if {
    "auditor" in input.user.roles
    input.resource.type in {"event", "review", "statistic"}
    input.method == "GET"
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
