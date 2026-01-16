package openidx.authz

import future.keywords.if
import future.keywords.in

default allow := false

# Allow if user has admin role
allow if {
    "admin" in input.user.roles
}

# Allow read access for authenticated users
allow if {
    input.method == "GET"
    input.user.authenticated
}

# Allow users to access their own resources
allow if {
    input.resource.owner == input.user.id
}

# Role-based permissions
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
    }
}

# Separation of Duties - prevent conflicting roles
deny[msg] if {
    conflicting_roles := sod_rules[_]
    all_present := [role | role := conflicting_roles[_]; role in input.user.roles]
    count(all_present) == count(conflicting_roles)
    msg := sprintf("Separation of duties violation: user has conflicting roles %v", [conflicting_roles])
}

sod_rules := [
    ["approver", "requester"],
    ["auditor", "admin"]
]
