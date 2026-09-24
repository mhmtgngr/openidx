package openidx.authz_test

import future.keywords.if

import data.openidx.authz

# Both halves of the rules authz.rego grants on, with the input shape
# internal/common/opa.Input sends: the caller's claims, the method, the path
# and the resource type inferred from the matched route. A rule that grants
# what it names and refuses what it does not name passes; one that grants
# nothing, or everything, fails a half.
#
# These live outside policies/ on purpose: the compose stack and the chart
# serve that directory, and a test file there would be loaded into the
# running OPA. CI runs them with `opa test policies tests`.

caller(roles, method, path, resource_type) := {
	"user": {"id": "u-1", "roles": roles, "authenticated": true},
	"method": method,
	"path": path,
	"resource": {"type": resource_type},
}

test_an_admin_may_do_anything if {
	authz.allow with input as caller(["admin"], "DELETE", "/api/v1/users/u-9", "user")
}

test_a_plain_user_may_not_read_an_admin_resource if {
	not authz.allow with input as caller(["user"], "GET", "/api/v1/users", "user")
}

test_nobody_is_allowed_by_default if {
	not authz.allow with input as caller([], "GET", "/api/v1/policies", "policy")
}

test_an_operator_may_read_but_not_write if {
	authz.allow with input as caller(["operator"], "GET", "/api/v1/policies", "policy")
	not authz.allow with input as caller(["operator"], "DELETE", "/api/v1/policies/p-1", "policy")
}

test_the_rbac_table_grants_only_its_own_method if {
	authz.allow with input as caller(["app-admin"], "POST", "/api/v1/applications", "application")
	not authz.allow with input as caller(["app-viewer"], "POST", "/api/v1/applications", "application")
}

test_the_rbac_table_grants_only_its_own_resource if {
	authz.allow with input as caller(["user-admin"], "PUT", "/api/v1/users/u-9", "user")
	not authz.allow with input as caller(["user-admin"], "PUT", "/api/v1/applications/a-1", "application")
}

test_helpdesk_updates_users_but_does_not_delete_them if {
	authz.allow with input as caller(["helpdesk"], "PUT", "/api/v1/users/u-9", "user")
	not authz.allow with input as caller(["helpdesk"], "DELETE", "/api/v1/users/u-9", "user")
}

test_an_auditor_reads_events_but_writes_none if {
	authz.allow with input as caller(["auditor"], "GET", "/api/v1/events", "event")
	not authz.allow with input as caller(["auditor"], "POST", "/api/v1/events", "event")
}

test_self_service_needs_an_authenticated_caller if {
	authz.allow with input as caller(["user"], "GET", "/api/v1/portal/apps", "")
	not authz.allow with input as {
		"user": {"id": "", "roles": ["user"], "authenticated": false},
		"method": "GET",
		"path": "/api/v1/portal/apps",
		"resource": {"type": ""},
	}
}

test_separation_of_duties_denies_conflicting_roles if {
	count(authz.deny) > 0 with input as caller(["approver", "requester"], "GET", "/api/v1/reviews", "review")
	count(authz.deny) == 0 with input as caller(["approver"], "GET", "/api/v1/reviews", "review")
}

test_a_duty_conflict_overrides_even_the_admin_bypass if {
	not authz.final_allow with input as caller(["admin", "auditor"], "GET", "/api/v1/users", "user")
	authz.final_allow with input as caller(["admin"], "GET", "/api/v1/users", "user")
}
