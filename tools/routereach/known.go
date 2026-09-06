package main

// knownUnmounted records each handler-shaped function no route mounts, with
// what its absence from the route table costs.
//
// The entry is a verdict, not a name. A register of names is a way to move a
// finding off a report; a register of verdicts is the finding, written down.
// An unregistered finding fails the run and so does an entry that no longer
// reproduces, so this map can only shrink.
//
// Three groups, three different defects:
//
//   - internal/identity/handler.go is a complete second user and group CRUD
//     implementation that no router has ever mounted. Its cost is not the dead
//     lines: it is the ONLY caller of emitUserLifecycleEvent and
//     emitGroupLifecycleEvent, so seven of the webhook event types this product
//     advertises have never been published by any install.
//   - internal/oauth/discovery.go is a second OpenID Connect discovery document
//     with a 415-line test suite, beside the one internal/oauth/service.go
//     actually serves. The tests pass and describe a document no relying party
//     ever fetches.
//   - the remaining two are a duplicate settings writer and an alias kept "for
//     compatibility" with a caller that does not exist.
var knownUnmounted = map[string]string{
	"admin.handleUpdateSettings": "A second writer for the system settings blob, beside admin/handlers.UpdateSettings, " +
		"which is the one routes.go mounts on PUT /settings. Its only caller anywhere is service_test.go, so the " +
		"test that covers it proves the behaviour of a handler no request can reach.",

	"identity.HandleCreateUser": "The unmounted twin of service.go's handleCreateUser. It emits the user.created " +
		"webhook; the mounted one publishes that event too, so this pair is the one place the two implementations agree.",
	"identity.HandleGetUser": "The unmounted twin of service.go's handleGetUser. It checks the caller's tenant_id " +
		"against the user's organisation in the handler; the mounted one gets the same isolation from the user " +
		"repository, which reads a cross-tenant id as not-found.",
	"identity.HandleUpdateUser": "The unmounted twin of service.go's handleUpdateUser, and the only emitter of the " +
		"user.updated webhook. An operator subscribed to user.updated has never received one.",
	"identity.HandleDeleteUser": "The unmounted twin of service.go's handleDeleteUser. It enforces tenant isolation " +
		"and emits user.deleted; the mounted one does neither from this path.",
	"identity.HandleListUsers": "The unmounted twin of service.go's handleListUsers, with a different pagination " +
		"contract (page/limit against offset/limit) that no client has ever spoken.",
	"identity.HandleSearchUsers": "The unmounted twin of service.go's handleSearchUsers. Nothing routes to it, so its " +
		"search semantics have never been exercised by a request.",
	"identity.HandleCreateGroup": "The unmounted twin of service.go's handleCreateGroup, and the only emitter of the " +
		"group.created webhook. No install has ever published one.",
	"identity.HandleGetGroup": "The unmounted twin of service.go's handleGetGroup. Dead alongside the rest of the " +
		"file rather than for any reason of its own.",
	"identity.HandleUpdateGroup": "The unmounted twin of service.go's handleUpdateGroup, and the only emitter of the " +
		"group.updated webhook -- an event type internal/webhooks declares as a constant and nothing publishes.",
	"identity.HandleDeleteGroup": "The unmounted twin of service.go's handleDeleteGroup, and the only emitter of the " +
		"group.deleted webhook. No install has ever published one.",
	"identity.HandleListGroups": "The unmounted twin of service.go's handleListGroups. Dead alongside the rest of the " +
		"file rather than for any reason of its own.",
	"identity.HandleGetGroupMembers": "The unmounted twin of service.go's handleGetGroupMembers. Dead alongside the " +
		"rest of the file rather than for any reason of its own.",
	"identity.HandleAddGroupMember": "The unmounted twin of service.go's handleAddGroupMember, and the only emitter " +
		"of group.member_added -- the event a downstream system needs to grant access when somebody joins a group.",
	"identity.HandleRemoveGroupMember": "The unmounted twin of service.go's handleRemoveGroupMember, and the only " +
		"emitter of group.member_removed -- the event a downstream system needs in order to REVOKE access when " +
		"somebody leaves a group. Nothing has ever sent it.",

	"oauth.HandleDiscovery": "A second OpenID Connect discovery handler, serving a document built by " +
		"buildDiscoveryDocument, beside service.go's handleDiscovery which every relying party actually fetches. " +
		"discovery_test.go is 415 lines proving this one correct; the served document is a different struct with " +
		"per-tenant issuers, and keeping the two in step is manual and undeclared.",
	"oauth.HandleIdPMetadataRequest": "An exported alias for handleIdPMetadata, added \"for compatibility\" with a " +
		"caller that does not exist in this tree. The SAML IdP metadata route mounts the unexported one.",
}
