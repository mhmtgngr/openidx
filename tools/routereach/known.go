package main

// knownUnmounted records each handler-shaped function no route mounts, with
// what its absence from the route table costs.
//
// The entry is a verdict, not a name. A register of names is a way to move a
// finding off a report; a register of verdicts is the finding, written down.
// An unregistered finding fails the run and so does an entry that no longer
// reproduces, so this map can only shrink.
//
// Opened at 17. internal/identity/handler.go was fourteen of them — a complete
// second user-and-group CRUD implementation no router had ever mounted, and the
// only caller of the two webhook emitters, so six event types the subscription
// form offers had never been published by any install. The file is deleted, the
// emitters run from the mounted handlers, and internal/webhooks/catalogue_test.go
// now fails on an event type nothing sends.
//
// The three that remain:
//
//   - internal/oauth/discovery.go is a second OpenID Connect discovery document
//     with a 415-line test suite, beside the one internal/oauth/service.go
//     actually serves. The tests pass and describe a document no relying party
//     ever fetches.
//   - a duplicate settings writer whose only caller is its own test.
//   - an alias kept "for compatibility" with a caller that does not exist.
var knownUnmounted = map[string]string{
	"admin.handleUpdateSettings": "A second writer for the system settings blob, beside admin/handlers.UpdateSettings, " +
		"which is the one routes.go mounts on PUT /settings. Its only caller anywhere is service_test.go, so the " +
		"test that covers it proves the behaviour of a handler no request can reach.",

	"oauth.HandleDiscovery": "A second OpenID Connect discovery handler, serving a document built by " +
		"buildDiscoveryDocument, beside service.go's handleDiscovery which every relying party actually fetches. " +
		"discovery_test.go is 415 lines proving this one correct; the served document is a different struct with " +
		"per-tenant issuers, and keeping the two in step is manual and undeclared.",
	"oauth.HandleIdPMetadataRequest": "An exported alias for handleIdPMetadata, added \"for compatibility\" with a " +
		"caller that does not exist in this tree. The SAML IdP metadata route mounts the unexported one.",
}
