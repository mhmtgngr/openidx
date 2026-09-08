package main

// knownUnmounted records each handler-shaped function no route mounts, with
// what its absence from the route table costs.
//
// It is empty, and that is the finished state of a sweep rather than a check
// that was turned off: routereach -fail stops the build on the next handler no
// router mounts, and on the next c.Param naming something its route does not
// declare.
//
// The register opened at 17.
//
//   - Fourteen were internal/identity/handler.go, a complete second
//     user-and-group CRUD implementation no router had ever mounted, and the
//     only caller of the two webhook emitters -- so six event types the
//     subscription form offered had never been published by any install. The
//     file is deleted, the emitters run from the mounted handlers, and
//     internal/webhooks/catalogue_test.go now fails on an event nothing sends.
//   - internal/oauth/discovery.go was a second OpenID Connect discovery
//     document with a 415-line test suite beside the one every relying party
//     actually fetches. Because the tests covered the dead one, the drift
//     between them was invisible: the SERVED document omitted
//     revocation_endpoint and introspection_endpoint (both routed) and "none"
//     from token_endpoint_auth_methods_supported (public clients exist and the
//     token endpoint skips secret verification for them). The three omissions
//     are fixed, the dead implementation deleted, and the assertions moved onto
//     the live handler.
//   - admin.handleUpdateSettings was a second writer for the system settings
//     blob whose only caller was its own test; routes.go mounts the other one.
//   - oauth.HandleIdPMetadataRequest was an alias kept "for compatibility" with
//     a caller that does not exist in this tree.
//
// An entry here must say what the absence costs, not merely name the function:
// a register of names is a way to move a finding off a report.
var knownUnmounted = map[string]string{}
