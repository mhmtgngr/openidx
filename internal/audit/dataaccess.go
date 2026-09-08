package audit

// What this product's audit trail calls a data access.
//
// The GDPR report's data-access section counted `event_type = 'data_access'`.
// Nothing has ever written that value. It is declared as EventTypeDataAccess in
// service.go and appears nowhere else in the tree except the four queries that
// filter on it, so TotalAccessEvents, AccessByActor, AccessByDataType and
// LastAccessLog were all empty on every report ever generated, and
// ComplianceStatus was permanently "partial" -- a control reporting that this
// installation cannot account for who read what.
//
// A CORRECTION. An earlier commit on this branch fixed the by-data-type query,
// which asked for a resource_type column audit_events does not have, and said
// the section "has therefore been empty in every report". The column was one
// reason and not the reason: with the column corrected the section is still
// empty, because the predicate above matches no row. Half a diagnosis reads
// like a whole one once the code compiles, which is the failure this file
// exists to end.
//
// SO WHAT IS A DATA ACCESS HERE. The audit trail records reads as an action
// under event_type 'authorization' (internal/access's logAuditEvent stamps that
// event type for every proxy and PAM event). Five of those actions are somebody
// reading protected data:
//
//	pam.entry_revealed              a stored credential shown to a person
//	pam.credential_injected         a stored credential handed to a session
//	guacamole_credential_injected   the same, on the Guacamole path
//	guacamole.recording_downloaded  a session recording taken off the system --
//	                                everything that was typed and seen
//	guacamole.transcript_downloaded the same, as text
//
// Deliberately NOT in the list: pam.entry_connected and pam.ws_connect, which
// establish a session rather than read stored data, and pam.checkout_released,
// which returns custody rather than taking it. A control that counts session
// establishment as a data access overstates, and an overstated control is as
// useless to an auditor as an empty one.
//
// dataaccess_test.go holds every name here against the tree: an action nothing
// writes fails, because the whole defect was a predicate matching nothing.
var DataAccessActions = []string{
	"pam.entry_revealed",
	"pam.credential_injected",
	"guacamole_credential_injected",
	"guacamole.recording_downloaded",
	"guacamole.transcript_downloaded",
}
