package migrations

// v179 — saml_service_providers.metadata_xml, the column the refresh writes to.
//
// A SAML service provider is registered either by URL or by pasting its
// metadata document, and the API accepts both (CreateSPRequest.MetadataXML).
// refreshSPMetadata then re-fetches that document on demand and rewrites the
// three fields that matter from it:
//
//	UPDATE saml_service_providers
//	SET entity_id = $1, acs_url = COALESCE($2, acs_url),
//	    certificate = COALESCE($3, certificate), metadata_xml = $4, ...
//
// The table has no metadata_xml column and never has, so that statement fails
// to plan and the whole refresh fails with it. The consequence is not a missing
// document: it is that **a service provider's rotated signing certificate never
// reaches this database**. An administrator clicks refresh, the operation
// errors, and assertions to that SP keep being signed against the old
// certificate until someone edits the record by hand.
//
// The document is worth keeping in its own right -- it is the evidence of what
// was fetched and what the parsed fields were derived from, and re-parsing it
// needs no second network call to a provider that may have changed since.
//
// TEXT and nullable, with no backfill: nothing has ever stored one, so every
// existing row's honest value is NULL, and a row's document arrives the first
// time its metadata is refreshed or re-uploaded.
const samlMetadataXMLUp = `-- Migration 179: the SAML SP metadata document.

ALTER TABLE saml_service_providers ADD COLUMN IF NOT EXISTS metadata_xml TEXT;
`

// Down drops the column. It loses the stored documents, which are recoverable
// by refreshing each SP from its metadata_url -- which is what the product does
// anyway, and what it could not do before this migration.
const samlMetadataXMLDown = `
ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS metadata_xml;
`
